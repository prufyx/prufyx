// SPDX-License-Identifier: AGPL-3.0-only

// Package rederiverenew holds the checks of the scheduled renewal workflow:
// which mechanical records are due, whether two independent derivations are
// byte-identical, and which of an applied pack's changes are renewals. Only
// a record that was due, that a new derivation at the planned time renewed,
// and that changed in nothing but its times (and its extractor build and
// sources when the build changed) is carried into the result; every other
// byte of the base pack is kept.
//
// It admits nothing: the knowledge gate re-derives the change on its own.
package rederiverenew

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	// PlanSchema identifies a renewal plan.
	PlanSchema = "prufyx.io/rederive-plan/v1"
	// DueWindow is how close to its end a record must be to be renewed.
	DueWindow = 45 * 24 * time.Hour
	// MaxLease bounds validUntil minus derivedAt of a renewed record.
	MaxLease = 90 * 24 * time.Hour
	// MinLeaseDays and leaseSpread give planned leases of 76 to 90 days.
	MinLeaseDays = 76
	leaseSpread  = 15
	// MaxAge and ClockSkew bound the derivation time against the clock.
	MaxAge    = 24 * time.Hour
	ClockSkew = 5 * time.Minute
	// MaxRecords is the hard cap on the records of one change, whatever the
	// caller asks for.
	MaxRecords = 45
	// familyPrefix is the only extractor family renewed here.
	familyPrefix        = "crd.version-removal."
	kubernetesComponent = "pkg:github/kubernetes/kubernetes"
	maxRunFiles         = 4096
	maxRunFileBytes     = 64 << 20
)

// ErrRefused is wrapped by every refusal.
var ErrRefused = errors.New("renewal refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRefused}, args...)...)
}

var extractorIDRE = regexp.MustCompile(`^crd\.version-removal\.[a-z0-9][a-z0-9-]{0,62}$`)

// Plan is the work of one run: one derivation time, and per extractor its
// repository, lease and due records.
type Plan struct {
	Schema     string      `json:"schema"`
	DerivedAt  string      `json:"derivedAt"`
	Extractors []Extractor `json:"extractors"`
	// Deferred are the extractors with due records that did not fit the cap.
	Deferred []string `json:"deferred"`
}

// Extractor is the work of one extractor.
type Extractor struct {
	ID        string   `json:"id"`
	Repo      string   `json:"repo"`
	LeaseDays int      `json:"leaseDays"`
	Records   []string `json:"records"`
}

// item is one record of a pack that carries evidence.
type item struct {
	key       string // "rule <id>" or "attestation <component> <family> <line>"
	index     int    // position in entries or lineAttestations
	attest    bool
	raw       json.RawMessage
	generic   map[string]any
	component string
}

type parsed struct {
	pack  *extractpack.Pack
	atts  []json.RawMessage
	items map[string]*item
}

func generic(raw []byte) (map[string]any, error) {
	if err := strictjson.Check(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil || v == nil {
		return nil, errors.New("not a JSON object")
	}
	return v, nil
}

func text(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func object(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	return o
}

// evidence is the evidence object of an item.
func (i *item) evidence() map[string]any { return evidenceOf(i.generic, i.attest) }

func evidenceOf(g map[string]any, attest bool) map[string]any {
	if attest {
		return object(g, "evidence")
	}
	return object(object(g, "rule"), "evidence")
}

func parsePack(raw []byte) (*parsed, error) {
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		return nil, err
	}
	out := &parsed{pack: p, items: map[string]*item{}}
	add := func(i *item) error {
		if _, dup := out.items[i.key]; dup {
			return refuse("%s appears twice", i.key)
		}
		out.items[i.key] = i
		return nil
	}
	for n, e := range p.Entries {
		g, err := generic(e)
		if err != nil {
			return nil, refuse("entry %d: %v", n, err)
		}
		rule := object(g, "rule")
		id := text(rule, "id")
		if id == "" {
			return nil, refuse("entry %d has no rule id", n)
		}
		if err := add(&item{key: "rule " + id, index: n, raw: e, generic: g, component: text(object(rule, "subject"), "component")}); err != nil {
			return nil, err
		}
	}
	if m, ok := p.Members[lineattest.PackMember]; ok {
		if err := json.Unmarshal(m, &out.atts); err != nil {
			return nil, refuse("line attestations: %v", err)
		}
	}
	for n, a := range out.atts {
		g, err := generic(a)
		if err != nil {
			return nil, refuse("line attestation %d: %v", n, err)
		}
		c, f, l := text(g, "component"), text(g, "factFamily"), text(g, "line")
		if c == "" || f == "" || l == "" {
			return nil, refuse("line attestation %d has no key", n)
		}
		if err := add(&item{key: "attestation " + c + " " + f + " " + l, index: n, attest: true, raw: a, generic: g, component: c}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// due returns the extractor of a record that this workflow may renew at at:
// active mechanical evidence of a renewed family, not of Kubernetes, whose
// validUntil is at most DueWindow after at.
func due(i *item, at time.Time) (string, time.Time, bool) {
	ev := i.evidence()
	id := text(object(ev, "extractor"), "id")
	if text(ev, "basis") != "mechanical" || !extractorIDRE.MatchString(id) || !strings.HasPrefix(id, familyPrefix) {
		return "", time.Time{}, false
	}
	if !i.attest && text(ev, "state") != "active" {
		return "", time.Time{}, false
	}
	if i.component == "" || i.component == kubernetesComponent {
		return "", time.Time{}, false
	}
	until, err := time.Parse(time.RFC3339, text(ev, "validUntil"))
	if err != nil || until.Sub(at) > DueWindow {
		return "", time.Time{}, false
	}
	return id, until, true
}

func leaseDays(id string, at time.Time) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return MinLeaseDays + int((h.Sum32()%leaseSpread+uint32(at.YearDay())%leaseSpread)%leaseSpread)
}

func parseStamp(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		return time.Time{}, refuse("%q is not a UTC time like 2026-10-02T00:00:00Z", s)
	}
	return t, nil
}

// fresh refuses a derivation time after the clock (beyond the skew) or
// older than MaxAge.
func fresh(at, now time.Time) error {
	if at.After(now.Add(ClockSkew)) {
		return refuse("the derivation time %s is in the future", at.Format(time.RFC3339))
	}
	if at.Before(now.Add(-MaxAge)) {
		return refuse("the derivation time %s is more than 24 hours old", at.Format(time.RFC3339))
	}
	return nil
}

// MakePlan lists the work at derivedAt: whole extractors, soonest end first,
// while their due records fit max (at most MaxRecords). repo names the
// repository of a registered extractor.
func MakePlan(packRaw []byte, derivedAt string, now time.Time, max int, repo func(id string) (string, bool)) (Plan, error) {
	plan := Plan{Schema: PlanSchema, DerivedAt: derivedAt, Extractors: []Extractor{}, Deferred: []string{}}
	at, err := parseStamp(derivedAt)
	if err != nil {
		return plan, err
	}
	if err := fresh(at, now); err != nil {
		return plan, err
	}
	if max < 0 || max > MaxRecords {
		return plan, refuse("the record cap must be 0-%d", MaxRecords)
	}
	p, err := parsePack(packRaw)
	if err != nil {
		return plan, err
	}
	records := map[string][]string{}
	first := map[string]time.Time{}
	for key, i := range p.items {
		id, until, ok := due(i, at)
		if !ok {
			continue
		}
		records[id] = append(records[id], key)
		if f, seen := first[id]; !seen || until.Before(f) {
			first[id] = until
		}
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if !first[ids[i]].Equal(first[ids[j]]) {
			return first[ids[i]].Before(first[ids[j]])
		}
		return ids[i] < ids[j]
	})
	used := 0
	for _, id := range ids {
		if used+len(records[id]) > max {
			plan.Deferred = append(plan.Deferred, id)
			continue
		}
		r, ok := repo(id)
		if !ok {
			return plan, refuse("extractor %s of a due record is not registered", id)
		}
		used += len(records[id])
		sort.Strings(records[id])
		plan.Extractors = append(plan.Extractors, Extractor{ID: id, Repo: r, LeaseDays: leaseDays(id, at), Records: records[id]})
	}
	sort.Slice(plan.Extractors, func(i, j int) bool { return plan.Extractors[i].ID < plan.Extractors[j].ID })
	return plan, nil
}

// readRun reads a run directory: regular files only.
func readRun(dir string) (map[string][]byte, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, refuse("%s is not a directory", dir)
	}
	out := map[string][]byte{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || fi.Size() > maxRunFileBytes || len(out) >= maxRunFiles {
			return refuse("%s is not a plain run file", path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, refuse("%s holds no files", dir)
	}
	return out, nil
}

// Compare requires two run directories to hold the same files with the same
// bytes, and returns the digest of that content.
func Compare(a, b string) (string, error) {
	x, err := readRun(a)
	if err != nil {
		return "", err
	}
	y, err := readRun(b)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(x))
	for name := range x {
		if _, ok := y[name]; !ok {
			return "", refuse("the two derivations differ: only the first holds %s", name)
		}
		names = append(names, name)
	}
	if len(x) != len(y) {
		return "", refuse("the two derivations differ: the second holds more files")
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		if !bytes.Equal(x[name], y[name]) {
			return "", refuse("the two derivations differ in %s", name)
		}
		fmt.Fprintf(h, "%s\x00%x\n", name, sha256.Sum256(x[name]))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Renewal is one record the result renews.
type Renewal struct {
	Record     string
	Extractor  string
	Version    string
	CodeDigest string
}

// Result says what Assemble carried.
type Result struct {
	Renewed []Renewal
	// NotRenewed are planned records the derivation left as they were.
	NotRenewed []string
	// LeftOut counts other differences of the applied pack (new records and
	// records that were not planned); they belong to the ordinary intake and
	// are not carried.
	LeftOut int
}

// renewalOf checks that nw is a renewal of the due record old at at with the
// planned lease.
func renewalOf(old, nw *item, extractorID string, at time.Time, lease int) (Renewal, error) {
	var none Renewal
	o, n := old.evidence(), nw.evidence()
	oe, ne := object(o, "extractor"), object(n, "extractor")
	if o == nil || n == nil || text(n, "basis") != "mechanical" || (!nw.attest && text(n, "state") != "active") {
		return none, refuse("%s: the derivation is not active mechanical evidence", old.key)
	}
	if text(ne, "id") != extractorID || text(ne, "version") == "" || text(ne, "codeDigest") == "" {
		return none, refuse("%s: the derivation names another extractor", old.key)
	}
	sameBuild := text(oe, "version") == text(ne, "version") && text(oe, "codeDigest") == text(ne, "codeDigest")
	if sources, _ := n["sources"].([]any); len(sources) == 0 {
		return none, refuse("%s: the derivation cites no source", old.key)
	}
	oldDerived, err1 := time.Parse(time.RFC3339, text(o, "derivedAt"))
	oldUntil, err2 := time.Parse(time.RFC3339, text(o, "validUntil"))
	if err1 != nil || err2 != nil {
		return none, refuse("%s: the base times cannot be read", old.key)
	}
	stamp := at.Format("2006-01-02T15:04:05Z")
	if text(n, "derivedAt") != stamp || text(n, "reviewedAt") != stamp || !at.After(oldDerived) {
		return none, refuse("%s: derivedAt and reviewedAt must both be the planned derivation time, after the old one", old.key)
	}
	until, err := parseStamp(text(n, "validUntil"))
	if err != nil {
		return none, err
	}
	switch life := until.Sub(at); {
	case life <= 0 || life > MaxLease:
		return none, refuse("%s: the lease must be over 0 and at most 90 days", old.key)
	case life != time.Duration(lease)*24*time.Hour:
		return none, refuse("%s: the lease is not the planned %d days", old.key, lease)
	case !until.After(oldUntil):
		return none, refuse("%s: validUntil is not later than before", old.key)
	}
	// Everything else is equal, the lease member and the range included.
	mutable := []string{"derivedAt", "reviewedAt", "validUntil"}
	if !sameBuild {
		mutable = append(mutable, "extractor", "sources")
	}
	rest := func(i *item) ([]byte, error) {
		g, err := generic(i.raw)
		if err != nil {
			return nil, err
		}
		ev := evidenceOf(g, i.attest)
		for _, k := range mutable {
			delete(ev, k)
		}
		return extract.Canonical(g)
	}
	a, err1 := rest(old)
	b, err2 := rest(nw)
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		return none, refuse("%s: the derivation changes more than a renewal may; it belongs to the ordinary intake", old.key)
	}
	return Renewal{Record: old.key, Extractor: extractorID, Version: text(ne, "version"), CodeDigest: text(ne, "codeDigest")}, nil
}

// Assemble returns the base pack with the planned records replaced by their
// renewals from applied. The plan is not trusted for what is due: a record
// it names that is not due in the base, or a record list that is not exactly
// the base's due records of that extractor, refuses the run.
func Assemble(baseRaw, appliedRaw []byte, plan Plan, now time.Time, max int) ([]byte, Result, error) {
	var res Result
	fail := func(err error) ([]byte, Result, error) { return nil, Result{}, err }
	if plan.Schema != PlanSchema || len(plan.Extractors) == 0 {
		return fail(refuse("the plan is empty or of another schema"))
	}
	at, err := parseStamp(plan.DerivedAt)
	if err != nil {
		return fail(err)
	}
	if err := fresh(at, now); err != nil {
		return fail(err)
	}
	if max < 1 || max > MaxRecords {
		return fail(refuse("the record cap must be 1-%d", MaxRecords))
	}
	base, err := parsePack(baseRaw)
	if err != nil {
		return fail(err)
	}
	if same, err := base.pack.Render(); err != nil || !bytes.Equal(same, baseRaw) {
		return fail(refuse("the base pack is not in its canonical rendering"))
	}
	applied, err := parsePack(appliedRaw)
	if err != nil {
		return fail(err)
	}
	head, err := parsePack(baseRaw)
	if err != nil {
		return fail(err)
	}
	seen := map[string]bool{}
	renewed := map[string]bool{}
	for _, x := range plan.Extractors {
		if seen[x.ID] || !extractorIDRE.MatchString(x.ID) || len(x.Records) == 0 || x.LeaseDays < MinLeaseDays || x.LeaseDays >= MinLeaseDays+leaseSpread {
			return fail(refuse("the plan entry of %q is not usable", x.ID))
		}
		seen[x.ID] = true
		want := map[string]bool{}
		for key, i := range base.items {
			if id, _, ok := due(i, at); ok && id == x.ID {
				want[key] = true
			}
		}
		if len(want) != len(x.Records) {
			return fail(refuse("%s: the planned records are not the due records of the base", x.ID))
		}
		for _, key := range x.Records {
			if !want[key] {
				return fail(refuse("%s: %s is not due in the base, or is planned twice", x.ID, key))
			}
			delete(want, key)
			old, nw := base.items[key], applied.items[key]
			if nw == nil {
				return fail(refuse("%s is missing from the applied pack", key))
			}
			a, err1 := extract.Canonical(old.generic)
			b, err2 := extract.Canonical(nw.generic)
			if err1 != nil || err2 != nil {
				return fail(refuse("%s cannot be compared", key))
			}
			if bytes.Equal(a, b) {
				res.NotRenewed = append(res.NotRenewed, key)
				continue
			}
			r, err := renewalOf(old, nw, x.ID, at, x.LeaseDays)
			if err != nil {
				return fail(err)
			}
			res.Renewed = append(res.Renewed, r)
			renewed[key] = true
			if old.attest {
				head.atts[old.index] = nw.raw
			} else {
				head.pack.Entries[old.index] = nw.raw
			}
		}
	}
	if len(res.Renewed) == 0 {
		return fail(refuse("no planned record was renewed"))
	}
	if len(res.Renewed) > max {
		return fail(refuse("%d renewals are over the cap of %d", len(res.Renewed), max))
	}
	for key, nw := range applied.items {
		if renewed[key] {
			continue
		}
		old := base.items[key]
		if old == nil {
			res.LeftOut++
			continue
		}
		a, err1 := extract.Canonical(old.generic)
		b, err2 := extract.Canonical(nw.generic)
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			res.LeftOut++
		}
	}
	if _, ok := head.pack.Members[lineattest.PackMember]; ok {
		// Joined by hand: json.Marshal would escape <, > and & inside the
		// records, and the pack keeps them as they are.
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, a := range head.atts {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(a)
		}
		buf.WriteByte(']')
		if !json.Valid(buf.Bytes()) {
			return fail(refuse("the line attestations cannot be rendered"))
		}
		head.pack.Members[lineattest.PackMember] = buf.Bytes()
	}
	out, err := head.pack.Render()
	if err != nil {
		return fail(err)
	}
	sort.Slice(res.Renewed, func(i, j int) bool { return res.Renewed[i].Record < res.Renewed[j].Record })
	sort.Strings(res.NotRenewed)
	return out, res, nil
}

// Run identifies the workflow run a change came from. It records, it does
// not authenticate: the knowledge gate re-derives the change.
type Run struct {
	ID, Attempt, Commit, WorkflowSHA string
}

var (
	numberRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Origin renders the origin block of the commit message and pull request.
// Every value is required; outputs holds the compared run digest of each
// renewed extractor.
func Origin(run Run, plan Plan, res Result, outputs map[string]string) (string, error) {
	if !numberRE.MatchString(run.ID) || !numberRE.MatchString(run.Attempt) || !commitRE.MatchString(run.Commit) || !commitRE.MatchString(run.WorkflowSHA) {
		return "", refuse("the origin is incomplete: run id, attempt, commit and workflow commit are required")
	}
	if len(res.Renewed) == 0 {
		return "", refuse("the origin names no renewed record")
	}
	leases := map[string]int{}
	for _, x := range plan.Extractors {
		leases[x.ID] = x.LeaseDays
	}
	var ids []string
	lines := map[string]bool{}
	for _, r := range res.Renewed {
		if !digestRE.MatchString(outputs[r.Extractor]) || !digestRE.MatchString(r.CodeDigest) || strings.ContainsAny(r.Version, " \r\n") {
			return "", refuse("the origin is incomplete: %s has no output digest or code digest", r.Extractor)
		}
		ids = append(ids, r.Record)
		lines[fmt.Sprintf("Origin-Extractor: %s version=%s codeDigest=%s leaseDays=%d output=%s", r.Extractor, r.Version, r.CodeDigest, leases[r.Extractor], outputs[r.Extractor])] = true
	}
	sort.Strings(ids)
	extractors := make([]string, 0, len(lines))
	for l := range lines {
		extractors = append(extractors, l)
	}
	sort.Strings(extractors)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n") + "\n"))
	out := []string{
		"Origin-Run: " + run.ID,
		"Origin-Attempt: " + run.Attempt,
		"Origin-Commit: " + run.Commit,
		"Origin-Workflow: " + run.WorkflowSHA,
		"Origin-Derived-At: " + plan.DerivedAt,
		fmt.Sprintf("Origin-Records: %d sha256:%x", len(ids), sum),
	}
	return strings.Join(append(out, extractors...), "\n") + "\n", nil
}
