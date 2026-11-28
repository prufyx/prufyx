// SPDX-License-Identifier: AGPL-3.0-only

package changelogrenew

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// ListedIDPrefix is the extractor family renewed here.
const ListedIDPrefix = "changelog.listed."

const (
	// DueWindow is how close to its end a record must be to be renewed.
	DueWindow = 45 * 24 * time.Hour
	// MaxAge and ClockSkew bound the derivation time against the clock.
	MaxAge    = 24 * time.Hour
	ClockSkew = 5 * time.Minute
	// MaxRecords is the most records of one change: the gate's per-change cap.
	MaxRecords = 200
	// MaxLeaseDays is MaxLease in days.
	MaxLeaseDays    = int(MaxLease / (24 * time.Hour))
	maxRunFiles     = 4096
	maxRunFileBytes = 64 << 20
)

// Options is one renewal of the due records of one extractor.
type Options struct {
	// Pack is the base pack, in its canonical rendering.
	Pack []byte
	// Extractor is the extractor id, changelog.listed.<project>.
	Extractor string
	// Repo is the repository the registered extractor reads.
	Repo extract.RepoRef
	// Current is the build of the extractor that the running binary holds (see
	// Current). A record of another build is renewed only by runs of exactly
	// this one; without it no record changes its build.
	Current constraintengine.Extractor
	// RunDir and SecondRunDir are two run directories of "extract run", made
	// independently with the same derivation time and lease.
	RunDir, SecondRunDir string
	// DerivedAt and LeaseDays are what both runs must have used.
	DerivedAt string
	LeaseDays int
	// Max is the most records to renew, soonest end first (1-MaxRecords).
	Max int
	// Now is the clock.
	Now time.Time
}

// PreviousBuild counts the renewed records that named one older build.
type PreviousBuild struct {
	Build   constraintengine.Extractor
	Records int
}

// Result says what a renewal did.
type Result struct {
	// Pack is the base pack with only the renewed records changed.
	Pack []byte
	// Renewed are the keys of the renewed records.
	Renewed []string
	// ListChanged are due records whose line has releases the base record does
	// not name; they are left as they are and belong to the ordinary intake.
	ListChanged []string
	// NotDerived are due records the runs do not attest; left as they are.
	NotDerived []string
	// Deferred are due records over Max.
	Deferred []string
	// LeftOut counts run records that the base does not hold.
	LeftOut int
	// RecordsDigest is the digest of the renewed keys, one per line.
	RecordsDigest string
	// OutputDigest is the digest of the content both runs hold.
	OutputDigest string
	// Build is the extractor build of the runs.
	Build constraintengine.Extractor
	// Previous are the older builds that renewed records named, in the order of
	// their code digest and version; empty when no record changed its build.
	Previous []PreviousBuild
}

// run is the checked content of a run directory.
type run struct {
	files    map[string][]byte
	digest   string
	manifest extract.Manifest
	records  map[lineattest.Key]lineattest.LineAttestation
}

func sum(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// readFiles reads a run directory: a real directory of regular files only.
func readFiles(dir string) (map[string][]byte, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, refuse(CodeRun, "%s is not a directory", dir)
	}
	out := map[string][]byte{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return refuse(CodeRun, "%s cannot be read: %v", p, err)
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return refuse(CodeRun, "%s cannot be read: %v", p, err)
		}
		if !fi.Mode().IsRegular() || fi.Size() > maxRunFileBytes || len(out) >= maxRunFiles {
			return refuse(CodeRun, "%s is not a plain run file within the limits", p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return refuse(CodeRun, "%s cannot be read: %v", p, err)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return refuse(CodeRun, "%s cannot be named: %v", p, err)
		}
		out[filepath.ToSlash(rel)] = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readRuns reads both run directories and requires the same files with the
// same bytes.
func readRuns(a, b string) (run, error) {
	var none run
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return none, refuse(CodeRun, "both run directories must exist")
	}
	if os.SameFile(ai, bi) {
		return none, refuse(CodeRunMismatch, "the two run directories are one directory")
	}
	x, err := readFiles(a)
	if err != nil {
		return none, err
	}
	y, err := readFiles(b)
	if err != nil {
		return none, err
	}
	if len(x) != len(y) {
		return none, refuse(CodeRunMismatch, "the two runs do not hold the same files")
	}
	names := make([]string, 0, len(x))
	for name := range x {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		other, ok := y[name]
		if !ok || !bytes.Equal(x[name], other) {
			return none, refuse(CodeRunMismatch, "the two runs differ in %s", name)
		}
		fmt.Fprintf(h, "%s\x00%s\n", name, sum(x[name]))
	}
	return run{files: x, digest: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

// check loads the manifest and the attestations of a run and requires every
// file to be one the manifest pins by digest, and the run to be the requested
// derivation of the requested extractor.
func (r *run) check(opts Options, until string) error {
	raw, ok := r.files[extract.FileManifest]
	if !ok {
		return refuse(CodeRun, "the run has no manifest")
	}
	if err := strictjson.Check(raw); err != nil {
		return refuse(CodeRun, "manifest: %v", err)
	}
	if err := json.Unmarshal(raw, &r.manifest); err != nil || r.manifest.Schema != extract.ManifestSchema {
		return refuse(CodeRun, "the manifest cannot be read")
	}
	m := r.manifest
	names := make([]string, 0, len(r.files)+len(m.Outputs))
	for name := range r.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name != extract.FileManifest && m.Outputs[name] != sum(r.files[name]) {
			return refuse(CodeUnpinned, "run file %s is not pinned by the manifest", name)
		}
	}
	names = names[:0]
	for name := range m.Outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := r.files[name]; !ok {
			return refuse(CodeUnpinned, "run file %s, which the manifest pins, is missing", name)
		}
	}
	if m.Extractor.ID != opts.Extractor || m.Repo != opts.Repo.Key {
		return refuse(CodeOtherExtractor, "the run is of extractor %s on %s", m.Extractor.ID, m.Repo)
	}
	if m.DerivedAt != opts.DerivedAt {
		return refuse(CodeDerivationTime, "the run was derived at %s, not %s", m.DerivedAt, opts.DerivedAt)
	}
	if m.ValidUntil != until {
		return refuse(CodeLease, "the run's lease ends %s, not %s", m.ValidUntil, until)
	}
	if _, drafts := r.files[extract.FileDrafts]; drafts || m.Totals.Rules != 0 || m.Totals.Drafts != 0 {
		return refuse(CodeRun, "a listed-entries run holds neither rules nor drafts")
	}
	attestations, ok := r.files[extract.FileAttestations]
	if !ok {
		return refuse(CodeNothing, "the run attests no line")
	}
	list, err := lineattest.Parse(attestations)
	if err != nil {
		return refuse(CodeRun, "attestations: %v", err)
	}
	r.records = map[lineattest.Key]lineattest.LineAttestation{}
	for _, a := range list {
		e := a.Evidence
		if a.FactFamily != lineattest.FamilyChangelogListedEntries || e.Extractor == nil || *e.Extractor != m.Extractor {
			return refuse(CodeOtherExtractor, "%s is not a listed record of the run's extractor", a.Key())
		}
		if e.DerivedAt != m.DerivedAt || e.ValidUntil != m.ValidUntil {
			return refuse(CodeRun, "%s does not carry the run's times", a.Key())
		}
		r.records[a.Key()] = a
	}
	return nil
}

// read reports whether the run recorded reading the cited file with the cited
// content.
func (r *run) read(s constraintengine.SourceEvidence, repo extract.RepoRef) bool {
	p, ok := sourcePath(s, repo)
	digest, has := strings.CutPrefix(s.ContentDigest, "sha256:")
	if !ok || !has {
		return false
	}
	for _, line := range strings.Split(string(r.files[extract.DirReads+"/"+s.Revision+".tsv"]), "\n") {
		if strings.HasPrefix(line, p+"\t"+digest+"\t") {
			return true
		}
	}
	return false
}

// grown reports whether next names every release of old at the same commit, in
// order, and at least one more: the upstream list changed.
func grown(old, next *lineattest.Releases) bool {
	if old == nil || next == nil {
		return false
	}
	extends := func(a, b []lineattest.Release) bool {
		i := 0
		for _, r := range b {
			if i < len(a) && a[i] == r {
				i++
			}
		}
		return i == len(a)
	}
	return extends(old.From, next.From) && extends(old.To, next.To) && len(next.From)+len(next.To) > len(old.From)+len(old.To)
}

// section reads the line attestations of a pack as structs.
func section(p *extractpack.Pack) ([]lineattest.LineAttestation, error) {
	raw, ok := p.Members[lineattest.PackMember]
	if !ok {
		return nil, refuse(CodeInput, "the pack has no line attestations")
	}
	return lineattest.Parse(raw)
}

// render writes the pack with the given attestations.
func render(p *extractpack.Pack, atts []lineattest.LineAttestation) ([]byte, error) {
	raw, err := lineattest.Marshal(atts)
	if err != nil {
		return nil, err
	}
	p.Members[lineattest.PackMember] = raw
	return p.Render()
}

// move copies into head[i] what a renewal moves from next: the three times and,
// for a newer build, the extractor. head may be a shallow clone of the base
// records, so the extractor is a new value and is never written through the
// pointer the base record holds.
func move(head []lineattest.LineAttestation, i int, next lineattest.LineAttestation, rebuilt bool) {
	head[i].Evidence.DerivedAt = next.Evidence.DerivedAt
	head[i].Evidence.ReviewedAt = next.Evidence.ReviewedAt
	head[i].Evidence.ValidUntil = next.Evidence.ValidUntil
	if rebuilt {
		build := *next.Evidence.Extractor
		head[i].Evidence.Extractor = &build
	}
}

// Assemble renews the due records of one extractor. A record of the runs' build
// is renewed by TimeOnly, a record of an older build by NewBuild. It refuses as
// a whole, and returns no pack, on any difference that is neither such a
// renewal nor a line that gained releases; a run that renews nothing is refused.
func Assemble(opts Options) (*Result, error) {
	if !strings.HasPrefix(opts.Extractor, ListedIDPrefix) || len(opts.Extractor) == len(ListedIDPrefix) || opts.Repo.Key == "" {
		return nil, refuse(CodeOtherExtractor, "only a %s<project> extractor is renewed here", ListedIDPrefix)
	}
	if opts.LeaseDays < 1 || opts.LeaseDays > MaxLeaseDays {
		return nil, refuse(CodeLease, "the lease must be 1-%d days", MaxLeaseDays)
	}
	if opts.Max < 1 || opts.Max > MaxRecords {
		return nil, refuse(CodeInput, "the record cap must be 1-%d", MaxRecords)
	}
	at, err := constraintengine.ParseUTC(opts.DerivedAt)
	if err != nil || at.Nanosecond() != 0 {
		return nil, refuse(CodeDerivationTime, "%q is not a UTC time like 2026-10-02T00:00:00Z", opts.DerivedAt)
	}
	if opts.Now.IsZero() || at.After(opts.Now.Add(ClockSkew)) {
		return nil, refuse(CodeDerivationTime, "the derivation time %s is in the future", opts.DerivedAt)
	}
	if at.Before(opts.Now.Add(-MaxAge)) {
		return nil, refuse(CodeDerivationTime, "the derivation time %s is more than 24 hours old", opts.DerivedAt)
	}
	until := at.Add(time.Duration(opts.LeaseDays) * 24 * time.Hour).Format(time.RFC3339)

	derived, err := readRuns(opts.RunDir, opts.SecondRunDir)
	if err != nil {
		return nil, err
	}
	if err := derived.check(opts, until); err != nil {
		return nil, err
	}

	pack, err := extractpack.ParsePack(opts.Pack)
	if err != nil {
		return nil, refuse(CodeInput, "the base pack: %v", err)
	}
	base, err := section(pack)
	if err != nil {
		return nil, refuse(CodeInput, "the base pack: %v", err)
	}
	head := slices.Clone(base)
	// Only a canonical base can be rewritten with nothing but the renewal.
	if same, err := render(pack, base); err != nil || !bytes.Equal(same, opts.Pack) {
		return nil, refuse(CodeInput, "the base pack is not in its canonical rendering")
	}

	var due []int
	for i, a := range base {
		e := a.Evidence
		if a.FactFamily != lineattest.FamilyChangelogListedEntries || e.Extractor == nil || e.Extractor.ID != opts.Extractor {
			continue
		}
		end, err := constraintengine.ParseUTC(e.ValidUntil)
		if err != nil {
			return nil, refuse(CodeInput, "%s: validUntil cannot be read", a.Key())
		}
		if end.Sub(at) <= DueWindow {
			due = append(due, i)
		}
	}
	// Soonest end first; the section's own order breaks ties.
	sort.SliceStable(due, func(i, j int) bool { return base[due[i]].Evidence.ValidUntil < base[due[j]].Evidence.ValidUntil })

	res := &Result{OutputDigest: derived.digest, Build: derived.manifest.Extractor}
	renewed := map[lineattest.Key]bool{}
	previous := map[constraintengine.Extractor]int{}
	for _, i := range due {
		old := base[i]
		key := old.Key()
		next, ok := derived.records[key]
		if !ok {
			res.NotDerived = append(res.NotDerived, key.String())
			continue
		}
		// A build the run may not renew from refuses the whole run, also for a
		// line that would be left as it is.
		rebuilt := *old.Evidence.Extractor != *next.Evidence.Extractor
		if rebuilt {
			if err := newerBuild(*old.Evidence.Extractor, *next.Evidence.Extractor); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if *next.Evidence.Extractor != opts.Current {
				return nil, refuse(CodeBuild, "%s: the base record is of another build, and the runs are not of the build this binary holds", key)
			}
		}
		if grown(old.Releases, next.Releases) {
			res.ListChanged = append(res.ListChanged, key.String())
			continue
		}
		for _, a := range []lineattest.LineAttestation{old, next} {
			if err := Pinned(a, opts.Repo); err != nil {
				return nil, err
			}
		}
		for _, s := range next.Evidence.Sources {
			if !derived.read(s, opts.Repo) {
				return nil, refuse(CodeUnpinned, "%s: the runs did not read source %s with the cited content", key, s.ID)
			}
		}
		x, err1 := json.Marshal(old)
		y, err2 := json.Marshal(next)
		if err1 != nil || err2 != nil {
			return nil, refuse(CodeInput, "%s cannot be compared", key)
		}
		if rebuilt {
			err = NewBuild(x, y, opts.Now)
		} else {
			err = TimeOnly(x, y)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if len(res.Renewed) == opts.Max {
			res.Deferred = append(res.Deferred, key.String())
			continue
		}
		move(head, i, next, rebuilt)
		if rebuilt {
			previous[*old.Evidence.Extractor]++
		}
		renewed[key] = true
		res.Renewed = append(res.Renewed, key.String())
	}
	if len(res.Renewed) == 0 {
		return nil, refuse(CodeNothing, "no due record of %s was renewed (%d due, %d with a changed list, %d not derived)",
			opts.Extractor, len(due), len(res.ListChanged), len(res.NotDerived))
	}
	held := map[lineattest.Key]bool{}
	for _, a := range base {
		held[a.Key()] = true
	}
	for key := range derived.records {
		if !held[key] {
			res.LeftOut++
		}
	}
	if res.Pack, err = render(pack, head); err != nil {
		return nil, refuse(CodeInput, "the result cannot be rendered: %v", err)
	}
	if err := audit(opts.Pack, res.Pack, renewed, opts.Current, opts.Now); err != nil {
		return nil, err
	}
	for build, n := range previous {
		res.Previous = append(res.Previous, PreviousBuild{Build: build, Records: n})
	}
	sort.Slice(res.Previous, func(i, j int) bool {
		a, b := res.Previous[i].Build, res.Previous[j].Build
		if a.CodeDigest != b.CodeDigest {
			return a.CodeDigest < b.CodeDigest
		}
		return a.Version < b.Version
	})
	sort.Strings(res.Renewed)
	sort.Strings(res.ListChanged)
	sort.Strings(res.NotDerived)
	sort.Strings(res.Deferred)
	res.RecordsDigest = sum([]byte(strings.Join(res.Renewed, "\n") + "\n"))
	return res, nil
}

// audit is the final check of the result itself, independent of how it was
// built: the same rules and pack members, the same records in the same order,
// and each record either unchanged or, when it is one of renewed, a time-only
// renewal or a renewal to the build current.
func audit(base, head []byte, renewed map[lineattest.Key]bool, current constraintengine.Extractor, now time.Time) error {
	read := func(raw []byte) (*extractpack.Pack, []json.RawMessage, error) {
		p, err := extractpack.ParsePack(raw)
		if err != nil {
			return nil, nil, err
		}
		var list []json.RawMessage
		if err := json.Unmarshal(p.Members[lineattest.PackMember], &list); err != nil {
			return nil, nil, err
		}
		return p, list, nil
	}
	same := func(a, b json.RawMessage) bool {
		var x, y bytes.Buffer
		return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
	}
	bp, bl, err1 := read(base)
	hp, hl, err2 := read(head)
	if err1 != nil || err2 != nil || len(bl) != len(hl) || len(bp.Entries) != len(hp.Entries) || len(bp.Members) != len(hp.Members) {
		return refuse(CodeChanged, "the result changes the shape of the pack")
	}
	for i := range bp.Entries {
		if !same(bp.Entries[i], hp.Entries[i]) {
			return refuse(CodeChanged, "the result changes a rule")
		}
	}
	for name, v := range bp.Members {
		if name != lineattest.PackMember && !same(v, hp.Members[name]) {
			return refuse(CodeChanged, "the result changes pack member %s", name)
		}
	}
	done := 0
	for i := range bl {
		if same(bl[i], hl[i]) {
			continue
		}
		var a, b lineattest.LineAttestation
		if err := json.Unmarshal(bl[i], &a); err != nil || !renewed[a.Key()] {
			return refuse(CodeChanged, "the result changes a record it does not renew")
		}
		if err := json.Unmarshal(hl[i], &b); err != nil || a.Evidence.Extractor == nil || b.Evidence.Extractor == nil {
			return refuse(CodeChanged, "the result holds a renewed record that cannot be read")
		}
		var err error
		switch {
		case *a.Evidence.Extractor == *b.Evidence.Extractor:
			err = TimeOnly(bl[i], hl[i])
		case *b.Evidence.Extractor != current:
			err = refuse(CodeBuild, "the result moves a record to a build this binary does not hold")
		default:
			err = NewBuild(bl[i], hl[i], now)
		}
		if err != nil {
			return err
		}
		done++
	}
	if done != len(renewed) {
		return refuse(CodeChanged, "the result changes %d records, not the %d renewed", done, len(renewed))
	}
	return nil
}
