// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

func extractDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func clonePack(p *Pack) *Pack {
	cp := &Pack{Members: map[string]json.RawMessage{}, Entries: append([]json.RawMessage(nil), p.Entries...)}
	for k, v := range p.Members {
		cp.Members[k] = v
	}
	return cp
}

func attKeyString(a lineattest.LineAttestation) string { return a.Key().String() }

func attAllowed(rep *Report) map[string]bool {
	out := map[string]bool{}
	for _, k := range rep.AttAdded {
		out[k] = true
	}
	return out
}

// merge adds the run's rules and attestations. A rule or attestation that
// exists with identical content is left alone; one that exists with
// different content is a collision.
func merge(base *Pack, run *Run, rep *Report) (*Pack, map[string]bool, error) {
	head := clonePack(base)
	byID := map[string][]byte{}
	for _, e := range base.Entries {
		v, err := viewOf(e)
		if err != nil {
			return nil, nil, err
		}
		c, err := canon(e)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := byID[v.Rule.ID]; dup {
			return nil, nil, fmt.Errorf("%w: rule id %s appears twice", ErrPack, v.Rule.ID)
		}
		byID[v.Rule.ID] = c
	}
	allowed := map[string]bool{}
	for _, e := range run.Entries {
		v, err := viewOf(e)
		if err != nil {
			return nil, nil, err
		}
		c, err := canon(e)
		if err != nil {
			return nil, nil, err
		}
		if old, ok := byID[v.Rule.ID]; ok {
			if !bytes.Equal(old, c) {
				return nil, nil, fmt.Errorf("%w: rule %s is in the pack with different content", ErrCollision, v.Rule.ID)
			}
			rep.Unchanged = append(rep.Unchanged, v.Rule.ID)
			continue
		}
		byID[v.Rule.ID] = c
		head.Entries = append(head.Entries, e)
		allowed[v.Rule.ID] = true
		rep.Added = append(rep.Added, v.Rule.ID)
	}
	if len(run.Attestations) == 0 {
		return head, allowed, nil
	}
	var existing []lineattest.LineAttestation
	if raw, ok := base.Members[lineattest.PackMember]; ok {
		var err error
		if existing, err = lineattest.Parse(raw); err != nil {
			return nil, nil, fmt.Errorf("%w: lineAttestations: %v", ErrPack, err)
		}
	}
	idx := map[lineattest.Key][]byte{}
	for _, a := range existing {
		c, err := json.Marshal(a)
		if err != nil {
			return nil, nil, err
		}
		idx[a.Key()] = c
	}
	merged := append([]lineattest.LineAttestation(nil), existing...)
	for _, a := range run.Attestations {
		c, err := json.Marshal(a)
		if err != nil {
			return nil, nil, err
		}
		if old, ok := idx[a.Key()]; ok {
			if !bytes.Equal(old, c) {
				return nil, nil, fmt.Errorf("%w: the attestation for %s is in the pack with different content (a renewal is not an apply)", ErrCollision, attKeyString(a))
			}
			rep.AttUnchanged = append(rep.AttUnchanged, attKeyString(a))
			continue
		}
		idx[a.Key()] = c
		merged = append(merged, a)
		rep.AttAdded = append(rep.AttAdded, attKeyString(a))
	}
	if len(rep.AttAdded) > 0 {
		raw, err := lineattest.Marshal(merged)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: lineAttestations: %v", ErrAdmission, err)
		}
		head.Members[lineattest.PackMember] = raw
	}
	return head, allowed, nil
}

// withdraw sets evidence.state to withdrawn on every active mechanical rule
// of the run's extractor that the run's derived pairs cover and no longer
// produce: the rule's subject is the anchor transition of a derived pair of
// the run, and the pair's rule list does not name it. Nothing else changes.
func withdraw(base *Pack, run *Run, rep *Report) (*Pack, map[string]bool, error) {
	head := clonePack(base)
	allowed := map[string]bool{}
	for i, e := range head.Entries {
		v, err := viewOf(e)
		if err != nil {
			return nil, nil, err
		}
		ev := v.Rule.Evidence
		if ev.State != "active" || ev.Basis != "mechanical" || ev.Extractor == nil || ev.Extractor.ID != run.Manifest.Extractor.ID {
			continue
		}
		covered, produced := false, false
		var covering *extract.PairRecord
		for pi := range run.Manifest.Pairs {
			pr := run.Manifest.Pairs[pi]
			if pr.Status != extract.PairDerived {
				continue
			}
			t := constraintengine.RuleTransition{Component: v.Rule.Subject.Component, From: v.Rule.Subject.From, To: v.Rule.Subject.To}
			if !t.IsAnchor(pr.From, pr.To) || v.Rule.Subject.Component != componentOf(run.Manifest.Repo) {
				continue
			}
			covered = true
			covering = &run.Manifest.Pairs[pi]
			for _, id := range pr.Rules {
				if id == v.Rule.ID {
					produced = true
				}
			}
		}
		if !covered || produced {
			continue
		}
		if err := supersedes(run, covering, v); err != nil {
			return nil, nil, err
		}
		c, err := setMember(e, []string{"rule", "evidence", "state"}, []byte(`"withdrawn"`))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: rule %s: %v", ErrPack, v.Rule.ID, err)
		}
		head.Entries[i] = c
		allowed[v.Rule.ID] = true
		rep.Withdrawn = append(rep.Withdrawn, v.Rule.ID)
	}
	return head, allowed, nil
}

// audit compares the result with the base and refuses any difference other
// than the allowed ones: new rules (add mode) or state-only changes
// (withdraw mode), new attestations, and the pack schema (add mode).
func audit(base, head *Pack, allowed map[string]bool, allowedAtt map[string]bool, withdrawMode bool) error {
	canonByID := func(p *Pack) (map[string][]byte, error) {
		out := map[string][]byte{}
		for _, e := range p.Entries {
			v, err := viewOf(e)
			if err != nil {
				return nil, err
			}
			c, err := canon(e)
			if err != nil {
				return nil, err
			}
			out[v.Rule.ID] = c
		}
		return out, nil
	}
	b, err := canonByID(base)
	if err != nil {
		return err
	}
	h, err := canonByID(head)
	if err != nil {
		return err
	}
	for id, bc := range b {
		hc, ok := h[id]
		if !ok {
			return fmt.Errorf("%w: rule %s would be removed", ErrForeignChange, id)
		}
		if bytes.Equal(bc, hc) {
			continue
		}
		if !withdrawMode || !allowed[id] || !withdrawalOnly(bc, hc) {
			return fmt.Errorf("%w: rule %s", ErrForeignChange, id)
		}
	}
	for id := range h {
		if _, ok := b[id]; !ok && (withdrawMode || !allowed[id]) {
			return fmt.Errorf("%w: rule %s would be added", ErrForeignChange, id)
		}
	}
	for name, bv := range base.Members {
		hv, ok := head.Members[name]
		if ok && jsonEqual(bv, hv) {
			continue
		}
		switch {
		case !withdrawMode && name == "schema" && ok && schemaNotLower(bv, hv):
		case !withdrawMode && name == lineattest.PackMember && ok && attestationsExtend(bv, hv, allowedAtt):
		default:
			return fmt.Errorf("%w: pack member %s", ErrForeignChange, name)
		}
	}
	for name, hv := range head.Members {
		if _, ok := base.Members[name]; ok {
			continue
		}
		if withdrawMode || name != lineattest.PackMember || !attestationsExtend(nil, hv, allowedAtt) {
			return fmt.Errorf("%w: pack member %s would be added", ErrForeignChange, name)
		}
	}
	return nil
}

func jsonEqual(a, b json.RawMessage) bool {
	ca, err1 := canon(a)
	cb, err2 := canon(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

// withdrawalOnly reports whether two canonical entries differ only in
// rule.evidence.state, which goes from active to withdrawn.
func withdrawalOnly(a, b []byte) bool {
	strip := func(raw []byte) ([]byte, string, bool) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var g map[string]any
		if dec.Decode(&g) != nil {
			return nil, "", false
		}
		rule, _ := g["rule"].(map[string]any)
		ev, _ := rule["evidence"].(map[string]any)
		if ev == nil {
			return nil, "", false
		}
		state, _ := ev["state"].(string)
		delete(ev, "state")
		out, err := extract.Canonical(g)
		return out, state, err == nil
	}
	sa, stateA, ok1 := strip(a)
	sb, stateB, ok2 := strip(b)
	return ok1 && ok2 && stateA == "active" && stateB == "withdrawn" && bytes.Equal(sa, sb)
}

// attestationsExtend reports whether after holds every attestation of
// before unchanged, and every other one is allowed.
func attestationsExtend(before, after json.RawMessage, allowed map[string]bool) bool {
	var b, a []lineattest.LineAttestation
	var err error
	if before != nil {
		if b, err = lineattest.Parse(before); err != nil {
			return false
		}
	}
	if a, err = lineattest.Parse(after); err != nil {
		return false
	}
	old := map[lineattest.Key][]byte{}
	for _, x := range b {
		c, _ := json.Marshal(x)
		old[x.Key()] = c
	}
	seen := 0
	for _, x := range a {
		c, _ := json.Marshal(x)
		if oc, ok := old[x.Key()]; ok {
			if !bytes.Equal(oc, c) {
				return false
			}
			seen++
			continue
		}
		if !allowed[x.Key().String()] {
			return false
		}
	}
	return seen == len(b)
}

// checkCandidates runs rulecheck over the rules the merge adds.
func checkCandidates(base, head *Pack, allowed map[string]bool, opts Options, _ []byte) error {
	var added []json.RawMessage
	for _, e := range head.Entries {
		v, err := viewOf(e)
		if err != nil {
			return err
		}
		if allowed[v.Rule.ID] {
			added = append(added, e)
		}
	}
	if len(added) == 0 {
		return nil
	}
	raw, err := json.Marshal(added)
	if err != nil {
		return err
	}
	existing := append(append([]string(nil), opts.ExistingRules...), opts.PackPath)
	res, err := rulecheck.Validate(raw, rulecheck.Options{AllowRange: true, ExistingRulesPaths: existing})
	if err != nil {
		return fmt.Errorf("%w: rulecheck: %v", ErrAdmission, err)
	}
	if !res.Valid {
		var lines []string
		for _, f := range res.Findings {
			lines = append(lines, fmt.Sprintf("%s: %s: %s", f.RuleID, f.Check, f.Message))
		}
		return fmt.Errorf("%w: rulecheck rejected the added rules:\n%s", ErrAdmission, strings.Join(lines, "\n"))
	}
	return nil
}

// checkAttestations validates the pack's attestation section against its own
// rules (exact set per component, line and family).
func checkAttestations(pack []byte) error {
	res, err := rulecheck.ValidatePackAttestations(pack, rulecheck.AttestationOptions{})
	if err != nil {
		return fmt.Errorf("%w: attestations: %v", ErrAdmission, err)
	}
	if !res.Valid {
		var lines []string
		for _, f := range res.Findings {
			lines = append(lines, fmt.Sprintf("%s: %s: %s", f.RuleID, f.Check, f.Message))
		}
		return fmt.Errorf("%w: rulecheck rejected the attestations:\n%s", ErrAdmission, strings.Join(lines, "\n"))
	}
	return nil
}

var schemaRE = regexp.MustCompile(`^(.*/v1alpha)([0-9]+)$`)

// bumpToAdmitted tries the pack at the next schema levels. A pack carries
// exactly the schema of the highest-level feature it uses, so the first
// level the loader admits is the right one.
func bumpToAdmitted(head *Pack, packPath string, admit func(string, []byte) error, levels int, first error) ([]byte, error) {
	m := schemaRE.FindStringSubmatch(schemaOf(head))
	if m == nil {
		return nil, fmt.Errorf("%w: %v", ErrAdmission, first)
	}
	n, _ := strconv.Atoi(m[2])
	for k := n + 1; k <= n+levels; k++ {
		cand := setSchema(head, m[1]+strconv.Itoa(k))
		out, err := cand.Render()
		if err != nil {
			return nil, err
		}
		if admit(packPath, out) == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: the engine loader refuses the merged pack at its schema and the next %d levels: %v", ErrAdmission, levels, first)
}

// AdmitFiles admits a rule pack with the engine loader of its family, using
// the registry files that sit beside the pack file (landscape-projects.json
// and priority-portfolio.json for the CNCF pack, projects.json for the
// community pack).
func AdmitFiles(packPath string, raw []byte) error {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return err
	}
	dir := filepath.Dir(packPath)
	switch {
	case strings.HasPrefix(head.Schema, "prufyx.io/cncf-source-rule-pack/"):
		l, err := os.ReadFile(filepath.Join(dir, "landscape-projects.json"))
		if err != nil {
			return err
		}
		p, err := os.ReadFile(filepath.Join(dir, "priority-portfolio.json"))
		if err != nil {
			return err
		}
		_, err = cncfcheck.CheckPackFiles(l, p, raw)
		return err
	case strings.HasPrefix(head.Schema, "prufyx.io/community-project-source-rule-pack/"):
		r, err := os.ReadFile(filepath.Join(dir, "projects.json"))
		if err != nil {
			return err
		}
		_, err = projectcheck.CheckPackFiles(r, raw)
		return err
	}
	return fmt.Errorf("unknown pack schema %q", head.Schema)
}

// setMember replaces the value of an existing member at path in a JSON
// object, keeping the order of every member. It fails when the path does
// not exist.
func setMember(raw []byte, path []string, value []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("not an object")
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	found := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		if key == path[0] {
			found = true
			if len(path) == 1 {
				val = value
			} else if val, err = setMember(val, path[1:], value); err != nil {
				return nil, err
			}
		}
		if buf.Len() > 1 {
			buf.WriteByte(',')
		}
		k, _ := json.Marshal(key)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(val)
	}
	if !found {
		return nil, fmt.Errorf("no member %s", path[0])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// newFactsHint names the facts the added rules require that no rule of the
// base pack uses. The engine refuses a rule whose fact its registry does
// not define, and says no more than that the pack failed its checks, so the
// names are the first thing to look at.
func newFactsHint(base, head *Pack, allowed map[string]bool) string {
	type entryFacts struct {
		RequiredFacts []struct {
			ID string `json:"id"`
		} `json:"requiredFacts"`
	}
	used := map[string]bool{}
	for _, e := range base.Entries {
		var f entryFacts
		if json.Unmarshal(e, &f) == nil {
			for _, rf := range f.RequiredFacts {
				used[rf.ID] = true
			}
		}
	}
	missing := map[string]bool{}
	for _, e := range head.Entries {
		v, err := viewOf(e)
		if err != nil || !allowed[v.Rule.ID] {
			continue
		}
		var f entryFacts
		if json.Unmarshal(e, &f) == nil {
			for _, rf := range f.RequiredFacts {
				if !used[rf.ID] {
					missing[rf.ID] = true
				}
			}
		}
	}
	if len(missing) == 0 {
		return ""
	}
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	sort.Strings(names)
	return "\nhint: the added rules require facts no rule of the pack uses yet (the engine's fact registry must define them): " + strings.Join(names, ", ")
}

// componentOf is the rule subject component of a repository key
// ("github.com/owner/name" is "pkg:github/owner/name").
func componentOf(repo string) string {
	return "pkg:github/" + strings.TrimPrefix(repo, "github.com/")
}

// supersedes requires that a run may withdraw a rule: the run is not older
// than the rule, was produced by the code that derived the rule, and read the
// commits the rule cites. A run that fails any of these says nothing about
// whether the rule still holds.
func supersedes(run *Run, pair *extract.PairRecord, v entryView) error {
	ev := v.Rule.Evidence
	runAt, err1 := time.Parse(time.RFC3339, run.Manifest.DerivedAt)
	ruleAt, err2 := time.Parse(time.RFC3339, ev.DerivedAt)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%w: rule %s or the run has no readable derivedAt", ErrStale, v.Rule.ID)
	}
	if runAt.Before(ruleAt) {
		return fmt.Errorf("%w: the run was derived at %s, before rule %s (%s)", ErrStale, run.Manifest.DerivedAt, v.Rule.ID, ev.DerivedAt)
	}
	if ev.Extractor == nil || ev.Extractor.CodeDigest == "" || ev.Extractor.CodeDigest != run.Manifest.Extractor.CodeDigest {
		return fmt.Errorf("%w: rule %s was derived by other code than the run's", ErrStale, v.Rule.ID)
	}
	if len(ev.Sources) == 0 {
		return fmt.Errorf("%w: rule %s cites no source", ErrStale, v.Rule.ID)
	}
	for _, s := range ev.Sources {
		if s.Revision != pair.FromCommit && s.Revision != pair.ToCommit {
			return fmt.Errorf("%w: rule %s cites commit %s, which the run's pair %s -> %s did not read", ErrStale, v.Rule.ID, s.Revision, pair.From, pair.To)
		}
	}
	return nil
}

// schemaNotLower reports whether the head schema is the base schema or a
// higher level of the same family (".../v1alphaN"); a schema that does not
// have that shape must be unchanged.
func schemaNotLower(base, head json.RawMessage) bool {
	var b, h string
	if json.Unmarshal(base, &b) != nil || json.Unmarshal(head, &h) != nil {
		return false
	}
	if b == h {
		return true
	}
	bm, hm := schemaRE.FindStringSubmatch(b), schemaRE.FindStringSubmatch(h)
	if bm == nil || hm == nil || bm[1] != hm[1] {
		return false
	}
	bn, _ := strconv.Atoi(bm[2])
	hn, _ := strconv.Atoi(hm[2])
	return hn >= bn
}
