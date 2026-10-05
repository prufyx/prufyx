// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// ErrSupersede means the run does not replace the reviewed rules it touches
// cleanly: a reviewed rule is only partly covered, covered twice, or not
// covered by a rule of the same constraint, the run replaces nothing, or a
// rule it would overlap is not a reviewed rule. Nothing is written.
var ErrSupersede = errors.New("extract supersede: the run does not replace the reviewed rules it overlaps exactly")

// Pair says that the reviewed rule Old is replaced by the mechanical rule New.
type Pair struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// SupersedeReport says what a supersede did.
type SupersedeReport struct {
	Pairs     []Pair   // old -> new, sorted by old id
	Added     []string // rule ids added
	Unchanged []string // run rules already in the pack with identical content
	Changed   bool
}

// Map renders the report as canonical JSON: the old to new map, the ids
// added and the ids already present.
func (r *SupersedeReport) Map() ([]byte, error) {
	m := map[string]any{}
	for _, p := range r.Pairs {
		m[p.Old] = p.New
	}
	ids := func(s []string) []any {
		out := make([]any, 0, len(s))
		for _, x := range s {
			out = append(out, x)
		}
		return out
	}
	return extract.Canonical(map[string]any{"added": ids(r.Added), "map": m, "unchanged": ids(r.Unchanged)})
}

// supersedeStep is the step Supersede runs; a variable only so a test can
// make it misbehave and show the final audit refuses it.
var supersedeStep = planSupersede

type bound struct {
	Gte string `json:"gte"`
	Lt  string `json:"lt"`
}

type fact struct {
	Side      string   `json:"side"`
	Component string   `json:"component"`
	FactID    string   `json:"factId"`
	Members   []string `json:"members"`
}

// shape is what supersede reads of a rule.
type shape struct {
	ID       string          `json:"id"`
	Operator string          `json:"operator"`
	Subject  extract.Subject `json:"subject"`
	Range    *struct {
		From bound `json:"from"`
		To   bound `json:"to"`
	} `json:"range"`
	Condition    *fact `json:"condition"`
	SetCondition *fact `json:"setCondition"`
	Dependency   *fact `json:"dependency"`
	Evidence     struct {
		Basis string `json:"basis"`
	} `json:"evidence"`

	// constraint is the engine's constraint key (constraintengine.ConstraintKey).
	constraint string
}

func shapeOf(raw json.RawMessage) (shape, error) {
	var v struct {
		Rule shape `json:"rule"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Rule.ID == "" {
		return shape{}, fmt.Errorf("%w: an entry has no rule id", ErrPack)
	}
	var obj struct {
		Rule json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return shape{}, fmt.Errorf("%w: an entry has no rule id", ErrPack)
	}
	key, err := constraintengine.ConstraintKey(obj.Rule)
	if err != nil {
		return shape{}, fmt.Errorf("%w: rule %s: %v", ErrPack, v.Rule.ID, err)
	}
	v.Rule.constraint = key
	return v.Rule, nil
}

type span struct {
	lo, hi string
	point  bool // [lo, lo]; otherwise [lo, hi)
}

func (s shape) region() (span, span) {
	if s.Range != nil {
		return span{lo: s.Range.From.Gte, hi: s.Range.From.Lt}, span{lo: s.Range.To.Gte, hi: s.Range.To.Lt}
	}
	return span{lo: s.Subject.From, hi: s.Subject.From, point: true}, span{lo: s.Subject.To, hi: s.Subject.To, point: true}
}

func le(a, b string) bool {
	return constraintengine.SameVersion(a, b) || constraintengine.VersionLess(a, b)
}

// overlaps is the engine lint's test; a version it cannot read overlaps.
func (a span) overlaps(b span) bool {
	below := func(x, y span) bool { // x starts below the end of y
		if !validVersion(x.lo) || !validVersion(y.hi) {
			return true
		}
		if y.point {
			return le(x.lo, y.hi)
		}
		return constraintengine.VersionLess(x.lo, y.hi)
	}
	return below(a, b) && below(b, a)
}

// covers reports a ⊇ b; a version it cannot read covers nothing.
func (a span) covers(b span) bool {
	if a.point {
		return b.point && constraintengine.SameVersion(a.lo, b.lo)
	}
	if !le(a.lo, b.lo) {
		return false
	}
	if b.point {
		return constraintengine.VersionLess(b.lo, a.hi)
	}
	return le(b.hi, a.hi)
}

func validVersion(v string) bool { return constraintengine.SameVersion(v, v) }

func (s shape) members() []string {
	if s.SetCondition != nil {
		return s.SetCondition.Members
	}
	return nil
}

func intersects(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if set[x] {
			return true
		}
	}
	return false
}

func subset(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range b {
		set[x] = true
	}
	for _, x := range a {
		if !set[x] {
			return false
		}
	}
	return true
}

// relevant reports whether m and r constrain the same thing over a common
// region: same component, equal constraint key, a common set member, and
// overlapping match regions.
func relevant(m, r shape) bool {
	if m.Subject.Component != r.Subject.Component || m.constraint != r.constraint {
		return false
	}
	if m.SetCondition != nil && !intersects(m.members(), r.members()) {
		return false
	}
	mf, mt := m.region()
	rf, rt := r.region()
	return mf.overlaps(rf) && mt.overlaps(rt)
}

// covers reports that m replaces r: the same constraint over a region and
// a member set that include r's.
func covers(m, r shape) bool {
	if m.SetCondition != nil && !subset(r.members(), m.members()) {
		return false
	}
	mf, mt := m.region()
	rf, rt := r.region()
	return mf.covers(rf) && mt.covers(rt)
}

// planSupersede decides what the run replaces and builds the result pack.
// Every refusal is an error; nothing is written here.
func planSupersede(base *Pack, run *Run, rep *SupersedeReport) (head *Pack, removed, added map[string]bool, err error) {
	baseCanon := map[string][]byte{}
	var baseShapes []shape
	for _, e := range base.Entries {
		s, err := shapeOf(e)
		if err != nil {
			return nil, nil, nil, err
		}
		c, err := canon(e)
		if err != nil {
			return nil, nil, nil, err
		}
		if _, dup := baseCanon[s.ID]; dup {
			return nil, nil, nil, fmt.Errorf("%w: rule id %s appears twice", ErrPack, s.ID)
		}
		baseCanon[s.ID] = c
		baseShapes = append(baseShapes, s)
	}
	var mine []shape
	added = map[string]bool{}
	for _, e := range run.Entries {
		s, err := shapeOf(e)
		if err != nil {
			return nil, nil, nil, err
		}
		c, err := canon(e)
		if err != nil {
			return nil, nil, nil, err
		}
		mine = append(mine, s)
		if old, ok := baseCanon[s.ID]; ok {
			if !bytes.Equal(old, c) {
				return nil, nil, nil, fmt.Errorf("%w: rule %s is in the pack with different content", ErrCollision, s.ID)
			}
			rep.Unchanged = append(rep.Unchanged, s.ID)
			continue
		}
		added[s.ID] = true
		rep.Added = append(rep.Added, s.ID)
	}
	removed = map[string]bool{}
	for _, r := range baseShapes {
		var hit []shape
		for _, m := range mine {
			if m.ID != r.ID && relevant(m, r) {
				hit = append(hit, m)
			}
		}
		if len(hit) == 0 {
			continue
		}
		if r.Evidence.Basis == "mechanical" {
			return nil, nil, nil, fmt.Errorf("%w: rule %s is a mechanical rule the run overlaps; only a reviewed rule can be superseded", ErrSupersede, r.ID)
		}
		if len(hit) > 1 {
			return nil, nil, nil, fmt.Errorf("%w: reviewed rule %s overlaps %d rules of the run (%s, %s, ...)", ErrSupersede, r.ID, len(hit), hit[0].ID, hit[1].ID)
		}
		if !covers(hit[0], r) {
			return nil, nil, nil, fmt.Errorf("%w: rule %s covers reviewed rule %s only in part", ErrSupersede, hit[0].ID, r.ID)
		}
		removed[r.ID] = true
		rep.Pairs = append(rep.Pairs, Pair{Old: r.ID, New: hit[0].ID})
	}
	if len(removed) == 0 && len(added) > 0 {
		return nil, nil, nil, fmt.Errorf("%w: no reviewed rule matches a rule of the run (that is an apply, not a supersede)", ErrSupersede)
	}
	head = clonePack(base)
	head.Entries = nil
	for _, e := range base.Entries {
		s, _ := shapeOf(e)
		if !removed[s.ID] {
			head.Entries = append(head.Entries, e)
		}
	}
	for _, e := range run.Entries {
		s, _ := shapeOf(e)
		if added[s.ID] {
			head.Entries = append(head.Entries, e)
		}
	}
	return head, removed, added, nil
}

// Supersede removes the reviewed rules the run's rules replace, adds the
// run's rules and rewrites the pack. It writes nothing on any refusal.
func Supersede(opts Options) (*SupersedeReport, error) {
	run, err := LoadRun(opts.RunDir)
	if err != nil {
		return nil, err
	}
	baseRaw, err := os.ReadFile(opts.PackPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPack, err)
	}
	base, err := ParsePack(baseRaw)
	if err != nil {
		return nil, err
	}
	rep := &SupersedeReport{}
	head, removed, added, err := supersedeStep(base, run, rep)
	if err != nil {
		return nil, err
	}
	if len(removed) == 0 && len(added) == 0 {
		return rep, nil
	}
	admit := opts.Admit
	if admit == nil {
		admit = AdmitFiles
	}
	// rulecheck sees the pack without the rules about to go, so a new rule
	// is not refused for overlapping the reviewed rule it replaces.
	rest := &Pack{Members: head.Members}
	for _, e := range head.Entries {
		s, _ := shapeOf(e)
		if !added[s.ID] {
			rest.Entries = append(rest.Entries, e)
		}
	}
	restRaw, err := rest.Render()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "extract-supersede-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	restPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(restPath, restRaw, 0o600); err != nil {
		return nil, err
	}
	ropts := opts
	ropts.PackPath = restPath
	if err := checkCandidates(base, head, added, ropts, baseRaw); err != nil {
		return nil, err
	}
	out, err := head.Render()
	if err != nil {
		return nil, err
	}
	if err := admit(opts.PackPath, out); err != nil {
		return nil, fmt.Errorf("%w: the engine loader refuses the merged pack: %v%s", ErrAdmission, err, newFactsHint(base, head, added))
	}
	if err := checkAttestations(out); err != nil {
		return nil, err
	}
	final, err := ParsePack(out)
	if err != nil {
		return nil, err
	}
	if err := auditSupersede(base, final, removed, added); err != nil {
		return nil, err
	}
	sort.Slice(rep.Pairs, func(i, j int) bool { return rep.Pairs[i].Old < rep.Pairs[j].Old })
	sort.Strings(rep.Added)
	sort.Strings(rep.Unchanged)
	rep.Changed = !bytes.Equal(out, baseRaw)
	if rep.Changed {
		if err := writeAtomic(opts.PackPath, out); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// auditSupersede is the final audit: the result is the base without the
// planned removals (each a reviewed rule that was in the base), plus the
// planned additions, and nothing else. The apply audit checks the second
// half; the schema and every other pack member must be exactly unchanged.
func auditSupersede(base, final *Pack, removed, added map[string]bool) error {
	rest := &Pack{Members: base.Members}
	seen := map[string]bool{}
	for _, e := range base.Entries {
		s, err := shapeOf(e)
		if err != nil {
			return err
		}
		if removed[s.ID] {
			if s.Evidence.Basis == "mechanical" {
				return fmt.Errorf("%w: rule %s is not a reviewed rule", ErrForeignChange, s.ID)
			}
			seen[s.ID] = true
			continue
		}
		rest.Entries = append(rest.Entries, e)
	}
	for id := range removed {
		if !seen[id] {
			return fmt.Errorf("%w: rule %s is not in the pack", ErrForeignChange, id)
		}
	}
	if err := audit(rest, final, added, nil, false); err != nil {
		return err
	}
	for name, bv := range base.Members {
		if hv, ok := final.Members[name]; !ok || !bytes.Equal(canonOrRaw(bv), canonOrRaw(hv)) {
			return fmt.Errorf("%w: pack member %s", ErrForeignChange, name)
		}
	}
	return nil
}

func canonOrRaw(raw json.RawMessage) []byte {
	if c, err := canon(raw); err == nil {
		return c
	}
	return raw
}
