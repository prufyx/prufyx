// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Change classes.
const (
	ClassTightening = "tightening"
	ClassLoosening  = "loosening"
)

// Change kinds. Tightening kinds first.
const (
	KindWithdraw     = "withdraw"      // evidence.state active -> withdrawn
	KindExpire       = "expire"        // evidence.validUntil moved earlier
	KindAddWithdrawn = "add-withdrawn" // a new rule that is already withdrawn

	KindNew         = "new"          // a new active rule
	KindRemove      = "remove"       // a rule deleted from the pack
	KindReactivate  = "reactivate"   // evidence.state withdrawn -> active
	KindRenew       = "renew"        // evidence dates moved later
	KindRepin       = "repin"        // evidence.sources changed
	KindWiden       = "widen"        // range added or extended
	KindNarrow      = "narrow"       // range removed or reduced
	KindRangeChange = "range-change" // range changed otherwise
	KindBasis       = "basis-change" // evidence basis or extractor changed
	KindModify      = "modify"       // anything else in the entry changed
	// KindPackMember is a change to a top-level pack member other than
	// entries (schema, revision, policy, any new member). No such change
	// is admitted by this version of the gate.
	KindPackMember = "pack-member"
)

// Change is one rule that differs between base and head.
type Change struct {
	Pack   string `json:"pack"`
	RuleID string `json:"ruleId"`
	// Member names the top-level pack member a pack-member change
	// concerns; RuleID is then empty.
	Member  string   `json:"member,omitempty"`
	Project string   `json:"project"`
	Class   string   `json:"class"`
	Kinds   []string `json:"kinds"`
	// Basis is the head rule's effective basis (the base rule's for a
	// removal).
	Basis string `json:"basis"`
	// Proof names how a loosening change was admitted ("rederived",
	// "reattestation", "approval"), or "none-required" for tightening.
	Proof string `json:"proof,omitempty"`
	// OK reports whether the change is admitted; Detail says why not.
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`

	base, head *entry
}

// diffPacks classifies every top-level member and every rule that differs
// between two loads of a pack. Only entries have classification rules:
// any other member that differs is a loosening change that is never
// admitted.
func diffPacks(base, head *loadedPack) []*Change {
	var out []*Change
	members := map[string]bool{}
	for m := range base.Members {
		members[m] = true
	}
	for m := range head.Members {
		members[m] = true
	}
	names := make([]string, 0, len(members))
	for m := range members {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		b, bok := base.Members[m]
		h, hok := head.Members[m]
		if bok == hok && bytes.Equal(canonicalRaw(b), canonicalRaw(h)) {
			continue
		}
		out = append(out, &Change{Pack: head.Spec.Name, Member: m, Class: ClassLoosening, Kinds: []string{KindPackMember}})
	}
	ids := map[string]bool{}
	for id := range base.Entries {
		ids[id] = true
	}
	for id := range head.Entries {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		b, h := base.Entries[id], head.Entries[id]
		if b != nil && h != nil && bytes.Equal(b.Canonical, h.Canonical) {
			continue
		}
		c := &Change{Pack: head.Spec.Name, RuleID: id, base: b, head: h}
		switch {
		case b == nil:
			c.Project, c.Basis = h.Project, h.effectiveBasis()
			if h.Evidence.State == "withdrawn" {
				c.Class, c.Kinds = ClassTightening, []string{KindAddWithdrawn}
			} else {
				c.Class, c.Kinds = ClassLoosening, []string{KindNew}
			}
		case h == nil:
			c.Project, c.Basis = b.Project, b.effectiveBasis()
			c.Class, c.Kinds = ClassLoosening, []string{KindRemove}
		default:
			c.Project, c.Basis = h.Project, h.effectiveBasis()
			c.Class, c.Kinds = classifyEdit(b, h)
		}
		out = append(out, c)
	}
	return out
}

// classifyEdit classifies a rule present in both packs. The change is
// tightening only when the head equals the base except for a withdrawal
// and/or an earlier validUntil; any other difference is loosening.
func classifyEdit(b, h *entry) (string, []string) {
	var kinds []string
	loosening := false
	stateB, stateH := b.Evidence.State, h.Evidence.State
	switch {
	case stateB == stateH:
	case stateB == "active" && stateH == "withdrawn":
		kinds = append(kinds, KindWithdraw)
	case stateB == "withdrawn" && stateH == "active":
		kinds, loosening = append(kinds, KindReactivate), true
	default:
		kinds, loosening = append(kinds, KindModify), true
	}
	if b.Evidence.ValidUntil != h.Evidence.ValidUntil {
		bu, errB := time.Parse(time.RFC3339, b.Evidence.ValidUntil)
		hu, errH := time.Parse(time.RFC3339, h.Evidence.ValidUntil)
		if errB == nil && errH == nil && hu.Before(bu) {
			kinds = append(kinds, KindExpire)
		} else {
			kinds, loosening = append(kinds, KindRenew), true
		}
	}

	// Everything except state and validUntil must be byte-identical for
	// the edit to stay tightening.
	rest := deepCopy(h.generic)
	for _, field := range []string{"state", "validUntil"} {
		v, ok := lookup(b.generic, "rule", "evidence", field)
		if !setOrDelete(rest, v, ok, "rule", "evidence", field) {
			return ClassLoosening, append(kinds, KindModify)
		}
	}
	if !bytes.Equal(canonicalOf(rest), canonicalOf(b.generic)) {
		loosening = true
		other := false
		if !sameAt(b.generic, h.generic, "rule", "evidence", "reviewedAt") || !sameAt(b.generic, h.generic, "rule", "evidence", "derivedAt") {
			if !containsKind(kinds, KindRenew) {
				kinds = append(kinds, KindRenew)
			}
		}
		if !sameAt(b.generic, h.generic, "rule", "evidence", "sources") {
			kinds = append(kinds, KindRepin)
		}
		if !sameAt(b.generic, h.generic, "rule", "evidence", "basis") || !sameAt(b.generic, h.generic, "rule", "evidence", "extractor") {
			kinds = append(kinds, KindBasis)
		}
		if !sameAt(b.generic, h.generic, "rule", "range") {
			kinds = append(kinds, rangeKind(b.Range, h.Range))
		}
		// Anything outside the fields named above.
		probe := deepCopy(rest)
		for _, keys := range [][]string{{"rule", "evidence", "reviewedAt"}, {"rule", "evidence", "derivedAt"}, {"rule", "evidence", "sources"}, {"rule", "evidence", "basis"}, {"rule", "evidence", "extractor"}, {"rule", "range"}} {
			v, ok := lookup(b.generic, keys...)
			if !setOrDelete(probe, v, ok, keys...) {
				other = true
			}
		}
		if other || !bytes.Equal(canonicalOf(probe), canonicalOf(b.generic)) {
			kinds = append(kinds, KindModify)
		}
	}
	if loosening {
		return ClassLoosening, kinds
	}
	return ClassTightening, kinds
}

// canonicalRaw is the canonical form of a JSON value; nil when it does not
// parse, so two unparsable values never compare equal to a valid one.
func canonicalRaw(raw json.RawMessage) []byte {
	if raw == nil {
		return nil
	}
	v, err := decodeAny(raw)
	if err != nil {
		return nil
	}
	return canonicalOf(v)
}

func containsKind(kinds []string, k string) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

// rangeKind describes a range change; every range change is loosening.
func rangeKind(baseRaw, headRaw json.RawMessage) string {
	parse := func(raw json.RawMessage) *constraintengine.VersionRange {
		if len(raw) == 0 || string(raw) == "null" {
			return nil
		}
		var r constraintengine.VersionRange
		if json.Unmarshal(raw, &r) != nil {
			return nil
		}
		return &r
	}
	b, h := parse(baseRaw), parse(headRaw)
	switch {
	case b == nil && h != nil:
		return KindWiden
	case b != nil && h == nil:
		return KindNarrow
	case b != nil && h != nil:
		inside := func(inner, outer constraintengine.VersionBound) bool {
			return !constraintengine.VersionLess(inner.Gte, outer.Gte) && !constraintengine.VersionLess(outer.Lt, inner.Lt)
		}
		switch {
		case inside(h.From, b.From) && inside(h.To, b.To):
			return KindNarrow
		case inside(b.From, h.From) && inside(b.To, h.To):
			return KindWiden
		}
	}
	return KindRangeChange
}

// Classification is the classified difference between two trees.
type Classification struct {
	Changes []*Change
	// ChainsChanged names the packs whose reattestation statement chain
	// directory differs between base and head.
	ChainsChanged []string
	// Paused is true when the kill switch exists in the base or the head.
	Paused bool
	base   map[string]*loadedPack
	head   map[string]*loadedPack
}

// Counts returns the number of tightening and loosening changes.
func (c Classification) Counts() (tightening, loosening int) {
	for _, ch := range c.Changes {
		if ch.Class == ClassLoosening {
			loosening++
		} else {
			tightening++
		}
	}
	return
}

// Classify loads every pack of the layout from both trees and classifies
// every rule that differs.
func Classify(layout Layout, base, head Tree) (*Classification, error) {
	out := &Classification{base: map[string]*loadedPack{}, head: map[string]*loadedPack{}}
	for _, spec := range layout.Packs {
		b, err := loadPack(base, spec)
		if err != nil {
			return nil, err
		}
		h, err := loadPack(head, spec)
		if err != nil {
			return nil, err
		}
		out.base[spec.Name], out.head[spec.Name] = b, h
		out.Changes = append(out.Changes, diffPacks(b, h)...)
		changed, err := chainChanged(layout, spec, base, head)
		if err != nil {
			return nil, err
		}
		if changed {
			out.ChainsChanged = append(out.ChainsChanged, spec.Name)
		}
	}
	out.Paused = base.Exists(layout.PausePath) || head.Exists(layout.PausePath)
	return out, nil
}

func chainChanged(layout Layout, spec PackSpec, base, head Tree) (bool, error) {
	dir := layout.ReattestDir + "/" + spec.Name + "/chain"
	b, err := base.Dir(dir, MaxFileBytes, maxChainFiles)
	if err != nil {
		return false, err
	}
	h, err := head.Dir(dir, MaxFileBytes, maxChainFiles)
	if err != nil {
		return false, err
	}
	if len(b) != len(h) {
		return true, nil
	}
	for name, raw := range b {
		if other, ok := h[name]; !ok || !bytes.Equal(raw, other) {
			return true, nil
		}
	}
	return false, nil
}
