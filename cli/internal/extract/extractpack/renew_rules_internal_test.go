// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"encoding/json"
	"errors"
	"testing"
)

func rEntry(mut func(rule, ev map[string]any)) json.RawMessage {
	ev := map[string]any{
		"state": "active", "basis": "mechanical",
		"extractor":  map[string]any{"id": "x.y", "version": "1", "codeDigest": "sha256:old"},
		"derivedAt":  "2026-10-01T00:00:00Z",
		"reviewedAt": "2026-10-01T00:00:00Z",
		"validUntil": "2026-10-31T00:00:00Z",
		"sources":    []any{map[string]any{"id": "s1", "url": "u1", "revision": "r1"}, map[string]any{"id": "s2", "url": "u2", "revision": "r2"}},
	}
	rule := map[string]any{"id": "r.1", "severity": "high", "evidence": ev}
	if mut != nil {
		mut(rule, ev)
	}
	b, _ := json.Marshal(map[string]any{"project": "p", "description": "d", "rule": rule})
	return b
}

func newer(rule, ev map[string]any) {
	ev["extractor"] = map[string]any{"id": "x.y", "version": "1", "codeDigest": "sha256:new"}
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-04T00:00:00Z", "2026-10-04T00:00:00Z", "2026-11-04T00:00:00Z"
}

func TestRuleRenewablePredicate(t *testing.T) {
	base := rEntry(nil)
	with := func(f func(rule, ev map[string]any)) json.RawMessage {
		return rEntry(func(rule, ev map[string]any) { newer(rule, ev); f(rule, ev) })
	}
	for _, c := range []struct {
		name      string
		old, nw   json.RawMessage
		renewable bool
	}{
		{"renewal", base, with(func(rule, ev map[string]any) {}), true},
		{"sources urls and revisions may change", base, with(func(rule, ev map[string]any) {
			ev["sources"] = []any{map[string]any{"id": "s2", "url": "n2", "revision": "n"}, map[string]any{"id": "s1", "url": "n1", "revision": "m"}}
		}), true},
		{"version differs only", base, with(func(rule, ev map[string]any) {
			ev["extractor"] = map[string]any{"id": "x.y", "version": "2", "codeDigest": "sha256:old"}
		}), true},
		{"body differs", base, with(func(rule, ev map[string]any) { rule["severity"] = "low" }), false},
		{"extra evidence member", base, with(func(rule, ev map[string]any) { ev["note"] = "n" }), false},
		{"reviewed new", base, with(func(rule, ev map[string]any) { ev["basis"] = "reviewed" }), false},
		{"reviewed old", rEntry(func(rule, ev map[string]any) { ev["basis"] = "reviewed" }), with(func(rule, ev map[string]any) {}), false},
		{"withdrawn old", rEntry(func(rule, ev map[string]any) { ev["state"] = "withdrawn" }), with(func(rule, ev map[string]any) {}), false},
		{"withdrawn new", base, with(func(rule, ev map[string]any) { ev["state"] = "withdrawn" }), false},
		{"other extractor id", base, with(func(rule, ev map[string]any) {
			ev["extractor"] = map[string]any{"id": "z", "version": "1", "codeDigest": "sha256:new"}
		}), false},
		{"same build", base, with(func(rule, ev map[string]any) {
			ev["extractor"] = map[string]any{"id": "x.y", "version": "1", "codeDigest": "sha256:old"}
		}), false},
		{"derivedAt equal", base, with(func(rule, ev map[string]any) {
			ev["derivedAt"], ev["reviewedAt"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"
		}), false},
		{"derivedAt older", base, with(func(rule, ev map[string]any) {
			ev["derivedAt"], ev["reviewedAt"] = "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"
		}), false},
		{"new derivedAt unparsable", base, with(func(rule, ev map[string]any) { ev["derivedAt"], ev["reviewedAt"] = "x", "x" }), false},
		{"old derivedAt unparsable", rEntry(func(rule, ev map[string]any) { ev["derivedAt"] = "x" }), with(func(rule, ev map[string]any) {}), false},
		{"reviewedAt differs from derivedAt", base, with(func(rule, ev map[string]any) { ev["reviewedAt"] = "2026-10-03T00:00:00Z" }), false},
		{"validUntil before derivedAt", base, with(func(rule, ev map[string]any) { ev["validUntil"] = "2026-10-03T00:00:00Z" }), false},
		{"validUntil equals derivedAt", base, with(func(rule, ev map[string]any) { ev["validUntil"] = "2026-10-04T00:00:00Z" }), false},
		{"validUntil unparsable", base, with(func(rule, ev map[string]any) { ev["validUntil"] = "later" }), false},
		{"source id added", base, with(func(rule, ev map[string]any) {
			ev["sources"] = append(ev["sources"].([]any), map[string]any{"id": "s3"})
		}), false},
		{"source id renamed", base, with(func(rule, ev map[string]any) {
			ev["sources"] = []any{map[string]any{"id": "s1"}, map[string]any{"id": "s9"}}
		}), false},
	} {
		if got := ruleRenewable(c.old, c.nw); got != c.renewable {
			t.Errorf("%s: ruleRenewable = %v, want %v", c.name, got, c.renewable)
		}
	}
}

// The audit does not trust a lookup keyed on the rule id: a result with the
// same id twice is refused, whatever else it holds, and a changed rule passes
// only as a withdrawal (withdraw mode) or a renewal (add mode).
func TestAuditRuleRenewalRows(t *testing.T) {
	old, nw := rEntry(nil), rEntry(newer)
	id := "r.1"
	ids := map[string]bool{id: true}
	for _, c := range []struct {
		name              string
		base, head        []json.RawMessage
		allowed, renewed  map[string]bool
		withdraw, refused bool
	}{
		{"renewal", []json.RawMessage{old}, []json.RawMessage{nw}, nil, ids, false, false},
		{"renewal not listed", []json.RawMessage{old}, []json.RawMessage{nw}, nil, nil, false, true},
		{"listed as added only", []json.RawMessage{old}, []json.RawMessage{nw}, ids, nil, false, true},
		{"renewal in withdraw mode", []json.RawMessage{old}, []json.RawMessage{nw}, ids, ids, true, true},
		{"appended instead of replaced", []json.RawMessage{old}, []json.RawMessage{old, nw}, nil, ids, false, true},
		{"appended, replaced and added", []json.RawMessage{old}, []json.RawMessage{nw, nw}, ids, ids, false, true},
		{"renewed body changed", []json.RawMessage{old}, []json.RawMessage{rEntry(func(r, e map[string]any) { newer(r, e); r["severity"] = "low" })}, nil, ids, false, true},
	} {
		err := audit(mkPack(c.base...), mkPack(c.head...), c.allowed, c.renewed, nil, c.withdraw)
		if c.refused != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", c.name, err, c.refused)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error type: %v", c.name, err)
		}
	}
}
