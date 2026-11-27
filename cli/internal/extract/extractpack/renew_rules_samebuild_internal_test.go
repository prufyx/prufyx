// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var sameBuildNow = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// retimed gives an entry later times and changes nothing else.
func retimed(_, ev map[string]any) {
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-04T00:00:00Z", "2026-10-04T00:00:00Z", "2026-11-04T00:00:00Z"
}

func TestSameBuildRuleRenewalPredicate(t *testing.T) {
	base := rEntry(nil)
	with := func(f func(rule, ev map[string]any)) json.RawMessage {
		return rEntry(func(rule, ev map[string]any) {
			retimed(rule, ev)
			f(rule, ev)
		})
	}
	same := with(func(_, _ map[string]any) {})
	both := func(f func(rule, ev map[string]any)) (json.RawMessage, json.RawMessage) {
		return rEntry(f), with(f)
	}
	times := func(derived, until string) json.RawMessage {
		return with(func(_, ev map[string]any) {
			ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = derived, derived, until
		})
	}
	source := func(i int, key string, value any) json.RawMessage {
		return with(func(_, ev map[string]any) { ev["sources"].([]any)[i].(map[string]any)[key] = value })
	}
	raw := func(b json.RawMessage, from, to string) json.RawMessage {
		out := strings.Replace(string(b), from, to, 1)
		if out == string(b) {
			t.Fatalf("%q not found", from)
		}
		return json.RawMessage(out)
	}

	type row struct {
		name    string
		old, nw json.RawMessage
		now     time.Time
		ok      bool
	}
	rows := []row{
		{"only the times moved", base, same, sameBuildNow, true},
		{"shorter duration than the old one", base, times("2026-10-04T00:00:00Z", "2026-11-01T00:00:00Z"), sameBuildNow, true},
		{"longer duration than the old one", base, times("2026-10-04T00:00:00Z", "2026-12-20T00:00:00Z"), sameBuildNow, true},
		{"end exactly 90 days after derivedAt", base, times("2026-10-04T00:00:00Z", "2027-01-02T00:00:00Z"), sameBuildNow, true},
		{"end over 90 days by a second", base, times("2026-10-04T00:00:00Z", "2027-01-02T00:00:01Z"), sameBuildNow, false},
		{"end over 90 days by a fraction", base, times("2026-10-04T00:00:00Z", "2027-01-02T00:00:00.001Z"), sameBuildNow, false},
		{"end centuries away", base, times("2026-10-04T00:00:00Z", "9999-01-01T00:00:00Z"), sameBuildNow, false},

		{"derivedAt five minutes ahead of the clock", base, same, sameBuildNow.Add(-5 * time.Minute), true},
		{"derivedAt more than five minutes ahead", base, same, sameBuildNow.Add(-5*time.Minute - time.Second), false},
		{"derivedAt a day ahead", base, same, sameBuildNow.Add(-24 * time.Hour), false},
		{"no clock", base, same, time.Time{}, false},

		{"derivedAt equal", base, times("2026-10-01T00:00:00Z", "2026-11-04T00:00:00Z"), sameBuildNow, false},
		{"derivedAt earlier", base, times("2026-09-30T00:00:00Z", "2026-11-04T00:00:00Z"), sameBuildNow, false},
		{"derivedAt the same instant, written differently", base, times("2026-10-01T02:00:00+02:00", "2026-11-04T00:00:00Z"), sameBuildNow, false},
		{"derivedAt unreadable", base, times("soon", "2026-11-04T00:00:00Z"), sameBuildNow, false},
		{"old derivedAt unreadable", rEntry(func(_, ev map[string]any) { ev["derivedAt"] = "x" }), same, sameBuildNow, false},
		{"old derivedAt absent", rEntry(func(_, ev map[string]any) { delete(ev, "derivedAt") }), same, sameBuildNow, false},
		{"reviewedAt differs", base, with(func(_, ev map[string]any) { ev["reviewedAt"] = "2026-10-03T00:00:00Z" }), sameBuildNow, false},
		{"reviewedAt absent", base, with(func(_, ev map[string]any) { delete(ev, "reviewedAt") }), sameBuildNow, false},

		{"end equal to the old one", base, times("2026-10-04T00:00:00Z", "2026-10-31T00:00:00Z"), sameBuildNow, false},
		{"end earlier than the old one", base, times("2026-10-04T00:00:00Z", "2026-10-30T00:00:00Z"), sameBuildNow, false},
		{"end not after derivedAt", rEntry(func(_, ev map[string]any) { ev["validUntil"] = "2026-10-02T00:00:00Z" }), times("2026-10-04T00:00:00Z", "2026-10-03T00:00:00Z"), sameBuildNow, false},
		{"end unreadable", base, times("2026-10-04T00:00:00Z", "later"), sameBuildNow, false},
		{"old end unreadable", rEntry(func(_, ev map[string]any) { ev["validUntil"] = "x" }), same, sameBuildNow, false},
		{"old end absent", rEntry(func(_, ev map[string]any) { delete(ev, "validUntil") }), same, sameBuildNow, false},

		{"source url", base, source(0, "url", "u9"), sameBuildNow, false},
		{"source revision", base, source(1, "revision", "r9"), sameBuildNow, false},
		{"source member added", base, source(0, "contentSha256", "sha256:x"), sameBuildNow, false},
		{"source line moved", base, source(0, "startLine", 2), sameBuildNow, false},
		{"source id", base, source(0, "id", "s9"), sameBuildNow, false},
		{"sources reordered", base, with(func(_, ev map[string]any) {
			s := ev["sources"].([]any)
			ev["sources"] = []any{s[1], s[0]}
		}), sameBuildNow, false},
		{"source dropped", base, with(func(_, ev map[string]any) { ev["sources"] = ev["sources"].([]any)[:1] }), sameBuildNow, false},
		{"source added", base, with(func(_, ev map[string]any) { ev["sources"] = append(ev["sources"].([]any), map[string]any{"id": "s3"}) }), sameBuildNow, false},

		{"content changed", base, with(func(rule, _ map[string]any) { rule["severity"] = "low" }), sameBuildNow, false},
		{"advice changed", base, with(func(rule, _ map[string]any) { rule["nextAction"] = "other" }), sameBuildNow, false},
		{"range added", base, with(func(rule, _ map[string]any) { rule["range"] = map[string]any{"from": "1", "to": "2"} }), sameBuildNow, false},
		{"rule id changed", base, with(func(rule, _ map[string]any) { rule["id"] = "r.2" }), sameBuildNow, false},
		{"project changed", base, raw(same, `"project":"p"`, `"project":"q"`), sameBuildNow, false},
		{"description changed", base, raw(same, `"description":"d"`, `"description":"e"`), sameBuildNow, false},
		{"evidence member added", base, with(func(_, ev map[string]any) { ev["note"] = "n" }), sameBuildNow, false},
		{"extractor member added", base, with(func(_, ev map[string]any) { ev["extractor"].(map[string]any)["note"] = "n" }), sameBuildNow, false},
		{"other extractor id", base, with(func(_, ev map[string]any) { ev["extractor"].(map[string]any)["id"] = "z" }), sameBuildNow, false},
		{"repeated member", base, raw(same, `"severity":"high"`, `"severity":"low","severity":"high"`), sameBuildNow, false},
		{"member differing only in case", base, raw(same, `"severity":"high"`, `"Severity":"low","severity":"high"`), sameBuildNow, false},
		{"trailing data", base, json.RawMessage(string(same) + "{}"), sameBuildNow, false},
	}
	// evidence.lease: the member's presence and value must be equal.
	leased := func(v string) func(rule, ev map[string]any) {
		return func(_, ev map[string]any) { ev["lease"] = v }
	}
	timeOld, timeNew := both(leased("time"))
	rows = append(rows,
		row{"lease equal", timeOld, timeNew, sameBuildNow, true},
		row{"lease added", base, timeNew, sameBuildNow, false},
		row{"lease removed", timeOld, same, sameBuildNow, false},
		row{"lease time to pinned", timeOld, with(leased("pinned")), sameBuildNow, false},
		row{"lease added pinned", base, with(leased("pinned")), sameBuildNow, false},
		row{"lease empty added", base, with(leased("")), sameBuildNow, false},
	)
	// Required members, wrong on one side or on both.
	for name, f := range map[string]func(rule, ev map[string]any){
		"reviewed":      func(_, ev map[string]any) { ev["basis"] = "reviewed" },
		"consensus":     func(_, ev map[string]any) { ev["basis"] = "consensus" },
		"no basis":      func(_, ev map[string]any) { delete(ev, "basis") },
		"withdrawn":     func(_, ev map[string]any) { ev["state"] = "withdrawn" },
		"no state":      func(_, ev map[string]any) { delete(ev, "state") },
		"no extractor":  func(_, ev map[string]any) { delete(ev, "extractor") },
		"no version":    func(_, ev map[string]any) { delete(ev["extractor"].(map[string]any), "version") },
		"empty digest":  func(_, ev map[string]any) { ev["extractor"].(map[string]any)["codeDigest"] = "" },
		"empty id":      func(_, ev map[string]any) { ev["extractor"].(map[string]any)["id"] = "" },
		"no sources":    func(_, ev map[string]any) { delete(ev, "sources") },
		"empty sources": func(_, ev map[string]any) { ev["sources"] = []any{} },
	} {
		o, n := both(f)
		rows = append(rows,
			row{name + " on both", o, n, sameBuildNow, false},
			row{name + " old", o, same, sameBuildNow, false},
			row{name + " new", base, n, sameBuildNow, false},
		)
	}

	ids := map[string]bool{"r.1": true, "r.2": true}
	// A version or digest missing on one side only makes the two entries
	// different builds, which the same-build predicate refuses and the
	// different-build path (unchanged, and followed by rule validation and the
	// engine loader) decides.
	otherBuild := map[string]bool{"no version old": true, "no version new": true, "empty digest old": true, "empty digest new": true}
	for _, c := range rows {
		if got := sameBuildRuleRenewal(c.old, c.nw, c.now); got != c.ok {
			t.Errorf("%s: sameBuildRuleRenewal = %v, want %v", c.name, got, c.ok)
		}
		if otherBuild[c.name] {
			continue
		}
		if got := ruleRenewable(c.old, c.nw, c.now); got != c.ok {
			t.Errorf("%s: ruleRenewable = %v, want %v", c.name, got, c.ok)
		}
		// The final audit holds the same line. It keys rules by id and reads
		// entries canonically, so rows it cannot express are left to the
		// predicate above.
		switch c.name {
		case "rule id changed", "repeated member", "trailing data":
			continue
		}
		err := audit(mkPack(c.old), mkPack(c.nw), nil, ids, nil, false, c.now)
		if c.ok != (err == nil) {
			t.Errorf("%s: audit = %v, want admitted %v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error type: %v", c.name, err)
		}
	}
}

// A renewal at another extractor build keeps its earlier conditions: it has no
// clock, no 90-day bound and no old-end comparison, and sources may move.
func TestDifferentBuildRuleRenewalUnchanged(t *testing.T) {
	old := rEntry(nil)
	nw := rEntry(func(rule, ev map[string]any) {
		newer(rule, ev)
		ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2030-01-01T00:00:00Z", "2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"
		ev["sources"].([]any)[0].(map[string]any)["url"] = "n1"
	})
	if !ruleRenewable(old, nw, time.Time{}) {
		t.Fatal("a different-build renewal is refused")
	}
	if sameBuildRuleRenewal(old, nw, time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("a different build passed the same-build predicate")
	}
}
