// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

// sameBuildOlder makes a pack entry look derived by this very extractor build,
// three days before the run, with a lease that ends earlier.
func sameBuildOlder(e map[string]any) {
	ev := ruleEv(e)
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"
}

func applyAt(pack, run string, now time.Time) (*extractpack.Report, error) {
	return extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, RenewAttestations: true, Admit: admitAll, Now: func() time.Time { return now }})
}

func TestRenewRulesSameBuildTimeOnly(t *testing.T) {
	for name, now := range map[string]time.Time{
		"at derivedAt":                 derivedAt,
		"clock five minutes behind it": derivedAt.Add(-5 * time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			pack, run, pre, order := ruleRenewSetup(t, sameBuildOlder)
			want := ruleIDs(t, run)
			rep, err := applyAt(pack, run, now)
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(rep.RenewedRules, want) || len(rep.Added) != 0 || len(rep.RemediationRenewed) != 0 || !rep.Changed {
				t.Fatalf("report %+v, want renewed %v", rep, want)
			}
			after, _ := os.ReadFile(pack)
			if bytes.Equal(after, pre) {
				t.Fatal("a renewal-only run did not write the pack")
			}
			if got := packOrder(t, after); !equalStrings(got, order) {
				t.Fatalf("entry order changed:\n%v\n%v", got, order)
			}
			again, err := applyAt(pack, run, now)
			if err != nil || again.Changed || len(again.RenewedRules) != 0 || len(again.Unchanged) != len(want) {
				t.Fatalf("second: %+v %v", again, err)
			}
		})
	}
}

func TestRenewRulesSameBuildRefusals(t *testing.T) {
	older := func(f func(e, ev map[string]any)) func(map[string]any) {
		return func(e map[string]any) {
			sameBuildOlder(e)
			f(e, ruleEv(e))
		}
	}
	firstSource := func(ev map[string]any) map[string]any { return ev["sources"].([]any)[0].(map[string]any) }
	for _, c := range []struct {
		name  string
		now   time.Time
		renew bool
		edit  func(e map[string]any)
	}{
		{"flag absent", derivedAt, false, sameBuildOlder},
		{"future derivedAt", derivedAt.Add(-5*time.Minute - time.Second), true, sameBuildOlder},
		{"sources not byte-equal", derivedAt, true, older(func(_, ev map[string]any) { firstSource(ev)["url"] = "https://example.invalid/moved" })},
		{"content changed", derivedAt, true, older(func(e, _ map[string]any) { e["description"] = "changed" })},
		{"range changed", derivedAt, true, older(func(e, _ map[string]any) {
			e["rule"].(map[string]any)["range"] = map[string]any{"changed": true}
		})},
		{"lease changed", derivedAt, true, older(func(_, ev map[string]any) { ev["lease"] = "pinned" })},
		{"derivedAt not later", derivedAt, true, older(func(_, ev map[string]any) {
			ev["derivedAt"], ev["reviewedAt"] = "2026-10-04T00:00:00Z", "2026-10-04T00:00:00Z"
		})},
		{"end not later than the old one", derivedAt, true, older(func(_, ev map[string]any) { ev["validUntil"] = "2027-12-31T00:00:00Z" })},
		{"non-mechanical", derivedAt, true, older(func(_, ev map[string]any) {
			ev["basis"] = "reviewed"
			delete(ev, "extractor")
			delete(ev, "derivedAt")
		})},
		{"withdrawn", derivedAt, true, older(func(_, ev map[string]any) { ev["state"] = "withdrawn" })},
	} {
		t.Run(c.name, func(t *testing.T) {
			pack, run, pre, _ := ruleRenewSetup(t, c.edit)
			_, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, RenewAttestations: c.renew, Admit: admitAll, Now: func() time.Time { return c.now }})
			if !errors.Is(err, extractpack.ErrCollision) {
				t.Fatalf("err = %v, want a collision", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
}

// With no injected clock apply uses the real one, so a run derived ahead of it
// renews nothing.
func TestRenewRulesSameBuildDefaultClock(t *testing.T) {
	future := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	run := runDir(t, cases[3], future)
	pack := prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, run, false); err != nil {
		t.Fatal(err)
	}
	mine := map[string]bool{}
	for _, id := range ruleIDs(t, run) {
		mine[id] = true
	}
	pre := mustModifyPack(t, pack, func(es []map[string]any) []map[string]any {
		for _, e := range es {
			if mine[e["rule"].(map[string]any)["id"].(string)] {
				sameBuildOlder(e)
			}
		}
		return es
	})
	if _, err := renewApply(t, pack, run, true); !errors.Is(err, extractpack.ErrCollision) {
		t.Fatalf("err = %v, want a collision", err)
	}
	assertUnchanged(t, pack, pre)
}

// A same-build merge step that changes more than the times is stopped by the
// final audit.
func TestRenewRulesSameBuildAuditRefusesAMisbehavingStep(t *testing.T) {
	pack, run, pre, _ := ruleRenewSetupWith(t, sameBuildOlder, false)
	defer extractpack.SetSteps(func(base *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
		head, allowed, err := extractpack.RealMerge(base, r, rep)
		if err != nil || len(rep.RenewedRules) == 0 {
			t.Fatalf("real merge: %+v %v", rep, err)
		}
		for i, e := range head.Entries {
			var m map[string]any
			_ = json.Unmarshal(e, &m)
			if m["rule"].(map[string]any)["id"] == rep.RenewedRules[0] {
				ruleEv(m)["sources"].([]any)[0].(map[string]any)["url"] = "https://example.invalid/moved"
				head.Entries[i], _ = json.Marshal(m)
			}
		}
		return head, allowed, nil
	}, nil)()
	if _, err := applyAt(pack, run, derivedAt); !errors.Is(err, extractpack.ErrForeignChange) {
		t.Fatalf("err = %v, want ErrForeignChange", err)
	}
	assertUnchanged(t, pack, pre)
}
