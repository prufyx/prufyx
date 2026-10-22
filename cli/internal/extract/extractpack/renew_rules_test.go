// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

func ruleEv(e map[string]any) map[string]any {
	return e["rule"].(map[string]any)["evidence"].(map[string]any)
}

// olderBuild makes a pack entry look derived by an earlier build of the
// extractor, three days before the run.
func olderBuild(e map[string]any) {
	ev := ruleEv(e)
	ev["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"
}

// ruleRenewSetup applies the argo-cd run, then ages every rule the run brought
// through edit. It returns the pack, the run, the bytes before the renewal and
// the rule ids in pack order.
func ruleRenewSetup(t *testing.T, edit func(e map[string]any)) (pack, run string, pre []byte, order []string) {
	t.Helper()
	return ruleRenewSetupWith(t, edit, false)
}

// ruleRenewSetupWith can drop the run's attestations first, so the pack holds
// rules only.
func ruleRenewSetupWith(t *testing.T, edit func(e map[string]any), noAttestations bool) (pack, run string, pre []byte, order []string) {
	t.Helper()
	run = runDir(t, cases[3], derivedAt)
	if noAttestations {
		trimRun(t, run, nil, true)
	}
	pack = prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, run, false); err != nil {
		t.Fatal(err)
	}
	mine := map[string]bool{}
	for _, id := range ruleIDs(t, run) {
		mine[id] = true
	}
	pre = mustModifyPack(t, pack, func(es []map[string]any) []map[string]any {
		for _, e := range es {
			if mine[e["rule"].(map[string]any)["id"].(string)] {
				edit(e)
			}
		}
		return es
	})
	return pack, run, pre, packOrder(t, pre)
}

func packOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range p.Entries {
		var v struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		_ = json.Unmarshal(e, &v)
		ids = append(ids, v.Rule.ID)
	}
	return ids
}

func TestRenewRulesReplacesInPlace(t *testing.T) {
	pack, run, pre, order := ruleRenewSetup(t, olderBuild)
	want := ruleIDs(t, run)
	if len(want) == 0 {
		t.Fatal("run has no rules")
	}
	rep, err := renewApply(t, pack, run, true)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(rep.RenewedRules, want) || len(rep.Added) != 0 || !rep.Changed {
		t.Fatalf("report %+v, want renewed %v", rep, want)
	}
	after, _ := os.ReadFile(pack)
	if bytes.Equal(after, pre) {
		t.Fatal("a renewal-only run did not write the pack")
	}
	if got := packOrder(t, after); !equalStrings(got, order) {
		t.Fatalf("entry order changed:\n%v\n%v", got, order)
	}
	// The stored rules are the run's again: a second run finds them identical.
	again, err := renewApply(t, pack, run, true)
	if err != nil || again.Changed || len(again.RenewedRules) != 0 || len(again.Unchanged) != len(want) {
		t.Fatalf("second: %+v %v", again, err)
	}
}

func TestRenewRulesRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		renew bool
		edit  func(e map[string]any)
	}{
		{"flag absent", false, olderBuild},
		{"body changed", true, func(e map[string]any) {
			olderBuild(e)
			e["description"] = "changed"
			e["rule"].(map[string]any)["severity"] = "x"
		}},
		{"reviewed base", true, func(e map[string]any) {
			olderBuild(e)
			ev := ruleEv(e)
			ev["basis"] = "reviewed"
			delete(ev, "extractor")
			delete(ev, "derivedAt")
		}},
		{"withdrawn base", true, func(e map[string]any) { olderBuild(e); ruleEv(e)["state"] = "withdrawn" }},
		{"other extractor id", true, func(e map[string]any) {
			olderBuild(e)
			ruleEv(e)["extractor"].(map[string]any)["id"] = "crd.version-removal.other"
		}},
		{"same build", true, func(e map[string]any) { ruleEv(e)["derivedAt"] = "2026-10-01T00:00:00Z" }},
		{"base derivedAt not older", true, func(e map[string]any) {
			olderBuild(e)
			ev := ruleEv(e)
			ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-04T00:00:00Z", "2026-10-04T00:00:00Z", "2026-11-04T00:00:00Z"
		}},
		{"base derivedAt unparsable", true, func(e map[string]any) { olderBuild(e); ruleEv(e)["derivedAt"] = "yesterday" }},
		{"source ids differ", true, func(e map[string]any) {
			olderBuild(e)
			ruleEv(e)["sources"].([]any)[0].(map[string]any)["id"] = "other-source"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pack, run, pre, _ := ruleRenewSetup(t, c.edit)
			if _, err := renewApply(t, pack, run, c.renew); !errors.Is(err, extractpack.ErrCollision) {
				t.Fatalf("err = %v, want a collision", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
}

// A merge step whose result renews more than a renewal may change, or appends
// where it should replace, is stopped by the final audit.
func TestRenewRulesFinalAuditRefusesAMisbehavingStep(t *testing.T) {
	for _, c := range []struct {
		name   string
		step   extractpack.Step
		noAtts bool
	}{
		{"appends instead of replacing", func(base *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
			// The real merge is not used: the stub keeps the base and appends
			// the run's rules next to the stored ones, reporting no rule it
			// would have to justify.
			head := &extractpack.Pack{Members: base.Members, Entries: append(append([]json.RawMessage(nil), base.Entries...), r.Entries...)}
			return head, map[string]bool{"unrelated.new.id": true}, nil
		}, true},
		{"changes the body", func(base *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
			head, allowed, err := extractpack.RealMerge(base, r, rep)
			if err != nil || len(rep.RenewedRules) == 0 {
				t.Fatalf("real merge: %+v %v", rep, err)
			}
			for i, e := range head.Entries {
				var m map[string]any
				_ = json.Unmarshal(e, &m)
				if m["rule"].(map[string]any)["id"] == rep.RenewedRules[0] {
					m["description"] = "sneaked in"
					head.Entries[i], _ = json.Marshal(m)
				}
			}
			return head, allowed, nil
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			pack, run, pre, _ := ruleRenewSetupWith(t, olderBuild, c.noAtts)
			defer extractpack.SetSteps(c.step, nil)()
			if _, err := renewApply(t, pack, run, true); !errors.Is(err, extractpack.ErrForeignChange) {
				t.Fatalf("err = %v, want ErrForeignChange", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
}
