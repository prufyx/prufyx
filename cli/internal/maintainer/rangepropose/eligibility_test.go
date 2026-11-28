// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// No upstream minimum source version is read, so no candidate reaches below the
// patch the rule was reviewed at.
func TestTheFromBoundNeverGoesBelowTheAnchor(t *testing.T) {
	releases := append(standard(), release{"v1.7.0", files{"flags.go": newCode}})
	f := newFixture(t, releases)
	clone := f.bare()
	for name, tc := range map[string]struct{ from, to, lt, ltBasis string }{
		"adjacent, first patch":      {"1.4.0", "1.5.0", "1.5.0", BasisReviewerMustDecide},
		"adjacent, middle patch":     {"1.4.1", "1.5.0", "1.5.0", BasisReviewerMustDecide},
		"adjacent, highest patch":    {"1.4.2", "1.5.1", "1.5.0", BasisReviewerMustDecide},
		"non-adjacent, first patch":  {"1.4.0", "1.7.0", "1.4.1", constraintengine.BasisAnchorOnly},
		"non-adjacent, middle patch": {"1.4.1", "1.7.0", "1.4.2", constraintengine.BasisAnchorOnly},
	} {
		t.Run(name, func(t *testing.T) {
			target := "v1.5.0"
			if strings.HasPrefix(tc.to, "1.7.") {
				target = "v1.7.0"
			}
			base := rule("flag-removed", tc.from, tc.to, []src{
				f.source("old-flags", "v1.4.1", "flags.go", 3, 5), f.source("new-flags", target, "flags.go", 3, 5)})
			p := wantProposal(t, run(t, options(t, clone, base)))
			c := p.Candidate
			if c.From.Gte != tc.from || c.From.Lt != tc.lt {
				t.Fatalf("from [%s, %s), want [%s, %s)", c.From.Gte, c.From.Lt, tc.from, tc.lt)
			}
			if c.Bounds[0] != (CandidateBound{Bound: "from.gte", Basis: constraintengine.BasisAnchorOnly, SourceID: "old-flags"}) ||
				c.Bounds[1].Bound != "from.lt" || c.Bounds[1].Basis != tc.ltBasis {
				t.Fatalf("bounds: %+v", c.Bounds)
			}
			if !slices.Contains(p.Flags, "from-floor-is-anchor") || !slices.Contains(p.Flags, "upstream-minimum-source-version-not-checked") {
				t.Fatalf("flags: %v", p.Flags)
			}
			candidate := asMap(t, c)
			delete(candidate, "reviewStatus")
			if tc.ltBasis == BasisReviewerMustDecide {
				for _, i := range []int{1, 2} {
					bound := candidate["bounds"].([]any)[i].(map[string]any)
					bound["basis"], bound["sourceId"] = constraintengine.BasisRemovedInRelease, "new-flags"
				}
			}
			if err := candidateInEngine(t, base, candidate); err != nil {
				t.Fatalf("the engine refuses the reviewed candidate: %v", err)
			}
		})
	}
}

func TestEvidenceThatIsNotCurrentIsRefused(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	at := testNow.Format(time.RFC3339)
	later := testNow.Add(time.Second).Format(time.RFC3339)
	earlier := testNow.Add(-time.Second).Format(time.RFC3339)
	with := func(reviewed, until any) map[string]any {
		r := standardRule(f)
		evidence := r["evidence"].(map[string]any)
		evidence["reviewedAt"], evidence["validUntil"] = reviewed, until
		return r
	}
	for name, tc := range map[string]struct {
		reviewed, until any
		code            string
	}{
		"expired":                {"2026-01-01T00:00:00Z", earlier, CodeEvidenceExpired},
		"expires now":            {"2026-01-01T00:00:00Z", at, CodeEvidenceExpired},
		"reviewed in the future": {later, "2027-01-01T00:00:00Z", CodeEvidenceEarly},
		"no validUntil":          {"2026-01-01T00:00:00Z", nil, CodeEvidenceTime},
		"no reviewedAt":          {nil, "2027-01-01T00:00:00Z", CodeEvidenceTime},
		"date only":              {"2026-01-01T00:00:00Z", "2027-01-01", CodeEvidenceTime},
		"offset":                 {"2026-01-01T00:00:00Z", "2027-01-01T00:00:00+02:00", CodeEvidenceTime},
		"zero offset spelling":   {"2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00Z", CodeEvidenceTime},
		"fraction":               {"2026-01-01T00:00:00Z", "2027-01-01T00:00:00.5Z", CodeEvidenceTime},
		"window empty":           {"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", CodeEvidenceTime},
		"window inverted":        {"2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z", CodeEvidenceTime},
	} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, run(t, options(t, clone, with(tc.reviewed, tc.until))), tc.code)
		})
	}
	t.Run("one second left", func(t *testing.T) {
		wantProposal(t, run(t, options(t, clone, with(at, later))))
	})
	t.Run("expired pinned rule", func(t *testing.T) {
		r := with("2026-01-01T00:00:00Z", earlier)
		r["evidence"].(map[string]any)["lease"] = "pinned"
		wantRefused(t, run(t, options(t, clone, r)), CodeEvidenceExpired)
	})
}

func TestOnlyATimeLeaseIsProposed(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	for lease, proposed := range map[string]bool{"": true, "time": true, "pinned": false, "forever": false, "Time": false} {
		r := standardRule(f)
		r["evidence"].(map[string]any)["lease"] = lease
		report := run(t, options(t, clone, r))
		if proposed {
			wantProposal(t, report)
		} else {
			wantReview(t, report, ReasonLease)
		}
	}
}

func TestACrossComponentRuleNeedsReview(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	const other = "pkg:github/acme/other"
	ref := func(component string) map[string]any {
		return map[string]any{"side": "proposed", "component": component, "factId": testFact, "boolValue": true}
	}
	set := func(component string) func(map[string]any) {
		return func(r map[string]any) {
			delete(r, "condition")
			r["operator"] = "forbid_set_member"
			r["setCondition"] = map[string]any{"side": "proposed", "component": component, "factId": testFact, "members": []string{"x"}}
		}
	}
	for name, change := range map[string]func(map[string]any){
		"condition":                      func(r map[string]any) { r["condition"] = ref(other) },
		"condition missing":              func(r map[string]any) { delete(r, "condition") },
		"condition null":                 func(r map[string]any) { r["condition"] = nil },
		"condition unnamed":              func(r map[string]any) { r["condition"] = ref("") },
		"set condition":                  set(other),
		"set condition absent":           func(r map[string]any) { delete(r, "condition"); r["operator"] = "forbid_set_member" },
		"set rule with only a condition": func(r map[string]any) { r["operator"] = "forbid_set_member" },
		"stray dependency":               func(r map[string]any) { r["dependency"] = map[string]any{"side": "proposed", "component": other} },
		"stray set condition": func(r map[string]any) {
			r["setCondition"] = map[string]any{"side": "proposed", "component": other, "factId": testFact, "members": []string{"x"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := standardRule(f)
			change(r)
			v := wantReview(t, run(t, options(t, clone, r)), ReasonCrossComponent)
			if len(v.Reasons) != 1 {
				t.Fatalf("reasons: %+v", v.Reasons)
			}
		})
	}
}

func TestARunNeedsACleanToolRevisionAndATime(t *testing.T) {
	f := newFixture(t, standard())
	good := options(t, f.bare(), standardRule(f))
	wantProposal(t, run(t, good))
	full := strings.Repeat("1", 40)
	for _, revision := range []string{"", "unknown", "unknown+modified", full + "+modified", full[:12], strings.Repeat("A", 40), full + "\n"} {
		o := good
		o.ToolRevision = revision
		r, err := Run(context.Background(), o)
		if err == nil || err.Error() != toolRevisionMessage {
			t.Errorf("revision %q: %v", revision, err)
		}
		if len(r.Proposals) != 0 {
			t.Errorf("revision %q proposed", revision)
		}
	}
	o := good
	o.Now = time.Time{}
	if r, err := Run(context.Background(), o); err == nil || err.Error() != "no evaluation time" || len(r.Proposals) != 0 {
		t.Errorf("no time: %v", err)
	}
}

// A git process that does not answer is ended.
func TestAHangingGitCommandIsEnded(t *testing.T) {
	hang := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(hang, []byte("#!/bin/sh\nexec /bin/sleep 20\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binaries, limit := gitBinaries, gitTimeout
	t.Cleanup(func() { gitBinaries, gitTimeout = binaries, limit })
	if limit != 2*time.Minute {
		t.Fatalf("git time limit: %v", limit)
	}
	gitBinaries, gitTimeout = []string{hang}, 200*time.Millisecond
	started := time.Now()
	out, err := runGit(context.Background(), "/nonexistent", "cat-file")
	var exit interface{ ExitCode() int }
	if err == nil || out != nil || !errors.As(err, &exit) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hanging git: %q %v", out, err)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("the command ran %v", took)
	}
}
