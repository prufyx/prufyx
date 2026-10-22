// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/servedlists"
)

// servedBatchLines are the 19 Kubernetes lines the first introduction of the
// servedAPIs member carries: every line the shipped pack's Kubernetes rules
// cover, 1.19 to 1.37.
func servedBatchLines() []string {
	var lines []string
	for minor := 19; minor <= 37; minor++ {
		lines = append(lines, fmt.Sprintf("1.%d", minor))
	}
	return lines
}

// newServedBatchFake has a tag per batch line, each at its own commit.
func newServedBatchFake(t *testing.T) *servedFake {
	t.Helper()
	data, err := os.ReadFile(servedSwaggerFile)
	if err != nil {
		t.Fatal(err)
	}
	f := &servedFake{files: map[string][]byte{}}
	for i, line := range servedBatchLines() {
		commit := fmt.Sprintf("%039x%x", i, 10)
		f.tags = append(f.tags, extract.Tag{Name: "v" + line + ".0", Commit: commit})
		f.files[commit] = data
	}
	return f
}

// servedBatchHead puts the lists of all batch lines, derived at stamp, into
// the head pack at the schema level they need.
func servedBatchHead(t *testing.T, head Tree, src *servedFake, stamp time.Time) {
	t.Helper()
	var recs []servedapis.Record
	for _, line := range servedBatchLines() {
		rec, err := servedlists.Build(context.Background(), src, src, line, stamp)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	section, err := servedapis.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	p := readPack(t, head, cncfRulesPath)
	p.fields[servedapis.PackMember] = json.RawMessage(section)
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha10"`)
	p.write(t, head, cncfRulesPath)
}

// The 19 lists of the first introduction arrive in one change, with the
// owner's approval of the introduction. The loosening cap (200) and the
// daily limit (50) do not stop it. The record stagger cap depends on the day:
// every list of one run has the same validUntil (derivedAt plus 89 days), so
// all 19 fall in one ISO week, and that week may hold at most 15 percent of
// the pack's rules and records. A day that puts them in a week that is
// already full is refused, whatever the lists are.
func TestServedIntroductionOfNineteenLists(t *testing.T) {
	t.Parallel()
	src := newServedBatchFake(t)
	key := newApprovalKey(t)

	// gateAt runs the whole route for a gate clock: the lists derived an hour
	// earlier, the owner's approval signed a minute before the gate runs.
	gateAt := func(t *testing.T, now time.Time, daily int) *Report {
		t.Helper()
		base, head := trees(t)
		key.pinBoth(t, base, head, "airstand")
		servedBatchHead(t, head, src, now.Add(-time.Hour))
		regenerate(t, head) // the corpus attestation and the support inventory follow the pack
		keys := filepath.Join(base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
		keysRaw, err := os.ReadFile(keys)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(head.Root, filepath.FromSlash(servedApprovalPath(DefaultLayout(), "cncf")))
		r := runApproval(t, nil, now.Add(-time.Minute), "sign", "--subject", "servedAPIs", "--pack", "cncf", "--base-root", base.Root, "--head-root", head.Root,
			"--keys", keys, "--keys-digest", pinnedDigest(keysRaw), "--identity", "airstand", "--candidate-id", "cand-1", "--key", key.keyFile(t, 0o600), "--output", out)
		if r.code != 0 {
			t.Fatalf("sign: %d %s %s", r.code, r.stdout, r.stderr)
		}
		return runGate(t, Options{Base: base, Head: head, Source: src, Now: now, DailyLoosening: &daily})
	}

	t.Run("derived on a day that lands in a quiet week", func(t *testing.T) {
		now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) // validUntil 2027-01-25, an empty week
		report := gateAt(t, now, 0)
		if n := requireServedAdmitted(t, report); n != 19 {
			t.Fatalf("%d lists", n)
		}
		if !report.Limits.OK || report.Limits.Loosening < 19 || report.Limits.Loosening > report.Limits.MaxLoosening {
			t.Fatalf("limits %+v", report.Limits)
		}
		if !report.Daily.OK || report.Daily.Change < 19 || report.Daily.Change > report.Daily.Cap {
			t.Fatalf("daily %+v", report.Daily)
		}
		if c, ok := check(report, "stagger/cncf/records"); !ok || !c.OK {
			t.Fatalf("stagger: %+v", c)
		}
		if !report.Passed() {
			t.Fatalf("not passed: %v", failedChecks(report))
		}
	})

	t.Run("derived on a day that lands in a busy week", func(t *testing.T) {
		// 2026-09-12 plus 88 days is in 2026-W50, where most of the pack's
		// rules expire.
		report := gateAt(t, time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC), 0)
		c, ok := check(report, "stagger/cncf/records")
		if !ok || c.OK || !strings.Contains(c.Detail, "2026-W50 holds") {
			t.Fatalf("stagger: %+v", c)
		}
		if report.Passed() {
			t.Fatal("passed")
		}
		// The lists themselves are admitted: only the week is the problem.
		if n := requireServedListsOK(t, report); n != 19 {
			t.Fatalf("%d lists", n)
		}
	})
}

// requireServedListsOK counts the served-list changes of a report and
// requires each to be admitted by re-derivation.
func requireServedListsOK(t *testing.T, r *Report) int {
	t.Helper()
	n := 0
	for _, c := range r.Changes {
		if c.Section != sectionServed {
			continue
		}
		n++
		if !c.OK || c.Proof != ProofRederived {
			t.Fatalf("%s: ok %v proof %q: %s", c.RuleID, c.OK, c.Proof, c.Detail)
		}
	}
	return n
}
