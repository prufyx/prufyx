// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// unchangedWorklist is a synthetic worklist over every citation of the pack
// in packRaw in which every citation is unchanged (NO_NEW_RELEASE against a
// latest-release baseline its own repository record backs), fresh at at.
func unchangedWorklist(t *testing.T, packPath string, packRaw []byte, at time.Time) []byte {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(at),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{packPath}},
	}
	n := 0
	for _, entry := range doc.Entries {
		fields, _ := parseRuleFields(entry.Rule)
		for _, source := range fields.Evidence.Sources {
			repo := fmt.Sprintf("r%05d", n)
			n++
			wl.Repos = append(wl.Repos, evidencerepin.RepoResolution{
				Owner: "o", Repo: repo, Status: "RESOLVED", CurrentTag: "v1", CurrentCommit: source.Revision, ResolvedAt: rfc3339(at.Add(-time.Hour)),
			})
			wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
				RulePack: packPath, RuleID: fields.ID, Project: entry.Project, SourceID: source.ID,
				Owner: "o", Repo: repo, OldCommit: source.Revision, NewCommit: source.Revision,
				Class: evidencerepin.ClassNoNewRelease, Baseline: evidencerepin.BaselineLatest, BaselineTag: "v1",
			})
		}
	}
	return marshalWorklist(t, wl)
}

type simReport struct {
	total, continuous, lapsedAtStart, renewals, cappedRules int
	lapsedBy                                               map[string]int
	minGapDays                                             int
	// cappedUntil is, for the rules at the cap after the last run, the
	// earliest and latest validUntil: with no individual review they expire
	// to UNKNOWN between these two instants.
	cappedUntilEarliest, cappedUntilLatest time.Time
}

func (r simReport) String() string {
	reasons := make([]string, 0, len(r.lapsedBy))
	for reason, count := range r.lapsedBy {
		reasons = append(reasons, fmt.Sprintf("%s=%d", reason, count))
	}
	sort.Strings(reasons)
	return fmt.Sprintf("rules=%d validThroughout=%d alreadyExpiredAtStart=%d expiredDuringRun{%s} renewals=%d rulesThatReachedTheCap=%d (they expire between %s and %s unless individually reviewed) shortestGapBetweenRenewalsDays=%d",
		r.total, r.continuous, r.lapsedAtStart, strings.Join(reasons, " "), r.renewals, r.cappedRules,
		r.cappedUntilEarliest.Format("2006-01-02"), r.cappedUntilLatest.Format("2006-01-02"), r.minGapDays)
}

// simulateAutomated runs automated prepare/verify/sign/append every step
// over runs runs on one pack, with every citation unchanged and no
// individual review ever supplied, and reports how many rules keep a valid
// lease for the whole period and why the others lose it.
func simulateAutomated(t *testing.T, packName, packPath string, start time.Time, step time.Duration, runs int) simReport {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	f := newRoleFixture(t)
	end := start.Add(time.Duration(runs) * step)
	lapsed := map[string]string{}
	lastReason := map[string]string{}
	lastRenewed := map[string]time.Time{}
	report := simReport{lapsedBy: map[string]int{}}
	capped := map[string]bool{}
	minGap := time.Duration(0)
	markLapsed := func(id string, at time.Time, validUntil time.Time) {
		if _, done := lapsed[id]; done || !validUntil.Before(at) {
			return
		}
		reason := lastReason[id]
		switch {
		case validUntil.Before(start):
			reason = "ALREADY_EXPIRED"
		case reason == "":
			reason = "NEVER_CONSIDERED"
		}
		lapsed[id] = reason
	}
	for run := 0; run < runs; run++ {
		at := start.Add(time.Duration(run) * step)
		doc, err := loadPack(raw)
		if err != nil {
			t.Fatal(err)
		}
		report.total = len(doc.Entries)
		current := map[string]time.Time{}
		for _, entry := range doc.Entries {
			fields, _ := parseRuleFields(entry.Rule)
			current[fields.ID], _ = parseUTC(fields.Evidence.ValidUntil)
			markLapsed(fields.ID, at, current[fields.ID])
		}
		worklistRaw := unchangedWorklist(t, packPath, raw, at)
		res, err := Prepare(PrepareOptions{
			Mode: ModeAutomated, WorklistRaw: worklistRaw, PackName: packName, PackPath: packPath, PackRaw: raw, Chain: f.chain(),
			AttestedAt: at, Now: at, NextRevision: fmt.Sprintf("sim-%03d", run+1), EngineCapabilityDigest: testEngineCapabilityDigest,
		})
		if err != nil {
			t.Fatalf("%s run %d: Prepare: %v", packName, run+1, err)
		}
		if _, err := Verify(VerifyOptions{
			StatementRaw: res.StatementCanonical, PriorPackRaw: raw, NextPackRaw: res.NextPack, WorklistRaw: worklistRaw,
			Chain: f.chain(), BaseChain: f.chain(), PackName: packName, PackPath: packPath, EngineCapabilityDigest: testEngineCapabilityDigest,
			AttestedAtNow: at.Add(time.Hour),
		}); err != nil {
			t.Fatalf("%s run %d: Verify rejected Prepare's own automated statement: %v", packName, run+1, err)
		}
		for _, ra := range res.Statement.Rules {
			report.renewals++
			validUntil := mustParse(ra.ValidUntil)
			if !validUntil.After(current[ra.RuleID]) || validUntil.Sub(at) <= automatedMinLease || validUntil.Sub(at) > maxLease {
				t.Fatalf("%s run %d: rule %s renewed from %s to %s at %s", packName, run+1, ra.RuleID, rfc3339(current[ra.RuleID]), ra.ValidUntil, rfc3339(at))
			}
			if ra.ConsecutiveBatchCycles == maxConsecutiveBatchCycles {
				capped[ra.RuleID] = true
			}
			if last, ok := lastRenewed[ra.RuleID]; ok && (minGap == 0 || at.Sub(last) < minGap) {
				minGap = at.Sub(last)
			}
			lastRenewed[ra.RuleID] = at
			lastReason[ra.RuleID] = ""
		}
		for _, ne := range res.Statement.NotExtended {
			if ne.WorstClass != reasonNotYetDue {
				lastReason[ne.RuleID] = ne.WorstClass
			}
		}
		// Every automated run is signed by the automation key and appended.
		envelope, err := f.signAs(RoleAutomation, f.automation, res.StatementCanonical)
		if err != nil {
			t.Fatalf("%s run %d: automation Sign: %v", packName, run+1, err)
		}
		f.entries = append(f.entries, ChainEntry{Name: fmt.Sprintf("%04d", run+1), Statement: res.StatementCanonical, Envelope: envelope})
		raw = res.NextPack
	}
	doc, err := loadPack(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc.Entries {
		fields, _ := parseRuleFields(entry.Rule)
		validUntil, _ := parseUTC(fields.Evidence.ValidUntil)
		markLapsed(fields.ID, end, validUntil)
		if capped[fields.ID] {
			if report.cappedUntilEarliest.IsZero() || validUntil.Before(report.cappedUntilEarliest) {
				report.cappedUntilEarliest = validUntil
			}
			if validUntil.After(report.cappedUntilLatest) {
				report.cappedUntilLatest = validUntil
			}
		}
	}
	for _, reason := range lapsed {
		if reason == "ALREADY_EXPIRED" {
			report.lapsedAtStart++
			continue
		}
		report.lapsedBy[reason]++
	}
	report.continuous = report.total - len(lapsed)
	report.cappedRules = len(capped)
	report.minGapDays = int(minGap.Hours() / 24)
	return report
}

var simPacks = []struct{ pack, path string }{
	{PackCNCF, filepath.Join("..", "..", "cncfcheck", "data", "rules.json")},
	{PackCommunity, filepath.Join("..", "..", "projectcheck", "data", "rules.json")},
}

// Weekly automated runs over the real embedded packs for sixteen weeks,
// every citation unchanged and no individual review ever supplied. Every
// run must verify; no renewal may move a rule's validUntil earlier or give
// a lease outside the automated window; and the report says how many rules
// stay valid throughout and how many expire at the consecutive-cycle cap.
func TestAutomatedWeeklySimulationOnRealPacks(t *testing.T) {
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range simPacks {
		report := simulateAutomated(t, tc.pack, tc.path, start, 7*24*time.Hour, 16)
		t.Logf("%s, weekly automated runs for 16 weeks from %s: %s", tc.pack, rfc3339(start), report)
		if report.minGapDays != 0 && report.minGapDays < int(renewalWindow.Hours()/24) {
			t.Fatalf("%s: a rule was renewed again only %d days after its previous renewal", tc.pack, report.minGapDays)
		}
		if report.continuous == 0 {
			t.Fatalf("%s: no rule stayed valid throughout", tc.pack)
		}
	}
}

// The same simulation with a run every day. It is slow, so it runs only
// when PRUFYX_REATTEST_DAILY_SIM is set.
func TestAutomatedDailySimulationOnRealPacks(t *testing.T) {
	if os.Getenv("PRUFYX_REATTEST_DAILY_SIM") == "" {
		t.Skip("set PRUFYX_REATTEST_DAILY_SIM=1 to run the daily simulation")
	}
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range simPacks {
		report := simulateAutomated(t, tc.pack, tc.path, start, 24*time.Hour, 16*7)
		t.Logf("%s, daily automated runs for 16 weeks from %s: %s", tc.pack, rfc3339(start), report)
	}
}
