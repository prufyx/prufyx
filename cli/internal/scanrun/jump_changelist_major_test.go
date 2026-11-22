// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

func TestChangeListMajorCitedSuffix(t *testing.T) {
	knowledge, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ slug, from, anchor, to, commit string }{
		{"in-toto", "2.3.0", "3.0.0", "3.1.0", "659942bde1cd732b0b9449445f9769b2def6aeb1"},
		{"the-update-framework-tuf", "4.0.0", "5.0.0", "5.1.0", "1b0c9f7d444e037d1e9b5635b993c46053442e1b"},
	} {
		t.Run(tc.slug, func(t *testing.T) {
			_, paths := files(t, map[string]string{"input.yaml": templatedConfigMap})
			request, err := ParseArgs(append(paths, "--from", tc.slug+"="+tc.from, "--to", tc.slug+"="+tc.to, "--now", "2026-11-22T08:05:00Z"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := Run(request, Options{Knowledge: knowledge, Build: &testBuild, Clock: func() time.Time { return request.Now }})
			if err != nil {
				t.Fatal(err)
			}
			if result.Exit != 11 || result.Report.Verdict != scanreport.VerdictUnknown {
				t.Fatalf("exit=%d verdict=%s", result.Exit, result.Report.Verdict)
			}
			if len(result.Report.Paths) != 1 {
				t.Fatalf("paths=%+v", result.Report.Paths)
			}
			path := result.Report.Paths[0]
			if path.Jump == nil || len(path.Jump.Hops) != 2 {
				t.Fatalf("known cited suffix omitted: %+v", path)
			}
			jump := path.Jump
			if jump.Status != scanreport.JumpAttention {
				t.Fatalf("jump status=%s", jump.Status)
			}
			for _, h := range jump.Hops {
				if h.Status == scanreport.JumpHopPass {
					t.Fatalf("unexpected pass: %+v", h)
				}
			}
			if path.From != tc.from || path.To != tc.to || jump.Hops[0].From != tc.from || jump.Hops[0].To != tc.anchor || jump.Hops[0].Status != scanreport.JumpHopUndecided || jump.Hops[1].From != tc.anchor || jump.Hops[1].To != tc.to || jump.Hops[1].Status != scanreport.JumpHopAttention {
				t.Fatalf("jump=%+v", jump)
			}
			if len(jump.Missing) != 1 || !strings.Contains(jump.Missing[0].Evidence, scanreport.ReasonLinesNotListed) || !strings.Contains(jump.Missing[0].Evidence, scanreport.ReasonMajorHopNotCovered) || !strings.Contains(jump.Missing[0].Action, "each release line") || !strings.Contains(jump.Missing[0].Action, "upstream upgrade guide") {
				t.Fatalf("missing=%+v", jump.Missing)
			}
			if len(jump.Releases) != 1 || jump.Releases[0].Version != tc.anchor || jump.Releases[0].Commit != tc.commit {
				t.Fatalf("releases=%+v", jump.Releases)
			}
			component, _ := knowledge.Component(tc.slug)
			line, _ := lineattest.LineOf(tc.to)
			source := knowledge.AttestationsFor(component, line, lineattest.FamilyChangelogListedEntries, request.Now)[0].Attestation.Evidence.Sources[0]
			if len(jump.Hops[1].Entries) != 1 {
				t.Fatalf("entries=%+v", jump.Hops[1].Entries)
			}
			for _, exact := range []string{source.URL, source.Revision, source.ContentDigest, fmt.Sprintf("lines %d-%d", source.StartLine, source.EndLine)} {
				if !strings.Contains(jump.Hops[1].Entries[0], exact) {
					t.Fatalf("citation lost %s: %s", exact, jump.Hops[1].Entries[0])
				}
			}
			for _, format := range []string{"human", "json", "markdown", "csv", "sarif"} {
				raw, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{})
				if err != nil {
					t.Fatal(err)
				}
				text := strings.ReplaceAll(string(raw), `\_`, "_")
				if !strings.Contains(text, "partial listed-entry explanation") || !strings.Contains(text, scanreport.ReasonLinesNotListed) || !strings.Contains(text, "each release line") || !strings.Contains(text, "upstream upgrade guide") {
					t.Fatalf("%s lost partial scope: %s", format, raw)
				}
			}
			plan := upgradeplan.Build(result.Report, nil, upgradeplan.Capabilities{})
			if plan.ExitCode != 11 {
				t.Fatalf("plan exit=%d", plan.ExitCode)
			}
			if len(plan.Routes) != 1 || len(plan.Routes[0].Stops) != 0 {
				t.Fatalf("partial citations became required stops: %+v", plan.Routes)
			}
			for _, format := range upgradeplan.Formats() {
				raw, err := upgradeplan.Render(plan, format)
				if err != nil {
					t.Fatal(err)
				}
				text := strings.ReplaceAll(string(raw), `\_`, "_")
				if !strings.Contains(text, "partial listed-entry explanation") || !strings.Contains(text, scanreport.ReasonMajorHopNotCovered) {
					t.Fatalf("plan %s lost scope: %s", format, raw)
				}
			}
		})
	}
}

func TestChangeListMajorSuffixSubsequentJoin(t *testing.T) {
	base, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-11-22T08:05:00Z")
	first := clRecord(lineattest.FamilyChangelogListedEntries, "4.1", []string{"4.0.0"}, []string{"4.1.0"})
	for _, name := range []string{"same commit", "conflicting commit", "no intersection", "missing line"} {
		t.Run(name, func(t *testing.T) {
			second := clRecord(lineattest.FamilyChangelogListedEntries, "4.2", []string{"4.1.0"}, []string{"4.2.0"})
			if name == "conflicting commit" {
				second.Releases.From[0].Commit = strings.Repeat("e", 40)
			}
			if name == "no intersection" {
				second.Releases.From[0].Version = "4.1.1"
				second.Releases.From[0].Commit = clCommit("4.1.1")
			}
			records := []lineattest.LineAttestation{first, second}
			if name == "missing line" {
				records = records[:1]
			}
			k := clKnowledge{Knowledge: base, index: lineattest.NewIndex(records)}
			var report scanreport.Report
			path, ok := changeListJump(k, now, &report, clSlug, clComponent, "3.4.0", "4.2.0", cncfcheck.DefaultTrustPolicy())
			if name != "same commit" {
				if ok {
					t.Fatalf("unbound subsequent join expanded: %+v", path)
				}
				if len(report.Gaps) != 0 {
					t.Fatalf("refusal leaked partial gaps: %+v", report.Gaps)
				}
				requireMajorSuffixFallback(t, k, now)
				return
			}
			if !ok || path.Jump == nil || len(path.Jump.Hops) != 3 {
				t.Fatalf("suffix missing: %+v", path)
			}
			if name == "same commit" {
				if len(path.Jump.Releases) != 2 || path.Jump.Releases[1].Version != "4.1.0" || path.Jump.Releases[1].Commit != clCommit("4.1.0") {
					t.Fatalf("join=%+v", path.Jump.Releases)
				}
			}
		})
	}
}

func TestChangeListMajorSuffixNonfinalRecords(t *testing.T) {
	base, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-11-22T08:05:00Z")
	// The prerelease parser admits only major 1, and release-list ordering
	// rejects every multi-entry list containing a prerelease. Use singleton
	// nonfinal sides: To retains the final H4 join; From is defensive refusal.
	first := clRecord(lineattest.FamilyChangelogListedEntries, "1.1", []string{"1.0.0"}, []string{"1.1.0"})
	for _, side := range []string{"from", "to"} {
		t.Run(side, func(t *testing.T) {
			from, to := []string{"1.1.0"}, []string{"1.2.0"}
			if side == "from" {
				from = []string{"1.1.0-rc.1"}
			} else {
				to = []string{"1.2.0-rc.1"}
			}
			second := clRecord(lineattest.FamilyChangelogListedEntries, "1.2", from, to)
			if err := second.Validate(); err != nil {
				t.Fatalf("fixture must otherwise validate: %v", err)
			}
			k := clKnowledge{Knowledge: base, index: lineattest.NewIndex([]lineattest.LineAttestation{first, second})}
			var report scanreport.Report
			if path, ok := changeListJump(k, now, &report, clSlug, clComponent, "0.4.0", "1.2.0", cncfcheck.DefaultTrustPolicy()); ok {
				t.Fatalf("nonfinal record expanded: %+v", path)
			}
			if len(report.Gaps) != 0 {
				t.Fatalf("refusal leaked partial gaps: %+v", report.Gaps)
			}
			requireMajorSuffixFallbackFor(t, k, now, "0.4.0", "1.2.0")
		})
	}
}

func TestChangeListMajorSuffixDigestBindsAnchor(t *testing.T) {
	base, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-11-22T08:05:00Z")
	var original *scanreport.Jump
	seen := map[string]bool{}
	for _, anchor := range []lineattest.Release{{Version: "4.0.0", Commit: clCommit("4.0.0")}, {Version: "4.0.0", Commit: strings.Repeat("e", 40)}, {Version: "4.0.1", Commit: clCommit("4.0.0")}} {
		record := clRecord(lineattest.FamilyChangelogListedEntries, "4.1", []string{"4.0.0"}, []string{"4.1.0"})
		record.Releases.From[0] = anchor
		if err := record.Validate(); err != nil {
			t.Fatalf("fixture must otherwise validate: %v", err)
		}
		k := clKnowledge{Knowledge: base, index: lineattest.NewIndex([]lineattest.LineAttestation{record})}
		var report scanreport.Report
		path, ok := changeListJump(k, now, &report, clSlug, clComponent, "3.4.0", "4.1.0", cncfcheck.DefaultTrustPolicy())
		if !ok || path.Jump == nil || len(path.Jump.Releases) != 1 || path.Jump.Releases[0].Version != anchor.Version || path.Jump.Releases[0].Commit != anchor.Commit {
			t.Fatalf("anchor not preserved: %+v", path)
		}
		jump := path.Jump
		if seen[jump.ObjectSetDigest] {
			t.Fatalf("different anchor retained digest %s", jump.ObjectSetDigest)
		}
		seen[jump.ObjectSetDigest] = true
		for _, hop := range jump.Hops {
			if hop.ObjectSetDigest != jump.ObjectSetDigest {
				t.Fatalf("hop digest not rebound: %+v", hop)
			}
		}
		if status, _ := scanreport.ComposeJump(jump.Hops, jump.ObjectSetDigest); status != scanreport.JumpAttention {
			t.Fatalf("new set not composable: %s", status)
		}
		if original != nil {
			if status, _ := scanreport.ComposeJump(original.Hops, jump.ObjectSetDigest); status != scanreport.JumpUnknown {
				t.Fatalf("old hops counted against new anchor: %s", status)
			}
		} else {
			original = jump
		}
	}
}

func requireMajorSuffixFallback(t *testing.T, knowledge Knowledge, now time.Time) {
	t.Helper()
	requireMajorSuffixFallbackFor(t, knowledge, now, "3.4.0", "4.2.0")
}

func requireMajorSuffixFallbackFor(t *testing.T, knowledge Knowledge, now time.Time, from, to string) {
	t.Helper()
	_, paths := files(t, map[string]string{"input.yaml": templatedConfigMap})
	request, err := ParseArgs(append(paths, "--from", clSlug+"="+from, "--to", clSlug+"="+to, "--now", now.Format(time.RFC3339)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(request, Options{Knowledge: knowledge, Build: &testBuild, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Exit != 11 || result.Report.Verdict != scanreport.VerdictUnknown || len(result.Report.Paths) != 1 {
		t.Fatalf("fallback result=%+v", result)
	}
	path := result.Report.Paths[0]
	if path.From != from || path.To != to || path.Jump == nil || path.Jump.Status != scanreport.JumpUnknown || len(path.Jump.Releases) != 0 || len(path.Jump.Hops) != 1 || len(path.Jump.Hops[0].Entries) != 0 || len(path.Jump.Missing) != 1 || path.Jump.Missing[0].Evidence == "" || path.Jump.Missing[0].Action == "" {
		t.Fatalf("false cited fallback: %+v", path)
	}
	for _, format := range []string{"human", "json", "markdown", "csv", "sarif"} {
		raw, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "lists changes for etcd") || strings.Contains(string(raw), clCommit("4.0.0")) || !strings.Contains(string(raw), "by hand") {
			t.Fatalf("%s lost fallback boundary: %s", format, raw)
		}
	}
	plan := upgradeplan.Build(result.Report, nil, upgradeplan.Capabilities{})
	if plan.ExitCode != 11 || len(plan.Routes) != 1 || len(plan.Routes[0].Stops) != 0 {
		t.Fatalf("fallback plan=%+v", plan)
	}
	for _, format := range upgradeplan.Formats() {
		raw, err := upgradeplan.Render(plan, format)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "lists changes for etcd") || strings.Contains(string(raw), clCommit("4.0.0")) || !strings.Contains(string(raw), "by hand") {
			t.Fatalf("plan %s lost fallback boundary: %s", format, raw)
		}
	}
}

type majorSuffixKnowledge struct {
	Knowledge
	alter func(component, line, family string, statuses []lineattest.Status) []lineattest.Status
	path  *upgradepath.Status
}

func (k majorSuffixKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.alter(component, line, family, k.Knowledge.AttestationsFor(component, line, family, now))
}

func (k majorSuffixKnowledge) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	if k.path != nil {
		return *k.path
	}
	return k.Knowledge.PathPolicyFor(component, now)
}

func TestChangeListMajorSuffixRefusals(t *testing.T) {
	base, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-11-22T08:05:00Z")
	component, _ := base.Component("in-toto")
	for _, name := range []string{"absent", "duplicate", "stale", "future", "withdrawn", "malformed", "component", "line", "family", "nonfinal", "ambiguous anchor", "commit conflict", "out of window", "basis", "direct policy", "stale policy", "excluded policy", "middle major"} {
		t.Run(name, func(t *testing.T) {
			k := majorSuffixKnowledge{Knowledge: base}
			k.alter = func(c, line, family string, statuses []lineattest.Status) []lineattest.Status {
				if c != component || family != lineattest.FamilyChangelogListedEntries {
					return statuses
				}
				if name == "commit conflict" && line == "3.0" {
					first := base.AttestationsFor(c, "3.1", family, now)[0]
					first.Attestation.Releases.From[0].Commit = strings.Repeat("e", 40)
					return []lineattest.Status{first}
				}
				if line != "3.1" || len(statuses) == 0 {
					return statuses
				}
				a := &statuses[0].Attestation
				switch name {
				case "absent":
					return nil
				case "duplicate":
					return append(statuses, statuses[0])
				case "stale":
					statuses[0].Freshness = lineattest.FreshnessStale
				case "future":
					a.Evidence.ReviewedAt = "2026-11-23T08:05:00Z"
				case "withdrawn":
					statuses[0].Freshness = "withdrawn"
				case "malformed":
					a.Evidence.Sources[0].ContentDigest = "bad"
				case "component":
					a.Component = clComponent
				case "line":
					a.Line = "3.2"
				case "family":
					a.FactFamily = lineattest.FamilyCustomResourceVersions
				case "nonfinal":
					a.Releases.From[0].Version = "3.0.0-rc.1"
				case "ambiguous anchor":
					a.Releases.From = append(a.Releases.From, lineattest.Release{Version: "3.0.1", Commit: clCommit("3.0.1")})
				case "out of window":
					a.Releases.To[0].Version = "3.1.1"
				}
				return statuses
			}
			trust := cncfcheck.DefaultTrustPolicy()
			if name == "basis" {
				trust, _ = cncfcheck.ParseTrustPolicy("reviewed")
			}
			if strings.Contains(name, "policy") {
				status := upgradepath.Status{Found: true, Freshness: upgradepath.FreshnessCurrent, Record: upgradepath.Record{Component: component, Policy: upgradepath.PolicyDirect, Evidence: upgradepath.Evidence{Basis: constraintengine.BasisReviewed}}}
				if name == "stale policy" {
					status.Freshness = upgradepath.FreshnessStale
				}
				if name == "excluded policy" {
					status.Record.Policy = upgradepath.PolicySequentialMinor
					status.Record.Evidence.Basis = constraintengine.BasisLead
				}
				k.path = &status
			}
			from := "2.3.0"
			if name == "middle major" {
				from = "1.3.0"
			}
			var report scanreport.Report
			if path, ok := changeListJump(k, now, &report, "in-toto", component, from, "3.1.0", trust); ok {
				t.Fatalf("refusal expanded: %+v", path)
			}
			if len(report.Gaps) != 0 {
				t.Fatalf("refusal leaked partial additions: %+v", report.Gaps)
			}
		})
	}
}
