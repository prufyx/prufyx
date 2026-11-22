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
			if name == "conflicting commit" {
				if ok {
					t.Fatalf("conflict expanded: %+v", path)
				}
				return
			}
			if !ok || path.Jump == nil || len(path.Jump.Hops) != 3 {
				t.Fatalf("suffix missing: %+v", path)
			}
			if name == "same commit" {
				if len(path.Jump.Releases) != 2 || path.Jump.Releases[1].Version != "4.1.0" || path.Jump.Releases[1].Commit != clCommit("4.1.0") {
					t.Fatalf("join=%+v", path.Jump.Releases)
				}
			} else if len(path.Jump.Releases) != 1 || path.Jump.Hops[1].To != "4.1" || path.Jump.Hops[2].From != "4.1" {
				t.Fatalf("unreviewed join invented: %+v", path.Jump)
			}
		})
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
