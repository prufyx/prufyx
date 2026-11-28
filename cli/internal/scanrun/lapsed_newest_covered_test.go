// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// newestCoveredAt is the shared test clock, which follows the review times of
// the shipped records.
var newestCoveredAt = supersedeids.ClockString()

// newestRecordEdit changes or drops (false) one record of a pack section.
type newestRecordEdit func(record map[string]any) bool

func lapseExpired(record map[string]any) bool {
	evidence := record["evidence"].(map[string]any)
	evidence["reviewedAt"], evidence["validUntil"] = "2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"
	if _, mechanical := evidence["derivedAt"]; mechanical {
		evidence["derivedAt"] = "2026-06-01T00:00:00Z"
	}
	return true
}

func lapseRemoved(map[string]any) bool { return false }

// A pack is admitted only while a review's rules are in it, so a review that
// outlives its line's rules lists none.
func reviewWithoutRules(record map[string]any) bool {
	record["ruleIds"] = []any{}
	return true
}

func expiredReviewWithoutRules(record map[string]any) bool {
	return reviewWithoutRules(record) && lapseExpired(record)
}

// editLine applies edits to the Kubernetes records of one line, per pack
// section, and with dropRules removes the rules that move onto that line.
func editLine(t *testing.T, line string, edits map[string]newestRecordEdit, dropRules bool) []byte {
	t.Helper()
	return editRecords(t, embeddedPack(t), kubernetesSlug, kubernetesKey, line, edits, dropRules)
}

func editRecords(t *testing.T, raw []byte, slug, component, line string, edits map[string]newestRecordEdit, dropRules bool) []byte {
	t.Helper()
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	for section, edit := range edits {
		var kept []any
		seen := false
		for _, item := range pack[section].([]any) {
			record := item.(map[string]any)
			if record["component"] != component || record["line"] != line {
				kept = append(kept, record)
				continue
			}
			seen = true
			if edit(record) {
				kept = append(kept, record)
			}
		}
		if !seen {
			t.Fatalf("%s has no record of line %s", section, line)
		}
		pack[section] = kept
	}
	if dropRules {
		scan, err := cncfcheck.LoadScanKnowledge()
		if err != nil {
			t.Fatal(err)
		}
		drop := map[string]bool{}
		for _, rule := range scan.Rules(slug) {
			if newestRuleLine("", []cncfcheck.ScanRule{rule}, component) == line {
				drop[rule.Scope.ID] = true
			}
		}
		if len(drop) == 0 {
			t.Fatalf("no rule of line %s", line)
		}
		var kept []any
		for _, item := range pack["entries"].([]any) {
			if !drop[item.(map[string]any)["rule"].(map[string]any)["id"].(string)] {
				kept = append(kept, item)
			}
		}
		pack["entries"] = kept
	}
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func scanNewestCovered(t *testing.T, layout string, pack []byte) Result {
	t.Helper()
	fixture := newStoreFixture(t, layout)
	fixture.importPack(pack, "7")
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	var result Result
	inDir(t, dir, func() {
		request, err := ParseArgs(storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.35.0"))
		if err != nil {
			t.Fatal(err)
		}
		request.NewestCovered = []string{kubernetesSlug}
		knowledge := openAt(t, fixture.store, newestCoveredAt)
		result, err = Run(request, Options{Knowledge: knowledge, Build: &testBuild})
		if err != nil {
			t.Fatal(err)
		}
	})
	return result
}

func newestGaps(report scanreport.Report) []scanreport.Gap {
	want := scanreport.NewGap(kubernetesSlug, nil, scanreport.GapNewestCoveredOlderLine, kubernetesSlug, "1.36", "1.37")
	// The gap names the missing line and the next action.
	if !strings.Contains(want.Detail, "newer line 1.37") || !strings.Contains(want.Action, "--to kubernetes=X.Y.Z") {
		return nil
	}
	var found []scanreport.Gap
	for _, gap := range report.Gaps {
		if gap.Reason == want.Reason && gap.Detail == want.Detail && gap.Action == want.Action {
			found = append(found, gap)
		}
	}
	return found
}

// A newest served list that expired or was removed never moves
// newest-covered to an older line without saying so.
func TestNewestCoveredNamesTheLapsedNewerLine(t *testing.T) {
	cases := []struct {
		name      string
		edits     map[string]newestRecordEdit
		dropRules bool
	}{
		{"list expired", map[string]newestRecordEdit{"servedAPIs": lapseExpired}, false},
		{"list removed", map[string]newestRecordEdit{"servedAPIs": lapseRemoved}, false},
		{"list and rules removed, review kept", map[string]newestRecordEdit{"servedAPIs": lapseRemoved, "lineAttestations": reviewWithoutRules}, true},
		{"list and rules removed, review expired", map[string]newestRecordEdit{"servedAPIs": lapseRemoved, "lineAttestations": expiredReviewWithoutRules}, true},
		{"list and review removed, rules kept", map[string]newestRecordEdit{"servedAPIs": lapseRemoved, "lineAttestations": lapseRemoved}, false},
		// Only the binary's own knowledge still names the line.
		{"every trace removed from the database", map[string]newestRecordEdit{"servedAPIs": lapseRemoved, "lineAttestations": lapseRemoved}, true},
	}
	for _, layout := range storeLayouts {
		t.Run(layout+"/control", func(t *testing.T) {
			result := scanNewestCovered(t, layout, embeddedPack(t))
			if len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.37.0" {
				t.Fatalf("paths %+v", result.Report.Paths)
			}
			for _, gap := range result.Report.Gaps {
				if gap.Reason == scanreport.ReasonLineNotAttested {
					t.Fatalf("gap with every record current: %+v", gap)
				}
			}
		})
		for _, tc := range cases {
			t.Run(layout+"/"+tc.name, func(t *testing.T) {
				result := scanNewestCovered(t, layout, editLine(t, "1.37", tc.edits, tc.dropRules))
				if len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.36.0" {
					t.Fatalf("paths %+v", result.Report.Paths)
				}
				if result.Exit != scanreport.ExitUnknown || result.Report.Verdict != scanreport.VerdictUnknown {
					t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
				}
				if len(newestGaps(result.Report)) != 1 {
					t.Fatalf("newer line not named: %+v", result.Report.Gaps)
				}
			})
		}
	}
}

// Served lists and line reviews have no withdrawn state: a pack that states
// one is refused whole, so a withdrawn list can never decide a target.
func TestNewestCoveredWithdrawnRecordIsRefused(t *testing.T) {
	if _, _, err := cncfcheck.BuildExternalTargetsFromPack(embeddedPack(t), "7"); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, section := range []string{"servedAPIs", "lineAttestations"} {
		pack := editLine(t, "1.37", map[string]newestRecordEdit{section: func(record map[string]any) bool {
			record["evidence"].(map[string]any)["state"] = "withdrawn"
			return true
		}}, false)
		if _, _, err := cncfcheck.BuildExternalTargetsFromPack(pack, "7"); err == nil {
			t.Fatalf("%s: a withdrawn state was admitted", section)
		}
	}
}

// A database resolves no application target: newest-covered for one is
// refused there, never moved to an older line.
func TestNewestCoveredAppFromDatabaseIsRefused(t *testing.T) {
	for _, layout := range storeLayouts {
		t.Run(layout, func(t *testing.T) {
			fixture := newStoreFixture(t, layout, "strimzi")
			fixture.importPack(embeddedPack(t), "7")
			opened, err := OpenStore(fixture.store, []string{"strimzi"})
			if err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339, newestCoveredAt)
			if err != nil {
				t.Fatal(err)
			}
			var effective scanconfig.Effective
			gaps, err := resolveNewestCovered(&effective, []string{"strimzi"}, opened, at)
			if !isUsage(err) || gaps != nil || len(effective.Target) != 0 {
				t.Fatalf("not refused: %v %+v %+v", err, gaps, effective.Target)
			}
		})
	}
}

// A rule outside every fact family has no scope line: its reviewed target
// version names the line.
func TestNewerLineFromRuleOutsideFamilies(t *testing.T) {
	const component = "pkg:github/x/app"
	rule, err := cncfcheck.NewScanRule("app", "d", json.RawMessage(`{"id":"app.rule","subject":{"component":"`+component+`","from":"1.2.5","to":"1.3.0"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if rule.Scope.Line != "" || len(rule.Scope.Families) != 0 {
		t.Fatalf("control: the rule has a scope line %+v", rule.Scope)
	}
	gaps, err := newerLineGaps(recordLines{line: "1.2", rules: []cncfcheck.ScanRule{rule}}, "app", component, "1.2")
	want := scanreport.NewGap("app", nil, scanreport.GapNewestCoveredOlderLine, "app", "1.2", "1.3")
	if err != nil || len(gaps) != 1 || gaps[0].Detail != want.Detail {
		t.Fatalf("err %v gaps %+v", err, gaps)
	}
	// A chart rule's versions are chart versions, never a line.
	chart := rule
	chart.Chart = &constraintengine.ChartRef{Name: "app"}
	if gaps, err := newerLineGaps(recordLines{line: "1.2", rules: []cncfcheck.ScanRule{chart}}, "app", component, "1.2"); err != nil || len(gaps) != 0 {
		t.Fatalf("chart rule: err %v gaps %+v", err, gaps)
	}
}

// The embedded knowledge, with its records current, gets no new gap.
func TestNewestCoveredEmbeddedHasNoOlderLineGap(t *testing.T) {
	knowledge, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, newestCoveredAt)
	if err != nil {
		t.Fatal(err)
	}
	var effective scanconfig.Effective
	gaps, err := resolveNewestCovered(&effective, []string{kubernetesSlug}, knowledge, now)
	if err != nil || len(gaps) != 0 || effective.Target[kubernetesSlug].Value != "1.37.0" {
		t.Fatalf("err %v gaps %+v target %+v", err, gaps, effective.Target)
	}
}

type recordLines struct {
	Knowledge
	line  string
	err   error
	rules []cncfcheck.ScanRule
}

func (k recordLines) NewestRecordLine(string) (string, error) { return k.line, k.err }
func (k recordLines) Rules(string) []cncfcheck.ScanRule       { return k.rules }

type noRecordLines struct{ Knowledge }

func TestNewerLineGaps(t *testing.T) {
	const component = "pkg:github/x/app"
	rule := func(subject, line string) []cncfcheck.ScanRule {
		var r cncfcheck.ScanRule
		r.Scope.Component, r.Scope.Line = subject, line
		return []cncfcheck.ScanRule{r}
	}
	for name, tc := range map[string]struct {
		k     recordLines
		named string
	}{
		"nothing newer":          {recordLines{line: "1.2"}, ""},
		"older records":          {recordLines{line: "1.1", rules: rule(component, "1.1")}, ""},
		"newer record":           {recordLines{line: "1.10"}, "1.10"},
		"newer major":            {recordLines{line: "2.0"}, "2.0"},
		"newer rule only":        {recordLines{line: "1.2", rules: rule(component, "1.3")}, "1.3"},
		"another component":      {recordLines{line: "1.2", rules: rule("pkg:github/x/other", "9.0")}, ""},
		"newest of both is kept": {recordLines{line: "1.5", rules: rule(component, "1.3")}, "1.5"},
	} {
		gaps, err := newerLineGaps(tc.k, "app", component, "1.2")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tc.named == "" {
			if len(gaps) != 0 {
				t.Fatalf("%s: %+v", name, gaps)
			}
			continue
		}
		want := scanreport.NewGap("app", nil, scanreport.GapNewestCoveredOlderLine, "app", "1.2", tc.named)
		if len(gaps) != 1 || gaps[0].Detail != want.Detail || gaps[0].Reason != scanreport.ReasonLineNotAttested {
			t.Fatalf("%s: %+v", name, gaps)
		}
	}
	// Knowledge that cannot say which lines it names decides nothing.
	if gaps, err := newerLineGaps(noRecordLines{}, "app", component, "1.2"); !isUsage(err) || gaps != nil {
		t.Fatalf("not refused: %v %+v", err, gaps)
	}
	if gaps, err := newerLineGaps(recordLines{err: cncfcheck.ErrIntegrity}, "app", component, "1.2"); !errors.Is(err, ErrIntegrity) || gaps != nil {
		t.Fatalf("not refused: %v %+v", err, gaps)
	}
}
