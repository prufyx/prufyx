// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const syntheticChartRuleID = "synthetic-chart-rule"

// syntheticChartEntry is a test-only chart rule for the kubernetes component
// whose anchor has the same numbers as an application hop: 1.21.0 -> 1.25.0.
// It is never published: the embedded pack is unchanged.
func syntheticChartEntry(t *testing.T) Entry {
	t.Helper()
	rule := `{"id":"` + syntheticChartRuleID + `","operator":"forbid_target_version","subject":{"component":"pkg:github/kubernetes/kubernetes","chart":{"source":"https://charts.example.io","name":"kubernetes"},"from":"1.21.0","to":"1.25.0"},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-chart","url":"https://github.com/kubernetes/kubernetes/blob/` + syntheticRevision + `/Chart.yaml","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"HELM_VALUES_REFUSED_BY_CHART","nextAction":"synthetic chart rule"}`
	return Entry{Project: "kubernetes", Description: "Synthetic test-only chart rule.", RequiredFacts: []Fact{}, Rule: json.RawMessage(rule)}
}

func TestPackChartLevel(t *testing.T) {
	t.Parallel()
	entry := syntheticChartEntry(t)
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChart, nil, entry), nil); err != nil {
		t.Fatalf("chart pack under the chart level refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs, packSchemaCrossing} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("chart pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChart, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("chart level without a chart rule accepted")
	}
}

// TestChartRuleNeverSelectedForAnApplicationHop: both selectors and the
// fallback serve application hops, so a chart rule with the hop's very
// numbers is never selected, counted or evaluated for one.
func TestChartRuleNeverSelectedForAnApplicationHop(t *testing.T) {
	t.Parallel()
	b, err := assembleSynthetic(syntheticPack(t, packSchemaChart, nil, syntheticChartEntry(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"1.21.0", "1.25.0"}, {"1.0.0", "1.1.0"}} {
		inputRaw := kubernetesInput(t, pair[0], pair[1], false)
		input, err := constraintengine.ParseInput(inputRaw, b.registry)
		if err != nil {
			t.Fatal(err)
		}
		for _, selector := range []string{"generic", "family"} {
			var selected selection
			if selector == "generic" {
				selected, err = b.selectForInput("kubernetes", inputRaw)
			} else {
				selected, err = b.selectFamily("kubernetes", []string{"component.kubernetes.cronjob_v1beta1_removed_gvk_present"}, inputRaw)
			}
			if err != nil {
				t.Fatal(selector, err)
			}
			report, err := constraintengine.Evaluate(input, selected.rules, mustTime(t, "2026-10-08T00:00:00Z"))
			if err != nil {
				t.Fatal(selector, err)
			}
			if report.EngineContractDigest == constraintengine.EngineContractDigestChart() {
				t.Fatalf("%s %v: an application hop was evaluated under the chart contract", selector, pair)
			}
			for _, claim := range report.Claims {
				if claim.RuleID == syntheticChartRuleID {
					t.Fatalf("%s %v: chart rule selected for an application hop", selector, pair)
				}
			}
		}
	}
}

func TestExternalRefusesChartRules(t *testing.T) {
	t.Parallel()
	// A rules-only envelope over syntheticBase: the export of the embedded
	// pack while it carries no record section.
	raw := syntheticBaseExternalBundle(t, "7")
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var value rulePack
	if err := json.Unmarshal(envelope["pack"], &value); err != nil {
		t.Fatal(err)
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExternalPack(base, value, "7", false, false); err != nil {
		t.Fatalf("the untouched export is refused, so the refusal below would prove nothing: %v", err)
	}
	value.Entries = append(value.Entries, syntheticChartEntry(t))
	if err := validateExternalPack(base, value, "7", false, false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted a chart rule: %v", err)
	}
}

// syntheticSetNoticeEntry is a test-only set notice on a chart subject
// over a registered set fact. It is never published.
func syntheticSetNoticeEntry(t *testing.T, operator string) Entry {
	t.Helper()
	entry := syntheticSetEntry(t)
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["id"], rule["operator"] = "synthetic-set-notice", operator
	rule["subject"].(map[string]any)["chart"] = map[string]any{"source": "https://charts.example.io", "name": "kubernetes"}
	rule["reasonCode"], rule["nextAction"] = "HELM_VALUES_KEY_NOT_REFERENCED", "review the listed setting before upgrading"
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule = raw
	return entry
}

// TestPackChartNoticeLevel: a pack holding a set notice carries exactly the
// set-notice level, every lower level refuses it, and the level is never
// used without one. A set notice is verdict-neutral for selection, and
// external packs refuse it.
func TestPackChartNoticeLevel(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{constraintengine.OperatorNoticeSetMemberPresent, constraintengine.OperatorNoticeSetMemberAbsent} {
		entry := syntheticSetNoticeEntry(t, operator)
		if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartNotice, nil, entry), nil); err != nil {
			t.Fatalf("%s: set-notice pack under the set-notice level refused: %v", operator, err)
		}
		for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs, packSchemaCrossing, packSchemaCommunity, packSchemaChart} {
			if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s: set-notice pack under %s accepted: %v", operator, schema, err)
			}
		}
		neutral, err := isVerdictNeutralRule(entry.Rule)
		if err != nil || !neutral {
			t.Fatalf("%s: not verdict-neutral: %v", operator, err)
		}
	}
	// A chart rule without a set notice stays at the chart level.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartNotice, nil, syntheticChartEntry(t)), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set-notice level without a set notice accepted")
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartNotice, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set-notice level for the published pack accepted")
	}
}

func TestExternalRefusesSetNotices(t *testing.T) {
	t.Parallel()
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var value rulePack
	if err := json.Unmarshal(envelope["pack"], &value); err != nil {
		t.Fatal(err)
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	value.Entries = append(value.Entries, syntheticSetNoticeEntry(t, constraintengine.OperatorNoticeSetMemberPresent))
	if err := validateExternalPack(base, value, "7", false, false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted a set notice: %v", err)
	}
}

// syntheticRangedChartEntry is a test-only chart rule over a registered set
// fact, widened to every release of two consecutive chart lines. It is
// never published.
func syntheticRangedChartEntry(t *testing.T) Entry {
	t.Helper()
	entry := syntheticSetEntry(t)
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["id"] = "synthetic-ranged-chart-rule"
	rule["subject"].(map[string]any)["chart"] = map[string]any{"source": "https://charts.example.io", "name": "kubernetes"}
	bound := func(name, basis string) map[string]any {
		return map[string]any{"bound": name, "basis": basis, "sourceId": "synthetic-gate-declaration"}
	}
	rule["range"] = map[string]any{
		"from": map[string]any{"gte": "1.38.0", "lt": "1.39.0"}, "to": map[string]any{"gte": "1.39.0", "lt": "1.40.0"},
		"bounds": []any{bound("from.gte", constraintengine.BasisPreviousMinorLine), bound("from.lt", constraintengine.BasisRemovedInRelease), bound("to.gte", constraintengine.BasisRemovedInRelease), bound("to.lt", constraintengine.BasisTargetSeries)},
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule = raw
	return entry
}

// TestPackChartRangedLevel: a pack holding a ranged chart rule carries
// exactly the ranged chart level, every lower level refuses it, and the
// level is never used without one.
func TestPackChartRangedLevel(t *testing.T) {
	t.Parallel()
	entry := syntheticRangedChartEntry(t)
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartRanged, nil, entry), nil); err != nil {
		t.Fatalf("ranged chart pack under the ranged chart level refused: %v", err)
	}
	// With a set notice beside it, the level is still the ranged chart one.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartRanged, nil, entry, syntheticSetNoticeEntry(t, constraintengine.OperatorNoticeSetMemberPresent)), nil); err != nil {
		t.Fatalf("ranged chart pack with a set notice refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs, packSchemaCrossing, packSchemaCommunity, packSchemaChart, packSchemaChartNotice} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("ranged chart pack under %s accepted: %v", schema, err)
		}
	}
	for name, entries := range map[string][]Entry{
		"anchor-only chart rule": {syntheticChartEntry(t)},
		"set notice":             {syntheticSetNoticeEntry(t, constraintengine.OperatorNoticeSetMemberPresent)},
		"published pack":         nil,
	} {
		if _, err := assembleSynthetic(syntheticPack(t, packSchemaChartRanged, nil, entries...), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("ranged chart level with only a %s accepted", name)
		}
	}
}
