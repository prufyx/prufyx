// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
)

const (
	chartTestComponent = "pkg:github/cert-manager/cert-manager"
	chartTestFact      = "component.cert_manager.chart_cert_manager_values_paths_set"
	chartTestSource    = "https://charts.jetstack.io"
	chartTestRevision  = "0123456789abcdef0123456789abcdef01234567"
)

// chartCandidate is a synthetic require_set_member chart rule.
func chartCandidate() map[string]any {
	return map[string]any{
		"project": "cert-manager", "description": "Synthetic chart rule.",
		"requiredFacts": []any{map[string]any{"side": "proposed", "id": chartTestFact, "component": chartTestComponent, "type": "set", "description": "Values paths the user sets."}},
		"rule": map[string]any{
			"id": "helm-values.cert-manager.synthetic", "operator": "require_set_member",
			"subject":      map[string]any{"component": chartTestComponent, "chart": map[string]any{"source": chartTestSource, "name": "cert-manager"}, "from": "1.16.0", "to": "1.17.0"},
			"setCondition": map[string]any{"side": "proposed", "component": chartTestComponent, "factId": chartTestFact, "members": []any{"a.b"}},
			"evidence": map[string]any{"state": "active", "reviewedAt": "2026-10-01T00:00:00Z", "validUntil": "2026-12-30T00:00:00Z", "sources": []any{map[string]any{
				"id": "schema-to", "url": "https://github.com/cert-manager/cert-manager/blob/" + chartTestRevision + "/deploy/charts/cert-manager/values.schema.json",
				"revision": chartTestRevision, "contentDigest": "sha256:" + strings.Repeat("a", 64), "startLine": 1, "endLine": 3}}},
			"reasonCode": "HELM_VALUES_REFUSED_BY_CHART", "nextAction": "set a.b in the chart values before upgrading",
		},
	}
}

func chartTable(state, component string) *chartidentity.SourceTable {
	return &chartidentity.SourceTable{Schema: "prufyx.io/chart-sources/v1alpha1", Records: []chartidentity.SourceRecord{{RepoURL: chartTestSource, Chart: "cert-manager", Component: component, Project: "cert-manager", Evidence: chartidentity.SourceEvidence{State: state}}}}
}

func chartFindings(t *testing.T, entry map[string]any, opts Options) []string {
	t.Helper()
	result, err := Validate(candidateFile(t, entry), opts)
	if err != nil {
		t.Fatal(err)
	}
	var checks []string
	for _, finding := range result.Findings {
		checks = append(checks, finding.Check+": "+finding.Message)
	}
	return checks
}

func TestRulecheckChartGate(t *testing.T) {
	maintainer := Options{AllowRange: true, ChartSources: chartTable(chartidentity.StateActive, chartTestComponent)}
	if findings := chartFindings(t, chartCandidate(), maintainer); len(findings) != 0 {
		t.Fatalf("valid chart candidate rejected: %v", findings)
	}
	cases := map[string]struct {
		edit func(map[string]any)
		opts Options
		want string
	}{
		"community contribution":                        {func(map[string]any) {}, Options{ChartSources: maintainer.ChartSources}, "not accepted from a community contribution"},
		"no chart-source row (embedded table is empty)": {func(map[string]any) {}, Options{AllowRange: true}, "no reviewed chart-source row"},
		"withdrawn row":                                 {func(map[string]any) {}, Options{AllowRange: true, ChartSources: chartTable(chartidentity.StateWithdrawn, chartTestComponent)}, "is withdrawn"},
		"row for another component":                     {func(map[string]any) {}, Options{AllowRange: true, ChartSources: chartTable(chartidentity.StateActive, "pkg:github/other/other")}, "maps to component"},
		"unnormalised source": {func(e map[string]any) {
			rule(e)["subject"].(map[string]any)["chart"].(map[string]any)["source"] = chartTestSource + "/"
		}, maintainer, "normalised https or oci"},
		"require on another set fact": {func(e map[string]any) {
			e["requiredFacts"].([]any)[0].(map[string]any)["id"] = "component.cert_manager.feature_gates_set"
			rule(e)["setCondition"].(map[string]any)["factId"] = "component.cert_manager.feature_gates_set"
		}, maintainer, "values-path set fact"},
		"chart rule with a range": {func(e map[string]any) {
			rule(e)["range"] = map[string]any{"from": map[string]any{"gte": "1.16.0", "lt": "1.17.0"}, "to": map[string]any{"gte": "1.17.0", "lt": "1.18.0"}, "bounds": []any{}}
		}, maintainer, "anchor-only"},
		"require with a range and no chart": {func(e map[string]any) {
			delete(rule(e)["subject"].(map[string]any), "chart")
			rule(e)["range"] = map[string]any{"from": map[string]any{"gte": "1.16.0", "lt": "1.17.0"}, "to": map[string]any{"gte": "1.17.0", "lt": "1.18.0"}, "bounds": []any{}}
		}, maintainer, "cannot carry a range"},
		"chart rule requiring another component": {func(e map[string]any) {
			rule(e)["operator"] = "require_component_version"
			delete(rule(e), "setCondition")
			rule(e)["dependency"] = map[string]any{"side": "proposed", "component": "pkg:github/other/other", "comparison": "gte", "version": "1.0.0"}
		}, maintainer, "may only require the proposed Kubernetes version"},
		"chart rule requiring the current Kubernetes version": {func(e map[string]any) {
			rule(e)["operator"] = "require_component_version"
			delete(rule(e), "setCondition")
			rule(e)["dependency"] = map[string]any{"side": "current", "component": "pkg:github/kubernetes/kubernetes", "comparison": "gte", "version": "1.0.0"}
		}, maintainer, "may only require the proposed Kubernetes version"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entry := chartCandidate()
			tc.edit(entry)
			findings := chartFindings(t, entry, tc.opts)
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("want %q in %v", tc.want, findings)
			}
		})
	}
}

// A member of a values-path set fact must be the canonical rendering of
// its key path: another spelling of the same path would never equal the
// member a values reader collects.
func TestRulecheckValuesPathMembers(t *testing.T) {
	maintainer := Options{AllowRange: true, ChartSources: chartTable(chartidentity.StateActive, chartTestComponent)}
	withMembers := func(members ...any) map[string]any {
		entry := chartCandidate()
		rule(entry)["setCondition"].(map[string]any)["members"] = members
		return entry
	}
	for _, good := range [][]any{
		{"a.b"},
		{"a._b"},
		{"k..a_2Eb"},
		{"k.._5Fa"},
		{"auth.token", "k..annotations..nginx_2Eingress_2Ekubernetes_2Eio/proxy-body-size", "rootKey"},
	} {
		if findings := chartFindings(t, withMembers(good...), maintainer); len(findings) != 0 {
			t.Fatalf("%v rejected: %v", good, findings)
		}
	}
	for _, bad := range []string{
		"k..a..b",   // plainly expressible
		"k..a",      // plainly expressible
		"k..a_2e",   // lower-case hex
		"k..",       // no key
		"k..a....b", // empty key
		"k..a_2",    // truncated escape
		"k.._41",    // escape of a byte written as itself
		"a..b",      // ".." in the plain form
		"a.",        // empty key
	} {
		findings := chartFindings(t, withMembers(bad), maintainer)
		if !strings.Contains(strings.Join(findings, "\n"), "not a canonical values-path member") {
			t.Fatalf("%q: want a canonical-member finding in %v", bad, findings)
		}
	}
}
