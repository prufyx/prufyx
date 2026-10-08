// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

type reviewedVector struct {
	Project string `json:"project"`
	RuleID  string `json:"ruleId"`
	Cases   []struct {
		Name   string          `json:"name"`
		Input  json.RawMessage `json:"input"`
		Status string          `json:"status"`
	} `json:"cases"`
}

func reviewClock(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-09-11T23:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func reviewedVectors(t *testing.T) []reviewedVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/reviewed-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var result []reviewedVector
	if err := strictJSON(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReviewedTransitionCorpus(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	vectors := reviewedVectors(t)
	if len(b.pack.Entries) != 195 || len(vectors) != 195 {
		t.Fatal("unexpected reviewed rule or vector count")
	}
	caseCount := 0
	for _, vector := range vectors {
		caseCount += len(vector.Cases)
	}
	if caseCount != 979 {
		t.Fatal("unexpected reviewed case count")
	}
	if len(vectors) != len(b.pack.Entries) {
		t.Fatal("each admitted rule needs source-reviewed vectors")
	}
	for i, vector := range vectors {
		if vector.RuleID == "" || !bytes.Contains(b.pack.Entries[i].Rule, []byte(vector.RuleID)) {
			t.Fatal("vector coverage does not match ordered rule pack")
		}
		for _, scenario := range vector.Cases {
			t.Run(vector.RuleID+"/"+scenario.Name, func(t *testing.T) {
				clock := reviewClock(t)
				switch vector.RuleID {
				case "kubernetes.admissionwebhook-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.apiservice-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.crd-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.csr-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.ingress-extensions-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.ingress-networking-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.ingressclass-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.lease-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.priorityclass-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.rbac-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.storage-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.subjectaccessreview-v1beta1-removed.1-21-0-to-1-22-0", "kubernetes.tokenreview-v1beta1-removed.1-21-0-to-1-22-0":
					clock = time.Date(2026, 9, 23, 13, 56, 0, 0, time.UTC)
				}
				switch vector.RuleID {
				case "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.csistoragecapacity-v1beta1-removed.1-26-0-to-1-27-0", "kubernetes.endpointslice-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.event-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.flowcontrol-v1beta1-removed.1-25-0-to-1-26-0", "kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0", "kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0", "kubernetes.hpa-v2beta2-removed.1-25-0-to-1-26-0", "kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.runtimeclass-v1beta1-removed.1-24-0-to-1-25-0":
					clock = time.Date(2026, 9, 23, 12, 36, 0, 0, time.UTC)
				}
				// This source review completed after the historical corpus clock;
				// preserve its real reviewedAt timestamp in the rule data.
				if vector.Project == "cloud-custodian" || vector.Project == "opencost" {
					clock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "argo-cd.plain-http-oci-repository-helm4.") {
					clock = time.Date(2026, 9, 12, 11, 30, 0, 0, time.UTC)
				}
				if vector.Project == "opentelemetry" {
					clock = time.Date(2026, 9, 12, 2, 35, 0, 0, time.UTC)
				}
				if vector.RuleID == "opentelemetry.internal-telemetry-default-bind.0-110-to-0-111" {
					clock = time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
				}
				if vector.RuleID == "containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0" {
					clock = time.Date(2026, 9, 12, 12, 30, 0, 0, time.UTC)
				}
				if vector.RuleID == "fluentd.z-literal-treatment.1-17-1-to-1-18-0" || vector.RuleID == "prometheus.alertmanager-api-v1-removed.3-1" {
					clock = time.Date(2026, 9, 12, 1, 0, 0, 0, time.UTC)
				}
				if vector.RuleID == "argo-cd.resource-exclusions-v2-visibility-preservation.3-0" {
					clock = time.Date(2026, 9, 12, 1, 23, 59, 0, time.UTC)
				}
				if (strings.HasPrefix(vector.RuleID, "cortex.querier-at-modifier-flag-target-argv.") && strings.HasSuffix(vector.RuleID, "-to-1-21-1")) ||
					(strings.HasPrefix(vector.RuleID, "thanos.receive-store-flags-target-argv.") && strings.HasSuffix(vector.RuleID, "-to-0-42-4")) {
					clock = time.Date(2026, 9, 12, 7, 38, 0, 0, time.UTC)
				}
				if strings.Contains(vector.RuleID, ".target-config.") || strings.HasPrefix(vector.RuleID, "fluentd.ruby-minimum-target.") {
					clock = time.Date(2026, 9, 12, 8, 6, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "prometheus.alertmanager-api-v1.target-config.") {
					clock = time.Date(2026, 9, 12, 9, 3, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "etcd.direct-minor-skip.") || strings.HasPrefix(vector.RuleID, "etcd.experimental-flags-unsupported.") || strings.HasPrefix(vector.RuleID, "rook.direct-minor-skip.") || vector.RuleID == "rook.minimum-kubernetes.1-20-7" {
					clock = time.Date(2026, 9, 12, 7, 38, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "rook.minimum-kubernetes.1-20-7-from-") {
					clock = time.Date(2026, 9, 12, 8, 32, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "nats.names-with-ascii-spaces-rejected.") && strings.HasSuffix(vector.RuleID, "-to-2-14-6") {
					clock = time.Date(2026, 9, 12, 8, 47, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "coredns.official-federation-absent-at-1-14-7-from-") || strings.HasPrefix(vector.RuleID, "envoy.xds-v2-unsupported-at-1-39-1-from-") {
					clock = time.Date(2026, 9, 12, 9, 1, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "opa.v0-consumer-producer-option-at-1-20-2-") || strings.HasPrefix(vector.RuleID, "kyverno.reports-chunk-size-unsupported-at-1-19-1-") {
					clock = time.Date(2026, 9, 12, 9, 34, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "flux.latest-beta-api-removal.") {
					clock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "kubernetes.kubelet-version-skew.") {
					clock = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
				}
				if vector.RuleID == "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0" || vector.RuleID == "cilium.cluster-name-invalid.1-16-19-to-1-17-18" {
					clock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "jaeger.explicit-config-required-for-non-memory.target.") {
					clock = time.Date(2026, 9, 12, 8, 39, 0, 0, time.UTC)
				}
				if strings.HasPrefix(vector.RuleID, "harbor.installer-with-chartmuseum-flag-removed.2-") && strings.HasSuffix(vector.RuleID, "-to-2-15") {
					clock = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
				}
				if strings.HasSuffix(vector.RuleID, ".2-55-1-to-3-14-0") {
					clock = time.Date(2026, 9, 12, 17, 29, 0, 0, time.UTC)
				}
				if vector.RuleID == "prometheus.remote-write-http2-default.2-55-1-to-3-14-0" {
					clock = time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
				}
				report, err := Check(vector.Project, scenario.Input, clock)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, claim := range report.Check.Claims {
					if claim.RuleID == vector.RuleID {
						found = true
						if claim.Status != scenario.Status {
							t.Fatalf("status %s, want %s", claim.Status, scenario.Status)
						}
						if len(claim.Sources) == 0 || claim.NextAction == "" {
							t.Fatal("missing evidence or bounded action")
						}
					}
				}
				if !found {
					t.Fatal("expected rule omitted")
				}
				if report.Assessment != "UNKNOWN" || report.Check.Assessment != "UNKNOWN" || report.RuntimeReproduced != 0 || report.NetworkUsed {
					t.Fatal("source preview escalated authority")
				}
				if report.Check.InputAuthority != constraintengine.InputAuthority || report.Check.RulesAuthority != "DECLARED_RULE_SOURCE_REFERENCES" || report.SourceAuthority != "PACKAGED_MAINTAINER_REVIEWED_SOURCE_RULES_NOT_RUNTIME_PROOF" {
					t.Fatal("authority provenance lost")
				}
				if _, err := MarshalReport(report); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestTektonDuplicatePrometheusFactIsInvalidInput(t *testing.T) {
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != "tekton.metrics-protocol-prometheus.1-10" {
			continue
		}
		for _, scenario := range vector.Cases {
			if scenario.Name != "old-key-only-blocked" {
				continue
			}
			var document map[string]any
			if err := json.Unmarshal(scenario.Input, &document); err != nil {
				t.Fatal(err)
			}
			proposed := document["proposed"].(map[string]any)
			component := proposed["components"].([]any)[0].(map[string]any)
			facts := component["facts"].([]any)
			for _, value := range facts {
				fact := value.(map[string]any)
				if fact["id"] == "component.tekton.proposed_metrics_protocol_prometheus" {
					facts = append(facts, fact)
					component["facts"] = facts
					break
				}
			}
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check("tekton", mutated, reviewClock(t)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("duplicate Tekton fact error = %v, want ErrInvalid", err)
			}
			return
		}
	}
	t.Fatal("Tekton blocked fixture missing")
}

func TestTektonCanonicalExamplePasses(t *testing.T) {
	raw, err := os.ReadFile("../../examples/cncf/tekton-input.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check("tekton", raw, reviewClock(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "PASS" || ClaimExit(report) != 0 {
		t.Fatalf("canonical Tekton example produced %+v", report.Check.Claims)
	}
}

func TestFluentdLatestRubyExamplesStayScoped(t *testing.T) {
	for name, want := range map[string]string{
		"blocked.json":              "BLOCKED",
		"fixed.json":                "PASS",
		"unknown-missing-ruby.json": "UNKNOWN",
		"unknown-wrong-pair.json":   "UNKNOWN",
		"unknown-custom-build.json": "UNKNOWN",
	} {
		raw, err := os.ReadFile("../../examples/cncf/fluentd-ruby-v1.19.3/" + name)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Check("fluentd", raw, time.Date(2026, 9, 12, 8, 6, 0, 0, time.UTC))
		status := ""
		for _, claim := range report.Check.Claims {
			if strings.HasPrefix(claim.RuleID, "fluentd.ruby-minimum-target.1-18-0-") {
				status = claim.Status
			}
		}
		if err != nil || status != want || ClaimExit(report) != map[string]int{"BLOCKED": 10, "PASS": 0, "UNKNOWN": 11}[want] {
			t.Fatalf("%s report=%+v err=%v", name, report, err)
		}
	}
}

func TestSelectedRuleKeepsIndependentPrometheusCapabilitiesSeparate(t *testing.T) {
	const (
		alertmanagerRule = "prometheus.alertmanager-api-v1-removed.3-1"
		scrapeRule       = "prometheus.scrape-classic-histograms-key-renamed.3-1"
	)
	var alertmanagerInput []byte
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != alertmanagerRule {
			continue
		}
		for _, scenario := range vector.Cases {
			if scenario.Name == "explicit-v2" {
				alertmanagerInput = append([]byte(nil), scenario.Input...)
			}
		}
	}
	if len(alertmanagerInput) == 0 {
		t.Fatal("Alertmanager pass vector missing")
	}
	report, err := CheckRule("prometheus", alertmanagerRule, alertmanagerInput, time.Date(2026, 9, 12, 0, 30, 0, 0, time.UTC))
	if err != nil || report.RequestedRuleID != alertmanagerRule || report.SelectedRuleID != alertmanagerRule || len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != alertmanagerRule || report.Check.Claims[0].Status != "PASS" || ClaimExit(report) != 0 {
		t.Fatalf("selected report=%+v err=%v", report, err)
	}
	generic, err := Check("prometheus", alertmanagerInput, time.Date(2026, 9, 12, 0, 30, 0, 0, time.UTC))
	if err != nil || generic.RequestedRuleID != "" || generic.SelectedRuleID != "" || len(generic.Check.Claims) != 2 || ClaimExit(generic) != 11 {
		t.Fatalf("generic report=%+v err=%v", generic, err)
	}
	if _, err := CheckRule("prometheus", "tekton.metrics-protocol-prometheus.1-10", alertmanagerInput, time.Date(2026, 9, 12, 0, 30, 0, 0, time.UTC)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-project selection error=%v", err)
	}
	mutated := report
	mutated.SelectedRuleID = scrapeRule
	if _, err := MarshalReport(mutated); err == nil {
		t.Fatal("selected rule mutation retained report seal")
	}
}

func TestKyvernoVectorsParseAndStayBoundToTheirRule(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	const ruleID = "kyverno.reports-chunk-size-removed.1-13"
	seen := map[string]bool{}
	count := 0
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != ruleID {
			continue
		}
		if vector.Project != "kyverno" {
			t.Fatal("Kyverno vectors have an unexpected project")
		}
		for _, scenario := range vector.Cases {
			if seen[string(scenario.Input)] {
				t.Fatal("Kyverno reviewed vector input is duplicated")
			}
			seen[string(scenario.Input)] = true
			if _, err := constraintengine.ParseInput(scenario.Input, registry); err != nil {
				t.Fatalf("Kyverno %s does not parse: %v", scenario.Name, err)
			}
			count++
		}
	}
	if count != 15 {
		t.Fatalf("Kyverno reviewed vectors = %d, want 15", count)
	}
}

func TestSPIREVectorsParseAndStayBoundToTheirRule(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	const ruleID = "spire.removed-entry-ttl.1-11"
	seen := map[string]bool{}
	count := 0
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != ruleID {
			continue
		}
		if vector.Project != "spire" {
			t.Fatal("SPIRE vectors have an unexpected project")
		}
		for _, scenario := range vector.Cases {
			if seen[string(scenario.Input)] {
				t.Fatal("SPIRE reviewed vector input is duplicated")
			}
			seen[string(scenario.Input)] = true
			if _, err := constraintengine.ParseInput(scenario.Input, registry); err != nil {
				t.Fatalf("SPIRE %s does not parse: %v", scenario.Name, err)
			}
			count++
		}
	}
	if count != 15 {
		t.Fatalf("SPIRE reviewed vectors = %d, want 15", count)
	}
}

func TestCortexStrimziVectorsParseAndStayBoundToTheirRule(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		project string
		count   int
	}{
		"cortex.querier-at-modifier-flag-removed.1-21": {project: "cortex", count: 16},
		"strimzi.kafka-v1beta2-api-removed.1-0":        {project: "strimzi", count: 20},
	}
	for _, vector := range reviewedVectors(t) {
		expected, ok := want[vector.RuleID]
		if !ok {
			continue
		}
		if vector.Project != expected.project || len(vector.Cases) != expected.count {
			t.Fatalf("%s vector identity/count changed", vector.RuleID)
		}
		seen := map[string]bool{}
		for _, scenario := range vector.Cases {
			if seen[string(scenario.Input)] {
				t.Fatalf("%s has duplicate input bytes", vector.RuleID)
			}
			seen[string(scenario.Input)] = true
			if _, err := constraintengine.ParseInput(scenario.Input, registry); err != nil {
				t.Fatalf("%s/%s does not parse: %v", vector.RuleID, scenario.Name, err)
			}
		}
		delete(want, vector.RuleID)
	}
	if len(want) != 0 {
		t.Fatalf("missing Cortex/Strimzi vectors: %v", want)
	}
}

func TestCortexStrimziClosedInputFailures(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	type mutation struct {
		ruleID string
		factID string
		kind   string
		value  string
	}
	tests := []mutation{
		{"cortex.querier-at-modifier-flag-removed.1-21", "component.cortex.distribution", "enum", "vendor_fork"},
		{"cortex.querier-at-modifier-flag-removed.1-21", "component.cortex.execution_surface", "enum", "querier_library"},
		{"cortex.querier-at-modifier-flag-removed.1-21", "component.cortex.removed_at_modifier_flag_present", "bool-as-enum", "true"},
		{"cortex.querier-at-modifier-flag-removed.1-21", "component.cortex.removed_at_modifier_flag_present", "duplicate", ""},
		{"strimzi.kafka-v1beta2-api-removed.1-0", "component.strimzi.distribution", "enum", "vendor_operator"},
		{"strimzi.kafka-v1beta2-api-removed.1-0", "component.strimzi.execution_surface", "enum", "kafkatopic_cr"},
		{"strimzi.kafka-v1beta2-api-removed.1-0", "component.strimzi.target_kafka_crd_admission_required", "bool-as-enum", "true"},
		{"strimzi.kafka-v1beta2-api-removed.1-0", "component.strimzi.target_kafka_crd_admission_required", "duplicate", ""},
	}
	vectors := reviewedVectors(t)
	for _, test := range tests {
		t.Run(test.ruleID+"/"+test.kind+"/"+test.factID, func(t *testing.T) {
			var raw json.RawMessage
			for _, vector := range vectors {
				if vector.RuleID != test.ruleID {
					continue
				}
				for _, scenario := range vector.Cases {
					if scenario.Name == "blocked" {
						raw = scenario.Input
					}
				}
			}
			if len(raw) == 0 {
				t.Fatal("blocked fixture missing")
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			proposed := document["proposed"].(map[string]any)
			components := proposed["components"].([]any)
			component := components[0].(map[string]any)
			facts := component["facts"].([]any)
			found := false
			for index, value := range facts {
				fact := value.(map[string]any)
				if fact["id"] != test.factID {
					continue
				}
				found = true
				switch test.kind {
				case "enum":
					fact["enumValue"] = test.value
				case "bool-as-enum":
					delete(fact, "boolValue")
					fact["enumValue"] = test.value
				case "duplicate":
					clone := make(map[string]any, len(fact))
					for key, item := range fact {
						clone[key] = item
					}
					facts = append(facts, nil)
					copy(facts[index+2:], facts[index+1:])
					facts[index+1] = clone
					component["facts"] = facts
				}
				break
			}
			if !found {
				t.Fatal("fact fixture missing")
			}
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := constraintengine.ParseInput(mutated, registry); !errors.Is(err, constraintengine.ErrInvalid) {
				t.Fatalf("ParseInput error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestFluentdInvalidRubyVersionIsInvalidInput(t *testing.T) {
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != "fluentd.ruby-minimum.1-16-to-1-17" {
			continue
		}
		for _, scenario := range vector.Cases {
			if scenario.Name != "satisfied" {
				continue
			}
			invalid := bytes.Replace(scenario.Input, []byte(`"version": "2.7.0"`), []byte(`"version": "2.7"`), 1)
			if _, err := Check(vector.Project, invalid, reviewClock(t)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid Ruby version error = %v, want ErrInvalid", err)
			}
			return
		}
	}
	t.Fatal("Fluentd satisfied fixture missing")
}

func TestCatalogueDoesNotInventCoverage(t *testing.T) {
	all, err := Catalog(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if all.Catalogued != 255 || all.PriorityProjects != 30 || len(all.Projects) != 255 || all.SourceRuleCovered != 54 || all.RuntimeReproduced != 0 {
		t.Fatalf("unexpected inventory: %+v", all)
	}
	priority, err := Catalog(true, "")
	if err != nil || len(priority.Projects) != 30 || priority.SourceRuleCovered != all.SourceRuleCovered {
		t.Fatal("filtered inventory changed total counters")
	}
	dragonfly, err := Catalog(false, "dragonfly")
	if err != nil || len(dragonfly.Projects) != 1 || dragonfly.Projects[0].SourceRuleCount != 2 || dragonfly.Projects[0].GenericCoverage != "source_rule_preview" || dragonfly.Projects[0].RuntimeReproduced != 0 {
		t.Fatal("Dragonfly source preview coverage missing or overstated")
	}
	linkerd, err := Catalog(false, "linkerd")
	if err != nil || len(linkerd.Projects) != 1 || linkerd.Projects[0].SourceRuleCount != 1 || linkerd.Projects[0].GenericCoverage != "source_rule_preview" || linkerd.Projects[0].RuntimeReproduced != 0 {
		t.Fatal("Linkerd source preview coverage missing or overstated")
	}
	nats, err := Catalog(false, "nats")
	if err != nil || len(nats.Projects) != 1 || nats.Projects[0].SourceRuleCount != 6 || nats.Projects[0].GenericCoverage != "source_rule_preview" || nats.Projects[0].RuntimeReproduced != 0 {
		t.Fatal("NATS source preview coverage missing or overstated")
	}
	for _, want := range []struct {
		slug  string
		rules int
	}{{"cortex", 5}, {"falco", 2}, {"karmada", 1}, {"kubeedge", 1}, {"kuma", 1}, {"spire", 1}, {"strimzi", 1}} {
		preview, err := Catalog(false, want.slug)
		if err != nil || len(preview.Projects) != 1 || preview.Projects[0].SourceRuleCount != want.rules || preview.Projects[0].GenericCoverage != "source_rule_preview" || preview.Projects[0].RuntimeReproduced != 0 {
			t.Fatalf("%s source preview coverage missing or overstated", want.slug)
		}
	}
	certManager, err := Catalog(false, "cert-manager")
	if err != nil || len(certManager.Projects[0].ExistingChecks) != 1 || certManager.Projects[0].SourceRuleCount != 0 {
		t.Fatal("cert-manager existing check lost or double counted")
	}
	prometheus, err := Catalog(false, "prometheus")
	if err != nil || len(prometheus.Projects[0].ExistingChecks) != 1 || prometheus.Projects[0].SourceRuleCount != 15 || prometheus.Projects[0].GenericCoverage != "source_rule_preview" {
		t.Fatal("Prometheus existing check or source rule lost or double counted")
	}
	fluentd, err := Catalog(false, "fluentd")
	if err != nil || fluentd.Projects[0].SourceRuleCount != 7 || fluentd.Projects[0].GenericCoverage != "source_rule_preview" {
		t.Fatal("Fluentd target package constraints not counted")
	}
	archived, err := Catalog(false, "curiefense")
	if err != nil || archived.Projects[0].RepositoryURL != "" {
		t.Fatal("absent archived repository identity fabricated")
	}
	if _, err := Catalog(false, "helm\x1b[31m"); err == nil {
		t.Fatal("untrusted project admitted")
	}
}

func TestTransitionDispatchDoesNotApplySiblingVersionRule(t *testing.T) {
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != "rook.minimum-kubernetes.1-20" {
			continue
		}
		report, err := Check("rook", vector.Cases[0].Input, reviewClock(t))
		if err != nil || len(report.Check.Claims) != 1 || ClaimExit(report) != 0 {
			t.Fatal("reviewed 1.19.5 hop contaminated by direct 1.19.4 rule", err)
		}
		if report.Check.Claims[0].RuleID != vector.RuleID || report.Assessment != "UNKNOWN" {
			t.Fatal("wrong transition or aggregate")
		}
		return
	}
	t.Fatal("fixture missing")
}

func TestSourceFreshnessWithdrawalsAndReplayRemainBounded(t *testing.T) {
	var vector reviewedVector
	for _, candidate := range reviewedVectors(t) {
		if candidate.RuleID == "argo-cd.required-rbac-inheritance.3-0" {
			vector = candidate
			break
		}
	}
	if vector.RuleID == "" {
		t.Fatal("freshness fixture missing")
	}
	raw := vector.Cases[0].Input
	report, err := Check(vector.Project, raw, reviewClock(t))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	prior := append(append([]byte(nil), encoded...), '\n')
	if _, err := Replay(vector.Project, raw, reviewClock(t), prior); err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{encoded, append(append([]byte(nil), prior...), '\n'), bytes.Replace(prior, []byte(`"assessment":"UNKNOWN"`), []byte(`"assessment":"SAFE"`), 1)} {
		if _, err := Replay(vector.Project, raw, reviewClock(t), expected); err == nil {
			t.Fatal("nonexact or escalated replay accepted")
		}
	}
	if _, err := Replay(vector.Project, append(raw, ' '), reviewClock(t), prior); err == nil {
		t.Fatal("raw input digest not bound")
	}
	for _, at := range []string{"2026-09-08T12:07:55Z", "2026-12-07T12:07:56Z"} {
		now, _ := time.Parse(time.RFC3339, at)
		result, err := Check(vector.Project, raw, now)
		if err != nil || ClaimExit(result) != 11 || result.Check.Claims[0].Status != "UNKNOWN" {
			t.Fatal("outside review window did not fail closed", err)
		}
	}
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.pack.Entries {
		b.pack.Entries[i].Rule = bytes.ReplaceAll(b.pack.Entries[i].Rule, []byte(`"state": "active"`), []byte(`"state": "withdrawn"`))
	}
	withdrawn, err := b.check(vector.Project, "", raw, reviewClock(t))
	if err != nil || ClaimExit(withdrawn) != 11 || withdrawn.Check.Claims[0].ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
		t.Fatal("withdrawn evidence did not fail closed", err)
	}
}

func TestReportsCannotBeForgedOrModified(t *testing.T) {
	if _, err := MarshalReport(Report{Assessment: "UNKNOWN"}); err == nil {
		t.Fatal("forged report accepted")
	}
	v := reviewedVectors(t)[0]
	report, err := Check(v.Project, v.Cases[0].Input, reviewClock(t))
	if err != nil {
		t.Fatal(err)
	}
	report.Check.Claims[0].Sources[0].ContentDigest = "sha256:" + strings.Repeat("a", 64)
	if _, err := MarshalReport(report); err == nil {
		t.Fatal("source mutation accepted")
	}
}

func TestUnsupportedProjectAndRawConfigurationAreNotAuthority(t *testing.T) {
	raw := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[]},"proposed":{"components":[]}}`)
	report, err := Check("agones", raw, reviewClock(t))
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 0 || report.NextAction == "" {
		t.Fatal("empty coverage not actionable UNKNOWN", err)
	}
	bad := bytes.Replace(raw, []byte(`"current":`), []byte(`"rawConfig":"synthetic-secret-canary","current":`), 1)
	if _, err := Check("helm", bad, reviewClock(t)); err == nil {
		t.Fatal("raw configuration admitted")
	}
}

func TestKarmadaVectorsParseAndStayBoundToTheirRule(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	const ruleID = "karmada.application-purge-mode-legacy-values-removed.1-19"
	seen, count := map[string]bool{}, 0
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID != ruleID {
			continue
		}
		if vector.Project != "karmada" || len(vector.Cases) != 12 {
			t.Fatal("Karmada vector identity/count changed")
		}
		for _, scenario := range vector.Cases {
			if seen[string(scenario.Input)] {
				t.Fatal("Karmada reviewed vector input is duplicated")
			}
			seen[string(scenario.Input)] = true
			if _, err := constraintengine.ParseInput(scenario.Input, registry); err != nil {
				t.Fatalf("Karmada %s does not parse: %v", scenario.Name, err)
			}
			count++
		}
	}
	if count != 12 {
		t.Fatalf("Karmada reviewed vectors = %d, want 12", count)
	}
}

func TestKarmadaClosedInputFailures(t *testing.T) {
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ factID, kind, value string }{
		{"component.karmada.distribution", "enum", "vendor_fork"},
		{"component.karmada.execution_surface", "enum", "cluster_failover_policy"},
		{"component.karmada.target_policy_crd_admission_required", "bool-as-enum", "true"},
		{"component.karmada.removed_application_purge_mode_present", "duplicate", ""},
	}
	var blocked json.RawMessage
	for _, vector := range reviewedVectors(t) {
		if vector.RuleID == "karmada.application-purge-mode-legacy-values-removed.1-19" {
			for _, scenario := range vector.Cases {
				if scenario.Name == "blocked-legacy-value-present" {
					blocked = scenario.Input
				}
			}
		}
	}
	if len(blocked) == 0 {
		t.Fatal("Karmada blocked fixture missing")
	}
	for _, test := range tests {
		t.Run(test.kind+"/"+test.factID, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(blocked, &document); err != nil {
				t.Fatal(err)
			}
			component := document["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)
			facts := component["facts"].([]any)
			found := false
			for _, value := range facts {
				fact := value.(map[string]any)
				if fact["id"] != test.factID {
					continue
				}
				found = true
				switch test.kind {
				case "enum":
					fact["enumValue"] = test.value
				case "bool-as-enum":
					delete(fact, "boolValue")
					fact["enumValue"] = test.value
				case "duplicate":
					clone := map[string]any{}
					for k, v := range fact {
						clone[k] = v
					}
					facts = append(facts, clone)
					component["facts"] = facts
				}
				break
			}
			if !found {
				t.Fatal("fact fixture missing")
			}
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := constraintengine.ParseInput(mutated, registry); !errors.Is(err, constraintengine.ErrInvalid) {
				t.Fatalf("ParseInput error = %v, want ErrInvalid", err)
			}
		})
	}
}
