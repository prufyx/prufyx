// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

type externalFixtureDocument struct {
	Schema                 string   `json:"schema"`
	Revision               string   `json:"revision"`
	Purpose                string   `json:"purpose"`
	EngineCapabilityDigest string   `json:"engineCapabilityDigest"`
	Pack                   rulePack `json:"pack"`
}

func externalFixture(t *testing.T, entries []Entry) []byte {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	capability, err := ExternalCapabilityDigest()
	if err != nil {
		t.Fatal(err)
	}
	pack := base.pack
	pack.Revision = "1"
	pack.Entries = entries
	pack.Schema = packSchema
	if !validPackSchema(pack) {
		pack.Schema = packSchemaRanged
	}
	raw, err := json.Marshal(externalFixtureDocument{Schema: externalBundleSchema, Revision: "1", Purpose: "operator_provided", EngineCapabilityDigest: capability, Pack: pack})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func kyvernoEntry(t *testing.T) Entry {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range base.pack.Entries {
		if entry.Project == "kyverno" {
			return entry
		}
	}
	t.Fatal("kyverno entry missing")
	return Entry{}
}

func ruleEntry(t *testing.T, project, ruleID string) Entry {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range base.pack.Entries {
		if entry.Project != project {
			continue
		}
		var shape struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(entry.Rule, &shape); err != nil {
			t.Fatal(err)
		}
		if shape.ID == ruleID {
			return entry
		}
	}
	t.Fatalf("rule %q for %q missing", ruleID, project)
	return Entry{}
}

func kyvernoInput(t *testing.T, want string) []byte {
	t.Helper()
	for _, vector := range reviewedVectors(t) {
		if vector.Project != "kyverno" {
			continue
		}
		for _, scenario := range vector.Cases {
			if scenario.Name == want {
				return scenario.Input
			}
		}
	}
	t.Fatalf("kyverno vector %q missing", want)
	return nil
}

func externalReviewClock() time.Time {
	return time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC)
}

func TestParseExternalBundleEmptyAndAdmissionBinding(t *testing.T) {
	requirements, err := ExternalProfileRequirements()
	if err != nil || requirements.Schema != externalBundleSchema || requirements.PackSchema == "" || requirements.EngineCapabilityDigest == "" || requirements.PolicyID == "" || requirements.PolicyDigest == "" || requirements.RegistryDigest == "" || requirements.LandscapeFileDigest == "" {
		t.Fatalf("invalid scalar profile requirements: %+v err=%v", requirements, err)
	}
	raw := externalFixture(t, []Entry{})
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Revision != "1" || admission.Purpose != "operator_provided" || admission.HasRule || admission.RuleDigest != "" || admission.EvidenceExpiresAt != "" {
		t.Fatalf("unexpected empty admission: %+v", admission)
	}
	if got, want := bundle.BundleDigest(), digest(raw); got != want {
		t.Fatalf("bundle digest=%s want %s", got, want)
	}
}

func TestParseExternalBundleRuleAdmissionAndExternalAuthority(t *testing.T) {
	raw := externalFixture(t, []Entry{kyvernoEntry(t)})
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil || !admission.HasRule || admission.RuleDigest == "" || admission.EvidenceExpiresAt == "" || admission.EngineCapabilityDigest == "" {
		t.Fatalf("invalid rule admission=%+v err=%v", admission, err)
	}
	report, err := bundle.Evaluate("kyverno", kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil {
		t.Fatal(err)
	}
	if report.KnowledgeOrigin != "external_declared" || report.SourceAuthority != externalSourceAuthority || report.KnowledgeRevision != "1" || report.KnowledgePackDigest != digest(raw) || report.NetworkUsed || report.RuntimeReproduced != 0 || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" {
		t.Fatalf("external authority/result lost: %+v", report)
	}
	if report.Check.RulesAuthority != externalSourceAuthority {
		t.Fatalf("rules authority=%q", report.Check.RulesAuthority)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestExternalBundleDoesNotFallbackToEmbeddedRules(t *testing.T) {
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := bundle.Evaluate("kyverno", kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 0 || report.Assessment != "UNKNOWN" {
		t.Fatalf("empty external bundle fell back to embedded rules: %+v", report.Check.Claims)
	}
}

func TestExternalSelectedRuleDoesNotFallbackOrCrossProjects(t *testing.T) {
	const kyvernoRuleID = "kyverno.reports-chunk-size-removed.1-13"
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := bundle.EvaluateRule("kyverno", kyvernoRuleID, kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil || report.RequestedRuleID != kyvernoRuleID || report.SelectedRuleID != "" || len(report.Check.Claims) != 0 || ClaimExit(report) != 11 || !strings.Contains(report.NextAction, "no exact rule") {
		t.Fatalf("selected empty report=%+v err=%v", report, err)
	}
	if _, err := bundle.EvaluateRule("prometheus", kyvernoRuleID, kyvernoInput(t, "blocked"), externalReviewClock()); err == nil {
		t.Fatal("cross-project external rule selection admitted")
	}

	bundle, err = ParseExternalBundle(externalFixture(t, []Entry{kyvernoEntry(t)}))
	if err != nil {
		t.Fatal(err)
	}
	report, err = bundle.EvaluateRule("kyverno", kyvernoRuleID, kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil || report.RequestedRuleID != kyvernoRuleID || report.SelectedRuleID != kyvernoRuleID || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || ClaimExit(report) != 10 {
		t.Fatalf("selected external report=%+v err=%v", report, err)
	}
}

func TestExternalSelectedPrometheusRuleCannotReuseSourceDefaultForFuturePair(t *testing.T) {
	const ruleID = "prometheus.alertmanager-api-v1-removed.3-1"
	prepared, err := cncfprepare.PreparePrometheusAlertmanagerConfig([]byte("scheme: http\n"), "3.1.0", "3.2.0", true, true)
	if err != nil || prepared.State != cncfprepare.StateUnknown || prepared.Reason != cncfprepare.ReasonPrometheusAlertmanagerUnsupported {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	entry := ruleEntry(t, "prometheus", ruleID)
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	var subject struct {
		Component string `json:"component"`
		From      string `json:"from"`
		To        string `json:"to"`
	}
	if err := json.Unmarshal(rule["subject"], &subject); err != nil {
		t.Fatal(err)
	}
	subject.From, subject.To = "3.1.0", "3.2.0"
	rule["subject"], err = json.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule, err = json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rule["subject"], &subject); err != nil || subject.Component != "pkg:github/prometheus/prometheus" || subject.From != "3.1.0" || subject.To != "3.2.0" {
		t.Fatalf("future selected rule subject=%+v err=%v", subject, err)
	}
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{entry}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := bundle.EvaluateRule("prometheus", ruleID, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 0, 30, 0, 0, time.UTC))
	if err != nil || report.RequestedRuleID != ruleID || report.SelectedRuleID != ruleID || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" || report.Check.Claims[0].ReasonCode != "RULE_FACT_UNAVAILABLE" || ClaimExit(report) != 11 {
		t.Fatalf("future-pair selected report=%+v err=%v", report, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), "omitted_default_v2") {
		t.Fatal("unreviewed target inherited the reviewed target's source-derived default")
	}
}

func TestExternalBundleRejectsMalformedClosedShapes(t *testing.T) {
	valid := externalFixture(t, []Entry{})
	tests := [][]byte{
		bytes.Replace(valid, []byte(`"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1"`), []byte(`"Schema":"prufyx.io/operator-cncf-knowledge/v1alpha1"`), 1),
		bytes.Replace(valid, []byte(`"pack":{`), []byte(`"authority":"operator" ,"pack":{`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":null`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[null]`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":{}`), 1),
		append([]byte(`{"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1","revision":"1","purpose":"operator_provided","engineCapabilityDigest":"`), []byte(strings.Repeat("a", 64)+`","pack":{}}`)...),
	}
	for i, raw := range tests {
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Errorf("malformed external shape %d admitted", i)
		}
	}
	duplicate := bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[],"Entries":[]`), 1)
	if _, err := ParseExternalBundle(duplicate); err == nil {
		t.Fatal("case alias admitted")
	}
	duplicate = bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[],"entries":[]`), 1)
	if _, err := ParseExternalBundle(duplicate); err == nil {
		t.Fatal("duplicate member admitted")
	}
	oversize := append([]byte(`{"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1","revision":"1","purpose":"operator_provided","engineCapabilityDigest":"`), []byte(strings.Repeat("a", 64)+`","pack":{"schema":"x","revision":"1","policyId":"x","policyDigest":"x","landscapeFileDigest":"x","registryDigest":"x","entries":[],"padding":"`+strings.Repeat("x", maxExternalBundleBytes)+`"}}`)...)
	if _, err := ParseExternalBundle(oversize); err == nil {
		t.Fatal("oversize bundle admitted")
	}
}

func TestExternalBundleRejectsIdentityAndRegistryMismatches(t *testing.T) {
	valid := externalFixture(t, []Entry{})
	mutations := [][]byte{
		bytes.Replace(valid, []byte(`"revision":"1"`), []byte(`"revision":"0"`), 1),
		bytes.Replace(valid, []byte(`"purpose":"operator_provided"`), []byte(`"purpose":"unknown"`), 1),
		bytes.Replace(valid, []byte(`"engineCapabilityDigest":"`), []byte(`"engineCapabilityDigest":"`+strings.Repeat("0", 64)), 1),
		bytes.Replace(valid, []byte(`"registryDigest":"`), []byte(`"registryDigest":"sha256:`+strings.Repeat("0", 64)+`"`), 1),
		bytes.Replace(valid, []byte(`"policyId":"cncf-source-preview-v1"`), []byte(`"policyId":"other"`), 1),
	}
	for i, raw := range mutations {
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Errorf("identity mutation %d admitted", i)
		}
	}
}

func TestExternalBundleSealRejectsMutation(t *testing.T) {
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	bundle.raw[0] ^= 1
	if _, err := bundle.Admission(); err == nil || bundle.BundleDigest() != "" {
		t.Fatal("raw mutation retained capability")
	}
	bundle, err = ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	bundle.admission.Revision = "2"
	if _, err := bundle.Admission(); err == nil {
		t.Fatal("admission mutation retained capability")
	}
}

func TestExternalBundleEvidenceStatesRemainScoped(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace []byte
		with    []byte
		reason  string
	}{
		{"withdrawn", []byte(`"state": "active"`), []byte(`"state": "withdrawn"`), "RULE_EVIDENCE_WITHDRAWN"},
		{"expired", []byte(`"validUntil": "2026-12-08T00:53:06Z"`), []byte(`"validUntil": "2026-09-09T00:59:59Z"`), "RULE_EVIDENCE_STALE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := kyvernoEntry(t)
			updated := bytes.Replace(entry.Rule, test.replace, test.with, 1)
			if bytes.Equal(updated, entry.Rule) {
				t.Fatal("evidence fixture mutation did not apply")
			}
			entry.Rule = updated
			bundle, err := ParseExternalBundle(externalFixture(t, []Entry{entry}))
			if err != nil {
				t.Fatal(err)
			}
			report, err := bundle.EvaluateRule("kyverno", "kyverno.reports-chunk-size-removed.1-13", kyvernoInput(t, "blocked"), externalReviewClock())
			if err != nil || report.SelectedRuleID == "" || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" || report.Check.Claims[0].ReasonCode != test.reason {
				t.Fatalf("evidence state=%+v err=%v", report.Check.Claims, err)
			}
		})
	}
}

func TestExportEmbeddedExternalBundlePreservesCompletePack(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ExportEmbeddedExternalBundle("73")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := parsed.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Revision != "73" || admission.Purpose != "operator_provided" || !admission.HasRule {
		t.Fatalf("admission=%+v", admission)
	}
	var document externalFixtureDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	want := base.pack
	want.Revision = "73"
	wantRaw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, err := json.Marshal(document.Pack)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatal("export changed embedded rule-pack content other than revision")
	}
	if len(document.Pack.Entries) == 0 || len(base.pack.Entries) == 0 {
		t.Fatalf("exported entries=%d embedded=%d", len(document.Pack.Entries), len(base.pack.Entries))
	}
}

func TestExportEmbeddedExternalBundleRejectsInvalidRevision(t *testing.T) {
	for _, revision := range []string{"", "0", "01", "main", "2147483648"} {
		t.Run(revision, func(t *testing.T) {
			if _, err := ExportEmbeddedExternalBundle(revision); err == nil {
				t.Fatalf("revision %q accepted", revision)
			}
		})
	}
}

func TestExternalProfileContractMatchesEnforcedRequirements(t *testing.T) {
	contract, err := ExternalProfileContractForCNCF()
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	if contract.Profile != "cncf" || contract.TargetPath != "knowledge/constraints.v1.json" || contract.Purpose != "operator_provided" || !reflect.DeepEqual(contract.Requirements, requirements) || contract.MaxBundleBytes != maxExternalBundleBytes || contract.MaxEntries != maxExternalEntries || contract.MaxFactsPerEntry != maxExternalFacts || !contract.ExplicitSelectionOnly || !contract.RequiresIndependentRoot {
		t.Fatalf("contract=%+v requirements=%+v", contract, requirements)
	}
}
