// SPDX-License-Identifier: AGPL-3.0-only

package certmanagervalues

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExternalActiveRuleMatchesEmbeddedPredicate(t *testing.T) {
	bundle := parseExternalFixture(t, externalFixture(t, "1", "active", true))
	now := mustExternalTime(t, "2026-09-08T12:00:00Z")
	tests := []string{
		`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`,
		`{"prometheus":{"servicemonitor":{"enabled":true}}}`,
		`{"prometheus":{"podmonitor":null}}`,
	}
	for _, raw := range tests {
		t.Run(fmt.Sprintf("values-%x", sha256.Sum256([]byte(raw))), func(t *testing.T) {
			embeddedArtifact := parse(t, raw)
			embedded, err := Evaluate(requestFor(embeddedArtifact))
			if err != nil {
				t.Fatal(err)
			}
			externalArtifact, err := ParseExternalArtifact([]byte(raw), "", bundle)
			if err != nil {
				t.Fatal(err)
			}
			external, err := EvaluateExternalProjection(ExternalRequest{Values: externalArtifact, From: CurrentVersion, To: TargetVersion}, bundle, now)
			if err != nil {
				t.Fatal(err)
			}
			externalTransition := external.Transition
			embeddedTransition := embedded.Transition
			externalTransition.IdentityAssumption = ""
			embeddedTransition.IdentityAssumption = ""
			if external.Claim != embedded.Claim || externalTransition != embeddedTransition || external.Question != embedded.Question || external.Scope != embedded.Scope || !equalStrings(external.MatchedPaths, embedded.MatchedPaths) {
				t.Fatalf("external predicate drift\nexternal=%#v\nembedded=%#v", external, embedded)
			}
			if external.Purpose != "synthetic_test_only" || external.EvidenceFreshness != "current" || external.RuleDigest == "" || external.BundleDigest == "" || external.EngineCapabilityDigest != ExternalEngineCapabilityDigest || !strings.Contains(external.Transition.IdentityAssumption, "projection") {
				t.Fatalf("external binding=%#v", external)
			}
		})
	}
}

func TestExternalCompleteZeroRuleBundleIsUnknownWithoutFallback(t *testing.T) {
	bundle := parseExternalFixture(t, externalFixture(t, "2", "active", false))
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Revision != "2" || admission.RuleID != "" || admission.RuleDigest != "" || admission.EvidenceExpiresAt != "" {
		t.Fatalf("admission=%#v", admission)
	}
	artifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/private"}}}`), "", bundle)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := EvaluateExternalProjection(ExternalRequest{Values: artifact, From: CurrentVersion, To: TargetVersion}, bundle, mustExternalTime(t, "2026-09-08T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Claim.Status != "UNKNOWN" || projection.Claim.ReasonCode != "CERT_MANAGER_KNOWLEDGE_RULE_MISSING" || projection.EvidenceFreshness != "missing" || len(projection.MatchedPaths) != 0 || len(projection.Sources) != 0 || projection.RuleDigest != "" {
		t.Fatalf("projection=%#v", projection)
	}
}

func TestExternalRevisionAddsReviewedRuleWithoutChangingEngine(t *testing.T) {
	empty := parseExternalFixture(t, externalFixture(t, "1", "active", false))
	active := parseExternalFixture(t, externalFixture(t, "2", "active", true))
	raw := []byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`)
	emptyArtifact, err := ParseExternalArtifact(raw, "", empty)
	if err != nil {
		t.Fatal(err)
	}
	activeArtifact, err := ParseExternalArtifact(raw, "", active)
	if err != nil {
		t.Fatal(err)
	}
	now := mustExternalTime(t, "2026-09-08T12:00:00Z")
	withoutCoverage, err := EvaluateExternalProjection(ExternalRequest{Values: emptyArtifact, From: CurrentVersion, To: TargetVersion}, empty, now)
	if err != nil {
		t.Fatal(err)
	}
	withCoverage, err := EvaluateExternalProjection(ExternalRequest{Values: activeArtifact, From: CurrentVersion, To: TargetVersion}, active, now)
	if err != nil {
		t.Fatal(err)
	}
	if withoutCoverage.Claim.Status != "UNKNOWN" || withoutCoverage.Claim.ReasonCode != "CERT_MANAGER_KNOWLEDGE_RULE_MISSING" || withCoverage.Claim.Status != "BLOCKED" || withCoverage.Claim.ReasonCode != "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT" {
		t.Fatalf("revision outcomes: empty=%#v active=%#v", withoutCoverage.Claim, withCoverage.Claim)
	}
	if withoutCoverage.EngineCapabilityDigest != withCoverage.EngineCapabilityDigest || withoutCoverage.Revision == withCoverage.Revision || withoutCoverage.BundleDigest == withCoverage.BundleDigest {
		t.Fatalf("revision identity: empty=%#v active=%#v", withoutCoverage, withCoverage)
	}
}

func TestExternalEvidenceFreshnessAndVisibleSyntheticWithdrawal(t *testing.T) {
	active := parseExternalFixture(t, externalFixture(t, "3", "active", true))
	withdrawn := parseExternalFixture(t, externalFixture(t, "4", "withdrawn", true))
	activeArtifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), "", active)
	if err != nil {
		t.Fatal(err)
	}
	withdrawnArtifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), "", withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	current, err := EvaluateExternalProjection(ExternalRequest{Values: activeArtifact, From: CurrentVersion, To: TargetVersion}, active, mustExternalTime(t, "2026-09-08T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := EvaluateExternalProjection(ExternalRequest{Values: activeArtifact, From: CurrentVersion, To: TargetVersion}, active, mustExternalTime(t, "2026-10-01T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	clockBeforeReview, err := EvaluateExternalProjection(ExternalRequest{Values: activeArtifact, From: CurrentVersion, To: TargetVersion}, active, mustExternalTime(t, "2026-08-31T23:59:59Z"))
	if err != nil {
		t.Fatal(err)
	}
	withdrawnResult, err := EvaluateExternalProjection(ExternalRequest{Values: withdrawnArtifact, From: CurrentVersion, To: TargetVersion}, withdrawn, mustExternalTime(t, "2026-09-08T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Claim.Status != "BLOCKED" || current.EvidenceFreshness != "current" {
		t.Fatalf("current=%#v", current)
	}
	if stale.Claim.ReasonCode != "CERT_MANAGER_KNOWLEDGE_EVIDENCE_STALE" || stale.EvidenceFreshness != "stale" {
		t.Fatalf("stale=%#v", stale)
	}
	if clockBeforeReview.Claim.ReasonCode != "CERT_MANAGER_KNOWLEDGE_TIME_UNVERIFIED" || clockBeforeReview.EvidenceFreshness != "clock_before_review" {
		t.Fatalf("clock-before-review=%#v", clockBeforeReview)
	}
	if withdrawnResult.Claim.ReasonCode != "CERT_MANAGER_KNOWLEDGE_EVIDENCE_WITHDRAWN" || withdrawnResult.EvidenceFreshness != "withdrawn" || withdrawnResult.Purpose != "synthetic_test_only" {
		t.Fatalf("withdrawn=%#v", withdrawnResult)
	}
}

func TestExternalArtifactCannotCrossBundleOrRule(t *testing.T) {
	first := parseExternalFixture(t, externalFixture(t, "5", "active", true))
	secondDocument := fixtureDocument("6", "active", true)
	secondDocument.Rules[0].RemovedPaths = []string{"prometheus.podmonitor.path"}
	second := parseExternalFixture(t, marshalFixture(t, secondDocument))
	artifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), "", first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateExternalProjection(ExternalRequest{Values: artifact, From: CurrentVersion, To: TargetVersion}, second, mustExternalTime(t, "2026-09-08T12:00:00Z")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("cross-bundle evaluation=%v", err)
	}
	secondArtifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), "", second)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := EvaluateExternalProjection(ExternalRequest{Values: secondArtifact, From: CurrentVersion, To: TargetVersion}, second, mustExternalTime(t, "2026-09-08T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Claim.Status != "PASS" || len(projection.MatchedPaths) != 0 {
		t.Fatalf("selected-rule projection=%#v", projection)
	}
}

func TestReadExternalArtifactRetainsPrivateFileContract(t *testing.T) {
	bundle := parseExternalFixture(t, externalFixture(t, "13", "active", true))
	path := t.TempDir() + "/values.json"
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExternalArtifact(path, "", bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExternalArtifact(path, "", bundle); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public external values=%v", err)
	}
}

func TestExternalReplacementFactsAreRuleBoundAndSanitized(t *testing.T) {
	document := fixtureDocument("7", "active", true)
	document.Rules[0].ReplacementFacts = externalReplacementFactsDocument{MetricsPath: "/new-metrics", MetricsPortName: "metrics-v2"}
	bundle := parseExternalFixture(t, marshalFixture(t, document))
	artifact, err := ParseExternalArtifact([]byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), "", bundle)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := EvaluateExternalProjection(ExternalRequest{Values: artifact, From: CurrentVersion, To: TargetVersion}, bundle, mustExternalTime(t, "2026-09-08T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(projection.Claim.Remediation, "/new-metrics and metrics-v2") || projection.ReplacementMetricsPath != "/new-metrics" || projection.ReplacementMetricsPortName != "metrics-v2" {
		t.Fatalf("replacement facts=%#v", projection)
	}

	bad := fixtureDocument("8", "active", true)
	bad.Rules[0].ReplacementFacts.MetricsPath = "/ok\nprivate"
	if _, err := ParseExternalBundle(marshalFixture(t, bad)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("control-bearing replacement=%v", err)
	}
}

func TestExternalParserRejectsNonCanonicalOrIncompleteData(t *testing.T) {
	valid := externalFixture(t, "9", "active", true)
	tests := map[string][]byte{
		"duplicate":     bytes.Replace(valid, []byte(`"revision":"9"`), []byte(`"revision":"9","revision":"10"`), 1),
		"trailing":      append(append([]byte(nil), valid...), []byte(` {}`)...),
		"unknown-field": bytes.Replace(valid, []byte(`"purpose":"synthetic_test_only"`), []byte(`"purpose":"synthetic_test_only","extra":true`), 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExternalBundle(raw); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}

	mutations := map[string]func(*externalBundleDocument){
		"zero-revision":      func(document *externalBundleDocument) { document.Revision = "0" },
		"overflow-revision":  func(document *externalBundleDocument) { document.Revision = "2147483648" },
		"unknown-purpose":    func(document *externalBundleDocument) { document.Purpose = "official" },
		"unknown-capability": func(document *externalBundleDocument) { document.RequiredCapabilities[0].ID = "unknown/v1" },
		"empty-paths":        func(document *externalBundleDocument) { document.Rules[0].RemovedPaths = []string{} },
		"duplicate-path": func(document *externalBundleDocument) {
			document.Rules[0].RemovedPaths = []string{removedPaths[0], removedPaths[0]}
		},
		"unknown-path": func(document *externalBundleDocument) {
			document.Rules[0].RemovedPaths = []string{"private.registry.path"}
		},
		"mutable-source-url": func(document *externalBundleDocument) {
			document.Rules[0].Sources[0].URL = "https://example.invalid/main/source.json"
		},
		"query-source-url": func(document *externalBundleDocument) { document.Rules[0].Sources[0].URL += "?secret=value" },
		"unknown-license":  func(document *externalBundleDocument) { document.Rules[0].Sources[0].LicensingDisposition = "unknown" },
		"partial-rule":     func(document *externalBundleDocument) { document.Rules[0].Target = externalChartDocument{} },
		"active-withdrawal": func(document *externalBundleDocument) {
			document.Rules[0].Evidence.Withdrawal = &externalWithdrawalDocument{ReasonCode: "SYNTHETIC_WITHDRAWAL", SourceID: "current-values-schema"}
		},
		"withdrawn-without-record": func(document *externalBundleDocument) {
			document.Rules[0].Evidence.State = "withdrawn"
			document.Rules[0].Evidence.Withdrawal = nil
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			document := fixtureDocument("10", "active", true)
			mutate(&document)
			if _, err := ParseExternalBundle(marshalFixture(t, document)); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := ParseExternalBundle(bytes.Repeat([]byte{' '}, maxExternalBundleBytes+1)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("oversize=%v", err)
	}
}

func TestExternalParserRequiresExactRecursiveFieldNamesAndArrays(t *testing.T) {
	active := externalFixture(t, "11", "active", true)
	withdrawn := externalFixture(t, "12", "withdrawn", true)
	aliases := map[string][]byte{
		"top":                bytes.Replace(active, []byte(`"schema":`), []byte(`"Schema":`), 1),
		"semantic-duplicate": bytes.Replace(active, []byte(`"schema":"`+ExternalBundleSchema+`"`), []byte(`"schema":"`+ExternalBundleSchema+`","Schema":"`+ExternalBundleSchema+`"`), 1),
		"capability":         bytes.Replace(active, []byte(`"requiredCapabilities":[{"id":`), []byte(`"requiredCapabilities":[{"ID":`), 1),
		"rule":               bytes.Replace(active, []byte(`"rules":[{"id":`), []byte(`"rules":[{"ID":`), 1),
		"current":            bytes.Replace(active, []byte(`"current":{"version":`), []byte(`"current":{"Version":`), 1),
		"target":             bytes.Replace(active, []byte(`"target":{"version":`), []byte(`"target":{"Version":`), 1),
		"replacement":        bytes.Replace(active, []byte(`"replacementFacts":{"metricsPath":`), []byte(`"replacementFacts":{"MetricsPath":`), 1),
		"source":             bytes.Replace(active, []byte(`"sources":[{"id":`), []byte(`"sources":[{"ID":`), 1),
		"evidence":           bytes.Replace(active, []byte(`"evidence":{"state":`), []byte(`"evidence":{"State":`), 1),
		"withdrawal":         bytes.Replace(withdrawn, []byte(`"withdrawal":{"reasonCode":`), []byte(`"withdrawal":{"ReasonCode":`), 1),
	}
	for name, raw := range aliases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, active) || bytes.Equal(raw, withdrawn) {
				t.Fatal("test replacement did not apply")
			}
			if _, err := ParseExternalBundle(raw); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted alias: %v", err)
			}
		})
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(active, &top); err != nil {
		t.Fatal(err)
	}
	delete(top, "rules")
	missingRules, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	top["rules"] = json.RawMessage("null")
	nullRules, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"missing-rules": missingRules, "null-rules": nullRules} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExternalBundle(raw); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted required array omission: %v", err)
			}
		})
	}
}

func TestExternalChangesPreserveAlpha4EmbeddedReportBytes(t *testing.T) {
	report, err := Evaluate(requestFor(parse(t, `{"prometheus":{"servicemonitor":{"path":"/custom"}}}`)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	const alpha4SHA256 = "ecf46554608c5dca61e21b5f1aa411dbb52fb09d1081a947a01905a060b804a0"
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != alpha4SHA256 {
		t.Fatalf("embedded report digest=%s want=%s", got, alpha4SHA256)
	}
}

func externalFixture(t *testing.T, revision, state string, includeRule bool) []byte {
	t.Helper()
	return marshalFixture(t, fixtureDocument(revision, state, includeRule))
}

func fixtureDocument(revision, state string, includeRule bool) externalBundleDocument {
	document := externalBundleDocument{
		Schema:               ExternalBundleSchema,
		Revision:             revision,
		Purpose:              "synthetic_test_only",
		RequiredCapabilities: []externalCapabilityDocument{{ID: ExternalEngineCapabilityID, Digest: ExternalEngineCapabilityDigest}},
		Rules:                []externalRuleDocument{},
	}
	if !includeRule {
		return document
	}
	rule := externalRuleDocument{
		ID:               "cert-manager-1.20.3-to-1.21.1-removed-monitor-values",
		Operator:         ExternalEngineCapabilityID,
		Component:        externalComponent,
		Current:          externalChartDocument{Version: CurrentVersion, ChartManifestDigest: CurrentChartDigest},
		Target:           externalChartDocument{Version: TargetVersion, ChartManifestDigest: TargetChartDigest},
		RemovedPaths:     append([]string(nil), removedPaths...),
		ReplacementFacts: externalReplacementFactsDocument{MetricsPath: "/metrics", MetricsPortName: "http-metrics"},
		Sources: []externalSourceDocument{
			{ID: "current-values-schema", URL: "https://raw.githubusercontent.com/cert-manager/cert-manager/1e1d16d1744e6d9c80e464e58e8d9ab1caed222b/deploy/charts/cert-manager/values.schema.json", Revision: "1e1d16d1744e6d9c80e464e58e8d9ab1caed222b", ContentDigest: "sha256:df61ae0ad0d368c5ae4a7d85ed89ff472e2e3d2d8392c01456ab3539399d2731", LicensingDisposition: "reference-only"},
			{ID: "target-values-schema", URL: "https://raw.githubusercontent.com/cert-manager/cert-manager/24e33194fb39488eff2bbf10c6dc640f407cad44/deploy/charts/cert-manager/values.schema.json", Revision: "24e33194fb39488eff2bbf10c6dc640f407cad44", ContentDigest: "sha256:47730ad9154f6cde7a081de7541f88e085ff92a5e5fd65a41a3d0223ff735bea", LicensingDisposition: "reference-only"},
			{ID: "release-notes", URL: "https://raw.githubusercontent.com/cert-manager/website/979f40477c362194b7bc794bfaa837f5f435b823/content/docs/releases/release-notes/release-notes-1.21.md", Revision: "979f40477c362194b7bc794bfaa837f5f435b823", ContentDigest: "sha256:a0574f2f71e08aed3bd6348db51aa718d9ec6d54b3d0da13ac14372cc365606a", Spans: []string{"28-32", "211-213"}, LicensingDisposition: "reference-only"},
			{ID: "upgrade-guide", URL: "https://raw.githubusercontent.com/cert-manager/website/5ed032b0ba04a4ecc66849088633c6ead901ec6e/content/docs/releases/upgrading/upgrading-1.20-1.21.md", Revision: "5ed032b0ba04a4ecc66849088633c6ead901ec6e", ContentDigest: "sha256:fd8b2fb1b228ca8c926bcde9e9d63dabc2614b29cc8c76ce49547ed5b248736b", Spans: []string{"44-56"}, LicensingDisposition: "reference-only"},
		},
		Evidence: externalEvidenceDocument{State: state, ReviewedAt: "2026-09-01T00:00:00Z", ValidUntil: "2026-10-01T00:00:00Z", TestVectorDigest: "sha256:b38cb213fbb68dc7bbff5490f96e1cf3d5de0a1604713ecdfa1502e6d985f80a"},
	}
	if state == "withdrawn" {
		rule.Evidence.Withdrawal = &externalWithdrawalDocument{ReasonCode: "SYNTHETIC_WITHDRAWAL", SourceID: "release-notes"}
	}
	document.Rules = []externalRuleDocument{rule}
	return document
}

func marshalFixture(t *testing.T, document externalBundleDocument) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parseExternalFixture(t *testing.T, raw []byte) ExternalBundle {
	t.Helper()
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func mustExternalTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
