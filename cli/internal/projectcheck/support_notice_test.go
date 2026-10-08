// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/packparity"
)

// These tests use synthetic support-range and one-way notice rules on the
// community pack's Grafana identity. They are built from the shipped pack and
// registry bytes in memory and are never published; the shipped pack holds
// neither kind.

const (
	grafanaComponent   = "pkg:github/grafana/grafana"
	k8sComponent       = "pkg:github/kubernetes/kubernetes"
	syntheticFrom      = "11.0.0"
	syntheticTo        = "11.1.0"
	syntheticFactID    = "component.grafana.legacy_alerting_explicitly_enabled"
	syntheticReviewed  = "2026-09-20T00:00:00Z"
	syntheticUntil     = "2026-12-19T00:00:00Z"
	syntheticSupportRC = "ADDON_KUBERNETES_SUPPORT_RANGE"
)

func syntheticRule(id, operator, reason, nextAction, extra string) string {
	return `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"` + grafanaComponent + `","from":"` + syntheticFrom + `","to":"` + syntheticTo + `"}` + extra + `,` +
		`"evidence":{"state":"active","reviewedAt":"` + syntheticReviewed + `","validUntil":"` + syntheticUntil + `","sources":[{"id":"synthetic-source","url":"https://github.com/grafana/grafana/blob/` + strings.Repeat("a", 40) + `/CHANGELOG.md","revision":"` + strings.Repeat("a", 40) + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"` + reason + `","nextAction":"` + nextAction + `"}`
}

func syntheticFactEntry(rule string) entry {
	return entry{Project: "grafana", Description: "Synthetic test-only verdict rule.", RequiredFacts: []fact{{Side: "proposed", ID: syntheticFactID, Component: grafanaComponent, Type: constraintengine.FactBool, Description: "Synthetic declared fact."}}, Rule: json.RawMessage(rule)}
}

// syntheticEntry is the concrete rule of one abstract parity kind.
func syntheticEntry(index int, kind packparity.Kind) entry {
	id := fmt.Sprintf("grafana.synthetic-%02d-%s", index, kind)
	switch kind {
	case packparity.Pass:
		return syntheticFactEntry(syntheticRule(id, "forbid_predicate_value", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed setting", `,"condition":{"side":"proposed","component":"`+grafanaComponent+`","factId":"`+syntheticFactID+`","boolValue":true}`))
	case packparity.Blocked:
		return syntheticFactEntry(syntheticRule(id, "forbid_predicate_value", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", `,"condition":{"side":"proposed","component":"`+grafanaComponent+`","factId":"`+syntheticFactID+`","boolValue":false}`))
	case packparity.Unsupported:
		return supportEntry(id, "1.38.0")
	case packparity.Supported:
		return supportEntry(id, "1.37.0")
	}
	return noticeEntry(id)
}

func supportEntry(id, minimum string) entry {
	rule := syntheticRule(id, "require_component_version", syntheticSupportRC, "move to a release line whose documented support range includes the target", `,"dependency":{"side":"proposed","component":"`+k8sComponent+`","comparison":"gte","version":"`+minimum+`"},"severity":"unsupported"`)
	return entry{Project: "grafana", Description: "Synthetic test-only support range.", RequiredFacts: []fact{}, Rule: json.RawMessage(rule)}
}

func noticeEntry(id string) entry {
	rule := syntheticRule(id, constraintengine.OperatorNoticeOneWay, constraintengine.ReasonOneWayTransition, "take a database backup and verify that it restores before upgrading", "")
	return entry{Project: "grafana", Description: "Synthetic test-only one-way transition.", RequiredFacts: []fact{}, Rule: json.RawMessage(rule)}
}

func syntheticInput() []byte {
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
		`"current":{"components":[{"component":"` + grafanaComponent + `","version":"` + syntheticFrom + `","facts":[]},{"component":"` + k8sComponent + `","version":"1.37.0","facts":[]}]},` +
		`"proposed":{"components":[{"component":"` + grafanaComponent + `","version":"` + syntheticTo + `","facts":[{"id":"` + syntheticFactID + `","state":"declared","boolValue":false}]},{"component":"` + k8sComponent + `","version":"1.37.0","facts":[]}]}}`)
}

func entryRuleID(t *testing.T, e entry) string {
	t.Helper()
	var shape struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(e.Rule, &shape); err != nil {
		t.Fatal(err)
	}
	return shape.ID
}

// syntheticPackBytes adds entries to the shipped pack under schema (empty
// keeps the shipped one) and returns the registry and pack bytes.
func syntheticPackBytes(t *testing.T, schema string, extra ...entry) ([]byte, []byte) {
	t.Helper()
	registry, err := packaged.ReadFile("data/projects.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packaged.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack packDocument
	if err := strict(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Entries = append(pack.Entries, extra...)
	sort.SliceStable(pack.Entries, func(i, j int) bool {
		if pack.Entries[i].Project != pack.Entries[j].Project {
			return pack.Entries[i].Project < pack.Entries[j].Project
		}
		return entryRuleID(t, pack.Entries[i]) < entryRuleID(t, pack.Entries[j])
	})
	if schema != "" {
		pack.Schema = schema
	}
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return registry, encoded
}

func syntheticBundle(t *testing.T, schema string, extra ...entry) (bundle, error) {
	t.Helper()
	registry, pack := syntheticPackBytes(t, schema, extra...)
	return loadRaw(registry, pack, definitions())
}

// TestCommunityPackNoticeLevel: a pack holding a one-way notice carries the
// notice schema, and only that one (or the severity one, which admits it).
func TestCommunityPackNoticeLevel(t *testing.T) {
	notice := noticeEntry("grafana.synthetic-notice")
	if _, err := syntheticBundle(t, packSchemaNotice, notice); err != nil {
		t.Fatalf("notice pack under the notice schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSeverity} {
		if _, err := syntheticBundle(t, schema, notice); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("notice pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := syntheticBundle(t, packSchemaNotice); !errors.Is(err, ErrIntegrity) {
		t.Fatal("notice schema without a notice rule accepted")
	}
	// Another reason code is refused by the engine.
	wrong := notice
	wrong.Rule = json.RawMessage(strings.Replace(string(notice.Rule), constraintengine.ReasonOneWayTransition, "REVIEWED_SOURCE_CONSTRAINT", 1))
	if _, err := syntheticBundle(t, packSchemaNotice, wrong); err == nil {
		t.Fatal("notice with another reason code accepted")
	}
	// A notice has no condition of its own.
	withCondition := notice
	withCondition.Rule = json.RawMessage(strings.Replace(string(notice.Rule), `"evidence"`, `"condition":{"side":"proposed","component":"`+grafanaComponent+`","factId":"`+syntheticFactID+`","boolValue":true},"evidence"`, 1))
	if _, err := syntheticBundle(t, packSchemaNotice, withCondition); err == nil {
		t.Fatal("notice with a condition accepted")
	}
}

// TestCommunityPackSeverityLevel: a pack holding a support-range rule carries
// the severity schema and no other.
func TestCommunityPackSeverityLevel(t *testing.T) {
	support := supportEntry("grafana.synthetic-support", "1.38.0")
	if _, err := syntheticBundle(t, packSchemaSeverity, support); err != nil {
		t.Fatalf("support-range pack under the severity schema refused: %v", err)
	}
	// The severity schema also admits notices.
	if _, err := syntheticBundle(t, packSchemaSeverity, support, noticeEntry("grafana.synthetic-notice")); err != nil {
		t.Fatalf("support-range and notice pack refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaNotice} {
		if _, err := syntheticBundle(t, schema, support); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("support-range pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := syntheticBundle(t, packSchemaSeverity); !errors.Is(err, ErrIntegrity) {
		t.Fatal("severity schema without a severity rule accepted")
	}
	// A require_component_version rule without the severity is a blocking
	// version rule, which this pack does not admit.
	plain := support
	plain.Rule = json.RawMessage(strings.Replace(string(support.Rule), `,"severity":"unsupported"`, "", 1))
	if _, err := syntheticBundle(t, packSchema, plain); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("plain require_component_version accepted: %v", err)
	}
	// A severity on a forbid rule is refused (here and by the engine).
	onForbid := syntheticEntry(1, packparity.Blocked)
	onForbid.Rule = json.RawMessage(strings.Replace(string(onForbid.Rule), `"evidence"`, `"severity":"unsupported","evidence"`, 1))
	if _, err := syntheticBundle(t, packSchemaSeverity, onForbid); err == nil {
		t.Fatal("severity on forbid_predicate_value accepted")
	}
	// An engine-issued reason code is refused for a support-range rule.
	reserved := support
	reserved.Rule = json.RawMessage(strings.Replace(string(support.Rule), syntheticSupportRC, "RULE_EVIDENCE_STALE", 1))
	if _, err := syntheticBundle(t, packSchemaSeverity, reserved); err == nil {
		t.Fatal("support-range rule with an engine reason code accepted")
	}
	// Consensus and lead rules stay refused by every community schema.
	for _, basis := range []string{constraintengine.BasisConsensus, constraintengine.BasisLead} {
		other := support
		other.Rule = json.RawMessage(strings.Replace(string(support.Rule), `"evidence":{`, `"evidence":{"basis":"`+basis+`",`, 1))
		if _, err := syntheticBundle(t, packSchemaSeverity, other); err == nil {
			t.Fatalf("%s rule accepted", basis)
		}
	}
}

// TestCommunityShippedPackKeepsItsSchema: the shipped pack holds neither
// kind, so its schema and bytes are unchanged and it still loads.
func TestCommunityShippedPackKeepsItsSchema(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if b.pack.Schema != packSchema {
		t.Fatalf("shipped schema=%s", b.pack.Schema)
	}
	// The older levels still load exactly as before.
	registry, pack := syntheticPackBytes(t, "")
	if _, err := loadRaw(registry, pack, definitions()); err != nil {
		t.Fatalf("shipped pack refused: %v", err)
	}
}

// TestCommunityPackParityTable runs the table the CNCF pack is tested
// against (see cncfcheck's parity test) through the community-project pack.
func TestCommunityPackParityTable(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range packparity.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			entries := make([]entry, 0, len(tc.Rules))
			schema := packSchema
			for index, kind := range tc.Rules {
				entries = append(entries, syntheticEntry(index, kind))
				switch {
				case kind == packparity.Unsupported || kind == packparity.Supported:
					schema = packSchemaSeverity
				case kind == packparity.Notice && schema != packSchemaSeverity:
					schema = packSchemaNotice
				}
			}
			b, err := syntheticBundle(t, schema, entries...)
			if err != nil {
				t.Fatal(err)
			}
			report, err := checkWithBundle(b, "grafana", syntheticInput(), now)
			if err != nil {
				t.Fatal(err)
			}
			claims := make([]packparity.Claim, 0, len(report.Check.Claims))
			for _, claim := range report.Check.Claims {
				claims = append(claims, packparity.Claim{Status: claim.Status, Notice: claim.IsVerdictNeutral()})
			}
			verdicts, notices := packparity.Statuses(claims)
			if got := ClaimExit(report); got != tc.Exit || fmt.Sprint(verdicts) != fmt.Sprint(tc.Verdicts) || notices != tc.Notices {
				t.Fatalf("exit=%d verdicts=%v notices=%d, want exit=%d verdicts=%v notices=%d", got, verdicts, notices, tc.Exit, tc.Verdicts, tc.Notices)
			}
			if _, err := MarshalReport(report); err != nil {
				t.Fatalf("report not publishable: %v", err)
			}
			if report.Assessment != "UNKNOWN" {
				t.Fatalf("assessment=%s", report.Assessment)
			}
		})
	}
}

// TestCommunityUnsupportedClaimCarriesItsOwnReason: the UNSUPPORTED claim has
// the rule's reason code and next action, is never BLOCKED or PASS, and a
// missing dependency stays UNKNOWN (fail closed).
func TestCommunityUnsupportedClaimCarriesItsOwnReason(t *testing.T) {
	support := supportEntry("grafana.synthetic-support", "1.38.0")
	b, err := syntheticBundle(t, packSchemaSeverity, support)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	report, err := checkWithBundle(b, "grafana", syntheticInput(), now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, claim := range report.Check.Claims {
		if claim.RuleID == "grafana.synthetic-support" {
			found = true
			if claim.Status != constraintengine.StatusUnsupported || claim.ReasonCode != syntheticSupportRC || claim.Severity != constraintengine.SeverityUnsupported {
				t.Fatalf("claim=%+v", claim)
			}
		}
	}
	if !found || report.Check.EngineContractDigest != constraintengine.EngineContractDigestSeverity() || ClaimExit(report) != 11 {
		t.Fatalf("found=%v digest=%s exit=%d", found, report.Check.EngineContractDigest, ClaimExit(report))
	}
	// No Kubernetes version is declared: the dependency is missing, the claim
	// is UNKNOWN, never UNSUPPORTED and never PASS.
	noDependency := []byte(strings.NewReplacer(`,{"component":"`+k8sComponent+`","version":"1.37.0","facts":[]}`, "").Replace(string(syntheticInput())))
	report, err = checkWithBundle(b, "grafana", noDependency, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range report.Check.Claims {
		if claim.RuleID == "grafana.synthetic-support" && claim.Status != "UNKNOWN" {
			t.Fatalf("missing dependency gave %s", claim.Status)
		}
	}
	if ClaimExit(report) != 11 {
		t.Fatalf("exit=%d", ClaimExit(report))
	}
}

// TestCommunityNoticeWordingAndScope: the notice claim is informational and
// its lines never word the upgrade as safe.
func TestCommunityNoticeWordingAndScope(t *testing.T) {
	b, err := syntheticBundle(t, packSchemaNotice, noticeEntry("grafana.synthetic-notice"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := checkWithBundle(b, "grafana", syntheticInput(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range report.Check.Claims {
		if claim.RuleID != "grafana.synthetic-notice" {
			continue
		}
		lines, ok := claim.NoticeLines()
		if !ok || len(lines) != 2 || !strings.HasPrefix(lines[0], "cannot be rolled back: ") || !strings.HasPrefix(lines[1], "before you upgrade: ") {
			t.Fatalf("lines=%q ok=%v", lines, ok)
		}
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "safe") {
				t.Fatalf("line %q words the upgrade as safe", line)
			}
		}
		if ClaimExit(report) != 11 {
			t.Fatalf("a notice-only report exits %d", ClaimExit(report))
		}
		return
	}
	t.Fatal("notice claim missing")
}

// TestScopeAssessmentNeverPassesOnSupportRangeOrNotice: over the attested
// corpus, an applicable support-range rule whose dependency the scope cannot
// declare (a scope names only compiled project identities) leaves the
// aggregate UNKNOWN, and a component whose only rules are notices has no
// evaluated rule: neither reaches SCOPE_COMPLETE_PASS. The sealed report
// passes the engine's own publication gate.
func TestScopeAssessmentNeverPassesOnSupportRangeOrNotice(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	input := scopeInput(t, []string{grafanaComponent}, map[string][2]string{grafanaComponent: {syntheticFrom, syntheticTo}}, map[string][]declaredFact{grafanaComponent: {{id: syntheticFactID, value: false}}})
	for name, tc := range map[string]struct {
		schema  string
		entries []entry
	}{
		"support range":         {packSchemaSeverity, []entry{supportEntry("grafana.synthetic-support", "1.38.0")}},
		"support range, met":    {packSchemaSeverity, []entry{supportEntry("grafana.synthetic-support", "1.37.0")}},
		"notice only":           {packSchemaNotice, []entry{noticeEntry("grafana.synthetic-notice")}},
		"support range, notice": {packSchemaSeverity, []entry{supportEntry("grafana.synthetic-support", "1.38.0"), noticeEntry("grafana.synthetic-notice")}},
	} {
		t.Run(name, func(t *testing.T) {
			registry, pack := syntheticPackBytes(t, tc.schema, tc.entries...)
			b, err := loadRaw(registry, pack, definitions())
			if err != nil {
				t.Fatal(err)
			}
			attestation, err := BuildAttestationFromFiles(registry, pack)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(attestation)
			if err != nil {
				t.Fatal(err)
			}
			report, err := assessScopeWith(b, raw, input, now)
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment == constraintengine.AssessmentScopeCompletePass || report.Assessment == "SAFE" {
				t.Fatalf("assessment=%s scope=%+v", report.Assessment, report.Check.ScopeCompleteness)
			}
			if _, err := MarshalScopeReport(report); err != nil {
				t.Fatalf("scope report not publishable: %v", err)
			}
		})
	}
}
