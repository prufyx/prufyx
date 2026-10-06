// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// These tests use synthetic one-way notice rules that are never published;
// the embedded pack carries none.

const (
	noticeComponent = "pkg:github/kubernetes/kubernetes"
	noticeRuleID    = "kubernetes.synthetic-one-way.1-36-0-to-1-37-0"
)

func syntheticKubernetesRule(id, operator, reason, nextAction, extra, reviewedAt, validUntil string) string {
	return `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"` + noticeComponent + `","from":"1.36.0","to":"1.37.0"}` + extra + `,` +
		`"evidence":{"state":"active","reviewedAt":"` + reviewedAt + `","validUntil":"` + validUntil + `","sources":[{"id":"synthetic-source","url":"https://github.com/kubernetes/kubernetes/blob/` + syntheticRevision + `/CHANGELOG.md","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"` + reason + `","nextAction":"` + nextAction + `"}`
}

func syntheticNoticeRule(id, reviewedAt, validUntil string) string {
	return syntheticKubernetesRule(id, constraintengine.OperatorNoticeOneWay, constraintengine.ReasonOneWayTransition, "take an etcd snapshot and verify that it restores before upgrading", "", reviewedAt, validUntil)
}

func syntheticNoticeEntry() Entry {
	return Entry{Project: "kubernetes", Description: "Synthetic test-only one-way transition.", RequiredFacts: []Fact{}, Rule: json.RawMessage(syntheticNoticeRule(noticeRuleID, "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"))}
}

func TestPackNoticeLevel(t *testing.T) {
	entry := syntheticNoticeEntry()
	b, err := assembleSynthetic(syntheticPack(t, packSchemaNotice, nil, entry), nil)
	if err != nil {
		t.Fatalf("notice pack under the notice schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, "prufyx.io/cncf-source-rule-pack/v1alpha5"} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("notice pack under %s accepted: %v", schema, err)
		}
	}
	// The notice schema is never used without a notice rule.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaNotice, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("notice schema without a notice rule accepted")
	}
	// A notice rule with another reason code is refused by the engine.
	wrong := entry
	wrong.Rule = json.RawMessage(strings.Replace(string(entry.Rule), constraintengine.ReasonOneWayTransition, "REVIEWED_SOURCE_CONSTRAINT", 1))
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaNotice, nil, wrong), nil); err == nil {
		t.Fatal("notice rule with another reason code accepted")
	}
	// The project's whole rule set now evaluates under the notice contract,
	// and the notice claim is NOTICE.
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	inputRaw := noticeInput()
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := b.rulesForAdmittedInput("kubernetes", inputRaw)
	if err != nil {
		t.Fatal(err)
	}
	report, err := b.report("kubernetes", "", false, input, rules, inputRaw, now)
	if err != nil {
		t.Fatal(err)
	}
	// No verdict rule reviews the pair, so every Kubernetes rule is reported
	// as not reviewed beside the one NOTICE claim.
	notices := report.Check.Claims[:0:0]
	for _, claim := range report.Check.Claims {
		if claim.IsNotice() {
			notices = append(notices, claim)
		}
	}
	if len(notices) != 1 || notices[0].Status != constraintengine.StatusNotice || len(report.Check.Claims) != 33 || report.Check.EngineContractDigest != constraintengine.EngineContractDigestNotice() || ClaimExit(report) != 11 {
		t.Fatalf("claims=%+v exit=%d", report.Check.Claims, ClaimExit(report))
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

func noticeInput() []byte {
	return []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"` + noticeComponent + `","version":"1.36.0","facts":[]}]},"proposed":{"components":[{"component":"` + noticeComponent + `","version":"1.37.0","facts":[]}]}}`)
}

func TestClaimExitNotice(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	const reviewed, until = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	pass := syntheticKubernetesRule("kubernetes.synthetic-a-pass", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"1.37.0"}`, reviewed, until)
	blocked := syntheticKubernetesRule("kubernetes.synthetic-b-blocked", "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "", reviewed, until)
	notice := syntheticNoticeRule("kubernetes.synthetic-c-notice", reviewed, until)
	staleNotice := syntheticNoticeRule("kubernetes.synthetic-d-notice-stale", "2026-06-01T00:00:00Z", "2026-08-30T00:00:00Z")
	notApplicable := strings.Replace(syntheticNoticeRule("kubernetes.synthetic-e-notice-other", reviewed, until), `"to":"1.37.0"`, `"to":"1.38.0"`, 1)
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	inputRaw := noticeInput()
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		rules []string
		exit  int
	}{
		{"all pass", []string{pass}, 0},
		{"all pass plus a notice", []string{pass, notice}, 0},
		{"all pass plus a stale notice", []string{pass, staleNotice}, 0},
		{"all pass plus a notice for another transition", []string{pass, notApplicable}, 0},
		{"only a notice", []string{notice}, 11},
		{"only notices, one stale", []string{notice, staleNotice}, 11},
		{"notice and a blocker", []string{blocked, notice}, 10},
		{"pass, blocker and notice", []string{pass, blocked, notice}, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]json.RawMessage, 0, len(tc.rules))
			for _, rule := range tc.rules {
				raw = append(raw, json.RawMessage(rule))
			}
			rules, err := b.parseRules(raw)
			if err != nil {
				t.Fatal(err)
			}
			report, err := b.report("kubernetes", "", false, input, rules, inputRaw, now)
			if err != nil {
				t.Fatal(err)
			}
			if got := ClaimExit(report); got != tc.exit {
				t.Fatalf("exit=%d want %d claims=%+v", got, tc.exit, report.Check.Claims)
			}
		})
	}
}

// verdictClaimsOf drops the notice claims of a report.
func verdictClaimsOf(claims []constraintengine.Claim) []constraintengine.Claim {
	var verdicts []constraintengine.Claim
	for _, claim := range claims {
		if !claim.IsNotice() {
			verdicts = append(verdicts, claim)
		}
	}
	return verdicts
}

// TestNoticeNeverChangesRuleSelection: a matching notice for a pair no
// verdict rule reviews keeps the fallback to every project rule, for the
// generic selector and for the fact-family selector, so the verdict claims are
// exactly those of the same report without the notice.
func TestNoticeNeverChangesRuleSelection(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	const pspFact = "component.kubernetes.psp_v1beta1_removed_gvk_present"
	family := []string{pspFact, "component.kubernetes.cronjob_v1beta1_removed_gvk_present"}
	guarded := syntheticNoticeEntry()
	guarded.Rule = json.RawMessage(strings.Replace(syntheticNoticeRule("kubernetes.synthetic-one-way-guarded.1-36-0-to-1-37-0", "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"), `,"evidence":`, `,"appliesWhen":[{"side":"proposed","component":"`+noticeComponent+`","factId":"`+pspFact+`","boolValue":true}],"evidence":`, 1))
	guarded.RequiredFacts = []Fact{{Side: "proposed", ID: pspFact, Component: noticeComponent, Type: constraintengine.FactBool, Description: "A removed PodSecurityPolicy v1beta1 object is present."}}
	withNotice, err := assembleSynthetic(syntheticPack(t, packSchemaNotice, nil, syntheticNoticeEntry(), guarded), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	inputRaw := noticeInput()
	evaluate := func(b bundle, familySelector bool) Report {
		t.Helper()
		input, err := constraintengine.ParseInput(inputRaw, b.registry)
		if err != nil {
			t.Fatal(err)
		}
		var rules constraintengine.RuleSet
		if familySelector {
			rules, err = b.factFamilyRuleSet("kubernetes", family, inputRaw)
		} else {
			rules, err = b.rulesForAdmittedInput("kubernetes", inputRaw)
		}
		if err != nil {
			t.Fatal(err)
		}
		report, err := b.report("kubernetes", "", familySelector, input, rules, inputRaw, now)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	for _, familySelector := range []bool{false, true} {
		without, with := evaluate(base, familySelector), evaluate(withNotice, familySelector)
		verdicts := verdictClaimsOf(with.Check.Claims)
		if len(verdicts) == 0 || !reflect.DeepEqual(verdicts, without.Check.Claims) {
			t.Fatalf("family=%v: verdict claims changed: %d -> %d", familySelector, len(without.Check.Claims), len(verdicts))
		}
		for _, claim := range verdicts {
			if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
				t.Fatalf("family=%v: claim %+v", familySelector, claim)
			}
		}
		if !familySelector && len(verdicts) != 32 {
			t.Fatalf("generic selection holds %d verdict claims, want the 32 Kubernetes rules", len(verdicts))
		}
		if len(with.Check.Claims) == len(verdicts) || ClaimExit(with) != ClaimExit(without) {
			t.Fatalf("family=%v: notices=%d exit %d vs %d", familySelector, len(with.Check.Claims)-len(verdicts), ClaimExit(with), ClaimExit(without))
		}
	}
}

// TestCorpusInventorySkipsNoticeOnlyComponents: the inventory an attestation
// is built from leaves out a component whose only rules are notices, so the
// generated attestation still binds.
func TestCorpusInventorySkipsNoticeOnlyComponents(t *testing.T) {
	const aeraki = "pkg:github/aeraki-mesh/aeraki"
	notice := Entry{Project: "aeraki-mesh", Description: "Synthetic test-only one-way transition.", RequiredFacts: []Fact{}, Rule: json.RawMessage(strings.Replace(syntheticNoticeRule("aeraki-mesh.synthetic-one-way.1-36-0-to-1-37-0", "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"), noticeComponent, aeraki, 1))}
	b, err := assembleSynthetic(syntheticPack(t, packSchemaNotice, nil, notice), nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range inventory.Components {
		if component == aeraki {
			t.Fatal("a notice-only component is in the corpus inventory")
		}
	}
	attestation, err := json.Marshal(Attestation{
		Schema: CorpusAttestationSchema, Attestation: constraintengine.CorpusAttestation,
		Revision: inventory.Revision, PackDigest: inventory.PackDigest, RuleSetDigest: inventory.RuleSetDigest,
		RuleCount: inventory.RuleCount, Components: inventory.Components, Limitations: AttestationLimitations(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.attestedRuleSet(attestation); err != nil {
		t.Fatalf("attestation over a pack with a notice-only component refused: %v", err)
	}
}

// TestExternalPackRefusesNotices: the external knowledge target does not
// accept one-way notices yet, even under the notice pack schema.
func TestExternalPackRefusesNotices(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	capability, err := ExternalCapabilityDigest()
	if err != nil {
		t.Fatal(err)
	}
	pack := base.pack
	pack.Revision, pack.Schema = "1", packSchemaNotice
	pack.Entries = []Entry{syntheticNoticeEntry()}
	if !validPackSchema(pack) {
		t.Fatal("fixture schema is not the notice level")
	}
	raw, err := json.Marshal(externalFixtureDocument{Schema: externalBundleSchema, Revision: "1", Purpose: "operator_provided", EngineCapabilityDigest: capability, Pack: pack})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(raw); err == nil {
		t.Fatal("external pack with a notice accepted")
	}
	if err := validateExternalPack(base, pack, "1"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack: %v", err)
	}
}
