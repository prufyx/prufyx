// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const syntheticSupportReason = "ADDON_KUBERNETES_SUPPORT_RANGE"

// syntheticSupportRule is a support-range rule on the synthetic Kubernetes
// pair that requires the proposed Kubernetes version to be at least minimum.
func syntheticSupportRule(id, minimum string) string {
	rule := syntheticKubernetesRule(id, "require_component_version", syntheticSupportReason, "move to a release line whose documented support range includes the target", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"`+minimum+`"},"severity":"unsupported"`, "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z")
	return rule
}

func syntheticSupportEntry(id, minimum string) Entry {
	return Entry{Project: "kubernetes", Description: "Synthetic test-only support range.", RequiredFacts: []Fact{}, Rule: json.RawMessage(syntheticSupportRule(id, minimum))}
}

func TestPackSeverityLevel(t *testing.T) {
	entry := syntheticSupportEntry("kubernetes.synthetic-support.1-35-0-to-1-36-0", "1.37.0")
	b, err := assembleSynthetic(syntheticPack(t, packSchemaSeverity, nil, entry), nil)
	if err != nil {
		t.Fatalf("support-range pack under the severity schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, "prufyx.io/cncf-source-rule-pack/v1alpha9"} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("support-range pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSeverity, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("severity schema without a severity rule accepted")
	}
	// A severity on another operator is refused by the engine.
	wrong := entry
	wrong.Rule = json.RawMessage(strings.Replace(string(entry.Rule), `"operator":"require_component_version"`, `"operator":"forbid_target_version"`, 1))
	wrong.Rule = json.RawMessage(strings.Replace(string(wrong.Rule), `"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"1.37.0"},`, "", 1))
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSeverity, nil, wrong), nil); err == nil {
		t.Fatal("severity on forbid_target_version accepted")
	}
	// The generic selector picks the support-range rule as a verdict rule:
	// the pair is reviewed, the claim is UNSUPPORTED and the check exits 11.
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
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
	claims := report.Check.Claims
	if len(claims) != 1 || claims[0].Status != constraintengine.StatusUnsupported || claims[0].ReasonCode != syntheticSupportReason || report.Check.EngineContractDigest != constraintengine.EngineContractDigestSeverity() || ClaimExit(report) != 11 {
		t.Fatalf("claims=%+v exit=%d", claims, ClaimExit(report))
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestClaimExitUnsupported(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	const reviewed, until = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	pass := syntheticKubernetesRule("kubernetes.synthetic-a-pass", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"1.36.0"}`, reviewed, until)
	blocked := syntheticKubernetesRule("kubernetes.synthetic-b-blocked", "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "", reviewed, until)
	unsupported := syntheticSupportRule("kubernetes.synthetic-c-unsupported", "1.37.0")
	supported := syntheticSupportRule("kubernetes.synthetic-d-supported", "1.36.0")
	notice := syntheticNoticeRule("kubernetes.synthetic-e-notice", reviewed, until)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
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
		{"pass", []string{pass}, 0},
		{"pass and a supported combination", []string{pass, supported}, 0},
		{"pass and UNSUPPORTED", []string{pass, unsupported}, 11},
		{"only UNSUPPORTED", []string{unsupported}, 11},
		{"UNSUPPORTED and a notice", []string{unsupported, notice}, 11},
		{"blocker and UNSUPPORTED", []string{blocked, unsupported}, 10},
		{"pass, blocker and UNSUPPORTED", []string{pass, blocked, unsupported}, 10},
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

// TestExternalPackRefusesSeverity: the external knowledge target does not
// accept support-range rules yet, even under the severity pack schema.
func TestExternalPackRefusesSeverity(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	entry := containerdBasisEntry("containerd.synthetic-support", "", "")
	entry.Rule = json.RawMessage(strings.NewReplacer(
		`"operator":"forbid_target_version"`, `"operator":"require_component_version"`,
		`"subject":{"component":"`+containerdComponent+`","from":"1.7.28","to":"2.0.0"}`, `"subject":{"component":"`+containerdComponent+`","from":"1.7.28","to":"2.0.0"},"dependency":{"side":"proposed","component":"`+containerdComponent+`","comparison":"gte","version":"2.1.0"},"severity":"unsupported"`,
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT"`, `"reasonCode":"`+syntheticSupportReason+`"`,
	).Replace(string(entry.Rule)))
	pack := base.pack
	pack.Entries = []Entry{entry}
	pack.Schema = packSchemaSeverity
	if err := validateExternalPack(base, pack, pack.Revision); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("external support-range pack accepted: %v", err)
	}
	// The same rule without the severity is admitted (control).
	plain := entry
	plain.Rule = json.RawMessage(strings.Replace(string(entry.Rule), `,"severity":"unsupported"`, "", 1))
	pack.Entries, pack.Schema = []Entry{plain}, packSchema
	if err := validateExternalPack(base, pack, pack.Revision); err != nil {
		t.Fatalf("external pack without severity refused: %v", err)
	}
}
