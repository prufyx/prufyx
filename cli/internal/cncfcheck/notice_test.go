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
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
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
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != constraintengine.StatusNotice || report.Check.EngineContractDigest != constraintengine.EngineContractDigestNotice() || ClaimExit(report) != 11 {
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
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
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
