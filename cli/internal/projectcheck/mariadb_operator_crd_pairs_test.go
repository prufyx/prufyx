// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

const (
	mdbCRDPairResource = `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_CRD_PAIR"},"spec":%s}`
	mdbPairA           = "0.38.1->25.0.0"
	mdbPairB           = "25.8.4->25.10.4"
)

// mariaDBCRDRules lists every CRD-family rule with a spec fragment that sets
// exactly the field the rule is about.
var mariaDBCRDRules = []struct{ pair, ruleID, spec string }{
	{mdbPairA, "mariadb-operator.sync-binlog-retyped-integer.0-38-1-to-25-0-0", `{"replication":{"syncBinlog":true}}`},
	{mdbPairB, "mariadb-operator.removed-field-embedded-max-scale.25-8-4-to-25-10-4", `{"maxScale":{"enabled":true}}`},
	{mdbPairB, "mariadb-operator.removed-field-galera-primary-automatic-failover.25-8-4-to-25-10-4", `{"galera":{"primary":{"automaticFailover":true}}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-primary-automatic-failover-delay.25-8-4-to-25-10-4", `{"replication":{"primary":{"automaticFailoverDelay":"10s"}}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-primary-automatic-failover.25-8-4-to-25-10-4", `{"replication":{"primary":{"automaticFailover":true}}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-probes-enabled.25-8-4-to-25-10-4", `{"replication":{"probesEnabled":true}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-replica-connection-retries.25-8-4-to-25-10-4", `{"replication":{"replica":{"connectionRetries":5}}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-replica-connection-timeout.25-8-4-to-25-10-4", `{"replication":{"replica":{"connectionTimeout":"5s"}}}`},
	{mdbPairB, "mariadb-operator.removed-field-replication-replica-wait-point.25-8-4-to-25-10-4", `{"replication":{"replica":{"waitPoint":"AfterSync"}}}`},
}

func mariaDBCRDStatuses(t *testing.T, spec, pair string, complete bool, now time.Time) map[string]string {
	t.Helper()
	parts := strings.Split(pair, "->")
	prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(mdbCRDPairResource, spec)), parts[0], parts[1], complete, false)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckNative(projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != "UNKNOWN" || report.NetworkUsed || report.RuntimeReproduced != 0 {
		t.Fatalf("authority fields=%+v", report)
	}
	out := map[string]string{}
	for _, claim := range report.Check.Claims {
		out[claim.RuleID] = claim.Status
	}
	return out
}

var mdbCRDNow = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

func TestMariaDBOperatorCRDRulesBlockOnlyTheirOwnField(t *testing.T) {
	for _, tc := range mariaDBCRDRules {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := mariaDBCRDStatuses(t, tc.spec, tc.pair, true, mdbCRDNow)
			want := 8
			if tc.pair == mdbPairA {
				want = 1
			}
			if len(got) != want {
				t.Fatalf("claims=%v", got)
			}
			for id, status := range got {
				expect := "PASS"
				if id == tc.ruleID {
					expect = "BLOCKED"
				}
				if status != expect {
					t.Fatalf("%s=%s want %s (all=%v)", id, status, expect, got)
				}
			}
		})
	}
}

func TestMariaDBOperatorCRDRulesPassOnlyScopedWhenFieldAbsentOrReplaced(t *testing.T) {
	for _, tc := range []struct{ pair, spec string }{
		{mdbPairA, `{}`},
		{mdbPairA, `{"replication":{"enabled":true,"syncBinlog":1}}`},
		{mdbPairA, `{"replication":{"syncBinlog":0}}`},
		{mdbPairB, `{}`},
		{mdbPairB, `{"maxScaleRef":{"name":"mxs"},"galera":{"primary":{"autoFailover":true}}}`},
		{mdbPairB, `{"replication":{"primary":{"autoFailover":true,"autoFailoverDelay":"5s"},"replica":{"connectionRetrySeconds":3}}}`},
	} {
		got := mariaDBCRDStatuses(t, tc.spec, tc.pair, true, mdbCRDNow)
		if len(got) == 0 {
			t.Fatalf("no claims for %s %s", tc.pair, tc.spec)
		}
		for id, status := range got {
			if status != "PASS" {
				t.Fatalf("%s %s: %s=%s", tc.pair, tc.spec, id, status)
			}
		}
	}
}

func TestMariaDBOperatorCRDRulesNeverPassOrBlockWithoutCompletenessOrOnAnUnsupportedShape(t *testing.T) {
	for _, tc := range mariaDBCRDRules {
		// Incomplete: a present field must not block and an absent one must not pass.
		for _, spec := range []string{tc.spec, `{}`} {
			for id, status := range mariaDBCRDStatuses(t, spec, tc.pair, false, mdbCRDNow) {
				if status == "PASS" || status == "BLOCKED" {
					t.Fatalf("incomplete %s: %s=%s", tc.pair, id, status)
				}
			}
		}
	}
	for _, tc := range []struct{ pair, spec string }{
		{mdbPairA, `{"replication":{"SyncBinlog":true}}`},
		{mdbPairA, `{"replication":{"syncBinlog":"true"}}`},
		{mdbPairA, `{"replication":{"syncBinlog":null}}`},
		{mdbPairB, `{"Galera":{"primary":{"automaticFailover":true}}}`},
		{mdbPairB, `{"replication":{"primary":null}}`},
		{mdbPairB, `{"maxScale":{},"MaxScale":{}}`},
	} {
		for id, status := range mariaDBCRDStatuses(t, tc.spec, tc.pair, true, mdbCRDNow) {
			if status == "PASS" || status == "BLOCKED" {
				t.Fatalf("unsupported shape %s %s: %s=%s", tc.pair, tc.spec, id, status)
			}
		}
	}
}

func TestMariaDBOperatorCRDRulesAreExactPairsAndNeverFireOnTheGaleraPair(t *testing.T) {
	// A CRD-pair input pointed at any other pair finds no CRD rule.
	for _, tc := range []struct{ from, to string }{
		{"25.8.3", "25.10.4"}, {"25.8.4", "25.10.3"}, {"25.0.0", "25.8.4"}, {"25.10.4", "26.3.0"}, {"26.6.0", "26.10.2"}, {"0.38.1", "25.8.4"}, {"25.8.4", "26.3.0"},
	} {
		prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(mdbCRDPairResource, `{"maxScale":{}}`)), tc.from, tc.to, true, false)
		if err != nil {
			t.Fatal(err)
		}
		report, err := CheckNative(projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, mdbCRDNow)
		if err != nil {
			t.Fatal(err)
		}
		for _, claim := range report.Check.Claims {
			if strings.Contains(claim.RuleID, "removed-field") || strings.Contains(claim.RuleID, "sync-binlog") {
				if claim.Status == "PASS" || claim.Status == "BLOCKED" {
					t.Fatalf("%s->%s decided by %s: %s", tc.from, tc.to, claim.RuleID, claim.Status)
				}
			}
		}
	}
	// And the Galera prerequisite pair carries none of the CRD rules.
	prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(mdbCRDPairResource, `{"galera":{"enabled":true},"maxScale":{},"updateStrategy":{"autoUpdateDataPlane":true}}`)), "26.3.0", "26.6.0", true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckNative(projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
		t.Fatalf("claims=%+v", report.Check.Claims)
	}
}

func TestMariaDBOperatorCRDRulesExpireFailClosed(t *testing.T) {
	for _, tc := range mariaDBCRDRules {
		got := mariaDBCRDStatuses(t, tc.spec, tc.pair, true, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
		for id, status := range got {
			if status == "PASS" || status == "BLOCKED" {
				t.Fatalf("expired evidence still decided %s: %s", id, status)
			}
		}
	}
	// Before review the rule is not yet valid.
	for id, status := range mariaDBCRDStatuses(t, `{"maxScale":{}}`, mdbPairB, true, time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)) {
		if status == "PASS" || status == "BLOCKED" {
			t.Fatalf("pre-review evidence decided %s: %s", id, status)
		}
	}
}

func TestMariaDBOperatorCRDRulesCarryEvidenceFromBothReleasesAndLimits(t *testing.T) {
	// The commit each subject version's tag points at.
	tagCommit := map[string]string{
		"0.38.1":  "1d616a2c931a115f503f7cfb5a08ae0aa608799d",
		"25.0.0":  "a6a96c1526151a2917f7db052d1be9b09908baca",
		"25.8.4":  "8ae3899ec3523669943d80458031fe8259285397",
		"25.10.4": "de26dcac098d1f8da0d5dfe4180d49cbb2e956cc",
	}
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range mariaDBCRDRules {
		want[r.ruleID] = true
	}
	seen := 0
	for _, e := range b.pack.Entries {
		var binding struct {
			ID      string `json:"id"`
			Subject struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"subject"`
			Evidence struct {
				ReviewedAt string `json:"reviewedAt"`
				ValidUntil string `json:"validUntil"`
				Sources    []struct {
					ID            string `json:"id"`
					URL           string `json:"url"`
					Revision      string `json:"revision"`
					ContentDigest string `json:"contentDigest"`
					StartLine     int    `json:"startLine"`
					EndLine       int    `json:"endLine"`
				} `json:"sources"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(e.Rule, &binding); err != nil {
			t.Fatal(err)
		}
		if !want[binding.ID] {
			continue
		}
		seen++
		sides := map[string]int{}
		for _, s := range binding.Evidence.Sources {
			if len(s.Revision) != 40 || !strings.HasPrefix(s.URL, "https://github.com/mariadb-operator/mariadb-operator/blob/"+s.Revision+"/") || !strings.HasPrefix(s.ContentDigest, "sha256:") || len(s.ContentDigest) != 71 || s.StartLine < 1 || s.EndLine < s.StartLine {
				t.Fatalf("%s source=%+v", binding.ID, s)
			}
			if s.Revision == tagCommit[binding.Subject.From] {
				sides["from"]++
			}
			if s.Revision == tagCommit[binding.Subject.To] {
				sides["to"]++
			}
		}
		if sides["from"] < 2 || sides["to"] < 2 || sides["from"]+sides["to"] != len(binding.Evidence.Sources) {
			t.Fatalf("%s must cite at least a CRD and an API source at each tag and nothing else: %v", binding.ID, sides)
		}
		reviewed, _ := time.Parse(time.RFC3339, binding.Evidence.ReviewedAt)
		until, _ := time.Parse(time.RFC3339, binding.Evidence.ValidUntil)
		if !until.After(reviewed) || until.Sub(reviewed) > 90*24*time.Hour {
			t.Fatalf("%s lease %s..%s", binding.ID, binding.Evidence.ReviewedAt, binding.Evidence.ValidUntil)
		}
		for _, phrase := range []string{"This checks only", "says nothing about the rest of the", "Helm values or flags"} {
			if !strings.Contains(e.Description, phrase) {
				t.Fatalf("%s description lacks %q", binding.ID, phrase)
			}
		}
		if strings.Contains(strings.ToLower(e.Description), "safe") {
			t.Fatalf("%s description implies safety", binding.ID)
		}
	}
	if seen != len(mariaDBCRDRules) {
		t.Fatalf("rules=%d want %d", seen, len(mariaDBCRDRules))
	}
}
