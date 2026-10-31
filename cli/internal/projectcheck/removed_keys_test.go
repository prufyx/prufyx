// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

// removedKeyRules lists every airflow and opensearch rule with a config line
// that sets exactly the removed key the rule is about.
var removedKeyRules = []struct {
	project, from, to, ruleID, config string
}{
	{"airflow", "3.0.6", "3.1.0", "airflow.removed-option-api-enable-xcom-deserialize-support.3-0-6-to-3-1-0", "[api]\nenable_xcom_deserialize_support = False\n"},
	{"airflow", "3.0.6", "3.1.0", "airflow.removed-option-scheduler-dag-stale-not-seen-duration.3-0-6-to-3-1-0", "[scheduler]\ndag_stale_not_seen_duration = 600\n"},
	{"airflow", "3.0.6", "3.1.0", "airflow.removed-option-webserver-instance-name-has-markup.3-0-6-to-3-1-0", "[webserver]\ninstance_name_has_markup = True\n"},
	{"airflow", "3.0.6", "3.1.0", "airflow.removed-option-webserver-warn-deployment-exposure.3-0-6-to-3-1-0", "[webserver]\nwarn_deployment_exposure = False\n"},
	{"opensearch", "2.19.7", "3.0.0", "opensearch.removed-setting-gateway-expected-nodes.2-19-7-to-3-0-0", "gateway:\n  expected_nodes: 3\n"},
	{"opensearch", "2.19.7", "3.0.0", "opensearch.removed-setting-gateway-recover-after-nodes.2-19-7-to-3-0-0", "gateway:\n  recover_after_nodes: 2\n"},
}

// removedKeyRuleCount is the number of shipped removed-key rules of a project.
func removedKeyRuleCount(project string) int {
	n := 0
	for _, r := range removedKeyRules {
		if r.project == project {
			n++
		}
	}
	return n
}

func statuses(t *testing.T, project, raw, from, to string, complete, resolved bool) map[string]string {
	t.Helper()
	prepared, err := projectprepare.PrepareEffectiveConfig(project, []byte(raw), from, to, complete, resolved)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check(project, prepared.CanonicalInputJSON, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != "UNKNOWN" || report.NetworkUsed || report.RuntimeReproduced != 0 {
		t.Fatalf("authority fields=%+v", report)
	}
	result := map[string]string{}
	for _, claim := range report.Check.Claims {
		result[claim.RuleID] = claim.Status
	}
	return result
}

func TestRemovedKeyRulesBlockOnlyTheirOwnKey(t *testing.T) {
	for _, tc := range removedKeyRules {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := statuses(t, tc.project, tc.config, tc.from, tc.to, true, true)
			if len(got) != removedKeyRuleCount(tc.project) {
				t.Fatalf("claims=%v", got)
			}
			for id, status := range got {
				want := "PASS"
				if id == tc.ruleID {
					want = "BLOCKED"
				}
				if status != want {
					t.Fatalf("%s=%s want %s (all=%v)", id, status, want, got)
				}
			}
		})
	}
}

func TestRemovedKeyRulesPassOnlyScopedWhenKeyAbsentOrUnrelated(t *testing.T) {
	for _, tc := range []struct{ project, from, to, config string }{
		{"airflow", "3.0.6", "3.1.0", "[core]\nexecutor = LocalExecutor\n[webserver]\nbase_url = http://example.invalid\n"},
		{"airflow", "3.0.6", "3.1.0", "[webserver]\ninstance_name = prod\n"},
		{"opensearch", "2.19.7", "3.0.0", "cluster.name: demo\ngateway.expected_data_nodes: 3\ngateway.recover_after_data_nodes: 2\n"},
	} {
		got := statuses(t, tc.project, tc.config, tc.from, tc.to, true, true)
		if len(got) != removedKeyRuleCount(tc.project) {
			t.Fatalf("claims=%v", got)
		}
		for id, status := range got {
			if status != "PASS" {
				t.Fatalf("%s=%s", id, status)
			}
		}
	}
}

func TestRemovedKeyRulesNeverPassWithoutDeclarationsOrWithUnsupportedShape(t *testing.T) {
	for _, tc := range []struct{ project, from, to, config string }{
		{"airflow", "3.0.6", "3.1.0", "[core]\nexecutor = LocalExecutor\n"},
		{"opensearch", "2.19.7", "3.0.0", "cluster.name: demo\n"},
	} {
		for _, declared := range [][2]bool{{false, true}, {true, false}, {false, false}} {
			for id, status := range statuses(t, tc.project, tc.config, tc.from, tc.to, declared[0], declared[1]) {
				if status == "PASS" || status == "BLOCKED" {
					t.Fatalf("%s %v: %s=%s", tc.project, declared, id, status)
				}
			}
		}
	}
	for project, config := range map[string]string{"airflow": "[webserver]\nInstance_Name_Has_Markup = True\n", "opensearch": "Gateway.Expected_Nodes: 3\n"} {
		from, to := "3.0.6", "3.1.0"
		if project == "opensearch" {
			from, to = "2.19.7", "3.0.0"
		}
		for id, status := range statuses(t, project, config, from, to, true, true) {
			if status == "PASS" || status == "BLOCKED" {
				t.Fatalf("%s unsupported shape: %s=%s", project, id, status)
			}
		}
	}
}

func TestRemovedKeyRulesAreExactPairs(t *testing.T) {
	for _, tc := range []struct{ project, from, to, config string }{
		{"airflow", "3.0.5", "3.1.0", "[webserver]\ninstance_name_has_markup = True\n"},
		{"airflow", "3.0.6", "3.1.1", "[webserver]\ninstance_name_has_markup = True\n"},
		{"opensearch", "2.19.6", "3.0.0", "gateway.expected_nodes: 3\n"},
		{"opensearch", "2.19.7", "3.0.1", "gateway.expected_nodes: 3\n"},
	} {
		if got := statuses(t, tc.project, tc.config, tc.from, tc.to, true, true); len(got) != 0 {
			t.Fatalf("%s %s->%s claimed %v", tc.project, tc.from, tc.to, got)
		}
	}
}

func TestRemovedKeyRulesCarryPinnedEvidenceAndLimits(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range b.pack.Entries {
		if e.Project != "airflow" && e.Project != "opensearch" {
			continue
		}
		seen++
		var binding struct {
			Evidence struct {
				Sources []struct {
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
		if len(binding.Evidence.Sources) < 2 {
			t.Fatalf("%s sources=%d", e.Description, len(binding.Evidence.Sources))
		}
		for _, s := range binding.Evidence.Sources {
			if len(s.Revision) != 40 || !strings.Contains(s.URL, "/blob/"+s.Revision+"/") || !strings.HasPrefix(s.ContentDigest, "sha256:") || s.StartLine < 1 || s.EndLine < s.StartLine {
				t.Fatalf("source=%+v", s)
			}
		}
		if !strings.Contains(e.Description, "says nothing about the rest of the") || !strings.Contains(e.Description, "This checks only") {
			t.Fatalf("description lacks explicit limits: %s", e.Description)
		}
	}
	if seen != len(removedKeyRules) {
		t.Fatalf("rules=%d", seen)
	}
}
