// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// The embedded pack carries one mechanical rule over each removal of the
// 1.33, 1.34 and 1.37 lines (derived by the served-API extractor). The
// Kubernetes rendered apply-set route of check cncf is run end to end
// against them.

// laterRemoval is one removal of the lines the embedded rules cover.
type laterRemoval struct {
	dir, group string
	line       int
	kinds      []string
	fact       string
}

var laterRemovals = []laterRemoval{
	{"authentication", "authentication.k8s.io", 33, []string{"SelfSubjectReview"}, "component.kubernetes.selfsubjectreview_v1beta1_removed_gvk_present"},
	{"admissionregistration", "admissionregistration.k8s.io", 34, []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}, "component.kubernetes.validatingadmissionpolicy_v1beta1_removed_gvk_present"},
	{"networking", "networking.k8s.io", 37, []string{"IPAddress", "ServiceCIDR"}, "component.kubernetes.ipaddress_servicecidr_v1beta1_removed_gvk_present"},
	{"storage", "storage.k8s.io", 37, []string{"VolumeAttributesClass"}, "component.kubernetes.volumeattributesclass_v1beta1_removed_gvk_present"},
}

// useLaterRemovalKnowledge reads the embedded rules over the later removals; it
// returns the rule id per fact.
func useLaterRemovalKnowledge(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []cncfcheck.Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, entry := range pack.Entries {
		var rule struct {
			ID        string `json:"id"`
			Condition struct {
				FactID string `json:"factId"`
			} `json:"condition"`
		}
		if err := json.Unmarshal(entry.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		for _, removal := range laterRemovals {
			if rule.Condition.FactID == removal.fact && strings.HasSuffix(rule.ID, fmt.Sprintf(".1-%d-0-to-1-%d-0", removal.line-1, removal.line)) {
				ids[removal.fact] = rule.ID
			}
		}
	}
	for _, removal := range laterRemovals {
		if ids[removal.fact] == "" {
			t.Fatalf("no embedded rule over %s: %v", removal.fact, ids)
		}
	}
	return ids
}

func laterObject(api, kind string) string {
	return `{"apiVersion":"` + api + `","kind":"` + kind + `","metadata":{"name":"private-name","namespace":"private-ns"}}`
}

func TestKubernetesLaterRemovalsThroughTheCommandRoute(t *testing.T) {
	if !supersedeids.Superseded() {
		t.Skip("the shipped pack still holds no rule over these removals: see TestSyntheticServedAPIRemovalCheckWithDerivedRules")
	}
	ids := useLaterRemovalKnowledge(t)
	configMap := laterObject("v1", "ConfigMap")
	for _, removal := range laterRemovals {
		from, to := fmt.Sprintf("1.%d.0", removal.line-1), fmt.Sprintf("1.%d.0", removal.line)
		for _, kind := range removal.kinds {
			removed, served, unreviewed := laterObject(removal.group+"/v1beta1", kind), laterObject(removal.group+"/v1", kind), laterObject(removal.group+"/v1alpha1", kind)
			for _, tc := range []struct {
				name     string
				items    []string
				from, to string
				complete bool
				exit     int
				status   string
			}{
				{"removed version blocks", []string{configMap, removed}, from, to, true, ExitBlocked, "BLOCKED"},
				{"removed version blocks between patches", []string{removed}, fmt.Sprintf("1.%d.4", removal.line-1), fmt.Sprintf("1.%d.2", removal.line), true, ExitBlocked, "BLOCKED"},
				{"served version passes", []string{served, configMap}, from, to, true, 0, "PASS"},
				{"served version passes between patches", []string{served}, fmt.Sprintf("1.%d.9", removal.line-1), fmt.Sprintf("1.%d.1", removal.line), true, 0, "PASS"},
				{"unreviewed version is unknown", []string{unreviewed}, from, to, true, ExitUnknown, "UNKNOWN"},
				{"incomplete scope is unknown", []string{removed}, from, to, false, ExitUnknown, "UNKNOWN"},
			} {
				t.Run(removal.fact+"/"+kind+"/"+tc.name, func(t *testing.T) {
					path := writeCNCFFile(t, "applyset.json", []byte(`{"apiVersion":"v1","kind":"List","items":[`+strings.Join(tc.items, ",")+`]}`), 0o600)
					args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", tc.from, "--to", tc.to, "--distribution", "official_upstream", "--target-api-apply-required", "--now", "2026-11-20T00:00:00Z", "--format", "json"}
					if tc.complete {
						args = append(args, "--resource-scope-complete")
					}
					code, stdout, stderr := runCNCFCLI(t, args...)
					if code != tc.exit || !quietOrAgeNote(stderr) || strings.Contains(stdout, "private-") {
						t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
					}
					var report cncfcheck.Report
					if err := json.Unmarshal([]byte(stdout), &report); err != nil {
						t.Fatal(err)
					}
					if report.KnowledgeOrigin != "embedded" {
						t.Fatalf("origin %s", report.KnowledgeOrigin)
					}
					// Exactly the derived rules of this line decide; no
					// other claim is decided.
					want := map[string]bool{}
					for _, other := range laterRemovals {
						if other.line == removal.line {
							want[ids[other.fact]] = true
						}
					}
					var got []string
					for _, claim := range report.Check.Claims {
						if claim.RuleID == ids[removal.fact] {
							if claim.Status != tc.status {
								t.Fatalf("%s: %s, want %s", claim.RuleID, claim.Status, tc.status)
							}
						} else if want[claim.RuleID] {
							// The other removal of the same line: its kinds
							// are absent, so it passes with a complete scope.
							if tc.complete && tc.status != "UNKNOWN" && claim.Status != "PASS" {
								t.Fatalf("%s: %s", claim.RuleID, claim.Status)
							}
						} else if claim.Status == "PASS" || claim.Status == "BLOCKED" {
							t.Fatalf("claim of rule %s decided %s", claim.RuleID, claim.Status)
						}
						got = append(got, claim.RuleID)
					}
					sort.Strings(got)
					var wantIDs []string
					for id := range want {
						wantIDs = append(wantIDs, id)
					}
					sort.Strings(wantIDs)
					if strings.Join(got, ",") != strings.Join(wantIDs, ",") {
						t.Fatalf("claims %v, want %v", got, wantIDs)
					}
				})
			}
		}
	}
	// A transition that crosses none of these lines is not decided by them.
	path := writeCNCFFile(t, "applyset.json", []byte(`{"apiVersion":"v1","kind":"List","items":[`+laterObject("storage.k8s.io/v1beta1", "VolumeAttributesClass")+`]}`), 0o600)
	code, stdout, _ := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", "1.37.0", "--to", "1.38.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", "2026-11-20T00:00:00Z", "--format", "json")
	if code != ExitUnknown || strings.Contains(stdout, `"BLOCKED"`) || strings.Contains(stdout, `"PASS"`) {
		t.Fatalf("1.37 -> 1.38: code=%d %s", code, stdout)
	}
	// Human output names the blocking rule and the fix.
	path = writeCNCFFile(t, "applyset.json", []byte(`{"apiVersion":"v1","kind":"List","items":[`+laterObject("networking.k8s.io/v1beta1", "ServiceCIDR")+`]}`), 0o600)
	code, stdout, _ = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", "1.36.0", "--to", "1.37.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", "2026-11-20T00:00:00Z")
	if code != ExitBlocked || !strings.Contains(stdout, ids["component.kubernetes.ipaddress_servicecidr_v1beta1_removed_gvk_present"]) || !strings.Contains(stdout, "networking.k8s.io/v1") {
		t.Fatalf("code=%d %q", code, stdout)
	}
}
