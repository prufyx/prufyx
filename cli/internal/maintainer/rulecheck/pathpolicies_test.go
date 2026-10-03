// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const policyComponent = "pkg:github/kubernetes/kubernetes"

// kubernetesEntry is a published, reviewed Kubernetes rule entry.
func kubernetesEntry(t *testing.T) map[string]any {
	t.Helper()
	for _, entry := range realEntries(t, filepath.Join("..", "..", "cncfcheck", "data", "rules.json")) {
		subject := rule(entry)["subject"].(map[string]any)
		if subject["component"] == policyComponent {
			return clone(t, entry)
		}
	}
	t.Fatal("no Kubernetes rule in the published pack")
	return nil
}

// policyDocument wraps a rule's evidence object in a path-policy record.
func policyDocument(t *testing.T, component string, evidence any) []byte {
	t.Helper()
	raw, err := json.Marshal([]map[string]any{{"component": component, "policy": "sequential_minor", "evidence": evidence}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A path-policy record's evidence passes exactly when the same evidence
// passes as a published rule's: every evidence defect the rule validator
// reports, the path-policy validator reports too.
func TestRulecheckPathPolicies(t *testing.T) {
	type mutation func(evidence map[string]any)
	source := func(e map[string]any) map[string]any { return e["sources"].([]any)[0].(map[string]any) }
	mutations := map[string]mutation{
		"unknown state":         func(e map[string]any) { e["state"] = "draft" },
		"unknown basis":         func(e map[string]any) { e["basis"] = "guessed" },
		"mechanical bare":       func(e map[string]any) { e["basis"] = "mechanical" },
		"derivedAt on reviewed": func(e map[string]any) { e["derivedAt"] = e["reviewedAt"] },
		"non-UTC review time":   func(e map[string]any) { e["reviewedAt"] = "2026-09-13T02:00:00+02:00" },
		"window inverted":       func(e map[string]any) { e["validUntil"] = e["reviewedAt"] },
		"no sources":            func(e map[string]any) { e["sources"] = []any{} },
		"branch revision":       func(e map[string]any) { source(e)["revision"] = "main" },
		"branch URL": func(e map[string]any) {
			source(e)["url"] = strings.Replace(source(e)["url"].(string), source(e)["revision"].(string), "main", 1)
		},
		"URL commit mismatch": func(e map[string]any) {
			source(e)["url"] = strings.Replace(source(e)["url"].(string), source(e)["revision"].(string), strings.Repeat("e", 40), 1)
		},
		"span digest": func(e map[string]any) { source(e)["contentDigest"] = "sha256:abc" },
		"start line":  func(e map[string]any) { source(e)["startLine"] = 0 },
		"end line":    func(e map[string]any) { source(e)["endLine"] = 0 },
		"query in URL": func(e map[string]any) {
			source(e)["url"] = source(e)["url"].(string) + "?plain=1"
		},
	}
	base := kubernetesEntry(t)
	evidenceOf := func(entry map[string]any) map[string]any { return rule(entry)["evidence"].(map[string]any) }
	ruleValid := func(entry map[string]any) bool {
		result, err := Validate(candidateFile(t, entry), Options{AllowRange: true})
		return err == nil && result.Valid
	}
	policyValid := func(evidence any) Result {
		result, err := ValidatePathPolicies(policyDocument(t, policyComponent, evidence), PathPolicyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if !ruleValid(base) {
		t.Fatal("the published rule does not validate")
	}
	if r := policyValid(evidenceOf(base)); !r.Valid || r.EntryCount != 1 {
		t.Fatalf("the published rule's evidence is refused for a path policy: %+v", r.Findings)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			entry := clone(t, base)
			mutate(evidenceOf(entry))
			if ruleValid(entry) {
				t.Fatal("fixture: the rule validator accepts this evidence")
			}
			r := policyValid(evidenceOf(entry))
			if r.Valid || len(r.Findings) != 1 || r.Findings[0].Check != CheckPathPolicySchema {
				t.Fatalf("path policy with the same evidence: %+v", r)
			}
		})
	}

	// Components must be catalog subject components.
	evidence := evidenceOf(base)
	for component, want := range map[string]bool{policyComponent: true, "pkg:github/cilium/cilium": true, "pkg:github/kubernetes-sigs/kind": false, "pkg:github/open-telemetry/opentelemetry-collector-contrib": false} {
		result, err := ValidatePathPolicies(policyDocument(t, component, evidence), PathPolicyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Valid != want || (!want && result.Findings[0].Check != CheckPathPolicyComponent) {
			t.Fatalf("component %s: %+v", component, result)
		}
	}
	explicit, err := ValidatePathPolicies(policyDocument(t, "pkg:github/example/tool", evidence), PathPolicyOptions{Components: []string{"pkg:github/example/tool"}})
	if err != nil || !explicit.Valid {
		t.Fatalf("explicit component list: %+v %v", explicit, err)
	}

	// Freshness, as for attestations: only reported when Now is given.
	reviewed, _ := time.Parse(time.RFC3339, evidence["reviewedAt"].(string))
	until, _ := time.Parse(time.RFC3339, evidence["validUntil"].(string))
	for at, want := range map[time.Time]bool{reviewed: true, until.Add(-time.Second): true, until: false, reviewed.Add(-time.Second): false} {
		result, err := ValidatePathPolicies(policyDocument(t, policyComponent, evidence), PathPolicyOptions{Now: at})
		if err != nil {
			t.Fatal(err)
		}
		if result.Valid != want || (!want && result.Findings[0].Check != CheckPathPolicyNotCurrent) {
			t.Fatalf("at %s: %+v", at, result)
		}
	}
	withdrawn := clone(t, base)
	evidenceOf(withdrawn)["state"] = "withdrawn"
	if result, _ := ValidatePathPolicies(policyDocument(t, policyComponent, evidenceOf(withdrawn)), PathPolicyOptions{Now: reviewed}); result.Valid {
		t.Fatal("a withdrawn record is reported current")
	}

	// Document-level strictness.
	unknownPolicy := bytes.Replace(policyDocument(t, policyComponent, evidence), []byte(`"sequential_minor"`), []byte(`"skip_minor"`), 1)
	for name, raw := range map[string][]byte{"empty": []byte(`[]`), "unknown policy": unknownPolicy, "not JSON": []byte(`[{`)} {
		result, err := ValidatePathPolicies(raw, PathPolicyOptions{})
		if err != nil || result.Valid || result.Findings[0].Check != CheckPathPolicySchema {
			t.Fatalf("%s: %+v %v", name, result, err)
		}
	}
}

func TestValidatePackPathPolicies(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r, err := ValidatePackPathPolicies(raw, PathPolicyOptions{}); err != nil || !r.Valid || r.EntryCount != 0 {
		t.Fatalf("published pack: %+v %v", r, err)
	}
	evidence := rule(kubernetesEntry(t))["evidence"]
	good := policyDocument(t, policyComponent, evidence)
	withSection := func(member string, section []byte) []byte {
		return bytes.Replace(raw, []byte(`"entries":`), append(append([]byte(`"`+member+`":`), section...), []byte(`,"entries":`)...), 1)
	}
	if r, err := ValidatePackPathPolicies(withSection("pathPolicies", good), PathPolicyOptions{}); err != nil || !r.Valid || r.EntryCount != 1 {
		t.Fatalf("pack with a valid section: %+v %v", r, err)
	}
	bad := bytes.Replace(good, []byte(`"sequential_minor"`), []byte(`"skip_minor"`), 1)
	if r, err := ValidatePackPathPolicies(withSection("pathPolicies", bad), PathPolicyOptions{}); err != nil || r.Valid {
		t.Fatalf("pack with an invalid section: %+v %v", r, err)
	}
	// A variant spelling is an error, never a pack "without" the section.
	if _, err := ValidatePackPathPolicies(withSection("PathPolicies", bad), PathPolicyOptions{}); err == nil {
		t.Fatal("a variant member spelling was read as no section")
	}
}
