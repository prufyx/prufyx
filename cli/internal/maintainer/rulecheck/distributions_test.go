// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// distributionSection wraps one evidence object in a synthetic section: an
// eks record and one statement, both citing evidence. The statements are
// test data, not knowledge.
func distributionSection(t *testing.T, recordEvidence, statementEvidence any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"records":       []any{map[string]any{"distribution": "eks", "controlPlane": "managed", "evidence": recordEvidence}},
		"applicability": []any{map[string]any{"distribution": "eks", "family": "kubernetes.removed_served_gvk", "status": "applies", "evidence": statementEvidence}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A distribution record's evidence passes exactly when the same evidence
// passes as a published rule's, offline and online.
func TestRulecheckDistributions(t *testing.T) {
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
		"non-Git URL":  func(e map[string]any) { source(e)["url"] = "https://docs.example.com/kubernetes-versions.html" },
		"span digest":  func(e map[string]any) { source(e)["contentDigest"] = "sha256:abc" },
		"start line":   func(e map[string]any) { source(e)["startLine"] = 0 },
		"end line":     func(e map[string]any) { source(e)["endLine"] = 0 },
		"query in URL": func(e map[string]any) { source(e)["url"] = source(e)["url"].(string) + "?plain=1" },
	}
	base := kubernetesEntry(t)
	evidenceOf := func(entry map[string]any) map[string]any { return rule(entry)["evidence"].(map[string]any) }
	ruleValid := func(entry map[string]any) bool {
		result, err := Validate(candidateFile(t, entry), Options{AllowRange: true})
		return err == nil && result.Valid
	}
	validate := func(raw []byte, opts DistributionOptions) Result {
		result, err := ValidateDistributions(raw, opts)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if !ruleValid(base) {
		t.Fatal("the published rule does not validate")
	}
	good := evidenceOf(base)
	if r := validate(distributionSection(t, good, good), DistributionOptions{}); !r.Valid || r.EntryCount != 2 {
		t.Fatalf("the published rule's evidence is refused for a distribution record: %+v", r.Findings)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			entry := clone(t, base)
			mutate(evidenceOf(entry))
			if ruleValid(entry) {
				t.Fatal("fixture: the rule validator accepts this evidence")
			}
			for _, raw := range [][]byte{distributionSection(t, evidenceOf(entry), good), distributionSection(t, good, evidenceOf(entry))} {
				r := validate(raw, DistributionOptions{})
				if r.Valid || len(r.Findings) != 1 || r.Findings[0].Check != CheckDistributionSchema {
					t.Fatalf("distribution section with the same evidence: %+v", r)
				}
			}
		})
	}

	// Freshness, only reported when Now is given.
	reviewed, _ := time.Parse(time.RFC3339, good["reviewedAt"].(string))
	until, _ := time.Parse(time.RFC3339, good["validUntil"].(string))
	for at, want := range map[time.Time]bool{reviewed: true, until.Add(-time.Second): true, until: false, reviewed.Add(-time.Second): false} {
		r := validate(distributionSection(t, good, good), DistributionOptions{Now: at})
		if r.Valid != want || (!want && (len(r.Findings) != 2 || r.Findings[0].Check != CheckDistributionNotCurrent)) {
			t.Fatalf("at %s: %+v", at, r)
		}
	}
	withdrawn := clone(t, base)
	evidenceOf(withdrawn)["state"] = "withdrawn"
	if r := validate(distributionSection(t, good, evidenceOf(withdrawn)), DistributionOptions{Now: reviewed}); r.Valid || len(r.Findings) != 1 || r.Findings[0].EntryIndex != 1 {
		t.Fatalf("a withdrawn statement is reported current: %+v", r)
	}

	// Online: the same check a rule source gets, through the same fetcher.
	pinned := clone(t, base)
	src := source(evidenceOf(pinned))
	revision := strings.Repeat("a", 40)
	src["url"] = "https://github.com/example/docs/blob/" + revision + "/versions.md"
	src["revision"] = revision
	content := []byte("line1\nline2\nline3\n")
	src["contentDigest"] = digestOf(content)
	src["startLine"], src["endLine"] = 1, 2
	evidenceOf(pinned)["sources"] = []any{src}
	rawURL := "https://raw.githubusercontent.com/example/docs/" + revision + "/versions.md"
	matching := fakeFetcher{content: map[string][]byte{rawURL: content}}
	section := distributionSection(t, evidenceOf(pinned), evidenceOf(pinned))
	if r := validate(section, DistributionOptions{Fetch: true, Fetcher: matching}); !r.Valid {
		t.Fatalf("matching fetched source: %+v", r.Findings)
	}
	ruleEntry := clone(t, pinned)
	for name, fetcher := range map[string]fakeFetcher{
		"content-digest-mismatch": {content: map[string][]byte{rawURL: []byte("other\nlines\nhere\n")}},
		"line-range-fetched":      {content: map[string][]byte{rawURL: []byte("line1\n")}},
		"fetch-failed":            {err: map[string]error{rawURL: fmt.Errorf("offline")}},
	} {
		t.Run("online "+name, func(t *testing.T) {
			ruleResult, err := Validate(candidateFile(t, ruleEntry), Options{AllowRange: true, Fetch: true, Fetcher: fetcher})
			if err != nil {
				t.Fatal(err)
			}
			r := validate(section, DistributionOptions{Fetch: true, Fetcher: fetcher})
			// The rule fixture also fails offline checks (its sources were
			// replaced); only the online checks are compared.
			online := func(findings []Finding) []string {
				var out []string
				for _, check := range SortedChecks(findings) {
					switch check {
					case "content-digest-mismatch", "line-range-fetched", "fetch-failed", "fetch-url":
						out = append(out, check)
					}
				}
				return out
			}
			ruleChecks, recordChecks := online(ruleResult.Findings), SortedChecks(r.Findings)
			if len(ruleChecks) == 0 || strings.Join(ruleChecks, ",") != strings.Join(recordChecks, ",") || !slices.Contains(ruleChecks, name) {
				t.Fatalf("rule checks %v, distribution checks %v (%+v)", ruleChecks, recordChecks, r.Findings)
			}
		})
	}
	if _, err := ValidateDistributions(section, DistributionOptions{Fetch: true}); err == nil {
		t.Fatal("Fetch without a Fetcher accepted")
	}

	// Section-level strictness.
	for name, raw := range map[string][]byte{
		"empty":          []byte(`{"records":[],"applicability":[]}`),
		"unknown family": bytes.Replace(distributionSection(t, good, good), []byte(`"kubernetes.removed_served_gvk"`), []byte(`"kubernetes.addons"`), 1),
		"not JSON":       []byte(`{`),
		"array":          []byte(`[]`),
	} {
		r, err := ValidateDistributions(raw, DistributionOptions{})
		if err != nil || r.Valid || r.Findings[0].Check != CheckDistributionSchema {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
	}
}

func TestValidatePackDistributions(t *testing.T) {
	packRaw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The published pack has no section: valid, nothing checked.
	if r, err := ValidatePackDistributions(packRaw, DistributionOptions{}); err != nil || !r.Valid || r.EntryCount != 0 {
		t.Fatalf("published pack: %+v %v", r, err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(packRaw, &pack); err != nil {
		t.Fatal(err)
	}
	good := rule(kubernetesEntry(t))["evidence"]
	pack["distributions"] = distributionSection(t, good, good)
	with, _ := json.Marshal(pack)
	if r, err := ValidatePackDistributions(with, DistributionOptions{}); err != nil || !r.Valid || r.EntryCount != 2 {
		t.Fatalf("pack with a section: %+v %v", r, err)
	}
	pack["distributions"] = json.RawMessage(`null`)
	withNull, _ := json.Marshal(pack)
	if r, err := ValidatePackDistributions(withNull, DistributionOptions{}); err != nil || r.Valid {
		t.Fatalf("null section: %+v %v", r, err)
	}
	// A variant spelling is an error, never "no section, valid".
	variant := bytes.Replace(with, []byte(`"distributions":`), []byte(`"Distributions":`), 1)
	if _, err := ValidatePackDistributions(variant, DistributionOptions{}); err == nil {
		t.Fatal("variant member spelling accepted")
	}
}
