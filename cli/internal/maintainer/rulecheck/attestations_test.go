// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const attRev = "2222222222222222222222222222222222222222"

func attestation(line string, ids ...string) lineattest.LineAttestation {
	if ids == nil {
		ids = []string{}
	}
	return lineattest.LineAttestation{Component: "pkg:github/kubernetes/kubernetes", Line: line, FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, Completeness: lineattest.Completeness, RuleIDs: ids,
		Evidence: lineattest.Evidence{Basis: "reviewed", ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z", Sources: []constraintengine.SourceEvidence{{ID: "guide", URL: "https://github.com/kubernetes/website/blob/" + attRev + "/guide.md", Revision: attRev, ContentDigest: "sha256:" + strings.Repeat("c", 64), StartLine: 1, EndLine: 3}}}}
}

func publishedRules(t *testing.T) []json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	var rules []json.RawMessage
	for _, e := range pack.Entries {
		rules = append(rules, e.Rule)
	}
	return rules
}

func doc(t *testing.T, atts ...lineattest.LineAttestation) []byte {
	t.Helper()
	raw, err := lineattest.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var rules126 = []string{"kubernetes.served-api-removal.autoscaling-v2beta2.1-25-0-to-1-26-0", "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta1.1-25-0-to-1-26-0"}

func TestAttestationMatchingThePackIsValid(t *testing.T) {
	r := ValidateLineAttestations(doc(t, attestation("1.26", rules126...), attestation("1.30")), publishedRules(t), AttestationOptions{})
	if !r.Valid || r.EntryCount != 2 {
		t.Fatalf("%+v", r)
	}
}

// An attestation listing fewer rules than the pack holds, or a rule the
// pack does not hold for that line and family, fails.
func TestAttestationMustListExactlyThePackRules(t *testing.T) {
	rules := publishedRules(t)
	for name, c := range map[string]struct {
		att   lineattest.LineAttestation
		check string
		rule  string
	}{
		"missing rule":         {attestation("1.26", rules126[0]), CheckAttestationMissingRule, rules126[1]},
		"extra rule":           {attestation("1.26", append(append([]string{}, rules126...), "kubernetes.zz-extra")...), CheckAttestationExtraRule, "kubernetes.zz-extra"},
		"rule of another line": {attestation("1.27", rules126[0], "kubernetes.served-api-removal.storage-k8s-io-v1beta1.1-26-0-to-1-27-0"), CheckAttestationExtraRule, rules126[0]},
		"falsely quiet line":   {attestation("1.32"), CheckAttestationMissingRule, "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0"},
		"other family":         {attestation("1.24", "kubernetes.in-tree-dockershim-removed.1-24"), CheckAttestationExtraRule, "kubernetes.in-tree-dockershim-removed.1-24"},
	} {
		t.Run(name, func(t *testing.T) {
			r := ValidateLineAttestations(doc(t, c.att), rules, AttestationOptions{})
			if r.Valid || len(r.Findings) != 1 || r.Findings[0].Check != c.check || r.Findings[0].RuleID != c.rule {
				t.Fatalf("%+v", r.Findings)
			}
		})
	}
}

// A rule that matches its anchor pair only cannot be listed in a line review:
// the published 1.32 rule is a range rule, so the case strips its range.
func TestAttestationRuleNotLineWide(t *testing.T) {
	const id = "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0"
	var rules []json.RawMessage
	stripped := false
	for _, raw := range publishedRules(t) {
		var rule map[string]any
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatal(err)
		}
		if rule["id"] == id {
			delete(rule, "range")
			stripped = true
			var err error
			if raw, err = json.Marshal(rule); err != nil {
				t.Fatal(err)
			}
		}
		rules = append(rules, raw)
	}
	if !stripped {
		t.Fatalf("%s is not in the pack", id)
	}
	r := ValidateLineAttestations(doc(t, attestation("1.32", id)), rules, AttestationOptions{})
	if r.Valid || len(r.Findings) != 1 || r.Findings[0].Check != CheckAttestationRuleNotLineWide || r.Findings[0].RuleID != id {
		t.Fatalf("%+v", r.Findings)
	}
	if r := ValidateLineAttestations(doc(t, attestation("1.32", id)), publishedRules(t), AttestationOptions{}); !r.Valid {
		t.Fatalf("the published range rule is refused: %+v", r.Findings)
	}
}

func TestAttestationSchemaAndFreshness(t *testing.T) {
	r := ValidateLineAttestations([]byte(`[{"component":"pkg:github/kubernetes/kubernetes"}]`), publishedRules(t), AttestationOptions{})
	if r.Valid || r.Findings[0].Check != CheckAttestationSchema {
		t.Fatalf("%+v", r)
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	for when, valid := range map[string]bool{"2026-11-01T00:00:00Z": true, "2026-12-30T00:00:00Z": false, "2026-09-01T00:00:00Z": false} {
		r := ValidateLineAttestations(doc(t, attestation("1.30")), publishedRules(t), AttestationOptions{Now: at(when)})
		if r.Valid != valid || (!valid && r.Findings[0].Check != CheckAttestationNotCurrent) {
			t.Fatalf("%s: %+v", when, r)
		}
	}
}

func TestValidatePackAttestations(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := ValidatePackAttestations(raw, AttestationOptions{}); err != nil || !r.Valid {
		t.Fatalf("a pack without attestations: %+v %v", r, err)
	}
	var pack map[string]json.RawMessage
	_ = json.Unmarshal(raw, &pack)
	pack["lineAttestations"] = doc(t, attestation("1.26", rules126[0]))
	bad, _ := json.Marshal(pack)
	if r, err := ValidatePackAttestations(bad, AttestationOptions{}); err != nil || r.Valid || r.Findings[0].Check != CheckAttestationMissingRule {
		t.Fatalf("%+v %v", r, err)
	}
	pack["lineAttestations"] = json.RawMessage("null")
	bad, _ = json.Marshal(pack)
	if r, err := ValidatePackAttestations(bad, AttestationOptions{}); err != nil || r.Valid {
		t.Fatalf("a null section is valid: %+v %v", r, err)
	}
}

// rulecheck locates the section through the same exact-name function as the
// pack loader: a variant spelling is an error, never "no section, valid".
func TestValidatePackAttestationsMatchesMemberNamesExactly(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	section := string(doc(t, attestation("1.30")))
	withMembers := func(members string) []byte {
		return []byte(strings.Replace(string(raw), `"entries":`, members+`"entries":`, 1))
	}
	if r, err := ValidatePackAttestations(withMembers(`"lineAttestations":`+section+`,`), AttestationOptions{}); err != nil || !r.Valid || r.EntryCount != 1 {
		t.Fatalf("exact spelling: %+v %v", r, err)
	}
	for name, members := range map[string]string{
		"LineAttestations": `"LineAttestations":` + section + `,`,
		"LINEATTESTATIONS": `"LINEATTESTATIONS":` + section + `,`,
		"long s":           `"lineAttestationſ":` + section + `,`,
		"two spellings":    `"lineAttestations":` + section + `,"LineAttestations":` + section + `,`,
		"repeated":         `"lineAttestations":` + section + `,"lineAttestations":` + section + `,`,
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := ValidatePackAttestations(withMembers(members), AttestationOptions{}); err == nil {
				t.Fatalf("accepted: %+v", r)
			}
		})
	}
}
