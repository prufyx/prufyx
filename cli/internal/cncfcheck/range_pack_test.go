// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

var cronJobRuleID = supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0")

// anchorOnlyRange returns a range that licenses nothing beyond the anchor
// pair: from [anchor.from, anchor.from+1 patch), to [anchor.to, anchor.to+1
// patch), every bound ANCHOR_ONLY. It exercises the ranged schema, contract
// and plumbing without widening any reviewed claim.
func anchorOnlyRange(t *testing.T, rule json.RawMessage) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(rule, &value); err != nil {
		t.Fatal(err)
	}
	subject := value["subject"].(map[string]any)
	source := value["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["id"].(string)
	next := func(version string) string {
		parts := strings.Split(version, ".")
		if parts[2] != "0" {
			t.Fatalf("fixture expects a .0 anchor, got %s", version)
		}
		return parts[0] + "." + parts[1] + ".1"
	}
	bounds := []any{}
	for _, name := range []string{"from.gte", "from.lt", "to.gte", "to.lt"} {
		bounds = append(bounds, map[string]any{"bound": name, "basis": constraintengine.BasisAnchorOnly, "sourceId": source})
	}
	value["range"] = map[string]any{
		"from":   map[string]any{"gte": subject["from"], "lt": next(subject["from"].(string))},
		"to":     map[string]any{"gte": subject["to"], "lt": next(subject["to"].(string))},
		"bounds": bounds,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withAnchorOnlyRange(t *testing.T, pack rulePack, ruleID string) rulePack {
	t.Helper()
	entries := append([]Entry(nil), pack.Entries...)
	changed := false
	for index, entry := range entries {
		var shape struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) == nil && shape.ID == ruleID {
			entries[index].Rule = anchorOnlyRange(t, entry.Rule)
			changed = true
		}
	}
	if !changed {
		t.Fatalf("rule %s missing", ruleID)
	}
	pack.Entries = entries
	return pack
}

func kubernetesInput(t *testing.T, from, to string, cronJobPresent bool) []byte {
	t.Helper()
	value := "false"
	if cronJobPresent {
		value = "true"
	}
	return []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + from + `","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + to + `","facts":[{"id":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","state":"declared","boolValue":` + value + `}]}]}}`)
}

var rangeReviewClock = supersedeids.Clock()

// withoutRanges strips the range field from every entry's rule, so tests can
// exercise the exact-only schema gate against a pack derived from the real
// published one rather than a hand-built approximation.
func withoutRanges(t *testing.T, pack rulePack) rulePack {
	t.Helper()
	entries := append([]Entry(nil), pack.Entries...)
	for index, entry := range entries {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(entry.Rule, &value); err != nil {
			t.Fatal(err)
		}
		if _, has := value["range"]; !has {
			continue
		}
		delete(value, "range")
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		entries[index].Rule = raw
	}
	pack.Entries = entries
	return pack
}

// TestPackSchemaStatesRangeUse: the embedded pack now carries the 24
// published Kubernetes removal ranges, so it uses the ranged schema. A pack
// with every range stripped back out must revert to the original schema, and
// a pack in either state is rejected under the other schema string.
func TestPackSchemaStatesRangeUse(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if base.pack.Schema != packSchemaRanged || !validPackSchema(base.pack) {
		t.Fatalf("embedded pack schema=%s", base.pack.Schema)
	}
	unranged := withoutRanges(t, base.pack)
	if validPackSchema(unranged) {
		t.Fatal("unranged pack accepted under the ranged schema")
	}
	unranged.Schema = packSchema
	if !validPackSchema(unranged) {
		t.Fatal("unranged pack rejected under the exact-only schema")
	}
	exact := base.pack
	exact.Schema = packSchema
	if validPackSchema(exact) {
		t.Fatal("ranged pack accepted under the exact-only schema")
	}
}

// TestExternalBundleRangeSchemaGate: an external bundle carrying a range is
// admitted only under the ranged pack schema. Binaries that predate ranges
// compare the pack schema with the exact-only string and reject the bundle;
// under that string this binary rejects it too.
func TestExternalBundleRangeSchemaGate(t *testing.T) {
	entry := ruleEntry(t, "kubernetes", cronJobRuleID)
	pack := withAnchorOnlyRange(t, rulePack{Entries: []Entry{entry}}, cronJobRuleID)
	// externalFixture upgrades the schema for ranged packs, so force the
	// exact-only schema here to prove the parser itself refuses a range.
	var document externalFixtureDocument
	if err := json.Unmarshal(externalFixture(t, pack.Entries), &document); err != nil {
		t.Fatal(err)
	}
	document.Pack.Schema = packSchema
	rawExact, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(rawExact); err == nil {
		t.Fatal("range admitted under the exact-only pack schema")
	}
	document.Pack.Schema = packSchemaRanged
	rawRanged, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExternalBundle(rawRanged)
	if err != nil {
		t.Fatalf("ranged external bundle rejected: %v", err)
	}
	report, err := parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || report.Check.EngineContractDigest != constraintengine.EngineContractDigestRanged() {
		t.Fatalf("report=%+v", report.Check)
	}
	// Still exact-only in effect: the anchor-only range matches nothing wider.
	report, err = parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.17", "1.25.3", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" || report.Check.Claims[0].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("report=%+v", report.Check)
	}
}

// TestRangeAwarePrefilterSelectsThroughTheMatcher: the per-project path narrows
// the pack with the shared matcher and renders the document under the schema
// its selection requires.
func TestRangeAwarePrefilterSelectsThroughTheMatcher(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	ranged := base
	ranged.pack = withAnchorOnlyRange(t, base.pack, cronJobRuleID)
	ranged.pack.Schema = packSchemaRanged
	report, err := ranged.check("kubernetes", "", kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, claim := range report.Check.Claims {
		if claim.Status == "BLOCKED" {
			blocked++
		}
	}
	if blocked != 1 || report.Check.EngineContractDigest != constraintengine.EngineContractDigestRanged() {
		t.Fatalf("claims=%+v digest=%s", report.Check.Claims, report.Check.EngineContractDigest)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
	// The 1.32 flow-control rule is ranged in both generations of the pack,
	// so the rules selected for its anchor pair render under the ranged
	// contract, like those of every other reviewed Kubernetes removal.
	wantDigest := constraintengine.EngineContractDigestRanged()
	exactOnly, err := ranged.rulesForAdmittedInput("kubernetes", kubernetesInput(t, "1.31.0", "1.32.0", true))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := constraintengine.Evaluate(mustInput(t, ranged, kubernetesInput(t, "1.31.0", "1.32.0", true)), exactOnly, rangeReviewClock)
	if err != nil || engine.EngineContractDigest != wantDigest {
		t.Fatalf("exact selection digest=%s err=%v", engine.EngineContractDigest, err)
	}
	// The fact-family selection, which is what the generic path uses once a
	// family has component-configuration rules, renders the same rule under
	// the same contract.
	family, err := ranged.factFamilyRuleSet("kubernetes", []string{"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"}, kubernetesInput(t, "1.31.0", "1.32.0", true))
	if err != nil {
		t.Fatal(err)
	}
	engine, err = constraintengine.Evaluate(mustInput(t, ranged, kubernetesInput(t, "1.31.0", "1.32.0", true)), family, rangeReviewClock)
	if err != nil || engine.EngineContractDigest != wantDigest {
		t.Fatalf("fact-family selection digest=%s err=%v", engine.EngineContractDigest, err)
	}
}

func mustInput(t *testing.T, b bundle, raw []byte) constraintengine.Input {
	t.Helper()
	input, err := constraintengine.ParseInput(raw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// TestPublishedRangeWidensSelectionAndClaims: with the published pack, an
// off-anchor pair on a reviewed line, such as 1.24.17 -> 1.25.3, now selects
// every rule on that line through the shared matcher's range mode. The
// cronjob rule decides (its fact is the only one this synthetic input
// declares); the other six rules on the same line also match the transition
// (SubjectMatch present, mode "range") but stay UNKNOWN for lack of their own
// declared fact, never a false PASS or BLOCKED. Whole-upgrade scope-complete
// PASS is still out of reach with an incomplete fact set.
func TestPublishedRangeWidensSelectionAndClaims(t *testing.T) {
	for _, tc := range []struct {
		present     bool
		wantExit    int
		wantCronjob string
	}{
		{true, 10, "BLOCKED"},
		{false, 11, "PASS"},
	} {
		report, err := Check("kubernetes", kubernetesInput(t, "1.24.17", "1.25.3", tc.present), currentKubernetesReviewClock(t, rangeReviewClock))
		if err != nil {
			t.Fatal(err)
		}
		if want := rulesAnchoredOn(t, "1.24.0", "1.25.0"); len(report.Check.Claims) != want || want < 7 {
			t.Fatalf("present=%v: claims=%d, want %d", tc.present, len(report.Check.Claims), want)
		}
		for _, claim := range report.Check.Claims {
			if claim.SubjectMatch == nil || claim.SubjectMatch.Mode != "range" || claim.SubjectMatch.AnchorFrom != "1.24.0" || claim.SubjectMatch.AnchorTo != "1.25.0" {
				t.Fatalf("present=%v: claim %s subjectMatch=%+v", tc.present, claim.RuleID, claim.SubjectMatch)
			}
			if claim.RuleID == cronJobRuleID {
				if claim.Status != tc.wantCronjob {
					t.Fatalf("present=%v: cronjob status=%s want %s", tc.present, claim.Status, tc.wantCronjob)
				}
				continue
			}
			if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_FACT_UNAVAILABLE" {
				t.Fatalf("present=%v: claim %s status=%s reason=%s", tc.present, claim.RuleID, claim.Status, claim.ReasonCode)
			}
		}
		if got := ClaimExit(report); got != tc.wantExit {
			t.Fatalf("present=%v: exit=%d want %d", tc.present, got, tc.wantExit)
		}
		if report.Check.EngineContractDigest != constraintengine.EngineContractDigestRanged() {
			t.Fatalf("present=%v: digest=%s", tc.present, report.Check.EngineContractDigest)
		}
	}
	scoped := strings.Replace(string(kubernetesInput(t, "1.24.17", "1.25.3", false)), `}]}]}}`, `}]}]},"scope":{"declaration":"`+constraintengine.ScopeDeclaration+`","components":["pkg:github/kubernetes/kubernetes"]}}`, 1)
	scope, err := AssessScope([]byte(scoped), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%s", scope.Assessment)
	}
	if _, err := Check("kubernetes", kubernetesInput(t, "v1.24.17", "1.25.3", true), rangeReviewClock); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v-prefixed version err=%v", err)
	}
}

// rulesAnchoredOn counts published Kubernetes rules anchored on one pair, so
// the range tests follow the pack as reviewed rules are added to a line.
func rulesAnchoredOn(t *testing.T, from, to string) int {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range b.pack.Entries {
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil {
			t.Fatal("rule shape")
		}
		if entry.Project == "kubernetes" && shape.Subject.From == from && shape.Subject.To == to {
			count++
		}
	}
	return count
}

// currentKubernetesReviewClock returns the later of fallback and one minute
// after the newest Kubernetes rule review, so a test that evaluates every
// Kubernetes rule on a transition runs while all of them are current.
func currentKubernetesReviewClock(t *testing.T, fallback time.Time) time.Time {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	latest := fallback
	for _, entry := range b.pack.Entries {
		if entry.Project != "kubernetes" {
			continue
		}
		var shape struct {
			Evidence struct {
				ReviewedAt string `json:"reviewedAt"`
			} `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			t.Fatal("rule evidence")
		}
		reviewed, err := time.Parse(time.RFC3339, shape.Evidence.ReviewedAt)
		if err != nil {
			t.Fatal(err)
		}
		if candidate := reviewed.Add(time.Minute); candidate.After(latest) {
			latest = candidate
		}
	}
	return latest
}
