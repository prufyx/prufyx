// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// These tests use synthetic consensus, lead and mechanical rules that are
// never published; the embedded pack carries only reviewed rules.

const containerdShimFact = "component.containerd.selected_runtime_uses_removed_official_shim"

// containerdBasisEntry renders a synthetic containerd 1.7.28 -> 2.0.0 rule
// with an evidence basis. A non-empty fact makes it forbid_predicate_value
// over that fact; otherwise it is forbid_target_version.
func containerdBasisEntry(id, basis, fact string) Entry {
	operator, extra, facts := "forbid_target_version", "", []Fact{}
	if fact != "" {
		operator = "forbid_predicate_value"
		extra = `,"condition":{"side":"proposed","component":"` + containerdComponent + `","factId":"` + fact + `","boolValue":true}`
		facts = []Fact{{Side: "proposed", ID: fact, Component: containerdComponent, Type: constraintengine.FactBool, Description: "The selected runtime uses a removed official shim."}}
	}
	provenance := ""
	switch basis {
	case "":
	case constraintengine.BasisMechanical:
		provenance = `"basis":"mechanical","extractor":{"id":"synthetic-extractor","version":"1.0.0","codeDigest":"sha256:` + strings.Repeat("1", 64) + `"},"derivedAt":"2026-09-01T00:00:00Z",`
	default:
		provenance = `"basis":"` + basis + `","derivedAt":"2026-09-01T00:00:00Z",`
	}
	rule := `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"` + containerdComponent + `","from":"1.7.28","to":"2.0.0"}` + extra +
		`,"evidence":{` + provenance + `"state":"active","reviewedAt":"2026-09-01T00:00:00Z","validUntil":"2026-11-01T00:00:00Z","sources":[{"id":"synthetic-source","url":"https://github.com/containerd/containerd/blob/` + syntheticRevision + `/RELEASES.md","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"plan the reviewed containerd route"}`
	return Entry{Project: "containerd", Description: "Synthetic test-only containerd rule.", RequiredFacts: facts, Rule: json.RawMessage(rule)}
}

func mustPolicy(t *testing.T, list string) TrustPolicy {
	t.Helper()
	policy, err := ParseTrustPolicy(list)
	if err != nil {
		t.Fatalf("policy %q: %v", list, err)
	}
	return policy
}

func TestTrustPolicyParse(t *testing.T) {
	if got := (TrustPolicy{}).String(); got != "reviewed,mechanical,empirical,consensus" || got != DefaultTrustPolicy().String() {
		t.Fatalf("default=%q", got)
	}
	if (TrustPolicy{}).Admits(constraintengine.BasisLead) || !(TrustPolicy{}).Admits("") || !(TrustPolicy{}).Admits(constraintengine.BasisConsensus) {
		t.Fatal("default admissions")
	}
	if got := mustPolicy(t, "lead,reviewed").String(); got != "reviewed,lead" {
		t.Fatalf("order=%q", got)
	}
	if policy := mustPolicy(t, "reviewed"); !policy.Admits("") || policy.Admits(constraintengine.BasisMechanical) {
		t.Fatal("an absent basis is reviewed")
	}
	for _, bad := range []string{"", ",", "reviewed,", "reviewed,reviewed", "Reviewed", "reviewed, mechanical", "model", "any", strings.Repeat("reviewed,", 40)} {
		if _, err := ParseTrustPolicy(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestPackBasisLevel(t *testing.T) {
	entry := containerdBasisEntry("containerd.synthetic-consensus", constraintengine.BasisConsensus, "")
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaBasis, nil, entry), nil); err != nil {
		t.Fatalf("consensus pack under the basis schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, "prufyx.io/cncf-source-rule-pack/v1alpha8"} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("consensus pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaBasis, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("basis schema without a consensus or lead rule accepted")
	}
	// A lead rule is validated at load even though the default policy never
	// evaluates it.
	lead := containerdBasisEntry("containerd.synthetic-lead", constraintengine.BasisLead, "")
	broken := lead
	broken.Rule = json.RawMessage(strings.Replace(string(lead.Rule), `"derivedAt":"2026-09-01T00:00:00Z",`, "", 1))
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaBasis, nil, broken), nil); err == nil {
		t.Fatal("a lead rule without derivedAt was admitted")
	}
	// Empirical rules keep the lower levels.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaRanged, nil, containerdBasisEntry("containerd.synthetic-empirical", constraintengine.BasisEmpirical, "")), nil); err != nil {
		t.Fatalf("empirical rule under the original schema refused: %v", err)
	}
}

// basisBundle is the embedded pack plus synthetic containerd rules.
func basisBundle(t *testing.T, entries ...Entry) bundle {
	t.Helper()
	schema := packSchemaRanged
	for _, entry := range entries {
		if basis, _ := constraintengine.RawRuleBasis(entry.Rule); basis == constraintengine.BasisConsensus || basis == constraintengine.BasisLead {
			schema = packSchemaBasis
		}
	}
	b, err := assembleSynthetic(syntheticPack(t, schema, nil, entries...), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evaluateSelection(t *testing.T, b bundle, policy TrustPolicy, selector string, inputRaw []byte) Report {
	t.Helper()
	b.policy = policy
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	var selected selection
	switch selector {
	case "generic":
		selected, err = b.selectForInput("containerd", inputRaw)
	case "family":
		selected, err = b.selectFamily("containerd", []string{containerdShimFact}, inputRaw)
	default:
		selected, err = b.selectRule("containerd", selector)
	}
	if err != nil {
		t.Fatal(err)
	}
	report, err := b.reportSelection("containerd", "", selector == "family", input, selected, inputRaw, mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("report refused: %v", err)
	}
	return report
}

func claimByID(report Report, id string) (constraintengine.Claim, bool) {
	for _, claim := range report.Check.Claims {
		if claim.RuleID == id {
			return claim, true
		}
	}
	return constraintengine.Claim{}, false
}

func TestTrustPolicySelection(t *testing.T) {
	consensusBlock := containerdBasisEntry("containerd.synthetic-a-consensus-block", constraintengine.BasisConsensus, "")
	consensusQuiet := containerdBasisEntry("containerd.synthetic-b-consensus-quiet", constraintengine.BasisConsensus, containerdShimFact)
	lead := containerdBasisEntry("containerd.synthetic-c-lead", constraintengine.BasisLead, "")
	mechanical := containerdBasisEntry("containerd.synthetic-d-mechanical", constraintengine.BasisMechanical, containerdShimFact)
	input := containerdInput(t)

	// Default policy: consensus evaluated, lead left out and counted apart.
	b := basisBundle(t, consensusQuiet, lead, mechanical)
	report := evaluateSelection(t, b, TrustPolicy{}, "generic", input)
	if claim, ok := claimByID(report, ruleID(t, consensusQuiet)); !ok || claim.Status != constraintengine.StatusNoKnownIssue {
		t.Fatalf("consensus claim=%+v", claim)
	}
	if _, ok := claimByID(report, ruleID(t, lead)); ok {
		t.Fatal("default policy evaluated a lead")
	}
	if claim, ok := claimByID(report, ruleID(t, mechanical)); !ok || claim.Status != "PASS" {
		t.Fatalf("mechanical claim=%+v", claim)
	}
	if !reflect.DeepEqual(report.TrustPolicy, &TrustPolicyDisclosure{RequiredBasis: DefaultTrustPolicy().Bases(), ExcludedRules: 0, ExcludedLeadRules: 1}) {
		t.Fatalf("disclosure=%+v", report.TrustPolicy)
	}
	if ClaimExit(report) != 11 {
		t.Fatalf("NO_KNOWN_ISSUE beside passes exits %d", ClaimExit(report))
	}

	// reviewed only: mechanical and consensus left out; the remaining
	// reviewed rules all pass, and the check still cannot pass.
	reviewedOnly := evaluateSelection(t, b, mustPolicy(t, "reviewed"), "generic", input)
	for _, claim := range reviewedOnly.Check.Claims {
		if claim.EvidenceBasis != "" || claim.Status != "PASS" {
			t.Fatalf("claim=%+v", claim)
		}
	}
	if reviewedOnly.TrustPolicy == nil || reviewedOnly.TrustPolicy.ExcludedRules != 2 || reviewedOnly.TrustPolicy.ExcludedLeadRules != 1 || ClaimExit(reviewedOnly) != 11 {
		t.Fatalf("disclosure=%+v exit=%d", reviewedOnly.TrustPolicy, ClaimExit(reviewedOnly))
	}
	if raw, _ := MarshalReport(reviewedOnly); !bytes.Contains(raw, []byte(`"trustPolicy":{"requiredBasis":["reviewed"],"excludedRules":2,"excludedLeadRules":1}`)) {
		t.Fatalf("json=%s", raw)
	}

	// Lead admitted: NOTICE, neutral for the exit code.
	withLead := evaluateSelection(t, basisBundle(t, lead), mustPolicy(t, "reviewed,mechanical,empirical,consensus,lead"), "generic", input)
	if claim, ok := claimByID(withLead, ruleID(t, lead)); !ok || claim.Status != constraintengine.StatusNotice || claim.ReasonCode != constraintengine.ReasonLeadNotVerified {
		t.Fatalf("lead claim=%+v", claim)
	}
	if withLead.TrustPolicy != nil || ClaimExit(withLead) != 0 {
		t.Fatalf("lead changed the exit: %d %+v", ClaimExit(withLead), withLead.TrustPolicy)
	}

	// Consensus blocks.
	blocked := evaluateSelection(t, basisBundle(t, consensusBlock), TrustPolicy{}, "generic", input)
	if ClaimExit(blocked) != 10 {
		t.Fatalf("consensus BLOCKED exits %d", ClaimExit(blocked))
	}

	// A selected rule the policy leaves out yields no claim, not another.
	selected := evaluateSelection(t, b, mustPolicy(t, "reviewed"), ruleID(t, mechanical), input)
	if len(selected.Check.Claims) != 0 || selected.TrustPolicy == nil || selected.TrustPolicy.ExcludedRules != 1 || ClaimExit(selected) != 11 {
		t.Fatalf("selected=%+v %+v", selected.Check.Claims, selected.TrustPolicy)
	}
	// The fact family counts only its own rules.
	family := evaluateSelection(t, b, mustPolicy(t, "reviewed"), "family", input)
	if family.TrustPolicy == nil || family.TrustPolicy.ExcludedRules != 2 || ClaimExit(family) != 11 {
		t.Fatalf("family=%+v", family.TrustPolicy)
	}
	for _, claim := range family.Check.Claims {
		if claim.EvidenceBasis != "" {
			t.Fatalf("family claim=%+v", claim)
		}
	}

	// A matching rule the policy leaves out is reported as left out, never
	// replaced by the other pairs' rules.
	other := strings.NewReplacer(`"version":"1.7.28"`, `"version":"1.7.0"`, `"version":"2.0.0"`, `"version":"1.8.0"`).Replace(string(input))
	otherPair := containerdBasisEntry("containerd.synthetic-e-other-pair", constraintengine.BasisMechanical, "")
	otherPair.Rule = json.RawMessage(strings.Replace(string(otherPair.Rule), `"from":"1.7.28","to":"2.0.0"`, `"from":"1.7.0","to":"1.8.0"`, 1))
	if fallback := evaluateSelection(t, basisBundle(t, otherPair), TrustPolicy{}, "generic", []byte(other)); len(fallback.Check.Claims) != 1 || fallback.Check.Claims[0].Status != "BLOCKED" {
		t.Fatalf("default selection=%+v", fallback.Check.Claims)
	}
	narrowed := evaluateSelection(t, basisBundle(t, otherPair), mustPolicy(t, "reviewed"), "generic", []byte(other))
	if len(narrowed.Check.Claims) != 0 || narrowed.TrustPolicy == nil || narrowed.TrustPolicy.ExcludedRules != 1 {
		t.Fatalf("narrowed claims=%d disclosure=%+v", len(narrowed.Check.Claims), narrowed.TrustPolicy)
	}

	// A matching lead alone never narrows the selection: the pair has no
	// verdict rule, so every containerd rule is reported, as without it.
	otherLead := containerdBasisEntry("containerd.synthetic-f-other-lead", constraintengine.BasisLead, "")
	otherLead.Rule = json.RawMessage(strings.Replace(string(otherLead.Rule), `"from":"1.7.28","to":"2.0.0"`, `"from":"1.7.0","to":"1.8.0"`, 1))
	leadPolicy := mustPolicy(t, "reviewed,lead")
	withOtherLead := evaluateSelection(t, basisBundle(t, otherLead), leadPolicy, "generic", []byte(other))
	withoutLead := evaluateSelection(t, testBundle(t), leadPolicy, "generic", []byte(other))
	if len(withoutLead.Check.Claims) == 0 || len(withOtherLead.Check.Claims) != len(withoutLead.Check.Claims)+1 {
		t.Fatalf("lead narrowed the selection: %d vs %d claims", len(withOtherLead.Check.Claims), len(withoutLead.Check.Claims))
	}

	// In a fallback selection only a lead that matches the transition is
	// counted as left out; a lead for another transition is not.
	unrelated := evaluateSelection(t, basisBundle(t, lead), TrustPolicy{}, "generic", []byte(other))
	if unrelated.TrustPolicy != nil {
		t.Fatalf("a lead for another transition was counted: %+v", unrelated.TrustPolicy)
	}
	related := evaluateSelection(t, basisBundle(t, otherLead), TrustPolicy{}, "generic", []byte(other))
	if related.TrustPolicy == nil || related.TrustPolicy.ExcludedLeadRules != 1 || related.TrustPolicy.ExcludedRules != 0 {
		t.Fatalf("matching lead not counted: %+v", related.TrustPolicy)
	}
	if !reflect.DeepEqual(unrelated.Check.Claims, related.Check.Claims) {
		t.Fatal("fallback verdict claims differ")
	}
	familyUnrelated := evaluateSelection(t, basisBundle(t, containerdBasisEntry("containerd.synthetic-g-lead-fact", constraintengine.BasisLead, containerdShimFact)), TrustPolicy{}, "family", []byte(other))
	if familyUnrelated.TrustPolicy != nil {
		t.Fatalf("family counted a lead for another transition: %+v", familyUnrelated.TrustPolicy)
	}

	// The default policy over a pack without consensus or lead rules is
	// exactly today's report.
	plain := testBundle(t)
	defaultReport := evaluateSelection(t, plain, TrustPolicy{}, "generic", input)
	explicit := evaluateSelection(t, plain, DefaultTrustPolicy(), "generic", input)
	a, _ := MarshalReport(defaultReport)
	c, _ := MarshalReport(explicit)
	if !bytes.Equal(a, c) || bytes.Contains(a, []byte("trustPolicy")) {
		t.Fatal("default policy changed the report")
	}
}

func TestTrustPolicyAndCorpus(t *testing.T) {
	lead := containerdBasisEntry("containerd.synthetic-c-lead", constraintengine.BasisLead, "")
	consensusQuiet := containerdBasisEntry("containerd.synthetic-b-consensus-quiet", constraintengine.BasisConsensus, containerdShimFact)
	now := mustTime(t, "2026-09-20T00:00:00Z")
	attest := func(b bundle) []byte {
		t.Helper()
		inventory, err := b.unfilteredCorpus()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(Attestation{
			Schema: CorpusAttestationSchema, Attestation: constraintengine.CorpusAttestation,
			Revision: inventory.Revision, PackDigest: inventory.PackDigest, RuleSetDigest: inventory.RuleSetDigest,
			RuleCount: inventory.RuleCount, Components: inventory.Components, Limitations: AttestationLimitations(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	assess := func(b bundle, policy TrustPolicy, attestation []byte) ScopeReport {
		t.Helper()
		b.policy = policy
		report, err := assessScopeWith(b, attestation, containerdInput(t), now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarshalScopeReport(report); err != nil {
			t.Fatalf("scope report refused: %v", err)
		}
		return report
	}
	// Leaving out only leads keeps the attestation: leads never support it.
	withLead := basisBundle(t, lead)
	report := assess(withLead, TrustPolicy{}, attest(withLead))
	if report.Assessment != constraintengine.AssessmentScopeCompletePass || report.TrustPolicy == nil || report.TrustPolicy.ExcludedLeadRules != 1 || report.TrustPolicy.ExcludedRules != 0 {
		t.Fatalf("assessment=%s disclosure=%+v", report.Assessment, report.TrustPolicy)
	}
	// Admitting the lead changes nothing either.
	admitted := assess(withLead, mustPolicy(t, "reviewed,mechanical,empirical,consensus,lead"), attest(withLead))
	if admitted.Assessment != constraintengine.AssessmentScopeCompletePass || admitted.Check.ScopeCompleteness.LeadRules != 1 {
		t.Fatalf("assessment=%s scope=%+v", admitted.Assessment, admitted.Check.ScopeCompleteness)
	}
	// A consensus rule that finds nothing keeps the scope UNKNOWN.
	withConsensus := basisBundle(t, consensusQuiet)
	quiet := assess(withConsensus, TrustPolicy{}, attest(withConsensus))
	if quiet.Assessment != constraintengine.AssessmentUnknown || quiet.Check.ScopeCompleteness == nil || quiet.Check.ScopeCompleteness.UnresolvedReason != "CONSENSUS_ONLY_SCOPE" {
		t.Fatalf("assessment=%s scope=%+v", quiet.Assessment, quiet.Check.ScopeCompleteness)
	}
	// Leaving out a verdict rule drops the attestation: no scope block, and
	// the aggregate is UNKNOWN even though every remaining rule passes.
	dropped := assess(withConsensus, mustPolicy(t, "reviewed,mechanical"), attest(withConsensus))
	if dropped.Assessment != constraintengine.AssessmentUnknown || dropped.Check.ScopeCompleteness != nil || dropped.TrustPolicy == nil || dropped.TrustPolicy.ExcludedRules != 1 {
		t.Fatalf("assessment=%s scope=%+v disclosure=%+v", dropped.Assessment, dropped.Check.ScopeCompleteness, dropped.TrustPolicy)
	}
	for _, claim := range dropped.Check.Claims {
		if claim.EvidenceBasis == constraintengine.BasisConsensus {
			t.Fatal("excluded consensus rule evaluated")
		}
	}
}

// TestPolicyAppliedEverywhere: every exported evaluation entry applies the
// trust policy. The embedded pack holds only reviewed rules, so a policy
// that admits only mechanical rules must leave every one of them out, on
// every entry, and none may exit 0.
func TestPolicyAppliedEverywhere(t *testing.T) {
	policy := mustPolicy(t, "mechanical")
	checker := WithTrustPolicy(policy)
	now := mustTime(t, "2026-09-20T00:00:00Z")
	input := containerdInput(t)
	const containerdRule = "containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0"
	check := func(name string, report Report, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if report.TrustPolicy == nil || report.TrustPolicy.ExcludedRules == 0 || !reflect.DeepEqual(report.TrustPolicy.RequiredBasis, []string{"mechanical"}) {
			t.Fatalf("%s: policy not applied: %+v", name, report.TrustPolicy)
		}
		if len(report.Check.Claims) != 0 || ClaimExit(report) == 0 || report.NextAction != trustPolicyNextAction {
			t.Fatalf("%s: claims=%d exit=%d next=%q", name, len(report.Check.Claims), ClaimExit(report), report.NextAction)
		}
	}
	report, err := checker.Check("containerd", input, now)
	check("Check", report, err)
	report, err = checker.CheckRule("containerd", containerdRule, input, now)
	check("CheckRule", report, err)
	report, err = checker.CheckFacts("containerd", []string{containerdShimFact, "component.containerd.official_bundled_runtimes_only", "component.containerd.official_upstream_distribution", "component.containerd.cri_api"}, input, now)
	check("CheckFacts", report, err)
	original, err := checker.Check("containerd", input, now)
	if err != nil {
		t.Fatal(err)
	}
	originalRaw, _ := MarshalReport(original)
	report, err = checker.Replay("containerd", input, now, append(originalRaw, '\n'))
	check("Replay", report, err)
	// A replay under another policy does not match.
	if _, err := Replay("containerd", input, now, append(originalRaw, '\n')); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replay under the default policy matched: %v", err)
	}
	scope, err := checker.AssessScope(input, now)
	if err != nil {
		t.Fatal(err)
	}
	if scope.TrustPolicy == nil || scope.TrustPolicy.ExcludedRules == 0 || scope.Assessment != constraintengine.AssessmentUnknown || scope.Check.ScopeCompleteness != nil {
		t.Fatalf("AssessScope: assessment=%s disclosure=%+v", scope.Assessment, scope.TrustPolicy)
	}
	exported, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	external, err := ParseExternalBundle(exported)
	if err != nil {
		t.Fatal(err)
	}
	report, err = external.WithTrustPolicy(policy).Evaluate("containerd", input, now)
	check("ExternalBundle.Evaluate", report, err)
	report, err = external.WithTrustPolicy(policy).EvaluateRule("containerd", containerdRule, input, now)
	check("ExternalBundle.EvaluateRule", report, err)

	// The zero checker is the package-level entry, byte for byte, and the
	// default policy leaves nothing out of the embedded pack.
	defaultScope, err := AssessScope(input, now)
	if err != nil || defaultScope.Assessment != constraintengine.AssessmentScopeCompletePass || defaultScope.TrustPolicy != nil {
		t.Fatalf("default scope=%s %+v %v", defaultScope.Assessment, defaultScope.TrustPolicy, err)
	}
	for name, pair := range map[string][2]func() (Report, error){
		"Check": {func() (Report, error) { return Check("containerd", input, now) }, func() (Report, error) { return Checker{}.Check("containerd", input, now) }},
		"CheckRule": {func() (Report, error) { return CheckRule("containerd", containerdRule, input, now) }, func() (Report, error) {
			return WithTrustPolicy(DefaultTrustPolicy()).CheckRule("containerd", containerdRule, input, now)
		}},
		"External": {func() (Report, error) { return external.Evaluate("containerd", input, now) }, func() (Report, error) {
			return external.WithTrustPolicy(TrustPolicy{}).Evaluate("containerd", input, now)
		}},
	} {
		left, err := pair[0]()
		if err != nil {
			t.Fatal(err)
		}
		right, err := pair[1]()
		if err != nil {
			t.Fatal(err)
		}
		l, _ := MarshalReport(left)
		r, _ := MarshalReport(right)
		if !bytes.Equal(l, r) || bytes.Contains(l, []byte("trustPolicy")) || ClaimExit(left) != 0 {
			t.Fatalf("%s: default policy changed the report (exit %d)", name, ClaimExit(left))
		}
	}
}

func TestTrustPolicyDisclosureIntegrity(t *testing.T) {
	report, err := WithTrustPolicy(mustPolicy(t, "mechanical")).Check("containerd", containerdInput(t), mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	reseal := func(r Report) Report {
		r.seal = &reportSeal{}
		raw, _ := json.Marshal(r)
		r.digest = digest(raw)
		return r
	}
	if _, err := MarshalReport(reseal(report)); err != nil {
		t.Fatal(err)
	}
	for name, disclosure := range map[string]*TrustPolicyDisclosure{
		"zero count":     {RequiredBasis: []string{"mechanical"}},
		"negative count": {RequiredBasis: []string{"mechanical"}, ExcludedRules: -1, ExcludedLeadRules: 2},
		"no bases":       {ExcludedRules: 1},
		"unknown basis":  {RequiredBasis: []string{"model"}, ExcludedRules: 1},
		"unordered":      {RequiredBasis: []string{"mechanical", "reviewed"}, ExcludedRules: 1},
		"duplicate":      {RequiredBasis: []string{"mechanical", "mechanical"}, ExcludedRules: 1},
	} {
		forged := report
		forged.TrustPolicy = disclosure
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Dropping the disclosure would hide the exclusion from ClaimExit; the
	// seal of the issued report refuses the edit.
	stripped := report
	stripped.TrustPolicy = nil
	if _, err := MarshalReport(stripped); err == nil {
		t.Fatal("unsealed edit accepted")
	}
}

func TestClaimExitBasis(t *testing.T) {
	b := testBundle(t)
	inputRaw := noticeInput()
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	const reviewed, until = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	withBasis := func(rule, basis string) string {
		return strings.Replace(rule, `"evidence":{"state":`, `"evidence":{"basis":"`+basis+`","derivedAt":"`+reviewed+`","state":`, 1)
	}
	pass := syntheticKubernetesRule("kubernetes.synthetic-a-pass", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"1.37.0"}`, reviewed, until)
	blocked := syntheticKubernetesRule("kubernetes.synthetic-b-blocked", "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "", reviewed, until)
	consensusPass := withBasis(strings.Replace(pass, "synthetic-a-pass", "synthetic-c-consensus", 1), constraintengine.BasisConsensus)
	consensusBlock := withBasis(strings.Replace(blocked, "synthetic-b-blocked", "synthetic-d-consensus-block", 1), constraintengine.BasisConsensus)
	leadBlock := withBasis(strings.Replace(blocked, "synthetic-b-blocked", "synthetic-e-lead", 1), constraintengine.BasisLead)
	leadPass := withBasis(strings.Replace(pass, "synthetic-a-pass", "synthetic-f-lead-pass", 1), constraintengine.BasisLead)
	b.policy = mustPolicy(t, "reviewed,consensus,lead")
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		rules []string
		exit  int
	}{
		{"pass", []string{pass}, 0},
		{"pass and consensus NO_KNOWN_ISSUE", []string{pass, consensusPass}, 11},
		{"only consensus NO_KNOWN_ISSUE", []string{consensusPass}, 11},
		{"consensus BLOCKED", []string{pass, consensusBlock}, 10},
		{"pass and lead NOTICE", []string{pass, leadBlock}, 0},
		{"pass and lead NO_KNOWN_ISSUE", []string{pass, leadPass}, 0},
		{"only leads", []string{leadBlock, leadPass}, 11},
		{"lead and blocker", []string{blocked, leadBlock}, 10},
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

// TestExternalPackRefusesBasis: the external knowledge target does not
// accept consensus or lead rules yet, even under the basis pack schema.
func TestExternalPackRefusesBasis(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, basis := range []string{constraintengine.BasisConsensus, constraintengine.BasisLead} {
		pack := base.pack
		pack.Entries = []Entry{containerdBasisEntry("containerd.synthetic-basis", basis, "")}
		pack.Schema = packSchemaBasis
		if err := validateExternalPack(base, pack, pack.Revision); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: external pack accepted: %v", basis, err)
		}
	}
	// An empirical rule is admitted.
	pack := base.pack
	pack.Entries = []Entry{containerdBasisEntry("containerd.synthetic-empirical", constraintengine.BasisEmpirical, "")}
	pack.Schema = packSchema
	if err := validateExternalPack(base, pack, pack.Revision); err != nil {
		t.Fatalf("empirical external pack refused: %v", err)
	}
}

// TestCorpusInventorySkipsLeadOnlyComponents: the inventory an attestation
// is built from leaves out a component whose only rule is a lead, so the
// generated attestation still binds and admits.
func TestCorpusInventorySkipsLeadOnlyComponents(t *testing.T) {
	const aeraki = "pkg:github/aeraki-mesh/aeraki"
	lead := containerdBasisEntry("aeraki-mesh.synthetic-lead", constraintengine.BasisLead, "")
	lead.Project = "aeraki-mesh"
	lead.Rule = json.RawMessage(strings.NewReplacer(containerdComponent, aeraki, "github.com/containerd/containerd", "github.com/aeraki-mesh/aeraki").Replace(string(lead.Rule)))
	b := basisBundle(t, lead)
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range inventory.Components {
		if component == aeraki {
			t.Fatal("a lead-only component is in the corpus inventory")
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
	for _, policy := range []TrustPolicy{{}, mustPolicy(t, "reviewed,lead")} {
		b.policy = policy
		if _, _, err := b.attestedSelection(attestation); err != nil {
			t.Fatalf("policy %s: attestation over a pack with a lead-only component refused: %v", policy, err)
		}
	}
}

// TestScopeReportDisclosureIntegrity: a scope report's disclosure is checked
// like a check report's.
func TestScopeReportDisclosureIntegrity(t *testing.T) {
	report, err := WithTrustPolicy(mustPolicy(t, "mechanical")).AssessScope(containerdInput(t), mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	reseal := func(r ScopeReport) ScopeReport {
		r.seal = &reportSeal{}
		raw, _ := json.Marshal(r)
		r.digest = digest(raw)
		return r
	}
	if _, err := MarshalScopeReport(reseal(report)); err != nil {
		t.Fatal(err)
	}
	for name, disclosure := range map[string]*TrustPolicyDisclosure{
		"zero count":    {RequiredBasis: []string{"mechanical"}},
		"unknown basis": {RequiredBasis: []string{"model"}, ExcludedRules: 1},
		"unordered":     {RequiredBasis: []string{"mechanical", "reviewed"}, ExcludedRules: 1},
	} {
		forged := report
		forged.TrustPolicy = disclosure
		if _, err := MarshalScopeReport(reseal(forged)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
