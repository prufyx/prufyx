// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// These tests attach synthetic line attestations to the embedded pack's own
// rules. The embedded pack carries none and stays byte-identical.

const k8sComponent = "pkg:github/kubernetes/kubernetes"

// line125Rules are the rules of the 1.25 line in the ascending order a line
// attestation lists them (the order depends on which ids the pack carries).
var line125Rules = sortedIDs(
	supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.endpointslice-v1beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.event-v1beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0"),
	supersedeids.ID("kubernetes.runtimeclass-v1beta1-removed.1-24-0-to-1-25-0"),
)

func sortedIDs(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

func testAttestation(line string, ids []string) lineattest.LineAttestation {
	return lineattest.LineAttestation{
		Component: k8sComponent, Line: line, FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, Completeness: lineattest.Completeness,
		RuleIDs: append([]string{}, ids...),
		Evidence: lineattest.Evidence{Basis: constraintengine.BasisReviewed, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "deprecation-guide", URL: "https://github.com/kubernetes/website/blob/" + syntheticRevision + "/content/en/docs/reference/using-api/deprecation-guide.md", Revision: syntheticRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}}},
	}
}

// attestedPack is the embedded pack with schema and a raw attestation
// section.
func attestedPack(t *testing.T, schema string, section []byte) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Schema, pack.LineAttestations = schema, section
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func section(t *testing.T, atts ...lineattest.LineAttestation) []byte {
	t.Helper()
	raw, err := lineattest.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validAttestations(t *testing.T) []byte {
	return section(t, testAttestation("1.25", line125Rules), testAttestation("1.30", nil))
}

func TestEmbeddedPackCarriesNoLineAttestations(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("lineAttestations")) {
		t.Fatal("the published pack carries line attestations")
	}
	got, err := AttestationsFor(k8sComponent, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(got) != 0 {
		t.Fatalf("embedded attestations: %v %v", got, err)
	}
}

func TestAttestedPackIsAdmittedAndLookedUp(t *testing.T) {
	b, err := assembleSynthetic(attestedPack(t, packSchemaAttested, validAttestations(t)), nil)
	if err != nil {
		t.Fatalf("attested pack refused: %v", err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	got := b.attestations.AttestationsFor(k8sComponent, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, now)
	if len(got) != 1 || !got[0].Current() || len(got[0].Attestation.RuleIDs) != 7 {
		t.Fatalf("1.25: %+v", got)
	}
	quiet := b.attestations.AttestationsFor(k8sComponent, "1.30", lineattest.FamilyKubernetesRemovedServedGVK, now)
	if len(quiet) != 1 || quiet[0].Attestation.RuleIDs == nil || len(quiet[0].Attestation.RuleIDs) != 0 {
		t.Fatalf("quiet line: %+v", quiet)
	}
	if got := b.attestations.AttestationsFor(k8sComponent, "1.28", lineattest.FamilyKubernetesRemovedServedGVK, now); len(got) != 0 {
		t.Fatal("unattested line returned an attestation")
	}
	stale := b.attestations.AttestationsFor(k8sComponent, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(stale) != 1 || stale[0].Current() || stale[0].Freshness != lineattest.FreshnessStale {
		t.Fatalf("expired attestation: %+v", stale)
	}
	// The attestations take no part in the rules the engine sees.
	plain, err := assembleSynthetic(attestedPack(t, packSchemaRanged, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := b.ruleSet("")
	p, _ := plain.ruleSet("")
	da, _ := a.Digest()
	dp, _ := p.Digest()
	if da != dp {
		t.Fatal("attestations changed the engine rule document")
	}
}

func TestLineAttestationSchemaGating(t *testing.T) {
	atts := validAttestations(t)
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, "prufyx.io/cncf-source-rule-pack/v1alpha5"} {
		if _, err := assembleSynthetic(attestedPack(t, schema, atts), nil); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("attestations under %s accepted: %v", schema, err)
		}
	}
	if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("the attested schema without attestations accepted")
	}
	for name, raw := range map[string]string{"null": "null", "empty": "[]", "object": "{}"} {
		pack := attestedPack(t, packSchemaRanged, nil)
		pack = bytes.Replace(pack, []byte(`"entries":`), []byte(`"lineAttestations":`+raw+`,"entries":`), 1)
		if _, err := assembleSynthetic(pack, nil); err == nil {
			t.Fatalf("lineAttestations %s accepted under the ranged schema", name)
		}
		pack = attestedPack(t, packSchemaAttested, nil)
		pack = bytes.Replace(pack, []byte(`"entries":`), []byte(`"lineAttestations":`+raw+`,"entries":`), 1)
		if _, err := assembleSynthetic(pack, nil); err == nil {
			t.Fatalf("lineAttestations %s accepted under the attested schema", name)
		}
	}
	// A binary that predates attestations decodes the pack into the
	// previous pack shape, strictly: the new section fails it closed.
	type previousPack struct {
		Schema              string  `json:"schema"`
		Revision            string  `json:"revision"`
		PolicyID            string  `json:"policyId"`
		PolicyDigest        string  `json:"policyDigest"`
		LandscapeFileDigest string  `json:"landscapeFileDigest"`
		RegistryDigest      string  `json:"registryDigest"`
		Entries             []Entry `json:"entries"`
	}
	var old previousPack
	if err := strictJSON(attestedPack(t, packSchemaAttested, atts), &old); err == nil {
		t.Fatal("the previous pack shape admits an attested pack")
	}
	if err := strictJSON(attestedPack(t, packSchemaRanged, nil), &old); err != nil {
		t.Fatalf("the previous pack shape refuses a pack without attestations: %v", err)
	}
}

func TestPackRejectsAttestationThatIsNotTheExactRuleSet(t *testing.T) {
	missing := line125Rules[:6]
	extra := append(append([]string{}, line125Rules...), "kubernetes.zz-not-a-rule")
	otherLine := append(append([]string{}, line125Rules...), supersedeids.ID("kubernetes.flowcontrol-v1beta1-removed.1-25-0-to-1-26-0"))
	sort.Strings(otherLine)
	for name, ids := range map[string][]string{"missing": missing, "extra": extra, "another line": otherLine, "falsely quiet": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, section(t, testAttestation("1.25", ids))), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	malformed := testAttestation("1.25", line125Rules)
	malformed.Evidence.ValidUntil = "2027-06-01T00:00:00Z"
	raw, _ := json.Marshal([]lineattest.LineAttestation{malformed})
	if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, raw), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("an attestation with a window over the policy limit accepted")
	}
}

func TestPackDigestCoversAttestations(t *testing.T) {
	a, err := assembleSynthetic(attestedPack(t, packSchemaAttested, validAttestations(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	later := testAttestation("1.30", nil)
	later.Evidence.ValidUntil = "2026-12-29T00:00:00Z"
	b, err := assembleSynthetic(attestedPack(t, packSchemaAttested, section(t, testAttestation("1.25", line125Rules), later)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.packDigest == b.packDigest {
		t.Fatal("the pack digest does not cover the attestations")
	}
}

func TestExternalBundleRefusesAttestations(t *testing.T) {
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
		t.Fatal(err)
	}
	pack["lineAttestations"] = validAttestations(t)
	pack["schema"], _ = json.Marshal(packSchemaAttested)
	envelope["pack"], _ = json.Marshal(pack)
	tampered, _ := json.Marshal(envelope)
	if _, err := ParseExternalBundle(tampered); err == nil {
		t.Fatal("an external bundle with line attestations was admitted")
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var value rulePack
	if err := json.Unmarshal(envelope["pack"], &value); err != nil {
		t.Fatal(err)
	}
	if err := validateExternalPack(base, value, "7", false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted attestations: %v", err)
	}
}

// The published flowcontrol v1beta3 rule is a range rule in both
// generations of the pack: it matches every hop into 1.32, so a 1.32
// attestation lists it and an attestation leaving it out is a missing rule.
func TestPackAttestationOfTheLineWideFlowControlRule(t *testing.T) {
	id := supersedeids.ID("kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0")
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, entry := range b.pack.Entries {
		if ruleID(t, entry) != id {
			continue
		}
		seen = true
		tr, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Match("1.31.4", "1.32.1") == constraintengine.MatchNone {
			t.Fatal("the 1.32 rule no longer matches every hop into 1.32")
		}
	}
	if !seen {
		t.Fatalf("%s is not in the embedded pack", id)
	}
	if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, section(t, testAttestation("1.32", []string{id}))), nil); err != nil {
		t.Fatalf("complete 1.32 attestation refused: %v", err)
	}
	if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, section(t, testAttestation("1.32", nil))), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("incomplete 1.32 attestation accepted: %v", err)
	}
}

// A rule that matches its anchor pair only cannot be listed by a line
// attestation: a 1.32 attestation listing it would present a hop such as
// 1.31.4 -> 1.32.1 as covered while no rule matches it. The loader refuses
// it, and an attestation leaving it out is a missing rule: 1.32 cannot be
// attested over such a pack. The pack here is the embedded one with the
// reviewed range taken off the 1.32 flow-control rule.
func TestPackRejectsAttestationListingARuleThatIsNotLineWide(t *testing.T) {
	id := supersedeids.ID("kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0")
	pack := anchorOnlyPack(t, id)
	if _, err := assembleSynthetic(withAttestations(t, pack, pack.Schema, nil), nil); err != nil {
		t.Fatalf("the anchor-only pack without attestations is refused: %v", err)
	}
	if _, err := assembleSynthetic(withAttestations(t, pack, packSchemaAttested, section(t, testAttestation("1.29", []string{supersedeids.ID("kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0")}))), nil); err != nil {
		t.Fatalf("an attestation of another line is refused over the anchor-only pack: %v", err)
	}
	for name, ids := range map[string][]string{"listed": {id}, "left out": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := assembleSynthetic(withAttestations(t, pack, packSchemaAttested, section(t, testAttestation("1.32", ids))), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// anchorOnlyPack is the embedded pack with the range of rule id removed. It
// fails the test unless that rule ranged over 1.31.4 -> 1.32.1 before and
// matches it no longer.
func anchorOnlyPack(t *testing.T, id string) rulePack {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	stripped := false
	for i, entry := range pack.Entries {
		if ruleID(t, entry) != id {
			continue
		}
		var rule map[string]json.RawMessage
		if err := json.Unmarshal(entry.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		if _, ranged := rule["range"]; !ranged {
			t.Fatalf("%s has no range", id)
		}
		delete(rule, "range")
		encoded, err := json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		tr, err := constraintengine.RuleTransitionOf(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Match("1.31.4", "1.32.1") != constraintengine.MatchNone {
			t.Fatal("the anchor-only rule still matches every hop into 1.32")
		}
		pack.Entries[i].Rule = encoded
		stripped = true
	}
	if !stripped {
		t.Fatalf("%s is not in the embedded pack", id)
	}
	return pack
}

// withAttestations is pack with schema and a raw attestation section.
func withAttestations(t *testing.T, pack rulePack, schema string, section []byte) []byte {
	t.Helper()
	pack.Schema, pack.LineAttestations = schema, section
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The pack's member names are matched exactly before decoding: encoding/json
// would serve a case or Unicode-folding variant as the attestation section
// while a case-sensitive reader saw no section at all.
func TestPackRejectsVariantSpellingsOfMembers(t *testing.T) {
	good := attestedPack(t, packSchemaAttested, validAttestations(t))
	if _, err := assembleSynthetic(good, nil); err != nil {
		t.Fatalf("unmutated pack refused: %v", err)
	}
	only125 := section(t, testAttestation("1.25", line125Rules))
	variants := map[string][]byte{
		"two spellings": bytes.Replace(good, []byte(`"lineAttestations":`), append(append([]byte(`"lineAttestations":`), only125...), []byte(`,"LineAttestations":`)...), 1),
		"repeated":      bytes.Replace(good, []byte(`"lineAttestations":`), append(append([]byte(`"lineAttestations":`), only125...), []byte(`,"lineAttestations":`)...), 1),
		"other member":  bytes.Replace(good, []byte(`"entries":`), []byte(`"Entries":`), 1),
	}
	for _, alias := range []string{"LineAttestations", "LINEATTESTATIONS", "lineAttestationſ"} {
		variants[alias] = bytes.Replace(good, []byte(`"lineAttestations"`), []byte(`"`+alias+`"`), 1)
	}
	for name, raw := range variants {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, good) {
				t.Fatal("fixture not mutated")
			}
			if _, err := assembleSynthetic(raw, nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("loader accepted: %v", err)
			}
		})
	}
}

// The loader's pack type names exactly the members PackSection allows.
func TestPackMembersMatchThePackType(t *testing.T) {
	var names []string
	typ := reflect.TypeOf(rulePack{})
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	want := append([]string{}, lineattest.PackMembers...)
	sort.Strings(names)
	sort.Strings(want)
	if !slices.Equal(names, want) {
		t.Fatalf("rulePack members %v, lineattest.PackMembers %v", names, want)
	}
}
