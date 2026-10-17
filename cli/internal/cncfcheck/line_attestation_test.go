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
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// These tests attach synthetic line attestations to the rules of
// syntheticBase (the shipped rules without the set rules and without the
// shipped line attestations). The embedded pack stays byte-identical; its
// own line attestations are held by TestEmbeddedPackLineAttestations.

const k8sComponent = "pkg:github/kubernetes/kubernetes"

// publishedKubernetesRules are the Kubernetes lines the embedded pack
// attests, with the number of served-API removal rules each lists (nine lines
// have no removal and an empty list). Changing the set is deliberate.
var publishedKubernetesRules = map[string]int{"1.20": 0, "1.21": 0, "1.22": 13, "1.23": 0, "1.24": 0, "1.25": 7, "1.26": 2, "1.27": 1, "1.28": 0,
	"1.29": 1, "1.30": 0, "1.31": 0, "1.32": 1, "1.33": 1, "1.34": 1, "1.35": 0, "1.36": 0, "1.37": 2}

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

// attestedPack is syntheticBase with schema and a raw attestation section.
func attestedPack(t *testing.T, schema string, section []byte) []byte {
	t.Helper()
	pack := syntheticBase(t)
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

// TestEmbeddedPackLineAttestations: the line attestations the embedded pack
// publishes are exactly the quiet custom-resource lines of the batch
// crdbatchids states (none before the batch ships). The section is located
// by its exact member name and parses strictly; every attestation validates,
// lists exactly the pack's rules of its scope (none), each of them line-wide
// (lineattest.CheckRuleSets finds no problem), is mechanical with the
// custom-resource extractor of its project, cites at least one source, is
// current at the review instant, and is what AttestationsFor returns for its
// scope. The Kubernetes lines attested are exactly the lines of
// publishedKubernetesRules, each listing the mechanical served-API removal
// rules of the pack for it.
func TestEmbeddedPackLineAttestations(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	section, present, err := lineattest.PackSection(raw)
	if err != nil {
		t.Fatal(err)
	}
	var want []crdbatchids.Line
	if crdbatchids.Shipped() {
		want = crdbatchids.Lines()
	}
	if !present || bytes.Contains(raw, []byte("lineAttestations")) != present {
		t.Fatalf("the published pack carries a line attestation section: %v, it must carry the Kubernetes lines", present)
	}
	{
		all, err := lineattest.Parse(section)
		if err != nil {
			t.Fatal(err)
		}
		if err := lineattest.Validate(all); err != nil {
			t.Fatal(err)
		}
		// The Kubernetes attestations are checked against the stated set;
		// the rest are the custom-resource batch's.
		var atts []lineattest.LineAttestation
		gotRules := map[string]int{}
		for _, a := range all {
			if a.Component == k8sComponent {
				gotRules[a.Line] = len(a.RuleIDs)
				continue
			}
			atts = append(atts, a)
		}
		if !reflect.DeepEqual(gotRules, publishedKubernetesRules) {
			t.Fatalf("attested Kubernetes lines and rule counts %v, want %v", gotRules, publishedKubernetesRules)
		}
		if len(atts) != len(want) {
			t.Fatalf("%d custom-resource line attestations, the batch states %d", len(atts), len(want))
		}
		var rules []json.RawMessage
		known := map[string]bool{}
		for _, entry := range shippedPack(t).Entries {
			rules = append(rules, entry.Rule)
			var rule struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(entry.Rule, &rule); err != nil {
				t.Fatal(err)
			}
			known[rule.ID] = true
		}
		if problems, err := lineattest.CheckRuleSets(all, rules); err != nil || len(problems) != 0 {
			t.Fatalf("published line attestations do not list the pack's rules: %v %v", problems, err)
		}
		for _, a := range all {
			if a.Component != k8sComponent {
				continue
			}
			if a.FactFamily != lineattest.FamilyKubernetesRemovedServedGVK || a.RuleIDs == nil || a.Evidence.Basis != constraintengine.BasisMechanical || a.Evidence.Extractor == nil || len(a.Evidence.Sources) == 0 {
				t.Fatalf("published Kubernetes attestation %s is not a mechanical attestation: %+v", a.Key(), a.Evidence)
			}
			for _, id := range a.RuleIDs {
				if !known[id] || !strings.HasPrefix(id, "kubernetes.served-api-removal.") {
					t.Fatalf("line %s lists %q, which is not a mechanical rule of the pack", a.Line, id)
				}
			}
			got, err := AttestationsFor(a.Component, a.Line, a.FactFamily, now)
			if err != nil || len(got) != 1 || !got[0].Current() || !reflect.DeepEqual(got[0].Attestation, a) {
				t.Fatalf("lookup of %s: %+v %v", a.Key(), got, err)
			}
		}
		for i, a := range atts {
			if a.Component != want[i].Component || a.Line != want[i].Line || a.FactFamily != crdbatchids.FactFamily || a.Completeness != lineattest.Completeness || a.RuleIDs == nil || len(a.RuleIDs) != 0 {
				t.Fatalf("published attestation %d %+v, the batch states %+v", i, a.Key(), want[i])
			}
			project, ok := customResourceProjectOf(a.Component)
			if a.Evidence.Basis != constraintengine.BasisMechanical || a.Evidence.Extractor == nil || !ok || a.Evidence.Extractor.ID != "crd.version-removal."+project || len(a.Evidence.Sources) == 0 {
				t.Fatalf("published attestation %s is not a mechanical custom-resource attestation: %+v", a.Key(), a.Evidence)
			}
			got, err := AttestationsFor(a.Component, a.Line, a.FactFamily, now)
			if err != nil || len(got) != 1 || !got[0].Current() || !reflect.DeepEqual(got[0].Attestation, a) {
				t.Fatalf("lookup of %s: %+v %v", a.Key(), got, err)
			}
		}
	}
	found, err := AttestationsFor(k8sComponent, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, now)
	if err != nil || len(found) != 1 || len(found[0].Attestation.RuleIDs) != 7 {
		t.Fatalf("1.25 must be attested with its seven removals: %v %v", found, err)
	}
}

// customResourceProjectOf is the slug of the custom-resource project whose
// component is component.
func customResourceProjectOf(component string) (string, bool) {
	for _, p := range customresources.Projects() {
		if p.Component == component {
			return p.Slug, true
		}
	}
	return "", false
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
	raw := syntheticBaseExternalBundle(t, "7")
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

// The published flowcontrol v1beta3 rule is a mechanical range rule: it
// matches every hop into 1.32, so a 1.32 attestation lists it and an
// attestation leaving it out is a missing rule.
func TestPackAttestationOfTheLineWideFlowControlRule(t *testing.T) {
	if !supersedeids.Superseded() {
		t.Skip("the shipped pack still holds the anchor-only reviewed 1.32 rule")
	}
	const id = "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0"
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

// The published flowcontrol v1beta3 rule matches its anchor pair only, so a
// 1.32 attestation listing it would present a hop such as 1.31.4 -> 1.32.1 as
// covered while no rule matches it. The loader refuses it, and an attestation
// leaving it out is a missing rule: 1.32 cannot be attested over this pack.
func TestPackRejectsAttestationListingARuleThatIsNotLineWide(t *testing.T) {
	if supersedeids.Superseded() {
		t.Skip("the published 1.32 rule is a range rule: see TestPackAttestationOfTheLineWideFlowControlRule")
	}
	id := "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0"
	for _, entry := range func() []Entry {
		b, err := load()
		if err != nil {
			t.Fatal(err)
		}
		return b.pack.Entries
	}() {
		tr, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(entry.Rule), `"id":"`+id+`"`) && tr.Match("1.31.4", "1.32.1") != constraintengine.MatchNone {
			t.Fatal("fixture assumption broken: the 1.32 rule now matches every hop into 1.32")
		}
	}
	for name, ids := range map[string][]string{"listed": {id}, "left out": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := assembleSynthetic(attestedPack(t, packSchemaAttested, section(t, testAttestation("1.32", ids))), nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
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
