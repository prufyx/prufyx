// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	k8s = "pkg:github/kubernetes/kubernetes"
	rev = "1111111111111111111111111111111111111111"
)

func source(id string) constraintengine.SourceEvidence {
	return constraintengine.SourceEvidence{ID: id, URL: "https://github.com/kubernetes/kubernetes/blob/" + rev + "/api/openapi-spec/swagger.json", Revision: rev, ContentDigest: "sha256:" + strings.Repeat("a", 64), StartLine: 1, EndLine: 10}
}

func reviewed(line string, ids ...string) LineAttestation {
	if ids == nil {
		ids = []string{}
	}
	return LineAttestation{Component: k8s, Line: line, FactFamily: FamilyKubernetesRemovedServedGVK, Completeness: Completeness, RuleIDs: ids,
		Evidence: Evidence{Basis: "reviewed", ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z", Sources: []constraintengine.SourceEvidence{source("openapi-a"), source("openapi-b")}}}
}

func mechanical(line string, ids ...string) LineAttestation {
	a := reviewed(line, ids...)
	a.Evidence.Basis = "mechanical"
	a.Evidence.Extractor = &constraintengine.Extractor{ID: "k8s.served-api-removal", Version: "1.1.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
	a.Evidence.DerivedAt = a.Evidence.ReviewedAt
	return a
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAcceptsValidDocuments(t *testing.T) {
	doc := []LineAttestation{reviewed("1.25", "a.rule", "b.rule"), mechanical("1.28"), reviewed("1.100")}
	got, err := Parse(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].RuleIDs == nil || len(got[1].RuleIDs) != 0 {
		t.Fatalf("parsed %+v", got)
	}
	raw, err := Marshal([]LineAttestation{doc[2], doc[0], doc[1]})
	if err != nil || string(raw) != string(encode(t, doc)) {
		t.Fatalf("Marshal does not restore canonical order: %v\n%s", err, raw)
	}
}

// Every mutation of a valid document must be rejected.
func TestParseIsStrict(t *testing.T) {
	valid := string(encode(t, []LineAttestation{mechanical("1.28", "a.rule")}))
	replace := func(old, new string) string {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(valid, old, new, 1)
	}
	two := func(a, b LineAttestation) string { return string(encode(t, []LineAttestation{a, b})) }
	reviewedDoc := string(encode(t, []LineAttestation{reviewed("1.28")}))
	withNull := func(member string) string {
		return strings.Replace(reviewedDoc, `"basis":"reviewed",`, `"basis":"reviewed",`+member+`:null,`, 1)
	}
	expired := mechanical("1.28")
	expired.Evidence.ValidUntil = "2027-01-01T00:00:00Z"
	derivedMismatch := mechanical("1.28")
	derivedMismatch.Evidence.DerivedAt = "2026-09-30T00:00:00Z"
	reviewedWithExtractor := mechanical("1.28")
	reviewedWithExtractor.Evidence.Basis = "reviewed"
	cases := map[string]string{
		"not an array":              `{}`,
		"empty array":               `[]`,
		"null document":             `null`,
		"trailing data":             valid + `[]`,
		"unknown member":            replace(`"line":`, `"extra":1,"line":`),
		"unknown evidence member":   replace(`"basis":`, `"state":"active","basis":`),
		"case alias":                replace(`"ruleIds"`, `"RuleIds"`),
		"case alias shadows member": replace(`"line":"1.28"`, `"line":"1.28","Line":"1.29"`),
		"repeated member":           replace(`"line":"1.28"`, `"line":"1.28","line":"1.29"`),
		"null ruleIds":              replace(`"ruleIds":["a.rule"]`, `"ruleIds":null`),
		"missing ruleIds":           replace(`"ruleIds":["a.rule"],`, ``),
		"null extractor":            replace(`"extractor":{`, `"extractor":null,"x":{`),
		"null optional extractor":   withNull(`"extractor"`),
		"null optional derivedAt":   withNull(`"derivedAt"`),
		"missing sources":           strings.Replace(valid, `"sources":`, `"sourcez":`, 1),
		"unknown family":            replace(FamilyKubernetesRemovedServedGVK, "kubernetes.other"),
		"wrong component":           replace(`"component":"`+k8s+`"`, `"component":"pkg:github/x/y"`),
		"bad line":                  replace(`"line":"1.28"`, `"line":"1.28.0"`),
		"leading zero line":         replace(`"line":"1.28"`, `"line":"1.028"`),
		"bad completeness":          replace(Completeness, "COMPLETE_REVIEWED_RULES_FOR_LISTED_COMPONENTS"),
		"unsorted rule ids":         replace(`["a.rule"]`, `["b.rule","a.rule"]`),
		"duplicate rule ids":        replace(`["a.rule"]`, `["a.rule","a.rule"]`),
		"bad rule id":               replace(`["a.rule"]`, `["A Rule"]`),
		"absent basis":              replace(`"basis":"mechanical",`, ``),
		"unknown basis":             replace(`"basis":"mechanical"`, `"basis":"consensus"`),
		"window over 90 days":       string(encode(t, []LineAttestation{expired})),
		"window reversed":           replace(`"validUntil":"2026-12-30T00:00:00Z"`, `"validUntil":"2026-09-01T00:00:00Z"`),
		"non-UTC time":              replace(`"reviewedAt":"2026-10-01T00:00:00Z"`, `"reviewedAt":"2026-10-01T00:00:00+00:00"`),
		"derivedAt != reviewedAt":   string(encode(t, []LineAttestation{derivedMismatch})),
		"reviewed with extractor":   string(encode(t, []LineAttestation{reviewedWithExtractor})),
		"no sources":                replace(`"sources":[`, `"sources":[],"x":[`),
		"unpinned source URL":       replace(`/blob/`+rev, `/blob/main`),
		"bad source digest":         replace(`"sha256:aaaa`, `"sha1:aaaa`),
		"duplicate scope":           two(reviewed("1.28"), mechanical("1.28")),
		"non-canonical order":       two(reviewed("1.29"), reviewed("1.28")),
		"numeric order, not text":   two(reviewed("1.100"), reviewed("1.99")),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted (%v):\n%s", err, doc)
			}
		})
	}
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatalf("the unmutated fixture is rejected: %v", err)
	}
}

func rule(id, from, to string, facts ...string) json.RawMessage {
	conds := ""
	if len(facts) > 0 {
		conds = fmt.Sprintf(`,"condition":{"side":"proposed","component":%q,"factId":%q,"boolValue":true}`, k8s, facts[0])
	}
	if len(facts) > 1 {
		var aw []string
		for _, f := range facts[1:] {
			aw = append(aw, fmt.Sprintf(`{"side":"current","component":%q,"factId":%q,"boolValue":true}`, k8s, f))
		}
		conds += `,"appliesWhen":[` + strings.Join(aw, ",") + `]`
	}
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"operator":"forbid_predicate_value","subject":{"component":%q,"from":%q,"to":%q}%s}`, id, k8s, from, to, conds))
}

const (
	cronFact = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"
	pdbFact  = "component.kubernetes.pdb_v1beta1_removed_gvk_present"
	dockFact = "component.kubernetes.in_tree_dockershim_required"
)

func packRules() []json.RawMessage {
	return []json.RawMessage{
		rule("cron.125", "1.24.0", "1.25.0", cronFact),
		rule("pdb.125", "1.24.0", "1.25.0", pdbFact),
		rule("dockershim.124", "1.23.17", "1.24.0", dockFact),
		rule("mixed.125", "1.24.0", "1.25.0", dockFact, pdbFact),
		rule("flow.132", "1.31.0", "1.32.0", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"),
	}
}

func TestScopeOfRules(t *testing.T) {
	s, err := ScopeOf(packRules()[3])
	if err != nil || s.Line != "1.25" || !slices.Equal(s.Families, []string{FamilyKubernetesRemovedServedGVK}) {
		t.Fatalf("a rule that reads one family fact belongs to the family: %+v %v", s, err)
	}
	s, _ = ScopeOf(packRules()[2])
	if len(s.Families) != 0 {
		t.Fatalf("dockershim is not a served-API removal: %+v", s)
	}
	other := json.RawMessage(`{"id":"x","subject":{"component":"pkg:github/x/y","to":"1.25.0"},"condition":{"component":"pkg:github/kubernetes/kubernetes","factId":"` + cronFact + `"}}`)
	if s, _ := ScopeOf(other); len(s.Families) != 0 {
		t.Fatalf("a rule about another component is not in the family: %+v", s)
	}
	if _, _, err := RulesByScope(append(packRules(), packRules()[0])); err == nil {
		t.Fatal("a repeated rule id is accepted")
	}
}

func TestCheckRuleSetsRequiresTheExactSet(t *testing.T) {
	rules := packRules()
	exact := []LineAttestation{reviewed("1.25", "cron.125", "mixed.125", "pdb.125"), reviewed("1.28"), reviewed("1.32", "flow.132")}
	if p, err := CheckRuleSets(exact, rules); err != nil || len(p) != 0 {
		t.Fatalf("exact sets rejected: %v %v", p, err)
	}
	for name, c := range map[string]struct {
		att  LineAttestation
		kind string
		id   string
	}{
		"missing rule":                {reviewed("1.25", "cron.125", "mixed.125"), ProblemMissingRule, "pdb.125"},
		"extra unknown rule":          {reviewed("1.25", "cron.125", "mixed.125", "nope", "pdb.125"), ProblemExtraRule, "nope"},
		"rule of another line":        {reviewed("1.32", "cron.125", "flow.132"), ProblemExtraRule, "cron.125"},
		"rule of another family":      {reviewed("1.24", "dockershim.124"), ProblemExtraRule, "dockershim.124"},
		"quiet line that is not":      {reviewed("1.32"), ProblemMissingRule, "flow.132"},
		"mixed-fact rule left out":    {reviewed("1.25", "cron.125", "pdb.125"), ProblemMissingRule, "mixed.125"},
		"listing on a line with none": {reviewed("1.28", "flow.132"), ProblemExtraRule, "flow.132"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := CheckRuleSets([]LineAttestation{c.att}, rules)
			if err != nil || len(p) != 1 || p[0].Kind != c.kind || p[0].RuleID != c.id {
				t.Fatalf("problems %+v (%v), want one %s %s", p, err, c.kind, c.id)
			}
		})
	}
}

func TestFreshnessAndIndex(t *testing.T) {
	ix := NewIndex([]LineAttestation{reviewed("1.28"), mechanical("1.29", "r")})
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	if got := ix.AttestationsFor(k8s, "1.30", FamilyKubernetesRemovedServedGVK, at("2026-11-01T00:00:00Z")); got != nil {
		t.Fatalf("unattested line returned %+v", got)
	}
	if got := ix.AttestationsFor(k8s, "1.28", "kubernetes.other", at("2026-11-01T00:00:00Z")); got != nil {
		t.Fatal("unknown family returned an attestation")
	}
	for when, want := range map[string]string{
		"2026-09-30T23:59:59Z": FreshnessClockBeforeReview,
		"2026-10-01T00:00:00Z": FreshnessCurrent,
		"2026-12-29T23:59:59Z": FreshnessCurrent,
		"2026-12-30T00:00:00Z": FreshnessStale,
	} {
		got := ix.AttestationsFor(k8s, "1.29", FamilyKubernetesRemovedServedGVK, at(when))
		if len(got) != 1 || got[0].Freshness != want || got[0].Current() != (want == FreshnessCurrent) {
			t.Fatalf("%s: %+v, want %s", when, got, want)
		}
	}
	got := ix.AttestationsFor(k8s, "1.29", FamilyKubernetesRemovedServedGVK, at("2026-11-01T00:00:00Z"))
	got[0].Attestation.RuleIDs[0] = "mutated"
	again := ix.AttestationsFor(k8s, "1.29", FamilyKubernetesRemovedServedGVK, at("2026-11-01T00:00:00Z"))
	if again[0].Attestation.RuleIDs[0] != "r" {
		t.Fatal("a caller can mutate the index")
	}
}

func TestClassify(t *testing.T) {
	base := mechanical("1.28")
	renewed := base
	renewed.Evidence.DerivedAt, renewed.Evidence.ReviewedAt, renewed.Evidence.ValidUntil = "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2027-01-30T00:00:00Z"
	shortened := base
	shortened.Evidence.ValidUntil = "2026-12-01T00:00:00Z"
	backdated := base
	backdated.Evidence.ReviewedAt, backdated.Evidence.DerivedAt = "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"
	moreRules := mechanical("1.28", "x")
	newSource := mechanical("1.28")
	newSource.Evidence.Sources = []constraintengine.SourceEvidence{source("openapi-a")}
	newExtractor := renewed
	x := *base.Evidence.Extractor
	x.Version = "1.2.0"
	newExtractor.Evidence.Extractor = &x
	toReviewed := reviewed("1.28")
	for name, c := range map[string]struct {
		before, after []LineAttestation
		want          Change
	}{
		"removed":       {[]LineAttestation{base}, nil, Change{Kind: ChangeRemoved, Class: Tightening, Basis: "mechanical"}},
		"added":         {nil, []LineAttestation{base}, Change{Kind: ChangeAdded, Class: Loosening, Basis: "mechanical"}},
		"renewed":       {[]LineAttestation{base}, []LineAttestation{renewed}, Change{Kind: ChangeModified, Class: Loosening, Renewal: true, Basis: "mechanical", Fields: []string{"evidence.derivedAt", "evidence.reviewedAt", "evidence.validUntil"}}},
		"shortened":     {[]LineAttestation{base}, []LineAttestation{shortened}, Change{Kind: ChangeModified, Class: Tightening, Basis: "mechanical", Fields: []string{"evidence.validUntil"}}},
		"backdated":     {[]LineAttestation{base}, []LineAttestation{backdated}, Change{Kind: ChangeModified, Class: Loosening, Basis: "mechanical", Fields: []string{"evidence.derivedAt", "evidence.reviewedAt"}}},
		"rules changed": {[]LineAttestation{base}, []LineAttestation{moreRules}, Change{Kind: ChangeModified, Class: Loosening, Basis: "mechanical", Fields: []string{"ruleIds"}}},
		"rules dropped": {[]LineAttestation{moreRules}, []LineAttestation{base}, Change{Kind: ChangeModified, Class: Loosening, Basis: "mechanical", Fields: []string{"ruleIds"}}},
		"source":        {[]LineAttestation{base}, []LineAttestation{newSource}, Change{Kind: ChangeModified, Class: Loosening, Basis: "mechanical", Fields: []string{"evidence.sources"}}},
		"extractor":     {[]LineAttestation{base}, []LineAttestation{newExtractor}, Change{Kind: ChangeModified, Class: Loosening, Basis: "mechanical", Fields: []string{"evidence.derivedAt", "evidence.extractor", "evidence.reviewedAt", "evidence.validUntil"}}},
		"basis":         {[]LineAttestation{base}, []LineAttestation{toReviewed}, Change{Kind: ChangeModified, Class: Loosening, Basis: "reviewed", Fields: []string{"evidence.basis", "evidence.derivedAt", "evidence.extractor"}}},
	} {
		t.Run(name, func(t *testing.T) {
			got := Classify(c.before, c.after)
			c.want.Key = base.Key()
			if len(got) != 1 || fmt.Sprint(got[0]) != fmt.Sprint(c.want) {
				t.Fatalf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
	if got := Classify([]LineAttestation{base}, []LineAttestation{base}); len(got) != 0 {
		t.Fatalf("unchanged reported: %+v", got)
	}
	if !Renewable(base) || Renewable(reviewed("1.28")) {
		t.Fatal("only mechanical attestations renew by re-derivation")
	}
	now, _ := time.Parse(time.RFC3339, "2026-12-01T00:00:00Z")
	if !base.ExpiresWithin(now, 30*24*time.Hour) || base.ExpiresWithin(now, 24*time.Hour) {
		t.Fatal("ExpiresWithin")
	}
}

func TestLineOf(t *testing.T) {
	for v, want := range map[string]string{"1.28.0": "1.28", "1.28.13": "1.28", "10.0.1": "10.0"} {
		if got, ok := LineOf(v); !ok || got != want {
			t.Fatalf("%s: %s", v, got)
		}
	}
	for _, v := range []string{"1.28", "1.28.01", "01.2.3", "1.x.0", ""} {
		if _, ok := LineOf(v); ok {
			t.Fatalf("%s accepted", v)
		}
	}
}
