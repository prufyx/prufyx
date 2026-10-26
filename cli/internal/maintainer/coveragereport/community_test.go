// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// A community-catalog project attests like a CNCF one. Its A is counted in
// the separate community total, carries the community label, and stays out of
// the CNCF totals and the per-family CNCF counters.

func gatewayScenario(lines ...string) scenario {
	return scenario{slug: "gateway-api", family: lineattest.FamilyCustomResourceVersions, component: "pkg:github/kubernetes-sigs/gateway-api", repo: "kubernetes-sigs/gateway-api", lines: lines, capturedOn: allCaptured,
		releases: map[string][]string{"1.1": {"1.1.0"}, "1.2": {"1.2.0"}, "1.3": {"1.3.0"}}}
}

// combined is the ALL-window report of several scenarios in one pack and one
// lines snapshot.
func combined(t *testing.T, ss ...scenario) Report {
	t.Helper()
	var atts []lineattest.LineAttestation
	file := LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{}}
	for _, s := range ss {
		for i := 1; i < len(s.lines); i++ {
			prev, ok := lineattest.PreviousLine(s.component, s.lines[i])
			if !ok || prev != s.lines[i-1] {
				continue
			}
			atts = append(atts, s.attestation(t, s.lines[i], prev))
		}
		file.Projects[s.slug] = ProjectLines{Lines: s.lines, Releases: s.releases, Component: s.component, Scheme: s.scheme}
	}
	section, err := lineattest.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	linesBytes, err := MarshalLines(file)
	if err != nil {
		t.Fatal(err)
	}
	packBytes := []byte(`{"schema":"test","revision":"synthetic","entries":[],"lineAttestations":` + string(section) + `}`)
	report, err := Compute(Input{Pack: packBytes, Lines: linesBytes, Now: allNow, All: true})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func rowOf(t *testing.T, r Report, slug string) Project {
	t.Helper()
	for _, p := range r.Projects {
		if p.Project == slug {
			return p
		}
	}
	t.Fatalf("no row for %s", slug)
	return Project{}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A community A is labelled, totalled apart, and kept out of every CNCF
// figure.
func TestCommunityAttestationIsCountedApart(t *testing.T) {
	r := combined(t, gatewayScenario("1.1", "1.2", "1.3"))
	p := rowOf(t, r, "gateway-api")
	if p.Catalog != CatalogCommunity || statuses(p) != "AA" || p.A != 2 || !p.Covered {
		t.Fatalf("row %+v (%s)", p, statuses(p))
	}
	c := r.CommunityCatalog
	if c == nil || c.Projects != 1 || c.Pairs != 2 || c.A != 2 || c.C1 != 1 || c.VCPairs != 1 {
		t.Fatalf("community totals %+v", c)
	}
	if r.Fleet.Projects != 0 || r.Fleet.A != 0 || r.Fleet.Pairs != 0 || r.Priority.Projects != 0 || r.Priority.A != 0 {
		t.Fatalf("CNCF totals moved: fleet %+v priority %+v", r.Fleet, r.Priority)
	}
	for _, f := range r.Families {
		if f.A != 0 || f.B != 0 || (f.Counts != nil && *f.Counts != (Counts{})) {
			t.Fatalf("a CNCF family counter moved: %+v", f)
		}
	}
	if r.PackProjects != 1 {
		t.Fatalf("pack projects %d, want 1", r.PackProjects)
	}
	// Complete by the same clauses as a CNCF project.
	assertComplete(t, p, true, "")
	if p.Counts != (Counts{LinesTotal: 3, Decided: 2}) {
		t.Fatalf("counts %+v", p.Counts)
	}
	md := string(r.Markdown())
	if !strings.Contains(md, "gateway-api (community catalog)") || !strings.Contains(md, "community catalog (not in the fleet; no CNCF status asserted)") {
		t.Fatalf("markdown:\n%s", md)
	}
}

// gatewayRule is a valid rule of the community project, which ties its
// component to its project in the pack.
const gatewayRule = `{"project":"gateway-api","rule":{"id":"gateway-api.crd-version-removal.synthetic.1-1-0-to-1-2-0","operator":"forbid_set_member","subject":{"component":"pkg:github/kubernetes-sigs/gateway-api","from":"1.1.0","to":"1.2.0"},` +
	`"setCondition":{"side":"proposed","component":"pkg:github/kubernetes-sigs/gateway-api","factId":"component.gateway_api.custom_resource_versions_set","members":["gateway.networking.k8s.io/v1beta1/Gateway"]},` +
	`"evidence":{"state":"active","reviewedAt":"2026-10-01T00:00:00Z","validUntil":"2026-12-15T00:00:00Z"}}}`

// A community project with a current attestation but no lines in the
// snapshot is counted as a pack project and listed as without lines, like a
// CNCF one; a community project with a rule only is neither.
func TestCommunityAttestationWithoutLines(t *testing.T) {
	s := gatewayScenario("1.1", "1.2", "1.3")
	prev, _ := lineattest.PreviousLine("", "1.3")
	section, err := lineattest.Marshal([]lineattest.LineAttestation{s.attestation(t, "1.3", prev)})
	if err != nil {
		t.Fatal(err)
	}
	linesBytes, err := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"other": {Lines: []string{"1.0", "1.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	compute := func(sectionJSON string) Report {
		t.Helper()
		r, err := Compute(Input{Pack: []byte(`{"schema":"test","revision":"synthetic","entries":[` + gatewayRule + `]` + sectionJSON + `}`), Lines: linesBytes, Now: allNow, All: true})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := compute(`,"lineAttestations":` + string(section))
	if r.PackProjects != 1 || !reflect.DeepEqual(r.WithoutLines, []string{"gateway-api"}) {
		t.Fatalf("pack projects %d, without lines %v", r.PackProjects, r.WithoutLines)
	}
	r = compute("")
	if r.PackProjects != 0 || len(r.WithoutLines) != 0 {
		t.Fatalf("a community rule without an attestation: pack projects %d, without lines %v", r.PackProjects, r.WithoutLines)
	}
}

// A record derived at an earlier code digest no longer decides the pair of a
// community project: the extractor change moves the digest, and every record
// derived before it stops counting until it is derived again.
func TestCommunityOldDigestRecordDoesNotCount(t *testing.T) {
	old := gatewayScenario("1.1", "1.2", "1.3")
	old.mutate = func(a *lineattest.LineAttestation) {
		a.Evidence.Extractor.CodeDigest = "sha256:" + strings.Repeat("b", 64)
	}
	p := old.project(t)
	assertComplete(t, p, false, "")
	if p.Counts.Decided != 0 {
		t.Fatalf("old-digest records decide %d pairs", p.Counts.Decided)
	}
	// Control: the shipped digest decides both.
	if got := gatewayScenario("1.1", "1.2", "1.3").project(t).Counts.Decided; got != 2 {
		t.Fatalf("control decides %d pairs", got)
	}
}

// Adding a community project's attestations changes no CNCF figure: the
// CNCF totals, the family counters and every CNCF row are the bytes they are
// without them, and a CNCF-only report carries no community field.
func TestCNCFOutputsAreIndependentOfCommunityRecords(t *testing.T) {
	cncf := combined(t, strimziScenario("0.49", "0.50", "0.51"))
	both := combined(t, strimziScenario("0.49", "0.50", "0.51"), gatewayScenario("1.1", "1.2", "1.3"))
	if cncf.CommunityCatalog != nil {
		t.Fatal("a community total without a community project")
	}
	raw, err := cncf.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("communityCatalog")) || bytes.Contains(raw, []byte(`"catalog"`)) {
		t.Fatal("a CNCF-only report names the community catalog")
	}
	if jsonOf(t, cncf.Fleet) != jsonOf(t, both.Fleet) || jsonOf(t, cncf.Priority) != jsonOf(t, both.Priority) || jsonOf(t, cncf.Families) != jsonOf(t, both.Families) {
		t.Fatalf("CNCF figures moved:\nfleet %s -> %s\nfamilies %s -> %s", jsonOf(t, cncf.Fleet), jsonOf(t, both.Fleet), jsonOf(t, cncf.Families), jsonOf(t, both.Families))
	}
	if jsonOf(t, rowOf(t, cncf, "strimzi")) != jsonOf(t, rowOf(t, both, "strimzi")) {
		t.Fatal("the CNCF row moved")
	}
	if both.PackProjects != cncf.PackProjects+1 {
		t.Fatalf("pack projects %d -> %d", cncf.PackProjects, both.PackProjects)
	}
	if !reflect.DeepEqual(cncf.WithoutLines, both.WithoutLines) {
		t.Fatalf("without lines %v -> %v", cncf.WithoutLines, both.WithoutLines)
	}
	if both.CommunityCatalog == nil || both.CommunityCatalog.A != 2 {
		t.Fatalf("community totals %+v", both.CommunityCatalog)
	}
}

// A reviewed target alone is not data: only a valid rule or a current line
// attestation of the CRD version family makes a target project count as
// published, and a project outside the target list never does.
func TestCRDPublishedProjects(t *testing.T) {
	s := gatewayScenario("1.1", "1.2", "1.3")
	prev, _ := lineattest.PreviousLine("", "1.3")
	section, err := lineattest.Marshal([]lineattest.LineAttestation{s.attestation(t, "1.3", prev)})
	if err != nil {
		t.Fatal(err)
	}
	linesBytes, err := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"other": {Lines: []string{"1.0", "1.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := lineattest.Marshal([]lineattest.LineAttestation{func() lineattest.LineAttestation {
		a := s.attestation(t, "1.3", prev)
		a.Evidence.ValidUntil = "2026-10-05T00:00:00Z"
		return a
	}()})
	if err != nil {
		t.Fatal(err)
	}
	expiredRule := strings.Replace(gatewayRule, "2026-12-15T00:00:00Z", "2026-10-05T00:00:00Z", 1)
	withdrawnRule := strings.Replace(gatewayRule, `"state":"active"`, `"state":"withdrawn"`, 1)
	community := func(entries, section string) string {
		return `{"schema":"test","revision":"synthetic","entries":[` + entries + `]` + section + `}`
	}
	component := map[string]string{"gateway-api": s.component, "kubeswift": "pkg:github/kubeswift-io/kubeswift"}
	cases := []struct {
		name    string
		entries string
		section string
		targets []string
		// pack is the community pack; empty means none.
		pack string
		want int
	}{
		{"targets only", "", "", []string{"gateway-api", "kubeswift"}, "", 0},
		{"rule", gatewayRule, "", []string{"gateway-api", "kubeswift"}, "", 1},
		{"attestation", "", `,"lineAttestations":` + string(section), []string{"gateway-api", "kubeswift"}, "", 1},
		{"rule and attestation count once", gatewayRule, `,"lineAttestations":` + string(section), []string{"gateway-api", "kubeswift"}, "", 1},
		{"data of a project without a target", gatewayRule, `,"lineAttestations":` + string(section), []string{"kubeswift"}, "", 0},
		{"no target list", gatewayRule, `,"lineAttestations":` + string(section), nil, "", 0},
		{"expired attestation", "", `,"lineAttestations":` + string(expired), []string{"gateway-api", "kubeswift"}, "", 0},
		{"expired rule", expiredRule, "", []string{"gateway-api", "kubeswift"}, "", 0},
		{"invalid rule", withdrawnRule, "", []string{"gateway-api", "kubeswift"}, "", 0},
		{"community rule", "", "", []string{"gateway-api", "kubeswift"}, community(gatewayRule, ""), 1},
		{"community attestation", "", "", []string{"gateway-api", "kubeswift"}, community("", `,"lineAttestations":`+string(section)), 1},
		{"community and main count once", gatewayRule, "", []string{"gateway-api", "kubeswift"}, community(gatewayRule, `,"lineAttestations":`+string(section)), 1},
		{"community expired attestation", "", "", []string{"gateway-api", "kubeswift"}, community("", `,"lineAttestations":`+string(expired)), 0},
		{"community expired rule", "", "", []string{"gateway-api", "kubeswift"}, community(expiredRule, ""), 0},
		{"community invalid rule", "", "", []string{"gateway-api", "kubeswift"}, community(withdrawnRule, ""), 0},
		{"community data of a project without a target", "", "", []string{"kubeswift"}, community(gatewayRule, `,"lineAttestations":`+string(section)), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			targets := map[string]string{}
			for _, p := range c.targets {
				targets[p] = component[p]
			}
			r, err := Compute(Input{Pack: []byte(`{"schema":"test","revision":"synthetic","entries":[` + c.entries + `]` + c.section + `}`), Lines: linesBytes, Now: allNow, All: true, CRDVersionProjects: len(c.targets), CRDTargetComponents: targets, CommunityPack: []byte(c.pack)})
			if err != nil {
				t.Fatal(err)
			}
			if r.CRDPublishedProjects != c.want {
				t.Fatalf("published CRD projects %d, want %d", r.CRDPublishedProjects, c.want)
			}
		})
	}
}
