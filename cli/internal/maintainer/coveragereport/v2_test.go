// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestEmbeddedV2DataParses(t *testing.T) {
	t.Parallel()
	tiers, err := ParseTiers(embeddedTiers)
	if err != nil {
		t.Fatal(err)
	}
	_ = tiers.Verified
	if _, err := ParseApplicability(embeddedApplicability); err != nil {
		t.Fatal(err)
	}
	// Tier 1 is the priority portfolio of the pinned snapshot.
	raw, err := os.ReadFile("../../../../" + PinnedLinesPath)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for slug, pl := range lines.Projects {
		if pl.Priority {
			want = append(want, slug)
		}
	}
	got := map[string]bool{}
	for _, p := range tiers.Tiers[0].Projects {
		got[p] = true
	}
	if len(got) != len(want) {
		t.Fatalf("tier 1 has %d projects, the snapshot's priority portfolio %d", len(got), len(want))
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("priority project %s missing from tier 1", p)
		}
	}
}

// A family with a producer shows it even with no attested cell.
func TestV2ProducerOverUniverse(t *testing.T) {
	t.Parallel()
	r := v2Report(Project{Project: "kubernetes", Pairs: []Pair{{Status: StatusG}}})
	applyV2(&r, testTiers([]string{"kubernetes"}, nil), ApplicabilityFile{})
	for _, f := range r.V2.Families {
		want := ProducerNone
		if f.Family == "k8s.api" {
			want = ProducerManifest
		}
		if f.Producer != want || f.Attested != 0 {
			t.Errorf("%s: producer %s attested %d", f.Family, f.Producer, f.Attested)
		}
	}
}

func TestParseV2Refusals(t *testing.T) {
	t.Parallel()
	good := `{"schema":"` + TiersSchema + `","verified":false,"source":"s","tiers":[{"tier":1,"projects":["a","b"]},{"tier":2,"projects":[]}]}`
	if _, err := ParseTiers([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unsorted":  strings.Replace(good, `"a","b"`, `"b","a"`, 1),
		"duplicate": strings.Replace(good, `"a","b"`, `"a","a"`, 1),
		"two tiers": strings.Replace(good, `"projects":[]`, `"projects":["a"]`, 1),
		"unknown":   strings.Replace(good, `"verified"`, `"extra":1,"verified"`, 1),
		"no source": strings.Replace(good, `"source":"s"`, `"source":""`, 1),
		"trailing":  good + "{}",
	} {
		if _, err := ParseTiers([]byte(doc)); err == nil {
			t.Errorf("tiers %s accepted", name)
		}
	}
	app := `{"schema":"` + ApplicabilitySchema + `","exemptions":[{"project":"a","family":"cli.flags","reason":"r","basis":"b"}]}`
	if _, err := ParseApplicability([]byte(app)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"no reason":      strings.Replace(app, `"reason":"r"`, `"reason":""`, 1),
		"no basis":       strings.Replace(app, `"basis":"b"`, `"basis":""`, 1),
		"unknown family": strings.Replace(app, `cli.flags`, `nope`, 1),
		"null list":      `{"schema":"` + ApplicabilitySchema + `","exemptions":null}`,
	} {
		if _, err := ParseApplicability([]byte(doc)); err == nil {
			t.Errorf("applicability %s accepted", name)
		}
	}
}

func v2Report(projects ...Project) Report { return Report{Projects: projects} }

func testTiers(t1, t2 []string) TiersFile {
	return TiersFile{Schema: TiersSchema, Source: "s", Tiers: []Tier{{Tier: 1, Projects: t1}, {Tier: 2, Projects: t2}}}
}

// Declared but unreachable cells never enter the reachable share; bounded,
// spot and gap pairs are never decided.
func TestApplyV2Honesty(t *testing.T) {
	t.Parallel()
	crd := lineattest.FamilyCustomResourceVersions
	k8s := lineattest.FamilyKubernetesRemovedServedGVK
	// "cilium" has a CNCF custom-resource row (manifest producer); the
	// community project does not get one. kubernetes has the k8s.api route.
	r := v2Report(
		Project{Project: "cilium", Pairs: []Pair{
			{From: "1.14", To: "1.15", Status: StatusG},
			{From: "1.15", To: "1.16", Status: StatusA, Families: []string{crd}},
			{From: "1.16", To: "1.17", Status: StatusB, Families: []string{crd}},
		}},
		Project{Project: "kubernetes", Pairs: []Pair{
			{From: "1.35", To: "1.36", Status: StatusA, Families: []string{k8s}},
			{From: "1.36", To: "1.37", Status: StatusS},
		}},
		Project{Project: "zzz-declared-only", Pairs: []Pair{
			{From: "1.0", To: "1.1", Status: StatusA, Families: []string{crd}},
			{From: "1.1", To: "1.2", Status: StatusA, Families: []string{crd}},
		}},
	)
	applyV2(&r, testTiers([]string{"cilium", "kubernetes", "missing-one", "zzz-declared-only"}, nil), ApplicabilityFile{})
	v := r.V2
	if v.Tier1 != 3 || v.Pairs != 6 || v.Cells != 42 {
		t.Fatalf("universe: %+v", v)
	}
	if len(v.NoLines) != 1 || v.NoLines[0] != "missing-one" {
		t.Fatalf("no lines: %v", v.NoLines)
	}
	// Only the last two pairs of cilium count; its older G pair is outside.
	if r.Projects[0].Pairs[0].Cells != nil {
		t.Fatal("a pair outside the last three lines got cells")
	}
	cc := r.Projects[0].Pairs[1].Cells
	if cc["crd.versions"] != CellAttested || cc["k8s.api"] != CellOpen || cc["crd.schema"] != CellOpen {
		t.Fatalf("cilium cells: %v", cc)
	}
	if got := r.Projects[0].Pairs[2].Cells["crd.versions"]; got != CellBounded {
		t.Fatalf("B pair: %s", got)
	}
	if got := r.Projects[1].Pairs[1].Cells["k8s.api"]; got != CellOpen {
		t.Fatalf("S pair: %s", got)
	}
	// Attested: cilium 1, kubernetes 1, zzz 2 = 4. The community-less
	// zzz project is a table-less slug: declared only, not reachable.
	if v.Attested != 4 || v.Bounded != 1 || v.Reachable != 2 || v.DeclaredOnly != 2 {
		t.Fatalf("counts: %+v", v)
	}
	if v.FullPairs != 0 {
		t.Fatalf("a pair with 1 of 7 cells attested is not full: %d", v.FullPairs)
	}
	if v.reachNum >= v.declNum || v.reachNum == 0 {
		t.Fatalf("reachable %d must be below declared %d and above 0", v.reachNum, v.declNum)
	}
	if v.DPCReachable >= v.DPCDeclared {
		t.Fatalf("reachable %v not below declared %v", v.DPCReachable, v.DPCDeclared)
	}
	// Exact weights: tier 1 = 3; newest pair 1.0, older 0.5.
	if w := r.Projects[0].Pairs[2].Weight; w != 3 {
		t.Fatalf("newest weight %v", w)
	}
	if w := r.Projects[0].Pairs[1].Weight; w != 1.5 {
		t.Fatalf("older weight %v", w)
	}
	// 4 attested cells of 7 per pair; weights 3+1.5 per project, 3 projects.
	wantDen := int64(3*2+3*1) * 3 * cellScale
	if v.den != wantDen {
		t.Fatalf("den %d want %d", v.den, wantDen)
	}
}

func TestApplyV2FullPairAndExemption(t *testing.T) {
	t.Parallel()
	crd := lineattest.FamilyCustomResourceVersions
	r := v2Report(Project{Project: "cilium", Pairs: []Pair{{From: "1.0", To: "1.1", Status: StatusA, Families: []string{crd}}}})
	var ex []Exemption
	for _, f := range V2Families {
		if f != "crd.versions" {
			ex = append(ex, Exemption{Project: "cilium", Family: f, Reason: "r", Basis: "b"})
		}
	}
	applyV2(&r, testTiers([]string{"cilium"}, nil), ApplicabilityFile{Schema: ApplicabilitySchema, Exemptions: ex})
	v := r.V2
	if v.Cells != 1 || v.Exempt != 6 || v.FullPairs != 1 || v.DPCDeclared != 1 || v.DPCReachable != 1 {
		t.Fatalf("%+v", v)
	}
}

func TestV2PctExact(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n, d int64
		want string
	}{{0, 0, "0%"}, {1, 3, "33.3%"}, {2, 3, "66.6%"}, {5, 5, "100%"}, {0, 9, "0%"}} {
		if got := v2Pct(c.n, c.d); got != c.want {
			t.Errorf("%d/%d: %s want %s", c.n, c.d, got, c.want)
		}
	}
}

func TestRenderV2KeepsDeclaredApartFromReachable(t *testing.T) {
	t.Parallel()
	crd := lineattest.FamilyCustomResourceVersions
	r := v2Report(Project{Project: "zzz-declared-only", Pairs: []Pair{{From: "1.0", To: "1.1", Status: StatusA, Families: []string{crd}}}})
	applyV2(&r, testTiers([]string{"zzz-declared-only", "gone"}, nil), ApplicabilityFile{})
	var b strings.Builder
	renderV2(&b, r.V2)
	out := b.String()
	for _, want := range []string{
		"| DPC-declared: weighted share of cells with a line attestation | 14.2% |",
		"| DPC-reachable: the same, counting only cells whose fact the shipped client can read from manifests | 0% |",
		"1 of 7 (0 of them reachable, 1 declared only)",
		"no reviewed tier definition exists yet",
		"Tier 2 has no reviewed list yet",
		"never as not applicable",
		"without a release-line snapshot are not in these numbers: gone.",
		"Neither share says that any upgrade is safe.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCheckExemptionsRefusesUntieredProject(t *testing.T) {
	t.Parallel()
	app := ApplicabilityFile{Exemptions: []Exemption{{Project: "nope", Family: "cli.flags", Reason: "r", Basis: "b"}}}
	if err := checkExemptions(testTiers([]string{"a"}, nil), app); err == nil {
		t.Fatal("an exemption for a project in no tier was accepted")
	}
	if err := checkExemptions(testTiers([]string{"nope"}, nil), app); err != nil {
		t.Fatal(err)
	}
}
