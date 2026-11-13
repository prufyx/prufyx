// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"strings"
	"testing"
)

const pfGlob = "api/config/crd/policy.networking.k8s.io_*.yaml"

func pfFilter(glob string) string {
	return `{"glob":"` + glob + `","reason":"r","evidence":"e"}`
}

func pfRules(t *testing.T, paths, filters string) *Rules {
	t.Helper()
	r, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":` + paths + `,"pathFilter":` + filters + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// pfSource is the calico-like tree: the chosen directory holds the owned
// definitions and a copy of a Network Policy API definition.
func pfSource(mutate func(tag string, m *memTree)) memSource {
	return ipSource(func(tag string, m *memTree) {
		m.files["api/config/crd/policy.networking.k8s.io_clusternetworkpolicies.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "ClusterNetworkPolicy"))
		if mutate != nil {
			mutate(tag, m)
		}
	})
}

func TestPathFilterRemovesOnlyTheCopy(t *testing.T) {
	rules := pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)
	// Without the filter the reserved group inside the chosen directory stops.
	_, err := Generate(ipInput(pfSource(nil), ipRules(t, `[`+ipEntry+`]`)))
	wantStop(t, err, StopReservedGroup)

	res := mustGenerate(t, ipInput(pfSource(nil), rules))
	wantCanonicalEqual(t, "half A", res.A, readFile(t, "testdata/installpaths/golden-a.json"))
	if !bytes.Equal(res.B, readFile(t, "testdata/installpaths/golden-b.json")) {
		t.Fatalf("half B differs from the golden:\n%s", res.B)
	}
	rep := res.Report
	if rep.FilteredCopyCount != 1 || len(rep.FilteredCopies) != 1 {
		t.Fatalf("filtered copies %+v", rep.FilteredCopies)
	}
	fc := rep.FilteredCopies[0]
	if fc.Path != "api/config/crd/policy.networking.k8s.io_clusternetworkpolicies.yaml" || fc.Glob != pfGlob ||
		strings.Join(fc.Groups, ",") != "policy.networking.k8s.io" || strings.Join(fc.Tags, ",") != strings.Join(ipTags, ",") {
		t.Fatalf("filtered copy %+v", fc)
	}
	if !hasDecision(rep, RuleFilteredCopy, fc.Path) {
		t.Fatal("no filtered-copy decision")
	}
	if rep.NonInstallCopyCount != 3 {
		t.Fatalf("non-install copies must stay separate: %d", rep.NonInstallCopyCount)
	}
	raw, _ := marshal(rep)
	if !strings.Contains(string(raw), `"filteredCopyCount": 1`) || !strings.Contains(string(raw), `"filteredCopies"`) {
		t.Fatalf("report.json lacks the filtered copy: %s", raw)
	}
	if !strings.Contains(string(res.Changelog), "1 definition file(s) inside the declared install paths") {
		t.Fatalf("changelog: %s", res.Changelog)
	}
	if res.Report.CRDCount != 2 || len(res.Report.Groups) != 1 {
		t.Fatalf("groups %+v", res.Report.Groups)
	}
}

func TestPathFilterStops(t *testing.T) {
	cases := []struct {
		name    string
		filters string
		mutate  func(tag string, m *memTree)
		code    string
	}{
		{"matches nothing", `[` + pfFilter(pfGlob) + `,` + pfFilter("api/config/crd/nothing_*.yaml") + `]`, nil, StopPathFilterNothing},
		{"matches nothing at the newest tag", `[` + pfFilter(pfGlob) + `]`, func(tag string, m *memTree) {
			if tag == "v1.3.0" {
				delete(m.files, "api/config/crd/policy.networking.k8s.io_clusternetworkpolicies.yaml")
			}
		}, StopPathFilterNothing},
		{"matches only a file outside installPaths", `[` + pfFilter("manifests/*.yaml") + `,` + pfFilter(pfGlob) + `]`, nil, StopPathFilterNothing},
		{"matches an owned-group file", `[` + pfFilter(pfGlob) + `,` + pfFilter("api/config/crd/widgets.example.test_alphas.yaml") + `]`, nil, StopFilterHidesOwned},
		{"star does not cross a segment", `[` + pfFilter(pfGlob) + `,` + pfFilter("api/*.yaml") + `]`, nil, StopPathFilterNothing},
		{"unreadable file matched by a filter", `[` + pfFilter(pfGlob) + `,` + pfFilter("api/config/crd/bad*.yaml") + `]`, func(_ string, m *memTree) {
			m.files["api/config/crd/bad.yaml"] = []byte("kind: CustomResourceDefinition\n{{ .x }}\n")
		}, StopUnreadableShape},
		{"owned and foreign kinds in one matched file", `[` + pfFilter("api/config/crd/mixed.yaml") + `]`, func(_ string, m *memTree) {
			m.files["api/config/crd/mixed.yaml"] = ipDocs(ipCRD("widgets.example.test", "Gamma"), ipCRD("policy.networking.k8s.io", "AdminNetworkPolicy"))
		}, StopFilterHidesOwned},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Generate(ipInput(pfSource(c.mutate), pfRules(t, `[`+ipEntry+`]`, c.filters)))
			wantStop(t, err, c.code)
		})
	}
}

// A filter that matches only the copy never lets the copy's reserved group be
// read, but a second reserved file the filter does not name still stops.
func TestPathFilterDoesNotWidenToOtherReservedFiles(t *testing.T) {
	src := pfSource(func(_ string, m *memTree) {
		m.files["api/config/crd/other_adminnetworkpolicies.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "AdminNetworkPolicy"))
	})
	_, err := Generate(ipInput(src, pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)))
	wantStop(t, err, StopReservedGroup)
}

func TestPathFilterDeterministic(t *testing.T) {
	one := func() [][]byte {
		res := mustGenerate(t, ipInput(pfSource(func(_ string, m *memTree) {
			m.files["api/config/crd/policy.networking.k8s.io_a.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "A"))
			m.files["api/config/crd/policy.networking.k8s.io_b.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "B"))
		}), pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)))
		rep, _ := marshal(res.Report)
		return [][]byte{res.A, res.B, res.TableRow, res.Changelog, rep}
	}
	a, b := one(), one()
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("output %d differs between two runs", i)
		}
	}
	res := mustGenerate(t, ipInput(pfSource(func(_ string, m *memTree) {
		m.files["api/config/crd/policy.networking.k8s.io_a.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "A"))
	}), pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)))
	var paths []string
	for _, c := range res.Report.FilteredCopies {
		paths = append(paths, c.Path)
	}
	if strings.Join(paths, " ") != "api/config/crd/policy.networking.k8s.io_a.yaml api/config/crd/policy.networking.k8s.io_clusternetworkpolicies.yaml" {
		t.Fatalf("not sorted: %v", paths)
	}
}

// A changed filtered list changes the facts digest while both halves stay equal.
func TestPathFilterListIsInFactsDigest(t *testing.T) {
	rules := pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)
	base := mustGenerate(t, ipInput(pfSource(nil), rules))
	other := mustGenerate(t, ipInput(pfSource(func(tag string, m *memTree) {
		if tag == "v1.3.0" {
			m.files["api/config/crd/policy.networking.k8s.io_extra.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "Extra"))
		}
	}), rules))
	if base.Report.FactsDigest == other.Report.FactsDigest {
		t.Fatal("a changed filtered list did not change the facts digest")
	}
	if !bytes.Equal(base.A, other.A) || !bytes.Equal(base.B, other.B) {
		t.Fatal("target halves must be equal for this test")
	}
}

// Without pathFilter nothing changes: no field in report.json, same digest as
// the installPaths-only run on the same chosen files.
func TestPathFilterAbsentChangesNothing(t *testing.T) {
	res := mustGenerate(t, ipInput(ipSource(nil), rulesFrom(t, "testdata/installpaths/rules.json")))
	if res.Report.FilteredCopyCount != 0 || res.Report.FilteredCopies != nil {
		t.Fatal("filtered copies reported without pathFilter")
	}
	raw, _ := marshal(res.Report)
	if strings.Contains(string(raw), "filteredCop") || strings.Contains(string(res.Changelog), "path filter") {
		t.Fatalf("output gained a pathFilter trace: %s", raw)
	}
	// The same chosen files with a filter that removes a file which a run
	// without it never had: the digest differs only by the filtered line.
	withFilter := mustGenerate(t, ipInput(pfSource(nil), pfRules(t, `[`+ipEntry+`]`, `[`+pfFilter(pfGlob)+`]`)))
	if withFilter.Report.FactsDigest == res.Report.FactsDigest {
		t.Fatal("filtered copies are not in the facts digest")
	}
	if !bytes.Equal(withFilter.A, res.A) || !bytes.Equal(withFilter.B, res.B) {
		t.Fatal("the filter changed the target bytes")
	}
}

func TestPathFilterParseFailsClosed(t *testing.T) {
	base := `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[` + ipEntry + `],"pathFilter":`
	bad := []string{
		`[{"glob":"","reason":"r","evidence":"e"}]`,
		`[{"glob":"../x/*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"/abs/*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"a//b*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"a/./b*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/**/x.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/**","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/?.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/[a].yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/{a,b}.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api\\b*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/*.yaml","reason":"","evidence":"e"}]`,
		`[{"glob":"api/*.yaml","reason":"r","evidence":""}]`,
		`[{"glob":"api/*.yaml","reason":"r","evidence":"e"},{"glob":"api/*.yaml","reason":"r","evidence":"e"}]`,
		`[{"glob":"api/*.yaml","reason":"r","evidence":"e","extra":1}]`,
	}
	for _, b := range bad {
		if _, err := ParseRules([]byte(base + b + `}`)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	if _, err := ParseRules([]byte(base + `[` + pfFilter(pfGlob) + `]}`)); err != nil {
		t.Fatalf("valid filter refused: %v", err)
	}
	noPaths := `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"pathFilter":[` + pfFilter(pfGlob) + `]}`
	if _, err := ParseRules([]byte(noPaths)); err == nil {
		t.Error("accepted pathFilter without installPaths")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		glob, p string
		want    bool
	}{
		{"a/b_*.yaml", "a/b_x.yaml", true},
		{"a/b_*.yaml", "a/b_.yaml", true},
		{"a/b_*.yaml", "a/c/b_x.yaml", false},
		{"a/*", "a/b/c", false},
		{"a/*/c.yaml", "a/b/c.yaml", true},
		{"a/*/c.yaml", "a/c.yaml", false},
		{"a/b.yaml", "a/B.yaml", false},
		{"a/b_*.yaml", "x/a/b_x.yaml", false},
	}
	for _, c := range cases {
		if got := globMatch(c.glob, c.p); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.glob, c.p, got)
		}
	}
}
