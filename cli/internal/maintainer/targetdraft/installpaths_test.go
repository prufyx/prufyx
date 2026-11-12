// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"strings"
	"testing"
)

var ipTags = []string{"v1.1.0", "v1.2.0", "v1.3.0"}

func ipCRD(group, kind string) string {
	return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + group +
		"\n  names:\n    kind: " + kind + "\n  versions:\n  - name: v1\n    served: true\n    storage: true\n"
}

func ipDocs(docs ...string) []byte { return []byte(strings.Join(docs, "---\n")) }

// ipTree is a calico-like tree: the same two definitions in four places; the
// reserved Network Policy group sits in a rendered copy only.
func ipTree() *memTree {
	m := newMemTree()
	a, b := ipCRD("widgets.example.test", "Alpha"), ipCRD("widgets.example.test", "Beta")
	m.files["api/config/crd/widgets.example.test_alphas.yaml"] = ipDocs(a)
	m.files["api/config/crd/widgets.example.test_betas.yaml"] = ipDocs(b)
	m.files["manifests/all.yaml"] = ipDocs(a, b, ipCRD("policy.networking.k8s.io", "ClusterNetworkPolicy"))
	m.files["charts/x/templates/crds.yaml"] = ipDocs(a, b)
	m.files["ocp/crds.yaml"] = ipDocs(a, b)
	m.files["README.md"] = []byte("not a definition")
	return m
}

func ipSource(mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range ipTags {
		m := ipTree()
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func ipInput(src Source, rules *Rules) Input {
	return Input{Slug: "widgets", Name: "Widgets", Repo: "github.com/example/widgets", Catalog: "cncf", Tags: ipTags, Source: src, Rules: rules}
}

func ipRules(t *testing.T, paths string) *Rules {
	t.Helper()
	r, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":` + paths + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const ipEntry = `{"path":"api/config/crd/","reason":"r","evidence":"e"}`

func TestInstallPathsGolden(t *testing.T) {
	res := mustGenerate(t, ipInput(ipSource(nil), rulesFrom(t, "testdata/installpaths/rules.json")))
	wantCanonicalEqual(t, "half A", res.A, readFile(t, "testdata/installpaths/golden-a.json"))
	rep := res.Report
	if rep.NonInstallCopyCount != 3 || len(rep.NonInstallCopies) != 3 {
		t.Fatalf("want 3 non-install copies, got %d: %+v", rep.NonInstallCopyCount, rep.NonInstallCopies)
	}
	want := map[string]string{
		"charts/x/templates/crds.yaml": "widgets.example.test",
		"manifests/all.yaml":           "policy.networking.k8s.io,widgets.example.test",
		"ocp/crds.yaml":                "widgets.example.test",
	}
	for _, c := range rep.NonInstallCopies {
		if strings.Join(c.Groups, ",") != want[c.Path] {
			t.Fatalf("copy %s groups %v", c.Path, c.Groups)
		}
		if !hasDecision(rep, RuleNonInstallCopy, c.Path) {
			t.Fatalf("no decision for %s", c.Path)
		}
	}
	raw, _ := marshal(rep)
	if !strings.Contains(string(raw), `"nonInstallCopyCount": 3`) || !strings.Contains(string(raw), `"path": "manifests/all.yaml"`) {
		t.Fatalf("report.json lacks the copies: %s", raw)
	}
	if !strings.Contains(string(res.Changelog), "3 further definition file(s)") {
		t.Fatalf("changelog does not name the copies: %s", res.Changelog)
	}
	if len(res.Report.Groups) != 1 || res.Report.CRDCount != 2 {
		t.Fatalf("groups %+v", res.Report.Groups)
	}
}

func TestInstallPathsDeterministic(t *testing.T) {
	run := func() [][]byte {
		res := mustGenerate(t, ipInput(ipSource(nil), rulesFrom(t, "testdata/installpaths/rules.json")))
		rep, _ := marshal(res.Report)
		return [][]byte{res.A, res.B, res.TableRow, res.Changelog, rep}
	}
	a, b := run(), run()
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("output %d differs between two runs", i)
		}
	}
}

func TestInstallPathsExactFileEntries(t *testing.T) {
	r := ipRules(t, `[{"path":"api/config/crd/widgets.example.test_alphas.yaml","reason":"r","evidence":"e"},{"path":"api/config/crd/widgets.example.test_betas.yaml","reason":"r","evidence":"e"}]`)
	res := mustGenerate(t, ipInput(ipSource(nil), r))
	wantCanonicalEqual(t, "half A", res.A, readFile(t, "testdata/installpaths/golden-a.json"))
}

func TestInstallPathsStops(t *testing.T) {
	cases := []struct {
		name   string
		paths  string
		mutate func(tag string, m *memTree)
		code   string
	}{
		{"entry matches nothing", `[` + ipEntry + `,{"path":"nowhere/","reason":"r","evidence":"e"}]`, nil, StopInstallPathNothing},
		{"entry matches nothing at the newest tag", `[` + ipEntry + `]`, func(tag string, m *memTree) {
			if tag == "v1.3.0" {
				delete(m.files, "api/config/crd/widgets.example.test_alphas.yaml")
				delete(m.files, "api/config/crd/widgets.example.test_betas.yaml")
			}
		}, StopInstallPathNothing},
		{"duplicate names among the chosen files", `[` + ipEntry + `,{"path":"ocp/crds.yaml","reason":"r","evidence":"e"}]`, nil, StopDuplicateCRD},
		{"reserved group inside a chosen file", `[` + ipEntry + `]`, func(_ string, m *memTree) {
			m.files["api/config/crd/policy.networking.k8s.io_cnp.yaml"] = ipDocs(ipCRD("policy.networking.k8s.io", "ClusterNetworkPolicy"))
		}, StopReservedGroup},
		{"group owned elsewhere inside a chosen file", `[` + ipEntry + `]`, func(_ string, m *memTree) {
			m.files["api/config/crd/istio.yaml"] = ipDocs(ipCRD("networking.istio.io", "Gateway"))
		}, StopGroupOwnedElsewhere},
		{"unreadable chosen file", `[` + ipEntry + `]`, func(_ string, m *memTree) {
			m.files["api/config/crd/bad.yaml"] = []byte("kind: CustomResourceDefinition\n{{ .x }}\n")
		}, StopUnreadableShape},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Generate(ipInput(ipSource(c.mutate), ipRules(t, c.paths)))
			wantStop(t, err, c.code)
		})
	}
}

func TestInstallPathsUnreadableOutsideIsReportedNotStopped(t *testing.T) {
	src := ipSource(func(_ string, m *memTree) {
		m.files["charts/y/templates/tmpl.yaml"] = []byte("kind: CustomResourceDefinition\n{{ .x }}\n")
	})
	res := mustGenerate(t, ipInput(src, rulesFrom(t, "testdata/installpaths/rules.json")))
	found := false
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == "charts/y/templates/tmpl.yaml" && c.Unreadable == "template syntax" {
			found = true
		}
	}
	if !found || res.Report.NonInstallCopyCount != 4 {
		t.Fatalf("copies %+v", res.Report.NonInstallCopies)
	}
}

func TestInstallPathsSeededDropIsCaught(t *testing.T) {
	rules := rulesFrom(t, "testdata/installpaths/rules.json")
	golden := readFile(t, "testdata/installpaths/golden-a.json")
	const dropped = "api/config/crd/widgets.example.test_betas.yaml"
	res := mustGenerate(t, ipInput(ipSource(func(_ string, m *memTree) { delete(m.files, dropped) }), rules))
	diffs, err := Diff(res.A, golden)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range diffs {
		found = found || strings.Contains(d, "path missing from generated: "+dropped)
	}
	if !found {
		t.Fatalf("drop not caught: %v", diffs)
	}
}

func TestInstallPathsParseFailsClosed(t *testing.T) {
	base := `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":`
	bad := []string{
		`[{"path":"../x/","reason":"r","evidence":"e"}]`,
		`[{"path":"/abs/","reason":"r","evidence":"e"}]`,
		`[{"path":"a//b/","reason":"r","evidence":"e"}]`,
		`[{"path":"./","reason":"r","evidence":"e"}]`,
		`[{"path":".","reason":"r","evidence":"e"}]`,
		`[{"path":"a\\b","reason":"r","evidence":"e"}]`,
		`[{"path":"a/","reason":"","evidence":"e"}]`,
		`[{"path":"a/","reason":"r","evidence":""}]`,
		`[{"path":"a/","reason":"r","evidence":"e"},{"path":"a/","reason":"r","evidence":"e"}]`,
		`[{"path":"a/","reason":"r","evidence":"e"},{"path":"a/b.yaml","reason":"r","evidence":"e"}]`,
		`[{"path":"a/","reason":"r","evidence":"e","extra":1}]`,
	}
	for _, b := range bad {
		if _, err := ParseRules([]byte(base + b + `}`)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	both := `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[{"path":"docs/a.yaml","reason":"r"}],"exclusions":[],"installPaths":[` + ipEntry + `]}`
	if _, err := ParseRules([]byte(both)); err == nil {
		t.Error("accepted installPaths together with installSurface")
	}
}

// A rules file without installPaths must behave as before: the same tree with
// no list stops on the duplicate definitions, and the shipped goldens (see
// TestGoldenKnative and TestGoldenTraefik) are unchanged.
func TestNoInstallPathsBehavesAsBefore(t *testing.T) {
	_, err := Generate(ipInput(ipSource(nil), nil))
	se := wantStop(t, err, StopDuplicateCRD)
	for _, s := range se.Stops {
		if s.Code == StopInstallPathNothing {
			t.Fatal("installPaths stop without installPaths")
		}
	}
	res := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
	if res.Report.NonInstallCopyCount != 0 || res.Report.NonInstallCopies != nil {
		t.Fatal("copies reported without installPaths")
	}
	raw, _ := marshal(res.Report)
	if strings.Contains(string(raw), "nonInstallCopy") {
		t.Fatal("report.json gained a field without installPaths")
	}
}
