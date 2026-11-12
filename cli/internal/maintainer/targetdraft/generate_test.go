// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustGenerate(t *testing.T, in Input) *Result {
	t.Helper()
	res, err := Generate(in)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return res
}

func wantCanonicalEqual(t *testing.T, label string, got, golden []byte) {
	t.Helper()
	c, err := Canonical(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, c) {
		diffs, _ := Diff(got, golden)
		t.Fatalf("%s differs from the reviewed target: %v", label, diffs)
	}
}

type rowShape struct {
	Slug, Catalog, FactProject, Component string
	Upstream                              *Upstream
	Groups                                map[string][]string
}

func shapeOf(t *testing.T, raw []byte) rowShape {
	t.Helper()
	var d struct {
		Slug        string    `json:"slug"`
		Catalog     string    `json:"catalog"`
		Upstream    *Upstream `json:"upstream"`
		FactProject string    `json:"factProject"`
		Component   string    `json:"component"`
		Groups      []struct {
			Name   string   `json:"name"`
			Source string   `json:"source"`
			Kinds  []string `json:"kinds"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	s := rowShape{Slug: d.Slug, Catalog: d.Catalog, FactProject: d.FactProject, Component: d.Component, Upstream: d.Upstream, Groups: map[string][]string{}}
	for _, g := range d.Groups {
		if !strings.HasPrefix(g.Source, "https://github.com/") || !strings.Contains(g.Source, "/blob/") {
			t.Fatalf("source %q is not a pinned blob URL", g.Source)
		}
		s.Groups[g.Name] = g.Kinds
	}
	return s
}

func hasDecision(r Report, rule, subject string) bool {
	for _, d := range r.Decisions {
		if d.Rule == rule && d.Subject == subject {
			return true
		}
	}
	return false
}

func TestGoldenKnative(t *testing.T) {
	res := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
	wantCanonicalEqual(t, "half A", res.A, readFile(t, "testdata/knative/golden-a.json"))
	wantCanonicalEqual(t, "half B", res.B, readFile(t, "testdata/knative/golden-b.json"))
	if got, want := shapeOf(t, res.TableRow), shapeOf(t, readFile(t, "testdata/knative/golden-row.json")); !reflect.DeepEqual(got, want) {
		t.Fatalf("table row %+v, want %+v", got, want)
	}
	for _, p := range []string{"vendor/knative.dev/networking/config/certificate.yaml", "vendor/knative.dev/caching/config/image.yaml"} {
		if !hasDecision(res.Report, RuleIncludeSymlinkResolved, p) {
			t.Errorf("no %s decision for %s", RuleIncludeSymlinkResolved, p)
		}
	}
	if !hasDecision(res.Report, RuleExcludePinnedFile, "third_party/gateway-api-latest/gateway-api.yaml") {
		t.Error("no pinned exclusion decision for the gateway bundle")
	}
	if !hasDecision(res.Report, RuleForeignCopy, "third_party/cert-manager-latest/cert-manager.yaml") {
		t.Error("the cert-manager copy should be a foreign copy that needs no exclusion")
	}
	if res.Report.MinFrom != "0.46" || len(res.Report.Tags) != 6 || len(res.Report.Dropped) != 0 || res.Report.CRDCount != 12 {
		t.Errorf("report %+v", res.Report)
	}
	if bytes.Contains(res.A, []byte(`"attest"`)) || !bytes.Contains(res.A, []byte(`"exclude": []`)) {
		t.Error("half A must carry no attest and no exclusion")
	}
	if !strings.HasPrefix(string(res.Changelog), "### Added\n\n- A CRD extractor target for Knative (12 CRDs in 4 groups") {
		t.Errorf("changelog %q", res.Changelog)
	}
}

func TestGoldenTraefik(t *testing.T) {
	res := mustGenerate(t, traefikInput(t, traefikSource(t, nil), rulesFrom(t, "testdata/traefik/rules.json")))
	wantCanonicalEqual(t, "half B", res.B, readFile(t, "testdata/traefik/golden-b.json"))
	got, want := shapeOf(t, res.TableRow), shapeOf(t, readFile(t, "testdata/traefik/golden-row.json"))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("table row %+v, want %+v", got, want)
	}
	if bytes.Contains(res.A, []byte(`"attest"`)) || !bytes.Contains(res.A, []byte(`"exclude": []`)) {
		t.Error("half A must carry no attest and no exclusion")
	}
	if res.Report.MinFrom != "3.2" || res.Report.CRDCount != 10 {
		t.Errorf("report %+v", res.Report)
	}
	if !hasDecision(res.Report, RuleIncludePinnedSurface, "docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml") ||
		!hasDecision(res.Report, RuleExcludePinnedFixtures, "integration/fixtures/knative/knative.yml") ||
		!hasDecision(res.Report, RuleFixtureDrop, "serving.knative.dev") {
		t.Errorf("decisions %+v", res.Report.Decisions)
	}
}

func TestDeterministic(t *testing.T) {
	run := func() [][]byte {
		res := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
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

func replaceCRD(m *memTree, p, from, to string) {
	m.files[p] = []byte(strings.ReplaceAll(string(m.files[p]), from, to))
}

func TestSeededWrongTargetIsCaught(t *testing.T) {
	const route = "config/core/300-resources/route.yaml"
	const ingress = "vendor/knative.dev/networking/config/ingress.yaml"
	cases := []struct {
		name   string
		mutate func(tag string, m *memTree)
		want   string // substring of one Diff line against the reviewed B
	}{
		{"drop a path at every tag", func(_ string, m *memTree) { delete(m.files, route) }, "path missing from generated: " + route},
		{"drop a symlink-reached vendored file", func(_ string, m *memTree) { delete(m.files, ingress) }, "path missing from generated: " + ingress},
		{"drop a path at the oldest tag only", func(tag string, m *memTree) {
			if tag == "v0.46.9" {
				delete(m.files, route)
			}
		}, `field minFrom: generated "0.47", reviewed "0.46"`},
	}
	rules := rulesFrom(t, "testdata/knative/rules.json")
	golden := readFile(t, "testdata/knative/golden-b.json")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustGenerate(t, knativeInput(t, knativeSource(t, c.mutate), rules))
			diffs, err := Diff(res.B, golden)
			if err != nil {
				t.Fatal(err)
			}
			if len(diffs) == 0 {
				t.Fatal("seeded drop produced a target equal to the reviewed one")
			}
			found := false
			for _, d := range diffs {
				found = found || strings.Contains(d, c.want)
			}
			if !found {
				t.Fatalf("diff %v lacks %q", diffs, c.want)
			}
		})
	}

	t.Run("drop one CRD version", func(t *testing.T) {
		two := func(m *memTree) {
			replaceCRD(m, route, "    storage: true\n", "    storage: true\n  - name: v1beta1\n    served: true\n    storage: false\n")
		}
		base := mustGenerate(t, knativeInput(t, knativeSource(t, func(_ string, m *memTree) { two(m) }), rules))
		seeded := mustGenerate(t, knativeInput(t, knativeSource(t, func(tag string, m *memTree) {
			two(m)
			if tag == "v0.51.0" {
				replaceCRD(m, route, "  - name: v1beta1\n    served: true\n    storage: false\n", "")
			}
		}), rules))
		if base.Report.FactsDigest == seeded.Report.FactsDigest {
			t.Fatal("a dropped version left the facts digest unchanged")
		}
	})

	t.Run("drop the install source of a project", func(t *testing.T) {
		src := traefikSource(t, func(_ string, m *memTree) {
			delete(m.files, "docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml")
		})
		_, err := Generate(traefikInput(t, src, rulesFrom(t, "testdata/traefik/rules.json")))
		wantStop(t, err, StopNoCRDSource)
	})
}

func wantStop(t *testing.T, err error, code string) *StopError {
	t.Helper()
	var se *StopError
	if !errors.As(err, &se) {
		t.Fatalf("want stop %s, got %v", code, err)
	}
	for _, s := range se.Stops {
		if s.Code == code {
			if s.Next == "" {
				t.Errorf("stop %s has no next action", code)
			}
			return se
		}
	}
	t.Fatalf("stops %+v lack %s", se.Stops, code)
	return nil
}

func TestTypedStops(t *testing.T) {
	gate := "third_party/gateway-api-latest/gateway-api.yaml"
	crdFile := func(group, kind string) []byte {
		return []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + group + "\n  names:\n    kind: " + kind + "\n  versions:\n  - name: v1\n")
	}
	kn := func(mutate func(tag string, m *memTree), rules *Rules) error {
		_, err := Generate(knativeInput(t, knativeSource(t, mutate), rules))
		return err
	}
	tr := func(mutate func(tag string, m *memTree), rules *Rules) error {
		_, err := Generate(traefikInput(t, traefikSource(t, mutate), rules))
		return err
	}
	kr := func() *Rules { return rulesFrom(t, "testdata/knative/rules.json") }
	trr := func() *Rules { return rulesFrom(t, "testdata/traefik/rules.json") }
	all := func(f func(m *memTree)) func(string, *memTree) { return func(_ string, m *memTree) { f(m) } }

	cases := []struct {
		name string
		run  func() error
		code string
	}{
		{"third-party bundle without a pinned rule", func() error { return kn(nil, nil) }, StopUnpinnedExclusion},
		{"docs-only CRD source without an accepted surface", func() error { return tr(nil, &Rules{Schema: RulesSchema, Upstream: trr().Upstream}) }, StopDocsOnlyCRDSource},
		{"template syntax", func() error {
			return kn(all(func(m *memTree) {
				m.files["config/core/300-resources/route.yaml"] = []byte("kind: CustomResourceDefinition\nname: {{ .Name }}\n")
			}), kr())
		}, StopUnreadableShape},
		{"patch without spec.group", func() error {
			return kn(all(func(m *memTree) {
				m.files["config/core/300-resources/route.yaml"] = []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: routes.serving.knative.dev\nspec:\n  versions:\n  - name: v1\n")
			}), kr())
		}, StopUnreadableShape},
		{"no spec.versions", func() error {
			return kn(all(func(m *memTree) {
				m.files["config/core/300-resources/route.yaml"] = []byte("kind: CustomResourceDefinition\nspec:\n  group: serving.knative.dev\n  names:\n    kind: Route\n")
			}), kr())
		}, StopUnreadableShape},
		{"excluded file defines an owned group", func() error {
			return kn(all(func(m *memTree) { m.files[gate] = crdFile("serving.knative.dev", "Other") }), kr())
		}, StopExclusionOwnedGroup},
		{"rule matches nothing", func() error {
			r := kr()
			r.Exclusions = append(r.Exclusions, ExclusionRule{Class: ClassExactFile, Path: "third_party/nope/nope.yaml", Reason: "r", Evidence: "e"})
			return kn(nil, r)
		}, StopRuleMatchesNothing},
		{"duplicate definition", func() error {
			return kn(all(func(m *memTree) {
				m.files["config/core/300-resources/service2.yaml"] = m.files["config/core/300-resources/service.yaml"]
			}), kr())
		}, StopDuplicateCRD},
		{"reserved group in an install path", func() error {
			return kn(all(func(m *memTree) { m.files["config/crd/mesh.yaml"] = crdFile("x-k8s.io", "Mesh") }), kr())
		}, StopReservedGroup},
		{"group owned by another project", func() error {
			return kn(all(func(m *memTree) { m.files["config/crd/issuer.yaml"] = crdFile("cert-manager.io", "Issuer") }), kr())
		}, StopGroupOwnedElsewhere},
		{"fixture hides an owned CRD", func() error {
			return tr(all(func(m *memTree) { m.files["integration/fixtures/extra.yml"] = crdFile("traefik.io", "Hidden") }), trr())
		}, StopFixtureHiddenOwnedCRD},
		{"community row without upstream", func() error {
			r := trr()
			r.Upstream = nil
			return tr(nil, r)
		}, StopCommunityUpstream},
		{"symbolic link leaving the tree", func() error {
			return kn(all(func(m *memTree) { m.links["config/core/escape.yaml"] = "../../../outside.yaml" }), kr())
		}, StopSymlinkEscapes},
		{"too few tags read the same files", func() error {
			return kn(func(tag string, m *memTree) {
				if tag != "v0.51.0" {
					delete(m.files, "config/core/300-resources/route.yaml")
				}
			}, kr())
		}, StopWindowTooShort},
		{"mixed tag prefixes", func() error {
			in := knativeInput(t, knativeSource(t, nil), kr())
			in.Tags = []string{"v0.50.0", "0.51.0"}
			_, err := Generate(in)
			return err
		}, StopTagPrefixMixed},
		{"two tags of one line", func() error {
			in := knativeInput(t, knativeSource(t, nil), kr())
			in.Tags = []string{"v0.50.0", "v0.50.1"}
			_, err := Generate(in)
			return err
		}, StopTagLineDuplicate},
		{"unsupported tag prefix", func() error {
			in := knativeInput(t, knativeSource(t, nil), kr())
			in.Tags = []string{"rel0.50.0", "rel0.51.0"}
			_, err := Generate(in)
			return err
		}, StopTagPrefixUnsupported},
		{"not a release tag", func() error {
			in := knativeInput(t, knativeSource(t, nil), kr())
			in.Tags = []string{"main", "v0.51.0"}
			_, err := Generate(in)
			return err
		}, StopTagGrammar},
		{"tag missing from the checkout", func() error {
			in := knativeInput(t, knativeSource(t, nil), kr())
			in.Tags = []string{"v0.51.0", "v0.52.0"}
			_, err := Generate(in)
			return err
		}, StopTagUnreadable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantStop(t, c.run(), c.code) })
	}
}

func TestOlderTagWithUnreadableShapeShrinksWindow(t *testing.T) {
	src := knativeSource(t, func(tag string, m *memTree) {
		if tag == "v0.46.9" {
			m.files["config/core/300-resources/route.yaml"] = []byte("kind: CustomResourceDefinition\nname: {{ .Name }}\n")
		}
	})
	res := mustGenerate(t, knativeInput(t, src, rulesFrom(t, "testdata/knative/rules.json")))
	if res.Report.MinFrom != "0.47" || len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != "v0.46.9" || !strings.Contains(res.Report.Dropped[0].Reason, StopUnreadableShape) {
		t.Fatalf("report %+v", res.Report)
	}
}

func TestUnreadableFixtureUnderPinnedDirIsReported(t *testing.T) {
	src := traefikSource(t, func(_ string, m *memTree) {
		m.files["integration/fixtures/knative/templated.yml"] = []byte("kind: CustomResourceDefinition\nname: {{ .Name }}\n")
	})
	res := mustGenerate(t, traefikInput(t, src, rulesFrom(t, "testdata/traefik/rules.json")))
	found := false
	for _, d := range res.Report.Decisions {
		found = found || (d.Rule == RuleExcludePinnedFixtures && strings.HasPrefix(d.Detail, "excluded-unread"))
	}
	if !found {
		t.Fatal("unread fixture not reported")
	}
}

func TestParseRulesFailsClosed(t *testing.T) {
	good := `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"a/b.yaml","reason":"r","evidence":"e"}]}`
	if _, err := ParseRules([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown field":   `{"schema":"` + RulesSchema + `","extra":1,"installSurface":[],"exclusions":[]}`,
		"wrong schema":    `{"schema":"x","installSurface":[],"exclusions":[]}`,
		"trailing data":   good + `{}`,
		"unknown class":   `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"glob","path":"a/","reason":"r","evidence":"e"}]}`,
		"dir for file":    `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"a/","reason":"r","evidence":"e"}]}`,
		"file for dir":    `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"fixture-dir","path":"a/b.yaml","reason":"r","evidence":"e"}]}`,
		"no evidence":     `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"a/b.yaml","reason":"r","evidence":""}]}`,
		"path traversal":  `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"../b.yaml","reason":"r","evidence":"e"}]}`,
		"duplicate rule":  `{"schema":"` + RulesSchema + `","installSurface":[],"exclusions":[{"class":"exact-file","path":"a.yaml","reason":"r","evidence":"e"},{"class":"exact-file","path":"a.yaml","reason":"r","evidence":"e"}]}`,
		"surface no why":  `{"schema":"` + RulesSchema + `","installSurface":[{"path":"a.yaml","reason":""}],"exclusions":[]}`,
		"surface is dir":  `{"schema":"` + RulesSchema + `","installSurface":[{"path":"a/","reason":"r"}],"exclusions":[]}`,
	} {
		if _, err := ParseRules([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
