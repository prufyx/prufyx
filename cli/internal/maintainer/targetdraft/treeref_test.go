// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"reflect"
	"testing"
)

func refTreeOf(files map[string]string, links ...string) ([]Entry, func(string) ([]byte, error)) {
	var es []Entry
	for p := range files {
		es = append(es, Entry{Path: p})
	}
	for _, l := range links {
		es = append(es, Entry{Path: l, IsLink: true})
	}
	return es, func(p string) ([]byte, error) {
		if c, ok := files[p]; ok {
			return []byte(c), nil
		}
		return nil, fmt.Errorf("no file %s", p)
	}
}

func TestReadTreeRefsLiteralSameTagOnly(t *testing.T) {
	es, rd := refTreeOf(map[string]string{
		"deploy/kustomization.yaml":   "resources:\n- ../config/crd\n- crd.yaml\n- ./sub/\n- missing.yaml\n- https://example.test/x\n- ../../escape\n- $(VAR)/x\n- '{{ .x }}'\n- /abs\n- 'a b'\nbases:\n- ../base\n",
		"deploy/crd.yaml":             "x: 1",
		"deploy/sub/a.yaml":           "x: 1",
		"config/crd/a.yaml":           "x: 1",
		"base/b.yaml":                 "x: 1",
		"charts/x/Chart.yaml":         "name: x",
		"charts/x/crds/c.yaml":        "x: 1",
		"charts/y/Chart.yaml":         "name: y",
		"docs/kustomization.yaml":     "resources:\n- ../base\n",
		"vendor/k/kustomization.yaml": "resources:\n- ../../base\n",
	})
	got := ReadTreeRefs(es, rd)
	want := []TreeRef{
		{From: "charts/x/Chart.yaml", To: "charts/x/crds/", Kind: RefChartCRDs},
		{From: "deploy/kustomization.yaml", To: "base/", Kind: RefKustomizeBase},
		{From: "deploy/kustomization.yaml", To: "config/crd/", Kind: RefKustomizeResource},
		{From: "deploy/kustomization.yaml", To: "deploy/crd.yaml", Kind: RefKustomizeResource},
		{From: "deploy/kustomization.yaml", To: "deploy/sub/", Kind: RefKustomizeResource},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("refs\n got %+v\nwant %+v", got, want)
	}
	// Deterministic.
	if again := ReadTreeRefs(es, rd); !reflect.DeepEqual(again, got) {
		t.Fatal("not deterministic")
	}
}

func TestCoveredFiles(t *testing.T) {
	es, rd := refTreeOf(map[string]string{
		"deploy/kustomization.yaml":     "resources:\n- sub\n- one.yaml\n",
		"deploy/one.yaml":               "x: 1",
		"deploy/two.yaml":               "x: 1",
		"deploy/sub/kustomization.yaml": "resources:\n- a.yaml\n",
		"deploy/sub/a.yaml":             "x: 1",
		"deploy/sub/b.yaml":             "x: 1",
		"charts/x/Chart.yaml":           "name: x",
		"charts/x/crds/c.yaml":          "x: 1",
		"charts/x/crds/deep/d.yaml":     "x: 1",
	}, "deploy/link.yaml")
	cov := CoveredFiles(es, ReadTreeRefs(es, rd))
	for _, p := range []string{"deploy/one.yaml", "deploy/sub/a.yaml", "charts/x/crds/c.yaml"} {
		if !cov[p] {
			t.Errorf("%s should be covered", p)
		}
	}
	// A directory reference covers nothing by itself; a file nobody lists and
	// a deeper chart file are not covered.
	for _, p := range []string{"deploy/two.yaml", "deploy/sub/b.yaml", "charts/x/crds/deep/d.yaml", "deploy/link.yaml"} {
		if cov[p] {
			t.Errorf("%s must not be covered", p)
		}
	}
	// A link is never a reference target.
	es2, rd2 := refTreeOf(map[string]string{"k/kustomization.yaml": "resources:\n- l.yaml\n"}, "k/l.yaml")
	if got := ReadTreeRefs(es2, rd2); len(got) != 0 {
		t.Fatalf("a link was followed: %+v", got)
	}
}
