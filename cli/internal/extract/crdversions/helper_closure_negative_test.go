// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha1" //nolint:gosec // Git object IDs for synthetic fixtures
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// helperClosureReader gives the synthetic tree Git blob IDs, including the
// header, so rejection tests reach the helper proof rather than fail hashing.
type helperClosureReader struct{ memReader }

func (r helperClosureReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	entries, err := r.memReader.List(repo, commit, dir)
	for i := range entries {
		if entries[i].Type == "tree" {
			entries[i].Mode = "040000"
			continue
		}
		data, e := r.memReader.Read(repo, commit, entries[i].Path)
		if e != nil {
			return nil, e
		}
		h := sha1.New()
		fmt.Fprintf(h, "blob %d%c", len(data), 0)
		h.Write(data)
		entries[i].SHA = hex.EncodeToString(h.Sum(nil))
	}
	return entries, err
}

type helperClosureSynth struct{ synthRepo }

func (s helperClosureSynth) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	return (helperClosureReader{s.files}).List(repo, commit, dir)
}

func TestStaticHelperClosureRefusesUnsafeChartAtScan(t *testing.T) {
	const chart = "charts/widgets"
	const helper = chart + "/templates/_helpers.tpl"
	const crdWord = "CustomResourceDefinition"
	good := `{{ define "widgets.validate" }}{{ if .Values.bad }}{{ fail "CustomResourceDefinition" }}{{ end }}{{ end }}`
	cases := map[string]struct {
		helper string
		extra  map[string]string
	}{
		"tpl sentinel":                {good + "<no value>", nil},
		"raw manifest":                {"kind: CustomResourceDefinition\n", nil},
		"nonempty unrelated output":   {good + "\nmetadata: unrelated\n", nil},
		"include":                     {`{{ define "x" }}{{ include "other" . }} CustomResourceDefinition {{ end }}`, nil},
		"template":                    {`{{ define "x" }}{{ template "other" . }} CustomResourceDefinition {{ end }}`, nil},
		"tpl":                         {`{{ define "x" }}{{ tpl .Values.x . }} CustomResourceDefinition {{ end }}`, nil},
		"range":                       {`{{ define "x" }}{{ range .Values.x }}CustomResourceDefinition{{ end }}{{ end }}`, nil},
		"mutation":                    {`{{ define "x" }}{{ $_ := set .Values "x" "CustomResourceDefinition" }}{{ end }}`, nil},
		"output branch":               {`{{ define "x" }}{{ if .Values.x }}CustomResourceDefinition{{ end }}{{ end }}`, nil},
		"malformed":                   {`{{ define "x" }} CustomResourceDefinition`, nil},
		"duplicate global definition": {good, map[string]string{chart + "/templates/_other.tpl": good}},
		"helmignore":                  {good, map[string]string{chart + "/.helmignore": "templates/*\n"}},
		"subchart":                    {good, map[string]string{chart + "/charts/sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"}},
		"dependency lock":             {good, map[string]string{chart + "/Chart.lock": "dependencies: []\n"}},
		"templated caller":            {good, map[string]string{chart + "/templates/caller.yaml": `{{ include "widgets.validate" . }}`}},
		"file cap":                    {good, map[string]string{chart + "/oversized.txt": strings.Repeat("x", 513<<10)}},
	}
	repo, err := extract.ParseRepo(synthTarget().Repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("inert control", func(t *testing.T) {
		r := helperClosureReader{specReader(map[string]string{chart + "/Chart.yaml": "apiVersion: v2\nname: widgets\nversion: 1.0.0\n", helper: good})}
		rec, err := New(synthTarget()).scan(context.Background(), r, repo, commitOf(specCommit), &Inventory{})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range rec.Findings {
			if f.Path == helper && f.Class == ClassNoDefinition && f.Reason == ReasonNoDefinition {
				return
			}
		}
		t.Fatalf("inert helper not proved at scanner seam: %+v", rec.Findings)
	})
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{chart + "/Chart.yaml": "apiVersion: v2\nname: widgets\nversion: 1.0.0\n", helper: tc.helper}
			for p, data := range tc.extra {
				files[p] = data
			}
			r := helperClosureReader{specReader(files)}
			rec, err := New(synthTarget()).scan(context.Background(), r, repo, commitOf(specCommit), &Inventory{})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range rec.Findings {
				if f.Path == helper {
					if f.Class != ClassUnsupported || f.Reason != ReasonSourceTemplate || !f.blocks() {
						t.Fatalf("unsafe helper accepted: %+v", f)
					}
					return
				}
			}
			t.Fatalf("missing typed refusal for %s: %+v", crdWord, rec.Findings)
		})
	}
}

func TestStaticHelperUnsafeClosureWithholdsPair(t *testing.T) {
	const helper = "charts/widgets/templates/_helpers.tpl"
	files := func(versions ...string) map[string]string {
		return map[string]string{
			"deploy/crds/a.yaml":        crd("Alpha", versions...),
			"charts/widgets/Chart.yaml": "apiVersion: v2\nname: widgets\nversion: 1.0.0\n",
			helper:                      `{{ define "widgets.validate" }}{{ if .Values.x }}CustomResourceDefinition{{ end }}{{ end }}`,
		}
	}
	s := newSynth(release{"v1.0.0", files("v1beta1", "v1")}, release{"v1.1.0", files("v1")})
	tg := synthTarget()
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extract.Run(context.Background(), New(tg).WithIndex(syntheticOwnership(tg, synthGroup)), ReleaseTags(New(tg), s), helperClosureSynth{s}, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || len(out.Entries) != 0 || (proof.Completeness != nil && proof.Completeness.Attestable) {
		t.Fatalf("unsafe helper yielded facts: pair=%+v entries=%d completeness=%+v", p, len(out.Entries), proof.Completeness)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		if inv == nil || inv.Scan == nil {
			t.Fatal("withheld pair lacks its source scan")
		}
		found := false
		for _, f := range inv.Scan.Findings {
			if f.Path == helper && f.Class == ClassUnsupported && f.Reason == ReasonSourceTemplate && f.blocks() {
				found = true
			}
		}
		if !found {
			t.Fatalf("pair withheld without the expected helper refusal: %+v", inv.Scan.Findings)
		}
	}
}
