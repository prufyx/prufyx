// SPDX-License-Identifier: AGPL-3.0-only

package k8sdeclared

import (
	"errors"
	"strings"
	"testing"
)

const hexA = "0123456789abcdef0123456789abcdef01234567"

type fakeFetcher struct {
	files map[string]string // "repo@tag@path" -> content
}

func (f fakeFetcher) ResolveTag(repo, tag string) (Resolution, error) {
	return Resolution{Commit: hexA, TagRefResponseSHA256: sha256Hex([]byte(repo + tag))}, nil
}

func (f fakeFetcher) ReadFile(repo, path, commit string) (File, error) {
	// the fake keys by path only; one tag per call site
	for k, v := range f.files {
		if strings.HasSuffix(k, "@"+path) {
			return File{BlobSHA: hexA, Data: []byte(v), ContentsResponseSHA256: sha256Hex([]byte(v))}, nil
		}
	}
	return File{}, ErrNotFound
}

const chartMin = "apiVersion: v2\nname: x\nversion: 1.2.3\nkubeVersion: \">=1.25.0-0\"\n"

const matrix = `# T
| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 | Kubernetes 1.35 | Kubernetes 1.36 |
|---|---|---|---|---|
| [` + "`release-0.17`" + `](u) | ✔ | ✔ | x | x |
| [` + "`release-0.18`" + `](u) | x | ✔ | ✔ | ✔ |
| [` + "`release-0.19`" + `](u) | x | ✔ | ✔ | x |
| [` + "`release-0.20`" + `](u) | ✔ | ✔ | x | ✔ |
`

func inputFor(src *InputSource, tags ...string) (Input, []byte) {
	return Input{Schema: "prufyx.k8s-declared-projects/v1", Projects: []InputProject{{Project: "p", Repo: "o/r", Source: src, Tags: tags}}}, []byte("raw-inputs")
}

func build(t *testing.T, src *InputSource, files map[string]string, tags ...string) Output {
	t.Helper()
	in, raw := inputFor(src, tags...)
	out, err := Build(in, raw, fakeFetcher{files}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(out, &in, raw); err != nil {
		t.Fatalf("own output fails Verify: %v", err)
	}
	return out
}

var chartSrc = &InputSource{Kind: KindChart, Path: "c/Chart.yaml"}
var matrixSrc = &InputSource{Kind: KindMatrix, Path: "README.md", Matrix: &InputMatrix{HeaderFirstCell: "kube-prometheus stack", RowKeyPrefix: "release-", RowKeySuffix: ""}}

func TestChartMinimumOnlyIsNeverARange(t *testing.T) {
	r := build(t, chartSrc, map[string]string{"o/r@t@c/Chart.yaml": chartMin}, "v1.2.3").Projects[0].Releases[0]
	if r.Status != StatusDeclared || r.Shape != ShapeMinOnly || r.Minimum != "1.25.0" || r.Maximum != "" || r.MaxAtMatrixEdge {
		t.Fatalf("%+v", r)
	}
	md := Markdown(Output{Schema: SchemaID, Label: Label, Projects: []OutputProject{{Project: "p", Repo: "o/r", Releases: []Release{r}}}})
	if strings.Contains(md, "range 1.25") || strings.Contains(md, "| range") || !strings.Contains(md, "no maximum declared") || !strings.Contains(md, "declared by the chart") {
		t.Fatalf("min-only rendered as a range or without the chart label:\n%s", md)
	}
	if strings.Contains(strings.ToLower(md), "supported by") {
		t.Fatal("support wording")
	}
}

func TestChartUpperBoundNeverBecomesMaximum(t *testing.T) {
	for _, c := range []string{`">=1.25.0-0 <1.40.0"`, `"^1.25.0"`, `"~1.25.0"`, `">=1.25.0 || >=1.20.0"`, `"1.x"`, `"1.25.0"`, `">=1.30.0-rc.1"`, `">= 1.25.0-beta"`} {
		src := "apiVersion: v2\nname: x\nversion: 1.2.3\nkubeVersion: " + c + "\n"
		r := build(t, chartSrc, map[string]string{"o/r@t@c/Chart.yaml": src}, "v1.2.3").Projects[0].Releases[0]
		if r.Status != StatusNotDeclared || r.Reason != ReasonNotLowerBound || r.Minimum != "" || r.Maximum != "" {
			t.Errorf("%s: %+v", c, r)
		}
	}
}

func TestPreReleaseCoreIsNotCompared(t *testing.T) {
	if _, err := ReleaseLine("v1.2.3-rc.1"); err == nil {
		t.Fatal("pre-release tag accepted")
	}
	if _, err := ReleaseLine("v1.2.3+build"); err == nil {
		t.Fatal("build tag accepted")
	}
	bad := "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34-rc | Kubernetes 1.35 |\n|---|---|---|---|\n| `release-0.17` | x | ✔ | ✔ |\n"
	r := build(t, matrixSrc, map[string]string{"o/r@t@README.md": bad}, "v0.17.0").Projects[0].Releases[0]
	if r.Status != StatusNotDeclared || r.Reason != ReasonMatrixLayout {
		t.Fatalf("%+v", r)
	}
}

func TestMissingSourceIsNotDeclared(t *testing.T) {
	r := build(t, nil, nil, "v1.2.3").Projects[0].Releases[0]
	if r.Status != StatusNotDeclared || r.Reason != ReasonNoSource || r.Citation != nil {
		t.Fatalf("%+v", r)
	}
	r = build(t, chartSrc, map[string]string{}, "v1.2.3").Projects[0].Releases[0]
	if r.Status != StatusNotDeclared || r.Reason != ReasonSourceAbsent {
		t.Fatalf("%+v", r)
	}
	r = build(t, chartSrc, map[string]string{"o/r@t@c/Chart.yaml": "apiVersion: v2\nname: x\nversion: 1.2.3\n"}, "v1.2.3").Projects[0].Releases[0]
	if r.Status != StatusNotDeclared || r.Reason != ReasonNoDeclaration || r.Citation == nil {
		t.Fatalf("%+v", r)
	}
}

func TestMatrixBounded(t *testing.T) {
	files := map[string]string{"o/r@t@README.md": matrix}
	cases := map[string]struct {
		status, min, max string
		edge             bool
		reason           string
	}{
		"v0.17.0": {reason: ReasonMatrixLowerEdge}, // run starts at the first column
		"v0.18.0": {status: StatusDeclared, min: "1.34", max: "1.36", edge: true},
		"v0.19.0": {status: StatusDeclared, min: "1.34", max: "1.35"},
		"v0.20.0": {reason: ReasonMatrixLayout}, // gap in the run
		"v0.21.0": {reason: ReasonMatrixRowAbsent},
	}
	for tag, want := range cases {
		r := build(t, matrixSrc, files, tag).Projects[0].Releases[0]
		if want.reason != "" {
			if r.Status != StatusNotDeclared || r.Reason != want.reason {
				t.Errorf("%s: %+v", tag, r)
			}
			continue
		}
		if r.Status != StatusDeclared || r.Shape != ShapeBounded || r.Minimum != want.min || r.Maximum != want.max || r.MaxAtMatrixEdge != want.edge {
			t.Errorf("%s: %+v", tag, r)
		}
		if got := len(r.Citation.CitedLines); got != 2 || r.Citation.LineStart != 2 {
			t.Errorf("%s: cited %+v", tag, r.Citation)
		}
	}
}

func TestMatrixFailsClosedOnLayoutChange(t *testing.T) {
	for name, doc := range map[string]string{
		"blank cell":    "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 |\n|---|---|---|\n| `release-0.17` | x |  |\n",
		"other symbol":  "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 |\n|---|---|---|\n| `release-0.17` | x | yes |\n",
		"non-adjacent":  "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.35 |\n|---|---|---|\n| `release-0.17` | x | ✔ |\n",
		"cell count":    "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 |\n|---|---|---|\n| `release-0.17` | ✔ |\n",
		"no header":     "| other | Kubernetes 1.33 |\n|---|---|\n| `release-0.17` | ✔ |\n",
		"duplicate row": "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 |\n|---|---|---|\n| `release-0.17` | x | ✔ |\n| `release-0.17` | x | ✔ |\n",
		"all crosses":   "| kube-prometheus stack | Kubernetes 1.33 | Kubernetes 1.34 |\n|---|---|---|\n| `release-0.17` | x | x |\n",
	} {
		r := build(t, matrixSrc, map[string]string{"o/r@t@README.md": doc}, "v0.17.0").Projects[0].Releases[0]
		if r.Status != StatusNotDeclared || r.Minimum != "" || r.Maximum != "" {
			t.Errorf("%s: declared %+v", name, r)
		}
	}
}

func TestDeterministic(t *testing.T) {
	files := map[string]string{"o/r@t@c/Chart.yaml": chartMin}
	a, _ := Marshal(build(t, chartSrc, files, "v1.2.3"))
	b, _ := Marshal(build(t, chartSrc, files, "v1.2.3"))
	if string(a) != string(b) {
		t.Fatal("JSON differs")
	}
	if Markdown(build(t, chartSrc, files, "v1.2.3")) != Markdown(build(t, chartSrc, files, "v1.2.3")) {
		t.Fatal("Markdown differs")
	}
}

func TestVerifyRefusesIncompleteOrTamperedCitations(t *testing.T) {
	in, raw := inputFor(chartSrc, "v1.2.3")
	good, err := Build(in, raw, fakeFetcher{map[string]string{"o/r@t@c/Chart.yaml": chartMin}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(o *Output){
		"no citation":    func(o *Output) { o.Projects[0].Releases[0].Citation = nil },
		"empty commit":   func(o *Output) { o.Projects[0].Releases[0].Citation.Commit = "" },
		"short commit":   func(o *Output) { o.Projects[0].Releases[0].Citation.Commit = hexA[:39] },
		"no file digest": func(o *Output) { o.Projects[0].Releases[0].Citation.FileSHA256 = "" },
		"no blob":        func(o *Output) { o.Projects[0].Releases[0].Citation.BlobSHA = "" },
		"no api digest":  func(o *Output) { o.Projects[0].Releases[0].Citation.TagRefResponseSHA256 = "" },
		"no contents":    func(o *Output) { o.Projects[0].Releases[0].Citation.ContentsResponseSHA256 = "" },
		"no path":        func(o *Output) { o.Projects[0].Releases[0].Citation.Path = "" },
		"no lines":       func(o *Output) { o.Projects[0].Releases[0].Citation.CitedLines = nil },
		"span":           func(o *Output) { o.Projects[0].Releases[0].Citation.LineEnd = 99 },
		"other tag":      func(o *Output) { o.Projects[0].Releases[0].Citation.Tag = "v9.9.9" },
		"min tampered":   func(o *Output) { o.Projects[0].Releases[0].Minimum = "1.20.0" },
		"max added":      func(o *Output) { o.Projects[0].Releases[0].Maximum = "1.40" },
		"bounded chart":  func(o *Output) { o.Projects[0].Releases[0].Shape = ShapeBounded },
		"kind":           func(o *Output) { o.Projects[0].Releases[0].SourceKind = KindMatrix },
		"unknown reason": func(o *Output) {
			r := &o.Projects[0].Releases[0]
			*r = Release{Tag: r.Tag, Line: r.Line, Status: StatusNotDeclared, Reason: "guess"}
		},
		"status": func(o *Output) { o.Projects[0].Releases[0].Status = "supported" },
		"label":  func(o *Output) { o.Label = "supported" },
	}
	for name, mutate := range mutations {
		o := clone(t, good)
		mutate(&o)
		if err := Verify(o, &in, raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Verify(good, &in, []byte("other-inputs")); err == nil {
		t.Error("changed projects file accepted")
	}
	other := in
	other.Projects = []InputProject{{Project: "p", Repo: "o/r", Source: chartSrc, Tags: []string{"v1.2.4"}}}
	if err := Verify(good, &other, raw); err == nil {
		t.Error("changed tags accepted")
	}
}

func clone(t *testing.T, o Output) Output {
	t.Helper()
	raw, err := Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var c Output
	if err := strictDecode(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecodeInputFailsClosed(t *testing.T) {
	ok := `{"schema":"prufyx.k8s-declared-projects/v1","projects":[{"project":"p","repo":"o/r","tags":["v1.2.3"]}]}`
	if _, err := DecodeInput([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown field": strings.Replace(ok, `"tags"`, `"x":1,"tags"`, 1),
		"pre-release":   strings.Replace(ok, "v1.2.3", "v1.2.3-rc.1", 1),
		"same line":     strings.Replace(ok, `["v1.2.3"]`, `["v1.2.3","v1.2.4"]`, 1),
		"bad repo":      strings.Replace(ok, "o/r", "o/r/x", 1),
		"bad kind":      strings.Replace(ok, `"tags"`, `"source":{"kind":"go_mod","path":"go.mod"},"tags"`, 1),
		"dotdot":        strings.Replace(ok, `"tags"`, `"source":{"kind":"chart_kubeversion","path":"a/../b"},"tags"`, 1),
		"schema":        strings.Replace(ok, "v1", "v2", 1),
		"trailing":      ok + "{}",
		"no tags":       strings.Replace(ok, `["v1.2.3"]`, `[]`, 1),
	} {
		if _, err := DecodeInput([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestErrNotFoundSentinel(t *testing.T) {
	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Fatal()
	}
}
