// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

func dirSpec(p string) crdversions.PathSpec {
	return crdversions.PathSpec{Path: p, Dir: true, Match: mapMatchRE, Guard: mapGuardRE}
}

func okTarget() crdversions.Target {
	return crdversions.Target{
		Project: "demo", Repo: "github.com/example/demo", TagPrefixes: []string{"v"},
		MinFrom: [2]int{1, 0}, Attest: true,
		Paths: []crdversions.PathSpec{dirSpec("config/crd")},
	}
}

func mustRE(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func codes(r Reasons) []string {
	out := []string{}
	for _, x := range r {
		out = append(out, x.Code)
	}
	return out
}

func TestTargetFromCRDVersionsSynthetic(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*crdversions.Target)
		want  []string // nil: maps clean
		files []string
		dirs  []string
	}{
		{name: "clean v", mut: func(*crdversions.Target) {}, dirs: []string{"config/crd"}},
		{name: "clean bare", mut: func(x *crdversions.Target) { x.TagPrefixes = []string{""} }, dirs: []string{"config/crd"}},
		{name: "clean dual", mut: func(x *crdversions.Target) { x.TagPrefixes = []string{"v", ""} }, dirs: []string{"config/crd"}},
		{name: "file and dir", mut: func(x *crdversions.Target) {
			x.Paths = append(x.Paths, crdversions.PathSpec{Path: "deploy/crd.yaml"})
		}, files: []string{"deploy/crd.yaml"}, dirs: []string{"config/crd"}},
		{name: "chart prefix", mut: func(x *crdversions.Target) { x.TagPrefixes = []string{"jenkins-"} }, want: []string{ReasonMapTagPrefix}},
		{name: "knative prefix", mut: func(x *crdversions.Target) { x.TagPrefixes = []string{"knative-v"} }, want: []string{ReasonMapTagPrefix}},
		{name: "no prefix list", mut: func(x *crdversions.Target) { x.TagPrefixes = nil }, want: []string{ReasonMapTagPrefix}},
		{name: "duplicate prefix", mut: func(x *crdversions.Target) { x.TagPrefixes = []string{"v", "v"} }, want: []string{ReasonMapTagPrefix}},
		{name: "calver scheme", mut: func(x *crdversions.Target) {
			x.TagPrefixes, x.ReleaseScheme = nil, crdversions.SchemeCalverEdge
		}, want: []string{ReasonMapReleaseScheme}},
		{name: "exclude", mut: func(x *crdversions.Target) {
			x.Exclude = []crdversions.Exclusion{{Path: "examples/"}}
		}, want: []string{ReasonMapExclude}},
		{name: "channels", mut: func(x *crdversions.Target) {
			x.DeclaredChannel = "standard"
			x.Channels = []crdversions.Channel{{Name: "experimental", Paths: []crdversions.PathSpec{dirSpec("exp")}}}
		}, want: []string{ReasonMapChannels}},
		{name: "declared channel only", mut: func(x *crdversions.Target) { x.DeclaredChannel = "standard" }, want: []string{ReasonMapChannels}},
		{name: "remote", mut: func(x *crdversions.Target) { x.Remote = &crdversions.Remote{} }, want: []string{ReasonMapRemote}},
		{name: "not attested", mut: func(x *crdversions.Target) { x.Attest = false }, want: []string{ReasonMapNotAttested}},
		{name: "recursive dir", mut: func(x *crdversions.Target) {
			p := dirSpec("config/crd")
			p.Recursive = true
			x.Paths = []crdversions.PathSpec{p}
		}, want: []string{ReasonMapPath}},
		{name: "optional path", mut: func(x *crdversions.Target) {
			p := dirSpec("config/crd")
			p.Optional = true
			x.Paths = []crdversions.PathSpec{p}
		}, want: []string{ReasonMapPath}},
		{name: "other match", mut: func(x *crdversions.Target) {
			p := dirSpec("config/crd")
			p.Match = mustRE(`^k8gb\..*$`)
			x.Paths = []crdversions.PathSpec{p}
		}, want: []string{ReasonMapPath}},
		{name: "other guard", mut: func(x *crdversions.Target) {
			p := dirSpec("config/crd")
			p.Guard = mustRE(`(?i)k8gb`)
			x.Paths = []crdversions.PathSpec{p}
		}, want: []string{ReasonMapPath}},
		{name: "dir without match", mut: func(x *crdversions.Target) {
			x.Paths = []crdversions.PathSpec{{Path: "config/crd", Dir: true}}
		}, want: []string{ReasonMapPath}},
		{name: "no paths", mut: func(x *crdversions.Target) { x.Paths = nil }, want: []string{ReasonMapPath}},
		{name: "unclean path", mut: func(x *crdversions.Target) {
			x.Paths = []crdversions.PathSpec{dirSpec("../crd")}
		}, want: []string{ReasonMapPath}},
		{name: "bad repo", mut: func(x *crdversions.Target) { x.Repo = "gitlab.com/a/b" }, want: []string{ReasonMapRepo}},
		{name: "several", mut: func(x *crdversions.Target) {
			x.Attest = false
			x.Exclude = []crdversions.Exclusion{{Path: "e/"}}
		}, want: []string{ReasonMapExclude, ReasonMapNotAttested}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := okTarget()
			c.mut(&in)
			got, rs := TargetFromCRDVersions(in)
			if c.want == nil {
				if len(rs) != 0 {
					t.Fatalf("refused: %v", rs)
				}
				if got.Repo.Key != "github.com/example/demo" || !reflect.DeepEqual(got.Files, c.files) || !reflect.DeepEqual(got.Dirs, c.dirs) {
					t.Fatalf("mapped %+v", got)
				}
				if err := got.validate(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !reflect.DeepEqual(codes(rs), c.want) {
				t.Fatalf("reasons %v want %v", codes(rs), c.want)
			}
			if !reflect.DeepEqual(got, Target{}) {
				t.Fatalf("refusal returned a partial target: %+v", got)
			}
		})
	}
}

// The tag grammar crdschema reads, which the mapper relies on when it accepts
// the plain prefixes.
func TestCrdschemaTagGrammar(t *testing.T) {
	c1, c2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	tag := func(n, c string) extract.Tag { return extract.Tag{Name: n, Commit: c} }
	cases := []struct {
		name     string
		tags     []extract.Tag
		versions []string // first-line versions in order, "" problem free
		problem  map[string]bool
	}{
		{name: "v prefix", tags: []extract.Tag{tag("v1.2.0", c1), tag("v1.2.1", c1)}, versions: []string{"1.2.0", "1.2.1"}},
		{name: "bare", tags: []extract.Tag{tag("1.2.0", c1)}, versions: []string{"1.2.0"}},
		{name: "dual prefix same commit", tags: []extract.Tag{tag("v1.2.0", c1), tag("1.2.0", c1)}, versions: []string{"1.2.0"}},
		{name: "dual prefix different commit withholds", tags: []extract.Tag{tag("v1.2.0", c1), tag("1.2.0", c2)}, versions: []string{"1.2.0"}, problem: map[string]bool{"1.2": true}},
		{name: "padded minor withholds", tags: []extract.Tag{tag("v26.02.0", c1)}, versions: nil, problem: map[string]bool{}},
		{name: "padded patch withholds", tags: []extract.Tag{tag("v1.2.03", c1), tag("v1.2.0", c1)}, versions: []string{"1.2.0"}, problem: map[string]bool{"1.2": true}},
		{name: "pre-release ignored", tags: []extract.Tag{tag("v1.3.0-rc.1", c1), tag("v1.3.0", c2)}, versions: []string{"1.3.0"}},
		{name: "pre-release alone is no line", tags: []extract.Tag{tag("v1.3.0-rc.1", c1)}, versions: nil},
		{name: "other prefix ignored", tags: []extract.Tag{tag("api/v1.2.0", c1), tag("jenkins-1.2.0", c1)}, versions: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := releaseLines(extract.ReleaseIndex{Repo: repo, Tags: c.tags})
			var vs []string
			for _, l := range lines {
				vs = append(vs, l.Versions...)
				if l.Problem != "" != c.problem[l.key()] {
					t.Errorf("line %s problem %q want %v", l.key(), l.Problem, c.problem[l.key()])
				}
			}
			if !reflect.DeepEqual(vs, c.versions) {
				t.Fatalf("versions %v want %v", vs, c.versions)
			}
			if c.name == "padded minor withholds" && len(c.problem) == 0 {
				// the padded tag has no canonical line; it must not vanish silently
				if len(lines) != 0 {
					t.Fatalf("lines %v", lines)
				}
			}
		})
	}
}

func realTargets(t *testing.T) []crdversions.Target {
	t.Helper()
	if len(crdversions.Targets) == 0 {
		t.Fatal("no real crdversions targets")
	}
	return crdversions.Targets
}

// The pilots are pinned exactly. If this fails, the pilots must be
// re-evaluated deliberately (is the change to the target or the mapper
// intended?); a new unrelated target never fails here.
func TestTargetFromCRDVersionsPilots(t *testing.T) {
	want := map[string][]string{
		"argo-cd":          nil,
		"cert-manager":     {ReasonMapExclude},
		"kuma":             {ReasonMapExclude},
		"mariadb-operator": {ReasonMapExclude},
	}
	seen := map[string]bool{}
	for _, tg := range realTargets(t) {
		w, ok := want[tg.Project]
		if !ok {
			continue
		}
		seen[tg.Project] = true
		got, rs := TargetFromCRDVersions(tg)
		if !reflect.DeepEqual(codes(rs), append([]string{}, w...)) && !(w == nil && len(rs) == 0) {
			t.Errorf("%s: reasons %v want %v; pilots must be re-evaluated deliberately", tg.Project, codes(rs), w)
		}
		if w == nil {
			if !reflect.DeepEqual(got.Dirs, []string{"manifests/crds"}) || len(got.Files) != 0 || got.Repo.Key != "github.com/argoproj/argo-cd" {
				t.Errorf("argo-cd mapped %+v", got)
			}
		}
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("pilot %s missing from the real targets", p)
		}
	}
}

// Invariants over every real target. A new or changed target file must not
// break this test: it only requires a closed outcome.
func TestTargetFromCRDVersionsRealInvariants(t *testing.T) {
	closed := map[string]bool{ReasonMapRepo: true, ReasonMapNotAttested: true, ReasonMapTagPrefix: true,
		ReasonMapReleaseScheme: true, ReasonMapExclude: true, ReasonMapChannels: true, ReasonMapRemote: true, ReasonMapPath: true}
	for _, tg := range realTargets(t) {
		got, rs := TargetFromCRDVersions(tg)
		got2, rs2 := TargetFromCRDVersions(tg)
		if !reflect.DeepEqual(got, got2) || !reflect.DeepEqual(rs, rs2) {
			t.Errorf("%s: not deterministic", tg.Project)
		}
		if len(rs) > 0 {
			if !reflect.DeepEqual(got, Target{}) {
				t.Errorf("%s: partial target with reasons", tg.Project)
			}
			for _, r := range rs {
				if !closed[r.Code] {
					t.Errorf("%s: unknown reason code %q", tg.Project, r.Code)
				}
			}
			continue
		}
		if err := got.validate(); err != nil {
			t.Errorf("%s maps to an invalid target: %v", tg.Project, err)
		}
		var files, dirs []string
		for _, p := range tg.Paths {
			if p.Dir {
				dirs = append(dirs, p.Path)
			} else {
				files = append(files, p.Path)
			}
		}
		if got.Repo.Key != strings.ToLower(tg.Repo) || !reflect.DeepEqual(got.Files, files) || !reflect.DeepEqual(got.Dirs, dirs) ||
			len(tg.Exclude) != 0 || len(tg.Channels) != 0 || tg.Remote != nil || !tg.Attest {
			t.Errorf("%s: mapped target disagrees with its source", tg.Project)
		}
	}
}
