// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/cliflags"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

type tree map[string]string

// File contents that stand for tree entries which are not regular files.
const (
	submodule = "\x00submodule"
	symlink   = "\x00symlink"
)

type memSource struct {
	commits map[string]tree
	tags    []extract.Tag
}

func (m memSource) Tags(extract.RepoRef) ([]extract.Tag, error) { return m.tags, nil }

func (m memSource) Read(_ extract.RepoRef, c, p string) ([]byte, error) {
	if v, ok := m.commits[c][p]; ok {
		return []byte(v), nil
	}
	return nil, extract.ErrNotFound
}

func (m memSource) List(_ extract.RepoRef, c, dir string) ([]extract.TreeEntry, error) {
	seen := map[string]extract.TreeEntry{}
	for p := range m.commits[c] {
		rest := p
		if dir != "" {
			r, ok := strings.CutPrefix(p, dir+"/")
			if !ok {
				continue
			}
			rest = r
		}
		first, _, deeper := strings.Cut(rest, "/")
		e := extract.TreeEntry{Mode: "100644", Type: "blob", Path: path.Join(dir, first)}
		switch {
		case deeper:
			e.Mode, e.Type = "040000", "tree"
		case m.commits[c][p] == submodule:
			e.Mode, e.Type = "160000", "commit"
		case m.commits[c][p] == symlink:
			e.Mode = "120000"
		}
		seen[e.Path] = e
	}
	if len(seen) == 0 {
		return nil, extract.ErrNotFound
	}
	return slices.Collect(maps.Values(seen)), nil
}

type memModules map[string][]byte

func (m memModules) Zip(p, v string, _ int) ([]byte, error) {
	if b, ok := m[p+"@"+v]; ok {
		return b, nil
	}
	return nil, errors.New("absent")
}

// makeZip builds a module zip and its go.sum hash.
func makeZip(t *testing.T, ref string, files map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	h := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		f, err := w.Create(ref + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%x  %s\n", sha256.Sum256([]byte(files[name])), ref+"/"+name)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

const (
	goMod = "module example.com/tool\n\ngo 1.22\n"
	// The older line registers old-flag and keep-flag.
	fromMain = `package main

import "flag"

func main() {
	flag.String("old-flag", "", "usage")
	flag.String("keep-flag", "", "usage")
	flag.Parse()
}
`
	toMain = `package main

import "flag"

func main() {
	flag.String("keep-flag", "", "usage")
	flag.Parse()
}
`
)

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
	shaD = strings.Repeat("d", 40)
)

type fixture struct {
	src     memSource
	pins    map[string]string
	lines   coveragereport.LinesFile
	modules memModules
	q       Request
	lim     limits
}

// clean is two releases per line that satisfy every source condition.
func clean() *fixture {
	from := func() tree { return tree{"go.mod": goMod, "main.go": fromMain} }
	to := func() tree { return tree{"go.mod": goMod, "main.go": toMain} }
	f := &fixture{
		src: memSource{commits: map[string]tree{shaA: from(), shaB: from(), shaC: to(), shaD: to()},
			tags: []extract.Tag{{Name: "v1.0.0", Commit: shaA}, {Name: "v1.0.1", Commit: shaB}, {Name: "v1.1.0", Commit: shaC}, {Name: "v1.1.1", Commit: shaD}}},
		pins: map[string]string{"v1.0.0": shaA, "v1.0.1": shaB, "v1.1.0": shaC, "v1.1.1": shaD},
		lines: coveragereport.LinesFile{Projects: map[string]coveragereport.ProjectLines{"tool": {
			Lines:    []string{"1.0", "1.1"},
			Releases: map[string][]string{"1.0": {"1.0.0", "1.0.1"}, "1.1": {"1.1.0", "1.1.1"}},
		}}},
		modules: memModules{},
		q: Request{Schema: RequestSchema, Project: "tool", Repository: "github.com/example/tool",
			FromLine: "1.0", ToLine: "1.1", Binary: ".", Names: []string{"old-flag"}},
		lim: defaultLimits(),
	}
	return f
}

func (f *fixture) run(t *testing.T) *Report {
	t.Helper()
	rep, err := verify(context.Background(), Inputs{Source: f.src, Pins: f.pins, Lines: f.lines, Modules: f.modules}, f.q, f.lim)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func codes(r *Report) []string {
	var out []string
	for _, x := range r.PairReasons {
		out = append(out, x.Side+" "+x.Code)
	}
	for _, n := range r.Names {
		for _, x := range n.Reasons {
			out = append(out, x.Side+" "+x.Code)
		}
	}
	return out
}

func wantRefused(t *testing.T, f *fixture, want ...string) {
	t.Helper()
	rep := f.run(t)
	if rep.Passed() || rep.Names[0].Verdict != VerdictRefused {
		t.Fatalf("not refused: %v", codes(rep))
	}
	got := codes(rep)
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

// withModule makes the binary of every release import a module that vendors a
// pflag-free helper package.
func withModule(t *testing.T, f *fixture, files map[string]string) string {
	t.Helper()
	const ref = "github.com/spf13/viper@v1.0.0"
	data, sum := makeZip(t, ref, files)
	f.modules[ref] = data
	for c, tr := range f.src.commits {
		tr["go.mod"] = goMod + "\nrequire github.com/spf13/viper v1.0.0\n"
		tr["go.sum"] = "github.com/spf13/viper v1.0.0 " + sum + "\n"
		tr["main.go"] = strings.Replace(tr["main.go"], `import "flag"`, "import (\n\t\"flag\"\n\t_ \"github.com/spf13/viper\"\n)", 1)
		f.src.commits[c] = tr
	}
	return ref
}

func TestCleanPairPassesSourceChecksOnly(t *testing.T) {
	f := clean()
	withModule(t, f, map[string]string{"v.go": "package viper\n\nconst x = \"other\"\n"})
	rep := f.run(t)
	if !rep.Passed() {
		t.Fatalf("refused: %v", codes(rep))
	}
	if !rep.ReportOnly || len(rep.Outstanding) == 0 || !strings.Contains(rep.Outstanding[0], "execution probe") {
		t.Fatal("a passing report must say it is not a proof")
	}
	if sites := rep.Names[0].FromSites; len(sites) != 2 || sites[0].Line != 9 || sites[0].Path != "main.go" || sites[0].Tag != "v1.0.0" {
		t.Fatalf("sites: %+v", rep.Names[0].FromSites)
	}
}

func TestRefusals(t *testing.T) {
	to := func(f *fixture, sha, src string) { f.src.commits[sha]["main.go"] = src }
	reg := func(extra string) string {
		return strings.Replace(toMain, "\tflag.Parse()", extra+"\n\tflag.Parse()", 1)
	}
	cases := []struct {
		name string
		edit func(*fixture)
		want []string
	}{
		{"re-added in a patch", func(f *fixture) { to(f, shaD, fromMain) }, []string{"to " + CodeStillRegistered, "to " + CodeLiteralHit}},
		{"hidden alias under another spelling", func(f *fixture) { to(f, shaC, reg("\tflag.String(\"old_flag\", \"\", \"\")")) }, []string{"to " + CodeStillRegistered}},
		{"alias list literal", func(f *fixture) { f.src.commits[shaC]["a/a.go"] = "package a\n\nconst x = \"keep, old-flag\"\n" }, []string{"to " + CodeLiteralHit}},
		{"struct tag", func(f *fixture) {
			f.src.commits[shaC]["a/a.go"] = "package a\n\ntype T struct {\n\tX string `long:\"old-flag,omitempty\"`\n}\n"
		}, []string{"to " + CodeLiteralHit}},
		{"negated form in vendor", func(f *fixture) {
			f.src.commits[shaD]["vendor/x/x.go"] = "package x\n\nconst x = \"--no-old-flag\"\n"
		}, []string{"to " + CodeLiteralHit}},
		{"dynamic registration", func(f *fixture) {
			to(f, shaC, reg("\tp := \"old-\"\n\tflag.String(p+\"flag\", \"\", \"\")"))
		}, []string{"to " + CodeSiteUndisposed + ":" + cliflags.ReasonDynamicRegistration}},
		{"registration in init", func(f *fixture) {
			to(f, shaC, toMain+"\nfunc init() { flag.String(\"other\", \"\", \"\") }\n")
		}, []string{"to " + CodeSiteUndisposed + ":" + cliflags.ReasonInitRegistration}},
		{"argument rewrite", func(f *fixture) {
			to(f, shaC, strings.Replace(reg("\tos.Args = os.Args[:1]"), `import "flag"`, "import (\n\t\"flag\"\n\t\"os\"\n)", 1))
		}, []string{"to " + CodeScanBlocking + ":" + cliflags.ReasonArgsRewritten}},
		{"blocking code on the older side", func(f *fixture) { delete(f.src.commits[shaA], "go.mod") }, []string{"from " + CodeScanBlocking + ":" + cliflags.ReasonGoModMissing, "from " + CodeNotAccepted}},
		{"unlisted module is unvendored", func(f *fixture) {
			to(f, shaC, strings.Replace(toMain, `import "flag"`, "import (\n\t\"flag\"\n\t_ \"example.org/other\"\n)", 1))
		}, []string{"to " + CodeImportUnresolved, "to " + CodeSiteUndisposed + ":" + cliflags.ReasonIdiomUnsupported}},
		{"not accepted at one older release", func(f *fixture) { to(f, shaB, toMain) }, []string{"from " + CodeNotAccepted, "from " + CodeFromSiteMissing}},
		{"builtin name on the older side", func(f *fixture) {
			f.q.Names = []string{"help"}
			for _, sha := range []string{shaA, shaB} {
				to(f, sha, strings.Replace(fromMain, "old-flag", "help", 1))
			}
		}, []string{"from " + CodeFromWithheld + ":" + cliflags.ReasonBuiltinName}},
		{"never registered", func(f *fixture) { f.q.Names = []string{"never-flag"} }, []string{"from " + CodeNotAccepted}},
		{"tolerant parser", func(f *fixture) {
			to(f, shaC, toMain+"\nvar x struct{ UnknownFlags bool }\n")
		}, []string{"to " + CodeParserTolerant}},
		{"flag set that continues", func(f *fixture) {
			to(f, shaC, toMain+"\nvar fs = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n")
		}, []string{"to " + CodeParserUnresolved}},
		{"command line re-initialised", func(f *fixture) {
			to(f, shaC, reg("\tflag.CommandLine.Init(\"x\", flag.ContinueOnError)"))
		}, []string{"to " + CodeParserUnresolved}},
		{"no parse site", func(f *fixture) { to(f, shaC, strings.Replace(toMain, "\tflag.Parse()\n", "", 1)) }, []string{"to " + CodeParserUnresolved}},
		{"binary removed", func(f *fixture) { f.q.Binary = "cmd/gone" }, []string{"to " + CodeBinaryMissing}},
		{"go.work", func(f *fixture) { f.src.commits[shaC]["go.work"] = "go 1.22\n" }, []string{"to " + CodeGoWork}},
		{"replace outside the tree", func(f *fixture) {
			f.src.commits[shaC]["go.mod"] = goMod + "replace example.com/x => ../x\n"
		}, []string{"to " + CodeOutsideReplace}},
		{"tree limit", func(f *fixture) { f.lim.unitBytes = 10 }, []string{"to " + CodeSweepIncomplete}},
		{"total limit", func(f *fixture) { f.lim.totalBytes = 10 }, []string{"to " + CodeSweepIncomplete}},
		{"untokenisable file", func(f *fixture) { f.src.commits[shaC]["a/a.go"] = "package a\nvar x = \"open\n" }, []string{"to " + CodeSweepIncomplete}},
		{"moved tag", func(f *fixture) { f.pins["v1.1.0"] = shaA }, []string{"release " + CodeTagMoved}},
		{"unpinned tag", func(f *fixture) { delete(f.pins, "v1.0.1") }, []string{"release " + CodeTagNotPinned}},
		{"duplicate tag", func(f *fixture) {
			f.src.tags = append(f.src.tags, extract.Tag{Name: "1.1.0", Commit: shaC})
			f.pins["1.1.0"] = shaC
		}, []string{"release " + CodeTagDuplicate, "release " + CodeNotChecked}},
		{"missing tag", func(f *fixture) { f.src.tags = f.src.tags[:3] }, []string{"release " + CodeTagMissing, "release " + CodeNotChecked}},
		{"new patch not in the snapshot", func(f *fixture) {
			f.src.tags = append(f.src.tags, extract.Tag{Name: "v1.1.2", Commit: shaD})
			f.pins["v1.1.2"] = shaD
		}, []string{"release " + CodeNotInSnapshot}},
		{"new patch only upstream", func(f *fixture) { f.pins["v1.1.2"] = shaD }, []string{"release " + CodeTagMissing}},
		{"no snapshot releases", func(f *fixture) { f.q.Project = "other" }, []string{"release " + CodeSnapshotMissing, "release " + CodeNotChecked}},
		{"skipped line", func(f *fixture) {
			p := f.lines.Projects["tool"]
			p.Lines = []string{"1.0", "1.05", "1.1"}
			f.lines.Projects["tool"] = p
		}, []string{"release " + CodeLinesNotAdjacent}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := clean()
			c.edit(f)
			wantRefused(t, f, c.want...)
		})
	}
}

func TestModuleRefusals(t *testing.T) {
	plain := map[string]string{"v.go": "package viper\n"}
	cases := []struct {
		name string
		edit func(t *testing.T, f *fixture, ref string)
		want string
	}{
		{"literal in a module", nil, "to " + CodeLiteralHit},
		{"module zip absent", func(_ *testing.T, f *fixture, ref string) { delete(f.modules, ref) }, "to " + CodeModuleUnavailable},
		{"module bytes differ from go.sum", func(t *testing.T, f *fixture, ref string) {
			f.modules[ref], _ = makeZip(t, ref, map[string]string{"v.go": "package viper\n\n// patched\n"})
		}, "to " + CodeModuleHash},
		{"patched vendor copy", func(_ *testing.T, f *fixture, _ string) {
			f.src.commits[shaC]["vendor/github.com/spf13/viper/v.go"] = "package viper\n\n// patched\n"
		}, "to " + CodeVendorMismatch},
		{"vendored file absent from the module", func(_ *testing.T, f *fixture, _ string) {
			f.src.commits[shaC]["vendor/github.com/spf13/viper/extra.go"] = "package viper\n"
		}, "to " + CodeVendorMismatch},
		{"dependency init on the global flag set", func(t *testing.T, f *fixture, _ string) {
			const ref = "example.org/dep@v1.0.0"
			data, sum := makeZip(t, ref, map[string]string{"d.go": "package dep\n\nimport \"flag\"\n\nfunc init() { flag.String(\"old\"+\"-flag\", \"\", \"\") }\n"})
			f.modules[ref] = data
			tr := f.src.commits[shaC]
			tr["go.mod"] += "require example.org/dep v1.0.0\n"
			tr["go.sum"] += "example.org/dep v1.0.0 " + sum + "\n"
			tr["main.go"] = strings.Replace(tr["main.go"], "import (", "import (\n\t_ \"example.org/dep\"", 1)
		}, "to " + CodeSiteUndisposed + ":FLAG_IDIOM_UNSUPPORTED"},
		{"no go.sum entry", func(_ *testing.T, f *fixture, _ string) { f.src.commits[shaC]["go.sum"] = "" }, "to " + CodeModuleNoSum},
		{"module limit", func(_ *testing.T, f *fixture, _ string) { f.lim.fileBytes = 1000 }, "to " + CodeSweepIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := clean()
			files := plain
			if c.edit == nil {
				// In a package the binary does not import: the whole module counts.
				files = map[string]string{"v.go": "package viper\n", "sub/s.go": "package sub\n\nconst x = \"old-flag\"\n"}
			}
			if c.name == "module limit" {
				files = map[string]string{"v.go": "package viper\n\n//" + strings.Repeat("x", 2000) + "\n"}
			}
			ref := withModule(t, f, files)
			if c.edit != nil {
				c.edit(t, f, ref)
			}
			wantRefused(t, f, c.want)
		})
	}
}

// Every code of the scanner that is not on the closed list blocks.
func TestClosedSiteCodeList(t *testing.T) {
	want := []string{"FLAG_DELEGATED_UNRESOLVED", "FLAG_DUPLICATE_REGISTRATION", "FLAG_DYNAMIC_REGISTRATION", "FLAG_GLOBAL_FLAGSET_SHARED", "FLAG_IDIOM_UNSUPPORTED", "FLAG_INIT_REGISTRATION", "FLAG_REGISTRATION_IN_LOOP"}
	if got := slices.Sorted(maps.Keys(siteCodes)); !slices.Equal(got, want) {
		t.Fatalf("the closed list changed: %v", got)
	}
}

func TestRequestRefused(t *testing.T) {
	good := `{"schema":"` + RequestSchema + `","project":"tool","repository":"github.com/example/tool","fromLine":"1.0","toLine":"1.1","binary":".","names":["old-flag"]}`
	if _, err := ParseRequest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"old-flag"`, `"old-flag=1"`, 1),
		strings.Replace(good, `"old-flag"`, `"--old-flag"`, 1),
		strings.Replace(good, `"old-flag"`, `"old-flag","old-flag"`, 1),
		strings.Replace(good, `["old-flag"]`, `[]`, 1),
		strings.Replace(good, `"binary":"."`, `"binary":"../x"`, 1),
		strings.Replace(good, `"binary":"."`, `"binary":".","exclude":[]`, 1),
		strings.Replace(good, `"binary":"."`, `"binary":".","Binary":"x"`, 1),
		good + "{}",
	} {
		if _, err := ParseRequest([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParsePins(t *testing.T) {
	got, err := ParsePins([]byte(shaA + "\trefs/tags/v1\n" + shaB + "\trefs/tags/v1^{}\n"))
	if err != nil || got["v1"] != shaB {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", "x\trefs/tags/v1\n", shaA + "\trefs/heads/main\n", shaA + "\trefs/tags/v1^{}\n",
		shaA + "\trefs/tags/v1\n" + shaB + "\trefs/tags/v1\n"} {
		if _, err := ParsePins([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
