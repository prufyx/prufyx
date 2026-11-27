// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/cliflags"
)

// Every way to obtain a parser that continues after an unknown flag refuses.
func TestParserEscapeRefusals(t *testing.T) {
	body := func(stmt string) string {
		return strings.Replace(toMain, "\tflag.Parse()", stmt+"\n\tflag.Parse()", 1)
	}
	cases := map[string]struct{ src, want string }{
		"flag set re-initialised":   {body("\tfs := flag.NewFlagSet(\"x\", flag.ExitOnError)\n\tfs.Init(\"x\", flag.ContinueOnError)"), CodeParserUnresolved},
		"command line alias":        {body("\tcl := flag.CommandLine\n\tcl.Init(\"x\", flag.ContinueOnError)"), CodeParserUnresolved},
		"command line alias only":   {toMain + "\nvar cl = flag.CommandLine\n", CodeParserUnresolved},
		"command line passed on":    {toMain + "\nfunc use(any)  {}\nfunc other() { use(flag.CommandLine) }\n", CodeParserUnresolved},
		"command line method value": {toMain + "\nvar parse = flag.CommandLine.Parse\n", CodeParserUnresolved},
		"init method value":         {toMain + "\nfunc other(fs *flag.FlagSet) { f := fs.Init; f(\"x\", flag.ContinueOnError) }\n", CodeParserUnresolved},
		"zero value":                {toMain + "\nvar fs flag.FlagSet\n", CodeParserUnresolved},
		"composite literal":         {toMain + "\nvar fs = &flag.FlagSet{}\n", CodeParserUnresolved},
		"new":                       {toMain + "\nvar fs = new(flag.FlagSet)\n", CodeParserUnresolved},
		"embedded":                  {toMain + "\ntype set struct{ flag.FlagSet }\n", CodeParserUnresolved},
		"named type":                {toMain + "\ntype set flag.FlagSet\n", CodeParserUnresolved},
		"method expression":         {toMain + "\nfunc other(fs *flag.FlagSet) { (*flag.FlagSet).Init(fs, \"x\", flag.ContinueOnError) }\n", CodeParserUnresolved},
		"known flags only":          {toMain + "\nfunc other(c interface{ ParseKnownFlags() }) { c.ParseKnownFlags() }\n", CodeParserUnresolved},
		"parsing disabled":          {toMain + "\nvar c = struct{ DisableFlagParsing bool }{true}\n", CodeParserTolerant},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := clean()
			f.src.commits[shaC]["main.go"] = c.src
			wantRefused(t, f, "to "+c.want)
		})
	}
}

// A pointer to a flag set constructs nothing.
func TestFlagSetPointerPasses(t *testing.T) {
	f := clean()
	f.src.commits[shaC]["main.go"] = toMain + "\nfunc other(fs *flag.FlagSet) {}\n"
	for _, p := range checkParser([]sourceFile{{path: "main.go", dir: ".", data: []byte(f.src.commits[shaC]["main.go"])}}, ".") {
		t.Errorf("%s %s", p.code, p.detail)
	}
}

// A required or replaced module with a dotless path is not the standard
// library: it would go unverified and unswept.
func TestDotlessModuleRefusals(t *testing.T) {
	imp := strings.Replace(toMain, `import "flag"`, "import (\n\t\"flag\"\n\t_ \"hidden/reg\"\n)", 1)
	for name, extra := range map[string]string{
		"replaced by a module":     "replace hidden => example.org/hidden v1.0.0\n",
		"replaced by a local path": "replace hidden => ./third\n",
		"required":                 "require hidden v1.0.0\n",
		"replaced for a version":   "replace hidden v1.0.0 => example.org/hidden v1.0.0\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := clean()
			f.src.commits[shaC]["go.mod"] = goMod + extra
			f.src.commits[shaC]["main.go"] = imp
			f.src.commits[shaC]["third/reg/r.go"] = "package reg\n"
			wantRefused(t, f, "to "+CodeImportUnresolved)
		})
	}
}

func TestGoModStrict(t *testing.T) {
	for _, bad := range []string{
		"replace(\n\texample.com/x => ../x\n)\n",
		"require(\n\texample.com/x v1.0.0\n)\n",
		"replace (example.com/x => ../x)\n",
		"require (\n\texample.com/x v1.0.0)\n",
		"Replace example.com/x => ../x\n",
		"include example.com/x v1.0.0\n",
		"include (\n)\n",
		"replace example.com/x => ./a\nreplace example.com/x => ./b\n",
	} {
		t.Run(bad, func(t *testing.T) {
			f := clean()
			f.src.commits[shaC]["go.mod"] = goMod + bad
			wantRefused(t, f, "to "+CodeGoModInvalid)
		})
	}
	good := goMod + "toolchain go1.22.1\nexclude (\n\texample.com/x v1.0.0\n)\nretract [v0.1.0, v0.2.0]\ngodebug x=1\ntool example.com/x/cmd\n"
	if _, err := parseModFile([]byte(good)); err != nil {
		t.Fatal(err)
	}
}

// As the go tool does, a replacement of the required version wins over one of
// every version, whether its target is a directory or a module, and a
// replacement of another version does nothing.
func TestReplacePrecedence(t *testing.T) {
	const req = "require github.com/spf13/viper v1.0.0\n"
	clash := "package viper\n\nconst x = \"old-flag\"\n"
	for name, c := range map[string]struct{ replaces, want string }{
		"exact module over wildcard directory": {
			"replace github.com/spf13/viper => ./local\nreplace github.com/spf13/viper v1.0.0 => example.org/fork v1.0.0\n", CodeLiteralHit},
		"exact module over earlier wildcard module": {
			"replace github.com/spf13/viper => github.com/spf13/viper v1.0.0\nreplace github.com/spf13/viper v1.0.0 => example.org/fork v1.0.0\n", CodeLiteralHit},
		"directory for another version is ignored": {
			"replace github.com/spf13/viper v0.9.0 => ./local\n", ""},
		"exact directory over wildcard module": {
			"replace github.com/spf13/viper => example.org/fork v1.0.0\nreplace github.com/spf13/viper v1.0.0 => ./local\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := clean()
			withModule(t, f, map[string]string{"v.go": "package viper\n"})
			data, sum := makeZip(t, "example.org/fork@v1.0.0", map[string]string{"v.go": clash})
			f.modules["example.org/fork@v1.0.0"] = data
			tr := f.src.commits[shaC]
			tr["go.mod"] = goMod + req + c.replaces
			tr["go.sum"] += "example.org/fork v1.0.0 " + sum + "\n"
			tr["local/v.go"] = "package viper\n"
			cl, err := newSweeper(f.modules, f.q.Names, f.lim).closure(context.Background(), f.src, extract.RepoRef{}, shaC, ".", true)
			if err != nil || len(cl.problems) != 0 {
				t.Fatal(err, cl.problems)
			}
			local := false
			for _, s := range cl.files {
				local = local || s.path == "local/v.go"
			}
			if strings.HasPrefix(name, "exact directory") != local {
				t.Fatalf("directory used: %v", local)
			}
			if c.want != "" {
				wantRefused(t, f, "to "+c.want)
			} else if name == "directory for another version is ignored" && (len(cl.modules) != 1 || cl.modules[0].path != "github.com/spf13/viper") {
				t.Fatalf("modules: %v", cl.modules)
			}
		})
	}
}

func TestTreeAndBinaryRefusals(t *testing.T) {
	second := "package main\n\nimport \"flag\"\n\nfunc main() {\n\tflag.String(\"NAME\", \"\", \"\")\n\tflag.Parse()\n}\n"
	cases := map[string]struct {
		path, content string
		want          []string
	}{
		"re-added in a second binary":  {"cmd/two/main.go", strings.Replace(second, "NAME", "old-flag", 1), []string{"to " + CodeStillRegistered}},
		"alias in a second binary":     {"cmd/two/main.go", strings.Replace(second, "NAME", "old_flag", 1), []string{"to " + CodeStillRegistered}},
		"submodule":                    {"dep", submodule, []string{"to " + CodeSweepIncomplete, "to " + CodeScanBlocking + ":" + cliflags.ReasonSubmodule}},
		"symlinked go file":            {"a/link.go", symlink, []string{"to " + CodeSweepIncomplete}},
		"symlinked file of the binary": {"link.go", symlink, []string{"to " + CodeImportUnresolved, "to " + CodeSweepIncomplete}},
		"nested module":                {"sub/go.mod", "module example.com/sub\n", []string{"to " + CodeScanBlocking + ":" + cliflags.ReasonNestedModule}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := clean()
			f.src.commits[shaC][c.path] = c.content
			wantRefused(t, f, c.want...)
		})
	}
}

func TestNormalizeFuncRefused(t *testing.T) {
	f := clean()
	const ref = "github.com/spf13/pflag@v1.0.0"
	data, sum := makeZip(t, ref, map[string]string{"p.go": "package pflag\n"})
	f.modules[ref] = data
	tr := f.src.commits[shaC]
	tr["go.mod"] = goMod + "require github.com/spf13/pflag v1.0.0\n"
	tr["go.sum"] = "github.com/spf13/pflag v1.0.0 " + sum + "\n"
	tr["main.go"] = "package main\n\nimport \"github.com/spf13/pflag\"\n\nfunc main() {\n\tpflag.CommandLine.SetNormalizeFunc(nil)\n\tpflag.String(\"keep-flag\", \"\", \"\")\n\tpflag.Parse()\n}\n"
	wantRefused(t, f, "to "+CodeScanBlocking+":"+cliflags.ReasonNormalizeFunc)
}

func TestTagWithoutCommitRefused(t *testing.T) {
	f := clean()
	f.src.tags[2].Commit = ""
	wantRefused(t, f, "release "+CodeTagMissing, "release "+CodeNotChecked)
}

type failing struct {
	memSource
	commit string
}

var errRead = errors.New("read failed")

func (f failing) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	if c == f.commit {
		return nil, errRead
	}
	return f.memSource.Read(r, c, p)
}

func TestReadErrorGivesNoReport(t *testing.T) {
	for _, sha := range []string{shaA, shaD} {
		f := clean()
		rep, err := Verify(context.Background(), Inputs{Source: failing{f.src, sha}, Pins: f.pins, Lines: f.lines, Modules: f.modules}, f.q)
		if rep != nil || !errors.Is(err, errRead) {
			t.Fatalf("%v %v", rep, err)
		}
	}
}
