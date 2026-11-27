// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"strings"
	"testing"
)

// A replacement of a path that is not required does nothing, so it must not
// hide the required module that really holds the import.
func TestUnrequiredReplaceDoesNotHideModule(t *testing.T) {
	f := clean()
	const ref = "example.org/m@v1.0.0"
	data, sum := makeZip(t, ref, map[string]string{"m.go": "package m\n", "sub/s.go": "package sub\n\nconst x = \"old-flag\"\n"})
	f.modules[ref] = data
	tr := f.src.commits[shaC]
	tr["go.mod"] = goMod + "require example.org/m v1.0.0\nreplace example.org/m/sub => ./local\n"
	tr["go.sum"] = "example.org/m v1.0.0 " + sum + "\n"
	tr["local/s.go"] = "package sub\n"
	tr["main.go"] = strings.Replace(toMain, `import "flag"`, "import (\n\t\"flag\"\n\t_ \"example.org/m/sub\"\n)", 1)
	wantRefused(t, f, "to "+CodeLiteralHit)
}

func TestFlagSetPositionAndInitRefusals(t *testing.T) {
	for name, decl := range map[string]string{
		"elided slice element": "var sets = []*flag.FlagSet{{}}\n",
		"elided map value":     "var sets = map[string]*flag.FlagSet{\"a\": {}}\n",
		"pointer alias":        "type p = *flag.FlagSet\n\nvar sets = []p{{}}\n",
		"type argument":        "type list[T any] []T\n\nvar sets = list[*flag.FlagSet]{{}}\n",
		"init through an alias of an embedding type": "type s struct{ *flag.FlagSet }\n\ntype a = s\n\nfunc other(x a) { a.Init(x, \"x\", flag.ContinueOnError) }\n",
		"init with spread results":                   "func two() (string, flag.ErrorHandling) { return \"x\", flag.ContinueOnError }\n\nfunc other(x interface{ Init(string, flag.ErrorHandling) }) { x.Init(two()) }\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := clean()
			f.src.commits[shaC]["main.go"] = toMain + "\n" + decl
			wantRefused(t, f, "to "+CodeParserUnresolved)
		})
	}
}

func TestPlainPointerPositionsPass(t *testing.T) {
	src := toMain + "\ntype s struct{ fs *flag.FlagSet }\n\nvar v *flag.FlagSet\n\nfunc other(fs *flag.FlagSet) *flag.FlagSet { return fs }\n"
	for _, p := range checkParser([]sourceFile{{path: "main.go", dir: ".", data: []byte(src)}}, ".") {
		t.Errorf("%s %s", p.code, p.detail)
	}
}

func TestGoModQuoting(t *testing.T) {
	for _, bad := range []string{
		"require \"example.com/x\\u0079\" v1.0.0\n",
		"require `example.com/x` v1.0.0\n",
		"require \"example.com/x v1.0.0\n",
		"require example.com/x\" v1.0.0\n",
		"require \"\"example.com/x\"\" v1.0.0\n",
		"require \" v1.0.0\n",
	} {
		t.Run(bad, func(t *testing.T) {
			if _, err := parseModFile([]byte(goMod + bad)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	m, err := parseModFile([]byte(goMod + "require \"example.com/x\" v1.0.0 // a \"note\n"))
	if err != nil || m.requires["example.com/x"] != "v1.0.0" {
		t.Fatal(m.requires, err)
	}
}
