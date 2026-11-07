// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"encoding/json"
	"fmt"
	goparser "go/parser"
	gotoken "go/token"
	"math/rand/v2"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	repo    = extract.RepoRef{Key: "github.com/example/envoy"}
	commitA = strings.Repeat("a", 40)
	commitB = strings.Repeat("b", 40)
)

type memReader struct {
	files  map[string]string
	modes  map[string]string
	extra  []extract.TreeEntry
	shuf   *rand.Rand
	noRoot bool
}

func (m *memReader) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if c, ok := m.files[p]; ok {
		return []byte(c), nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m *memReader) List(_ extract.RepoRef, _, dir string) ([]extract.TreeEntry, error) {
	if m.noRoot {
		return nil, extract.ErrNotFound
	}
	seen := map[string]bool{}
	var out []extract.TreeEntry
	for p := range m.files {
		rest, ok := strings.CutPrefix(p, dir+"/")
		if !ok {
			continue
		}
		first, tail, nested := strings.Cut(rest, "/")
		full := dir + "/" + first
		if seen[full] {
			continue
		}
		seen[full] = true
		if nested && tail != "" {
			out = append(out, extract.TreeEntry{Mode: "040000", Type: "tree", Path: full})
			continue
		}
		mode := "100644"
		if v, ok := m.modes[full]; ok {
			mode = v
		}
		out = append(out, extract.TreeEntry{Mode: mode, Type: "blob", Path: full})
	}
	for _, e := range m.extra {
		if path.Dir(e.Path) == dir {
			out = append(out, e)
		}
	}
	if m.shuf != nil {
		m.shuf.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out, nil
}

func tree(files map[string]string) *memReader { return &memReader{files: files} }

func one(src string) map[string]string { return map[string]string{Root + "/a/v3/a.proto": src} }

func mustScan(t *testing.T, files map[string]string) Result {
	t.Helper()
	res, err := Scan(tree(files), repo, commitA)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func members(r Result) []string {
	var out []string
	for _, c := range r.Candidates {
		out = append(out, c.Kind+":"+c.Member)
	}
	return out
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got == nil {
		got = []string{}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
}

const hdr = "syntax = \"proto3\";\npackage envoy.a.v3;\n"

func TestFindsEveryMarkerForm(t *testing.T) {
	src := hdr + `
import "udpa/annotations/status.proto";
option java_package = "io.envoyproxy.envoy.a.v3";
message Outer {
  option deprecated = true;
  string keep = 1;
  string old = 2 [deprecated = true, (envoy.annotations.deprecated_at_minor_version) = "3.0"];
  string gone = 3 [(envoy.annotations.disallowed_by_default) = true, deprecated = true];
  string marked = 4 [(envoy.annotations.deprecated_at_minor_version) = "3.1"];
  message Inner { string x = 1 [deprecated = true]; }
  enum Mode { option deprecated = true; A = 0; B = 1 [deprecated = true, (envoy.annotations.deprecated_at_minor_version_enum) = "3.2"]; }
}
enum Top { Z = 0; Y = 1 [deprecated = true]; }
`
	r := mustScan(t, one(src))
	if len(r.Ledger) != 0 {
		t.Fatal(r.Ledger)
	}
	eq(t, members(r),
		"message:envoy.a.v3.Outer",
		"field:envoy.a.v3.Outer.Inner.x",
		"enum:envoy.a.v3.Outer.Mode",
		"enum_value:envoy.a.v3.Outer.Mode.B",
		"field:envoy.a.v3.Outer.gone",
		"field:envoy.a.v3.Outer.marked",
		"field:envoy.a.v3.Outer.old",
		"enum_value:envoy.a.v3.Top.Y")
	for _, c := range r.Candidates {
		switch c.Member {
		case "envoy.a.v3.Outer.old":
			if c.DeprecatedAtMinor != "3.0" || c.Number != 2 {
				t.Fatalf("%+v", c)
			}
		case "envoy.a.v3.Outer.gone":
			if !c.DisallowedByDefault {
				t.Fatalf("%+v", c)
			}
		}
	}
}

func TestNegativeFixtures(t *testing.T) {
	cases := map[string]string{
		"line comment":               "message M {\n // deprecated = true\n // [deprecated = true]\n string a = 1; // deprecated = true\n}\n",
		"block comment":              "message M {\n /* string b = 2 [deprecated = true]; */\n string a = 1;\n /* option deprecated = true;\n spans lines */\n}\n",
		"string literal":             "message M {\n string a = 1 [json_name = \"x [deprecated = true]\"];\n option java_package = \"option deprecated = true;\";\n}\n",
		"string in option name text": "message M {\n string a = 1 [(foo.bar) = \"deprecated\"];\n}\n",
		"false value":                "message M {\n option deprecated = false;\n string a = 1 [deprecated = false];\n}\n",
		"foreign option":             "message M {\n string a = 1 [(other.deprecated) = true];\n string b = 2 [(foo).deprecated = true];\n}\n",
		"oneof option":               "message M {\n oneof o { option deprecated = true; string a = 1; int32 b = 2; }\n}\n",
		"map and oneof fields":       "message M {\n map<string, string> m = 1;\n oneof o { string a = 2; string b = 3; }\n repeated string r = 4;\n}\n",
		"reserved ranges":            "message M {\n reserved 1, 3 to 5, 9 to max;\n reserved \"a\", \"b\";\n string c = 2;\n}\n",
		"keyword as type name":       "message M {\n message x = 1;\n enum y = 2;\n}\n",
		"extensions and extend":      "message M {\n extensions 100 to 199;\n}\nextend M { string q = 100 [deprecated = true]; }\n",
		"service":                    "service S { rpc A(M) returns (M) { option deprecated = true; } }\nmessage M {}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustScan(t, one(hdr+body))
			if len(r.Ledger) != 0 {
				t.Fatalf("ledger %v", r.Ledger)
			}
			eq(t, members(r))
		})
	}
}

func TestScopesAndShapes(t *testing.T) {
	src := hdr + `
message A {
  message B { message C { string f = 1 [deprecated = true]; } }
  oneof pick { string in_oneof = 1 [deprecated = true]; }
  map<string, string> in_map = 2 [deprecated = true];
  optional string opt = 3 [deprecated = true];
  repeated .envoy.a.v3.A.B rep = 4 [deprecated = true];
}
`
	r := mustScan(t, one(src))
	if len(r.Ledger) != 0 {
		t.Fatal(r.Ledger)
	}
	eq(t, members(r),
		"field:envoy.a.v3.A.B.C.f",
		"field:envoy.a.v3.A.in_map",
		"field:envoy.a.v3.A.in_oneof",
		"field:envoy.a.v3.A.opt",
		"field:envoy.a.v3.A.rep")
}

func TestHideMarker(t *testing.T) {
	src := hdr + `
// [#not-implemented-hide:]
message Hidden {
  string a = 1 [deprecated = true];
}
message Shown {
  // Comment text.
  // [#not-implemented-hide:]
  string h = 1 [deprecated = true];

  // [#not-implemented-hide:]

  string blank_line_breaks = 2 [deprecated = true];
  string trailing = 3 [deprecated = true]; // [#not-implemented-hide:]
  /* [#not-implemented-hide:] */
  string block = 4 [deprecated = true];
  string v = 5 [deprecated = true];
}
`
	r := mustScan(t, one(src))
	eq(t, members(r),
		"field:envoy.a.v3.Shown.blank_line_breaks",
		"field:envoy.a.v3.Shown.block",
		"field:envoy.a.v3.Shown.trailing",
		"field:envoy.a.v3.Shown.v")
	if r.Hidden != 3 { // Hidden, its field a (inherited), Shown.h
		t.Fatalf("hidden=%d", r.Hidden)
	}
}

func TestFailClosedOnUnparsed(t *testing.T) {
	cases := map[string]string{
		"unterminated string": "message M { string a = 1 [json_name = \"x]; }\n",
		"unterminated block":  "message M { /* string a = 1;\n",
		"unterminated msg":    "message M { string a = 1;\n",
		"nul byte":            "message M {}\x00\n",
		"non ascii":           "message M { string a = 1; } \u00e9\n",
		"group":               "message M { optional group G = 1 { string a = 1; } }\n",
		"bad deprecated":      "message M { string a = 1 [deprecated = TRUE]; }\n",
		"deprecated string":   "message M { option deprecated = \"true\"; }\n",
		"bad minor":           "message M { string a = 1 [(envoy.annotations.deprecated_at_minor_version) = 3]; }\n",
		"dup field":           "message M { string a = 1; string a = 2; }\n",
		"dup number":          "message M { string a = 1; string b = 1; }\n",
		"dup symbol":          "message M {}\nmessage M {}\n",
		"bad number":          "message M { string a = x; }\n",
		"huge number":         "message M { string a = 536870912; }\n",
		"rev range":           "message M { reserved 5 to 2; }\n",
		"stray token":         "message M { ) }\n",
		"top level junk":      "foo bar;\n",
		"two packages":        "package a;\npackage b;\n",
		"unbalanced option":   "message M { string a = 1 [deprecated = true; }\n",
		"underscore segment":  "message _item_ { string a = 1 [deprecated = true]; }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustScan(t, one(hdr+body))
			if r.Attestable() || len(r.Ledger) == 0 {
				t.Fatalf("not withheld: %v", r.Ledger)
			}
		})
	}
}

func TestFailClosedTreeShapes(t *testing.T) {
	good := hdr + "message M { string a = 1 [deprecated = true]; }\n"
	t.Run("root missing", func(t *testing.T) {
		r, err := Scan(&memReader{files: map[string]string{}, noRoot: true}, repo, commitA)
		if err != nil || r.Attestable() || r.Ledger[0].Code != ReasonRootNotFound {
			t.Fatalf("%v %v", err, r.Ledger)
		}
	})
	t.Run("symlink proto", func(t *testing.T) {
		m := tree(one(good))
		m.modes = map[string]string{Root + "/a/v3/a.proto": "120000"}
		r, _ := Scan(m, repo, commitA)
		if r.Attestable() || r.Ledger[0].Code != ReasonNotRegular {
			t.Fatal(r.Ledger)
		}
	})
	t.Run("submodule", func(t *testing.T) {
		m := tree(one(good))
		m.extra = []extract.TreeEntry{{Mode: "160000", Type: "commit", Path: Root + "/a/v3/x"}}
		r, _ := Scan(m, repo, commitA)
		if r.Attestable() {
			t.Fatal("submodule accepted")
		}
	})
	t.Run("duplicate across files", func(t *testing.T) {
		f := map[string]string{Root + "/a.proto": good, Root + "/b.proto": good}
		r := mustScan(t, f)
		if r.Attestable() || r.Ledger[0].Code != ReasonDuplicate {
			t.Fatal(r.Ledger)
		}
	})
	t.Run("non proto files ignored", func(t *testing.T) {
		f := one(good)
		f[Root+"/a/v3/BUILD"] = "deprecated = true"
		f[Root+"/a/v3/README.md"] = "[deprecated = true]"
		if r := mustScan(t, f); !r.Attestable() || len(r.Candidates) != 1 {
			t.Fatal(r.Ledger, r.Candidates)
		}
	})
	t.Run("bad commit", func(t *testing.T) {
		if _, err := Scan(tree(one(good)), repo, "main"); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestBounds(t *testing.T) {
	body := func(n int) string {
		return hdr + "message M {\n" + strings.Repeat("string a = 1;\n", 0) + "}\n" + strings.Repeat("", n)
	}
	_ = body
	run := func(files map[string]string, lim limits) Result {
		r, err := scan(tree(files), repo, commitA, lim)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	base := defaultLimits()
	expect := func(name string, r Result, ok bool, code string) {
		t.Helper()
		if ok && !r.Attestable() {
			t.Fatalf("%s: at the limit must pass: %v", name, r.Ledger)
		}
		if !ok && (r.Attestable() || r.Ledger[0].Code != code) {
			t.Fatalf("%s: over the limit must be withheld with %s: %v", name, code, r.Ledger)
		}
	}
	// file size
	src := hdr + "message M {}\n"
	l := base
	l.fileBytes = len(src)
	expect("size at", run(one(src), l), true, "")
	l.fileBytes = len(src) - 1
	expect("size over", run(one(src), l), false, ReasonFileTooLarge)
	// file count
	two := map[string]string{Root + "/a.proto": hdr + "message A {}\n", Root + "/b.proto": hdr + "message B {}\n"}
	l = base
	l.files = 2
	expect("files at", run(two, l), true, "")
	l.files = 1
	expect("files over", run(two, l), false, ReasonLimit)
	// dirs (root counts as one)
	l = base
	l.dirs = 2
	expect("dirs at", run(map[string]string{Root + "/x/a.proto": hdr + "message A {}\n"}, l), true, "")
	l.dirs = 1
	expect("dirs over", run(map[string]string{Root + "/x/a.proto": hdr + "message A {}\n"}, l), false, ReasonLimit)
	// directory depth
	deep := map[string]string{Root + "/x/y/a.proto": hdr + "message A {}\n"}
	l = base
	l.depth = 2
	expect("depth at", run(deep, l), true, "")
	l.depth = 1
	expect("depth over", run(deep, l), false, ReasonLimit)
	// message nesting
	nest := hdr + "message A { message B { message C {} } }\n"
	l = base
	l.nest = 3
	expect("nest at", run(one(nest), l), true, "")
	l.nest = 2
	expect("nest over", run(one(nest), l), false, ReasonLimit)
	// declaration count: M, a, b = 3
	items := hdr + "message M { string a = 1; string b = 2; }\n"
	l = base
	l.items = 3
	expect("items at", run(one(items), l), true, "")
	l.items = 2
	expect("items over", run(one(items), l), false, ReasonLimit)
	// ledger bound
	f := map[string]string{}
	for i := 0; i <= MaxLedgerEntries; i++ {
		f[Root+"/f"+strconv.Itoa(i)+".proto"] = "junk;"
	}
	if r := run(f, base); r.Attestable() || r.Ledger[0].Code != LedgerOverflow || len(r.Ledger) != 1 {
		t.Fatal(r.Ledger)
	}
}

func TestLedgerCanonical(t *testing.T) {
	got := ledgerOf([]LedgerEntry{{"ENVOY_B_X", "z"}, {"ENVOY_A_X", "y"}, {"ENVOY_A_X", "y"}, {"ENVOY_A_X", "b"}})
	want := []LedgerEntry{{"ENVOY_A_X", "b"}, {"ENVOY_A_X", "y"}, {"ENVOY_B_X", "z"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatal(got)
	}
	for name, e := range map[string]LedgerEntry{
		"bad code": {"low", "x"}, "reserved": {"LEDGER_FAKE", "x"}, "item charset": {"ENVOY_A_X", "has space"},
		"empty item": {"ENVOY_A_X", ""}, "long item": {"ENVOY_A_X", strings.Repeat("a", MaxLedgerItemLen+1)},
	} {
		if g := ledgerOf([]LedgerEntry{e}); len(g) != 1 || g[0].Code != LedgerInvalid {
			t.Fatalf("%s: %v", name, g)
		}
	}
	if g := ledgerOf(nil); g == nil || len(g) != 0 {
		t.Fatal("empty ledger must be a non-nil empty slice")
	}
}

func TestMemberRefusals(t *testing.T) {
	long := strings.Repeat("a", 130)
	for name, body := range map[string]string{
		"too long": "message M { string " + long + " = 1 [deprecated = true]; }\n",
		"item seg": "message M { string _any_ = 1 [deprecated = true]; }\n",
		"dash":     "message M { string a = 1; }\n",
	} {
		r := mustScan(t, one(hdr+body))
		if name == "dash" {
			if !r.Attestable() {
				t.Fatal(r.Ledger)
			}
			continue
		}
		if r.Attestable() || len(r.Candidates) != 0 {
			t.Fatalf("%s: %v %v", name, r.Ledger, r.Candidates)
		}
	}
}

func TestDeterministicOutput(t *testing.T) {
	files := map[string]string{
		Root + "/b/v3/b.proto": hdr + "message B { string x = 1 [deprecated = true]; }\n",
		Root + "/a/v3/a.proto": "package envoy.q;\nmessage A { string y = 1 [deprecated = true]; }\n",
		Root + "/c.proto":      "package envoy.c;\nenum E { V = 0 [deprecated = true]; }\n",
	}
	var first string
	for i := 0; i < 20; i++ {
		m := tree(files)
		m.shuf = rand.New(rand.NewPCG(uint64(i), 7))
		r, err := Scan(m, repo, commitA)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r)
		if i == 0 {
			first = string(b)
			if !sort.SliceIsSorted(r.Candidates, func(a, b int) bool { return r.Candidates[a].Member < r.Candidates[b].Member }) {
				t.Fatal("unsorted")
			}
		} else if string(b) != first {
			t.Fatal("output depends on listing order")
		}
	}
}

func TestScanNeverMechanical(t *testing.T) {
	src := hdr + "message M { reserved 2; reserved \"gone\"; string a = 1 [deprecated = true]; string b = 3 [deprecated = true]; }\n"
	for _, c := range mustScan(t, one(src)).Candidates {
		if c.Status != StatusDraft || c.Proof != "" {
			t.Fatalf("a single scan produced %+v", c)
		}
	}
}

// pair builds the older and newer scans of one message.
func pair(t *testing.T, oldMsg, newMsg string) (Comparison, error) {
	t.Helper()
	o := mustScan(t, one(hdr+oldMsg))
	n, err := Scan(tree(one(hdr+newMsg)), repo, commitB)
	if err != nil {
		t.Fatal(err)
	}
	return Compare(o, n)
}

func statusOf(c Comparison, member string) string {
	for _, x := range c.Candidates {
		if x.Member == member {
			return x.Status
		}
	}
	return "absent"
}

func TestCompareMechanicalOnlyForReservedProof(t *testing.T) {
	const old = "message M { string keep = 1; string old = 2 [deprecated = true]; }\n"
	const m = "envoy.a.v3.M.old"
	cases := []struct {
		name, newMsg, want string
	}{
		{"proven", "message M { reserved 2; reserved \"old\"; string keep = 1; }\n", StatusMechanical},
		{"proven in range", "message M { reserved 1 to 5; reserved \"old\"; }\n", StatusMechanical},
		{"proven to max", "message M { reserved 2 to max; reserved \"old\"; }\n", StatusMechanical},
		{"number only", "message M { reserved 2; string keep = 1; }\n", StatusDraft},
		{"name only", "message M { reserved \"old\"; string keep = 1; }\n", StatusDraft},
		{"wrong number", "message M { reserved 3; reserved \"old\"; string keep = 1; }\n", StatusDraft},
		{"range misses", "message M { reserved 3 to 9; reserved \"old\"; }\n", StatusDraft},
		{"other name", "message M { reserved 2; reserved \"older\"; }\n", StatusDraft},
		{"still deprecated", "message M { reserved 2; reserved \"old\"; string old = 2 [deprecated = true]; }\n", StatusDraft},
		{"still present", "message M { string old = 2; }\n", StatusDraft},
		{"renumbered", "message M { reserved 2; reserved \"old\"; string old = 7; }\n", StatusDraft},
		{"number reused", "message M { reserved 2; reserved \"old\"; string other = 2; }\n", StatusDraft},
		{"nothing left", "message M { string keep = 1; }\n", StatusDraft},
		{"message removed", "message Other { reserved 2; reserved \"old\"; }\n", StatusDraft},
		{"became enum", "enum M { reserved 2; reserved \"old\"; Z = 0; }\n", StatusDraft},
		{"moved to nested", "message M { message N { reserved 2; reserved \"old\"; } }\n", StatusDraft},
		{"reserved in other message", "message M {} message N { reserved 2; reserved \"old\"; }\n", StatusDraft},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmp, err := pair(t, old, c.newMsg)
			if err != nil {
				t.Fatal(err)
			}
			if got := statusOf(cmp, m); got != c.want {
				t.Fatalf("got %s want %s (%v)", got, c.want, cmp.Ledger)
			}
			for _, x := range cmp.Candidates {
				if x.Status == StatusMechanical && (x.Proof != ProofReservedNumberAndName || x.Kind != KindField) {
					t.Fatalf("mechanical without the proof: %+v", x)
				}
			}
		})
	}
}

func TestCompareNeverMechanicalForOtherKinds(t *testing.T) {
	old := "message M { option deprecated = true; string a = 1; }\nenum E { option deprecated = true; A = 0; B = 1 [deprecated = true]; }\n"
	cmp, err := pair(t, old, "enum E { reserved 1; reserved \"B\"; A = 0; }\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp.Candidates) != 3 {
		t.Fatal(cmp.Candidates)
	}
	for _, c := range cmp.Candidates {
		if c.Status != StatusDraft {
			t.Fatalf("%+v", c)
		}
	}
}

func TestCompareHiddenAndIncomplete(t *testing.T) {
	const old = "message M { string old = 2 [deprecated = true]; }\n"
	t.Run("hidden old field is no candidate", func(t *testing.T) {
		cmp, err := pair(t, "message M {\n // [#not-implemented-hide:]\n string old = 2 [deprecated = true]; }\n", "message M { reserved 2; reserved \"old\"; }\n")
		if err != nil || len(cmp.Candidates) != 0 {
			t.Fatal(err, cmp.Candidates)
		}
	})
	t.Run("hidden new field still counts as present", func(t *testing.T) {
		cmp, _ := pair(t, old, "message M { reserved 2; reserved \"old\";\n // [#not-implemented-hide:]\n string old = 9; }\n")
		if statusOf(cmp, "envoy.a.v3.M.old") != StatusDraft {
			t.Fatal("hidden declaration treated as removed")
		}
	})
	t.Run("incomplete newer", func(t *testing.T) {
		cmp, err := pair(t, old, "message M { reserved 2; reserved \"old\"; }\njunk;\n")
		if err != nil {
			t.Fatal(err)
		}
		if statusOf(cmp, "envoy.a.v3.M.old") != StatusDraft || len(cmp.Ledger) != 1 || cmp.Ledger[0].Code != ReasonSideIncomplete {
			t.Fatalf("%v %v", cmp.Candidates, cmp.Ledger)
		}
	})
	t.Run("incomplete older", func(t *testing.T) {
		o := mustScan(t, one(hdr+old+"junk;\n"))
		n, _ := Scan(tree(one(hdr+"message M { reserved 2; reserved \"old\"; }\n")), repo, commitB)
		cmp, err := Compare(o, n)
		if err != nil || statusOf(cmp, "envoy.a.v3.M.old") == StatusMechanical {
			t.Fatal(err, cmp)
		}
	})
}

func TestCompareRefusals(t *testing.T) {
	good := mustScan(t, one(hdr+"message M {}\n"))
	if _, err := Compare(Result{}, good); err == nil {
		t.Fatal("zero Result accepted")
	}
	if _, err := Compare(good, Result{}); err == nil {
		t.Fatal("zero Result accepted")
	}
	if _, err := Compare(good, good); err == nil {
		t.Fatal("same commit accepted")
	}
	other, _ := Scan(tree(one(hdr+"message M {}\n")), extract.RepoRef{Key: "github.com/example/other"}, commitB)
	if _, err := Compare(good, other); err == nil {
		t.Fatal("different repositories accepted")
	}
	var decoded Result
	b, _ := json.Marshal(good)
	_ = json.Unmarshal(b, &decoded)
	if _, err := Compare(decoded, other); err == nil {
		t.Fatal("a decoded Result (no symbol table) was accepted")
	}
}

// TestImportsDefaultDeny: the package may import only what is listed here.
// Anything that could execute, reach the network, read the host or run
// reflection is absent by default.
func TestImportsDefaultDeny(t *testing.T) {
	allowed := map[string]bool{
		"embed": true, "errors": true, "fmt": true, "io": true, "io/fs": true, "regexp": true,
		"sort": true, "strconv": true, "strings": true, "time": true,
		"github.com/prufyx/prufyx/cli/internal/extract":            true,
		"github.com/prufyx/prufyx/cli/internal/extract/membercode": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		n++
		f, err := goparser.ParseFile(gotoken.NewFileSet(), e.Name(), nil, goparser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if !allowed[p] {
				t.Errorf("%s imports %q, which is not on the allowlist", e.Name(), p)
			}
		}
	}
	if n < 5 {
		t.Fatalf("only %d source files seen", n)
	}
}

func TestSourceSetCoversEncoder(t *testing.T) {
	files, err := extract.CodeFiles(SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	var own, enc, tests bool
	for _, f := range files {
		switch {
		case strings.Contains(f.Path, "membercode_membercode.go"):
			enc = true
		case strings.HasSuffix(f.Path, "scan.go"):
			own = true
		case strings.HasSuffix(f.Path, "_test.go"):
			tests = true
		}
	}
	if !own || !enc || tests {
		t.Fatalf("own=%v encoder=%v tests=%v", own, enc, tests)
	}
}

func TestLexRefusals(t *testing.T) {
	for name, src := range map[string]string{"nul in comment": "// a\x00b\n", "lone slash quote": "'abc\n", "escape at end": "\"abc\\"} {
		if _, err := lex([]byte(src)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	lx, err := lex([]byte("a // c\n// pure\n/* b */ // after block\n"))
	if err != nil || len(lx.toks) != 1 || !lx.commentOnly[2] || lx.commentOnly[1] || lx.commentOnly[3] {
		t.Fatalf("%v %+v", err, lx)
	}
}
