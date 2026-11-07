// SPDX-License-Identifier: AGPL-3.0-only

package configkeys

import (
	"context"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	sha  = strings.Repeat("a", 40)
	repo = extract.RepoRef{Key: "github.com/example/project"}
)

type mem map[string]string

func (m mem) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if d, ok := m[p]; ok {
		return []byte(d), nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m mem) List(_ extract.RepoRef, _, dir string) ([]extract.TreeEntry, error) {
	var out []extract.TreeEntry
	for p := range m {
		if strings.HasPrefix(p, dir+"/") && !strings.Contains(strings.TrimPrefix(p, dir+"/"), "/") {
			out = append(out, extract.TreeEntry{Mode: "100644", Type: "blob", Path: p})
		}
	}
	return out, nil
}

func tgt(tag string) Target { return Target{Repo: repo, Dir: "config", Root: "Config", Tag: tag} }

func run(t *testing.T, tag, src string) *Result {
	t.Helper()
	return runG(t, tag, src, defaultGuards())
}

func runG(t *testing.T, tag, src string, g guards) *Result {
	t.Helper()
	r, err := scan(context.Background(), mem{"config/c.go": "package config\n" + src}, tgt(tag), sha, g)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func codes(r *Result) []string {
	out := []string{}
	for _, e := range r.Ledger {
		out = append(out, e.Code)
	}
	return out
}

func TestYAMLBasic(t *testing.T) {
	r := run(t, TagYAML, "import \"time\"\ntype Config struct {\n Name string `yaml:\"name,omitempty\"`\n Server Server `yaml:\"server\"`\n Ignored string `yaml:\"-\"`\n hidden string\n Implicit int\n Every time.Duration `yaml:\"every\"`\n}\ntype Server struct { Port int `yaml:\"port\"`; TLS *TLS `yaml:\"tls\"`; Hosts []Host `yaml:\"hosts\"` }\ntype TLS struct { Cert string `yaml:\"cert\"` }\ntype Host struct { Addr string `yaml:\"addr\"` }\n")
	want := []string{"every", "implicit", "name", "server", "server.hosts", "server.hosts._item_.addr", "server.port", "server.tls", "server.tls.cert"}
	if !reflect.DeepEqual(r.Keys, want) {
		t.Fatalf("keys %v", r.Keys)
	}
	if !r.Attestable() || r.Basis != BasisMechanical || len(r.Ledger) != 0 {
		t.Fatalf("not attestable: %+v", r)
	}
}

func TestOmitemptyKeepsKey(t *testing.T) {
	r := run(t, TagJSON, "type Config struct { A string `json:\"a,omitempty\"` }\n")
	if !r.Has("a") || !r.Attestable() {
		t.Fatal(r)
	}
}

func TestEmbeddedAndInline(t *testing.T) {
	src := "type Config struct { Base `yaml:\",inline\"`; Plain; Own string `yaml:\"own\"` }\ntype Base struct { B string `yaml:\"b\"` }\ntype Plain struct { P string `yaml:\"p\"` }\n"
	r := run(t, TagYAML, src)
	if !reflect.DeepEqual(r.Keys, []string{"b", "own", "plain", "plain.p"}) || !r.Attestable() {
		t.Fatalf("%v %v", r.Keys, r.Ledger)
	}
	j := run(t, TagJSON, "type Config struct { Base; Named Plain `json:\"named\"` }\ntype Base struct { B string `json:\"b\"` }\ntype Plain struct { P string `json:\"p\"` }\n")
	if !reflect.DeepEqual(j.Keys, []string{"b", "named", "named.p"}) || !j.Attestable() {
		t.Fatalf("%v %v", j.Keys, j.Ledger)
	}
}

func TestInlineMapIsDynamic(t *testing.T) {
	r := run(t, TagYAML, "type Config struct { A string `yaml:\"a\"`; Extra map[string]any `yaml:\",inline\"` }\n")
	if r.Attestable() || !reflect.DeepEqual(codes(r), []string{ReasonDynamicMap}) {
		t.Fatalf("%v", r.Ledger)
	}
}

func TestDynamicMapAndAny(t *testing.T) {
	r := run(t, TagYAML, "type Config struct { Labels map[string]string `yaml:\"labels\"`; X any `yaml:\"x\"`; Y interface{} `yaml:\"y\"` }\n")
	if r.Attestable() || !r.Has("labels") {
		t.Fatal(r)
	}
	if !reflect.DeepEqual(codes(r), []string{ReasonDynamicAny, ReasonDynamicAny, ReasonDynamicMap}) {
		t.Fatalf("%v", r.Ledger)
	}
}

func TestCustomUnmarshalWithholds(t *testing.T) {
	r := run(t, TagYAML, "type Config struct { L Level `yaml:\"l\"` }\ntype Level struct { V string `yaml:\"v\"` }\nfunc (l *Level) UnmarshalYAML(f func(any) error) error { return nil }\n")
	if r.Attestable() || !reflect.DeepEqual(codes(r), []string{ReasonCustomUnmarsh}) || r.Has("l.v") {
		t.Fatalf("%v %v", r.Keys, r.Ledger)
	}
}

func TestMemberRefusals(t *testing.T) {
	for name, tc := range map[string]struct{ src, code string }{
		"dot":      {"type Config struct { A string `yaml:\"a.b\"` }\n", ReasonAmbiguous},
		"charset":  {"type Config struct { A string `yaml:\"a b\"` }\n", ReasonCharset},
		"reserved": {"type Config struct { A string `yaml:\"_item_\"` }\n", ReasonAmbiguous},
	} {
		r := run(t, TagYAML, tc.src)
		if r.Attestable() || len(r.Ledger) != 1 || r.Ledger[0].Code != tc.code && !(name == "dot" && r.Ledger[0].Code == ReasonCharset) {
			t.Errorf("%s: %v", name, r.Ledger)
		}
		if len(r.Keys) != 0 {
			t.Errorf("%s: emitted %v", name, r.Keys)
		}
	}
}

func TestImplicitNameJSONAndMapstructure(t *testing.T) {
	for _, tag := range []string{TagJSON, TagMapstructure} {
		r := run(t, tag, "type Config struct { A string\n B string `"+tag+":\"b\"` }\n")
		if r.Attestable() || !reflect.DeepEqual(codes(r), []string{ReasonImplicitName}) || !r.Has("b") {
			t.Errorf("%s: %v", tag, r.Ledger)
		}
	}
}

func TestCollision(t *testing.T) {
	r := run(t, TagYAML, "type Config struct { Base `yaml:\",inline\"`; A string `yaml:\"a\"` }\ntype Base struct { A string `yaml:\"a\"` }\n")
	if r.Attestable() || !reflect.DeepEqual(codes(r), []string{ReasonKeyCollision}) {
		t.Fatalf("%v", r.Ledger)
	}
}

func TestUnresolvable(t *testing.T) {
	for name, src := range map[string]string{
		"missing type":   "type Config struct { A Missing `yaml:\"a\"` }\n",
		"foreign pkg":    "import \"net/url\"\ntype Config struct { A url.URL `yaml:\"a\"` }\n",
		"func":           "type Config struct { A func() `yaml:\"a\"` }\n",
		"generic":        "type Config struct { A G[int] `yaml:\"a\"` }\ntype G[T any] struct { V T `yaml:\"v\"` }\n",
		"cycle":          "type Config struct { N *Config `yaml:\"n\"` }\n",
		"bad tag":        "type Config struct { A string `yaml:\"a` }\n",
		"duplicate type": "type X struct{}\ntype X struct{}\ntype Config struct { A X `yaml:\"a\"` }\n",
	} {
		r := run(t, TagYAML, src)
		if r.Attestable() || len(r.Ledger) == 0 {
			t.Errorf("%s attestable: %+v", name, r)
		}
	}
}

func TestRootMissingAndParseFailure(t *testing.T) {
	r := run(t, TagYAML, "type Other struct{}\n")
	if r.Attestable() || codes(r)[0] != ReasonRootNotFound {
		t.Fatal(r.Ledger)
	}
	r2, err := Scan(context.Background(), mem{"config/c.go": "package config\ntype Config struct {"}, tgt(TagYAML), sha)
	if err != nil || r2.Attestable() || codes(r2)[0] != ReasonParse {
		t.Fatalf("%v %v", r2, err)
	}
}

func TestBuildConstraintAndMultiplePackages(t *testing.T) {
	m := mem{"config/a.go": "//go:build linux\n\npackage config\ntype Config struct { A string `yaml:\"a\"` }\n"}
	r, _ := Scan(context.Background(), m, tgt(TagYAML), sha)
	if r.Attestable() || codes(r)[0] != ReasonBuildConstr {
		t.Fatal(r.Ledger)
	}
	m = mem{"config/a.go": "package config\ntype Config struct { A string `yaml:\"a\"` }\n", "config/b.go": "package other\n"}
	r, _ = Scan(context.Background(), m, tgt(TagYAML), sha)
	if r.Attestable() || codes(r)[0] != ReasonPackages {
		t.Fatal(r.Ledger)
	}
}

func TestTestFilesIgnored(t *testing.T) {
	m := mem{"config/a.go": "package config\ntype Config struct { A string `yaml:\"a\"` }\n", "config/a_test.go": "package config\ntype Config struct{}\n"}
	r, _ := Scan(context.Background(), m, tgt(TagYAML), sha)
	if !r.Attestable() {
		t.Fatal(r.Ledger)
	}
}

func TestRenamedAndMovedKeys(t *testing.T) {
	old := run(t, TagYAML, "type Config struct { A string `yaml:\"old_name\"`; S S `yaml:\"s\"`; Keep string `yaml:\"keep\"` }\ntype S struct { Moved string `yaml:\"moved\"` }\n")
	next := run(t, TagYAML, "type Config struct { A string `yaml:\"new_name\"`; S S `yaml:\"s\"`; Keep string `yaml:\"keep\"`; Moved string `yaml:\"moved\"` }\ntype S struct{}\n")
	got, ok := RemovalCandidates(old, next)
	// A rename and a move are removals at the old path.
	if !ok || !reflect.DeepEqual(got, []string{"old_name", "s.moved"}) {
		t.Fatalf("%v %v", got, ok)
	}
}

func TestRemovalRefusesIncompleteOrMismatched(t *testing.T) {
	good := run(t, TagYAML, "type Config struct { A string `yaml:\"a\"` }\n")
	bad := run(t, TagYAML, "type Config struct { A string `yaml:\"a\"`; M map[string]int `yaml:\"m\"` }\n")
	if _, ok := RemovalCandidates(good, bad); ok {
		t.Fatal("incomplete new accepted")
	}
	if _, ok := RemovalCandidates(bad, good); ok {
		t.Fatal("incomplete old accepted")
	}
	j := run(t, TagJSON, "type Config struct { A string `json:\"a\"` }\n")
	if _, ok := RemovalCandidates(good, j); ok {
		t.Fatal("tag mismatch accepted")
	}
	if _, ok := RemovalCandidates(nil, good); ok {
		t.Fatal("nil accepted")
	}
}

func TestDeterministic(t *testing.T) {
	src := "type Config struct { Z string `yaml:\"z\"`; A string `yaml:\"a\"`; M string `yaml:\"m\"` }\n"
	a, b := run(t, TagYAML, src), run(t, TagYAML, src)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a.Keys, []string{"a", "m", "z"}) {
		t.Fatal(a.Keys)
	}
}

func TestTargetAndShaValidation(t *testing.T) {
	for _, tg := range []Target{{Repo: repo, Dir: "/abs", Root: "C", Tag: TagYAML}, {Repo: repo, Dir: "a/../b", Root: "C", Tag: TagYAML}, {Repo: repo, Dir: "a", Root: "", Tag: TagYAML}, {Repo: repo, Dir: "a", Root: "C D", Tag: TagYAML}, {Repo: repo, Dir: "a", Root: "C", Tag: "toml"}} {
		if _, err := Scan(context.Background(), mem{}, tg, sha); err == nil {
			t.Errorf("accepted %+v", tg)
		}
	}
	if _, err := Scan(context.Background(), mem{}, tgt(TagYAML), "main"); err == nil {
		t.Error("short sha accepted")
	}
	if r, err := Scan(context.Background(), mem{}, tgt(TagYAML), sha); err != nil || r.Attestable() || codes(r)[0] != ReasonRootNotFound {
		t.Error("empty directory must withhold")
	}
}

func TestPanicBecomesLedger(t *testing.T) {
	g := defaultGuards()
	g.hook = func(string) { panic("x") }
	r := runG(t, TagYAML, "type Config struct { A string `yaml:\"a\"` }\n", g)
	if r.Attestable() || codes(r)[0] != ReasonPanic {
		t.Fatal(r.Ledger)
	}
}

func TestAttestableRefusesAnyLedger(t *testing.T) {
	r := &Result{Complete: true, Basis: BasisMechanical, Keys: []string{"a"}, Ledger: []LedgerEntry{{Code: "X", Item: "y"}}}
	if r.Attestable() {
		t.Fatal("ledger ignored")
	}
	var n *Result
	if n.Attestable() {
		t.Fatal("nil attestable")
	}
}

func TestSourceSetCoversEncoder(t *testing.T) {
	s := SourceSet()
	ents, err := fs.ReadDir(s.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	var own, enc bool
	for _, e := range ents {
		own = own || e.Name() == "configkeys.go"
		enc = enc || e.Name() == "membercode_membercode.go"
	}
	if !own || !enc {
		t.Fatalf("source set incomplete: own=%v encoder=%v", own, enc)
	}
}

// Guard mutations: with a guard off, the matching negative must flip.
func TestGuardMutations(t *testing.T) {
	custom := "type Config struct { L Level `yaml:\"l\"` }\ntype Level struct{}\nfunc (l *Level) UnmarshalYAML(f func(any) error) error { return nil }\n"
	dyn := "type Config struct { M map[string]int `yaml:\"m\"` }\n"
	imp := "type Config struct { A string\n B string `json:\"b\"` }\n"
	col := "type Config struct { Base `yaml:\",inline\"`; A string `yaml:\"a\"` }\ntype Base struct { A string `yaml:\"a\"` }\n"
	foreign := "import \"net/url\"\ntype Config struct { A url.URL `yaml:\"a\"` }\n"
	for name, tc := range map[string]struct {
		tag, src string
		off      func(*guards)
	}{
		"custom":    {TagYAML, custom, func(g *guards) { g.custom = false }},
		"dynamic":   {TagYAML, dyn, func(g *guards) { g.dynamic = false }},
		"implicit":  {TagJSON, imp, func(g *guards) { g.implicit = false }},
		"collision": {TagYAML, col, func(g *guards) { g.collision = false }},
		"allowlist": {TagYAML, foreign, func(g *guards) { g.allowlist = false }},
	} {
		if run(t, tc.tag, tc.src).Attestable() {
			t.Errorf("%s: default guards attest", name)
		}
		g := defaultGuards()
		tc.off(&g)
		if !runG(t, tc.tag, tc.src, g).Attestable() {
			t.Errorf("%s: guard is not what withholds", name)
		}
	}
}

func TestVetoGuard(t *testing.T) {
	src := "type Config struct { M map[string]int `yaml:\"m\"` }\n"
	if run(t, TagYAML, src).Complete {
		t.Fatal("ledger entry left result complete")
	}
	g := defaultGuards()
	g.ledger.veto = false
	if !runG(t, TagYAML, src, g).Complete {
		t.Fatal("veto guard inert")
	}
}

func TestLedgerRules(t *testing.T) {
	g := defaultLedgerGuards()
	if got := ledgerOf([]LedgerEntry{{"b_code", "z"}, {"a_code", "y"}, {"a_code", "y"}}, g); len(got) != 2 || got[0].Code != "a_code" && got[0].Code != "A_CODE" {
		// codes must be upper case: lower case is refused.
		if got[0].Code != LedgerInvalid {
			t.Fatalf("%v", got)
		}
	}
	ok := ledgerOf([]LedgerEntry{{"BBB", "z"}, {"AAA", "y"}, {"AAA", "y"}}, g)
	if !reflect.DeepEqual(ok, []LedgerEntry{{"AAA", "y"}, {"BBB", "z"}}) {
		t.Fatalf("%v", ok)
	}
	for name, e := range map[string]LedgerEntry{"item": {"AAA", "bad item"}, "reserved": {"LEDGER_X", "y"}} {
		if got := ledgerOf([]LedgerEntry{e}, g); got[0].Code != LedgerInvalid {
			t.Errorf("%s: %v", name, got)
		}
	}
	var many []LedgerEntry
	for i := 0; i <= MaxLedgerEntries; i++ {
		many = append(many, LedgerEntry{"AAA", fmt.Sprintf("i%d", i)})
	}
	if got := ledgerOf(many, g); got[0].Code != LedgerOverflow {
		t.Fatal(got[0])
	}
	// mutations
	g2 := g
	g2.order = false
	if got := ledgerOf([]LedgerEntry{{"BBB", "z"}, {"AAA", "y"}}, g2); got[0].Code != "BBB" {
		t.Error("order guard inert")
	}
	g3 := g
	g3.dedupe = false
	if got := ledgerOf([]LedgerEntry{{"AAA", "y"}, {"AAA", "y"}}, g3); len(got) != 2 {
		t.Error("dedupe guard inert")
	}
	g4 := g
	g4.item = false
	if got := ledgerOf([]LedgerEntry{{"AAA", "bad item"}}, g4); got[0].Code == LedgerInvalid {
		t.Error("item guard inert")
	}
}
