// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestFixtures(t *testing.T) {
	all, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 40 {
		t.Fatalf("only %d fixtures", len(all))
	}
	for _, fx := range all {
		t.Run(fx.name, func(t *testing.T) {
			res, err := fx.scan(defaultGuards(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := fx.check(res); err != nil {
				t.Fatal(err)
			}
			// Every member is a valid, sorted, bounded set member.
			for _, b := range res.Binaries {
				if !sort.StringsAreSorted(b.Set.Members) || len(b.Set.Members) > constraintengine.MaxSetMembers {
					t.Errorf("%s members not sorted or too many: %v", b.Dir, b.Set.Members)
				}
				for i, m := range b.Set.Members {
					if !constraintengine.ValidSetMember(m) || strings.ToLower(m) != m || strings.Contains(m, "/") || len(m) < 2 || (i > 0 && b.Set.Members[i-1] == m) {
						t.Errorf("%s member %q breaks the member contract", b.Dir, m)
					}
				}
			}
		})
	}
}

// Determinism: the same tree listed in any order, and scanned any number of
// times, gives the same bytes.
func TestFixturesDeterministic(t *testing.T) {
	all, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, fx := range all {
		base, err := fx.scan(defaultGuards(), nil)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := base.Canonical()
		for seed := uint64(1); seed <= 6; seed++ {
			res, err := fx.scan(defaultGuards(), rand.New(rand.NewPCG(seed, seed*7)))
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := res.Canonical(); !bytes.Equal(got, want) {
				t.Fatalf("%s: shuffled listing (seed %d) changed the result:\n%s\nvs\n%s", fx.name, seed, got, want)
			}
		}
	}
}

// A result with any ledger entry is never attestable, a clean one is.
func TestFixturesAttestable(t *testing.T) {
	all, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}
	clean := 0
	for _, fx := range all {
		res, err := fx.scan(defaultGuards(), nil)
		if err != nil {
			t.Fatal(err)
		}
		complete := len(res.Binaries) > 0
		for _, b := range res.Binaries {
			complete = complete && b.Set.Complete
		}
		want := len(res.Ledger) == 0 && complete
		if got := res.Attestable(); got != want {
			t.Errorf("%s: Attestable %v, want %v (ledger %v)", fx.name, got, want, ledgerStrings(res.Ledger))
		}
		if len(res.Ledger) > 0 && res.Attestable() {
			t.Errorf("%s: a non-empty ledger is attestable", fx.name)
		}
		if res.Attestable() {
			clean++
		}
	}
	if clean < 10 {
		t.Errorf("only %d attestable fixtures: the control side is too thin", clean)
	}
}

func TestScanReadsOnlyThePinnedCommit(t *testing.T) {
	m := newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": "package main\n\nfunc main() {}\n"})
	if _, err := Scan(context.Background(), m, Target{Repo: repo}, commitA); err != nil {
		t.Fatal(err)
	}
	if len(m.seen) != 1 || !m.seen[commitA] {
		t.Fatalf("commits read: %v", m.seen)
	}
}

func TestScanInputErrors(t *testing.T) {
	m := newMem(map[string]string{"go.mod": goMod})
	for name, sha := range map[string]string{"empty": "", "short": "abc", "upper": strings.Repeat("A", 40), "branch": "main"} {
		if _, err := Scan(context.Background(), m, Target{Repo: repo}, sha); err == nil {
			t.Errorf("%s sha accepted", name)
		}
	}
	for name, tg := range map[string]Target{
		"dotdot":    {Repo: repo, Exclude: []Exclusion{{Dir: "../x", Reason: "r"}}},
		"abs":       {Repo: repo, Exclude: []Exclusion{{Dir: "/x", Reason: "r"}}},
		"unclean":   {Repo: repo, Exclude: []Exclusion{{Dir: "a//b", Reason: "r"}}},
		"empty":     {Repo: repo, Exclude: []Exclusion{{Dir: "", Reason: "r"}}},
		"noreason":  {Repo: repo, Exclude: []Exclusion{{Dir: "a", Reason: ""}}},
		"blank":     {Repo: repo, Exclude: []Exclusion{{Dir: "a", Reason: "   "}}},
		"newline":   {Repo: repo, Exclude: []Exclusion{{Dir: "a", Reason: "x\ny"}}},
		"toolong":   {Repo: repo, Exclude: []Exclusion{{Dir: "a", Reason: strings.Repeat("x", 201)}}},
		"duplicate": {Repo: repo, Exclude: []Exclusion{{Dir: "a", Reason: "r"}, {Dir: "a", Reason: "s"}}},
	} {
		if _, err := Scan(context.Background(), m, tg, commitA); err == nil {
			t.Errorf("target %s accepted", name)
		}
	}
}

func TestScanReaderFailureAndCancel(t *testing.T) {
	boom := errors.New("boom")
	m := newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": "package main\n"})
	m.readErr = boom
	if _, err := Scan(context.Background(), m, Target{Repo: repo}, commitA); !errors.Is(err, boom) {
		t.Fatalf("reader failure: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m = newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": "package main\n"})
	if _, err := Scan(ctx, m, Target{Repo: repo}, commitA); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}

// ---- import allowlist (default deny) ----

func importSrc(path string) map[string]string {
	return map[string]string{"cmd/t/main.go": fmt.Sprintf("package main\n\nimport (\n\t\"flag\"\n\t_ %q\n)\n\nfunc main() { flag.String(\"real\", \"\", \"u\"); flag.Parse() }\n", path)}
}

func TestImportAllowlistDefaultDeny(t *testing.T) {
	denied := []string{
		"k8s.io/klog/v2", "k8s.io/klog", "k8s.io/component-base/cli/flag", "k8s.io/component-base/logs",
		"github.com/golang/glog", "github.com/alecthomas/kong", "github.com/jessevdk/go-flags",
		"github.com/peterbourgon/ff/v3", "github.com/spf13/pflagx", "github.com/spf13/cobrax", "github.com/spf13",
		"github.com/alecthomas/kingpinx", "github.com/urfave/clix", "example.org/anything/else",
	}
	for _, p := range denied {
		res := scanFiles(t, importSrc(p), defaultGuards())
		if want := []string{"FLAG_IDIOM_UNSUPPORTED cmd/t"}; !equal(ledgerStrings(res.Ledger), want) {
			t.Errorf("%s: ledger %v", p, ledgerStrings(res.Ledger))
		}
		if b := binaryByDir(res, "cmd/t"); b == nil || b.Set.Complete || res.Attestable() {
			t.Errorf("%s: binary not withheld", p)
		}
	}
	allowed := []string{
		"fmt", "net/http", "path/filepath", "github.com/spf13/pflag", "github.com/spf13/cobra", "github.com/spf13/cobra/doc",
		"gopkg.in/alecthomas/kingpin.v2", "github.com/alecthomas/kingpin/v2", "github.com/urfave/cli/v2",
		"github.com/urfave/cli/v2/altsrc", "gopkg.in/urfave/cli.v1", "github.com/spf13/viper", "github.com/pkg/errors",
		"golang.org/x/sync/errgroup", "golang.org/x/sys/unix", "golang.org/x/term",
	}
	for _, p := range allowed {
		res := scanFiles(t, importSrc(p), defaultGuards())
		if len(res.Ledger) != 0 {
			t.Errorf("%s: ledger %v", p, ledgerStrings(res.Ledger))
		}
	}
}

func TestImportAllowlistReachesThroughModulePackages(t *testing.T) {
	res := scanFiles(t, map[string]string{
		"cmd/t/main.go":     "package main\n\nimport _ \"example.com/m/internal/a\"\n\nfunc main() {}\n",
		"internal/a/a.go":   "package a\n\nimport _ \"example.com/m/internal/b\"\n",
		"internal/b/b.go":   "package b\n\nimport _ \"github.com/golang/glog\"\n",
		"cmd/other/main.go": "package main\n\nfunc main() {}\n",
	}, defaultGuards())
	if want := []string{"FLAG_IDIOM_UNSUPPORTED cmd/t"}; !equal(ledgerStrings(res.Ledger), want) {
		t.Fatalf("ledger %v", ledgerStrings(res.Ledger))
	}
	if b := binaryByDir(res, "cmd/other"); b == nil || !b.Set.Complete {
		t.Fatalf("an unrelated binary is withheld: %+v", b)
	}
}

func TestDotImportOfAFlagLibraryIsUnsupported(t *testing.T) {
	res := scanFiles(t, map[string]string{"cmd/t/main.go": "package main\n\nimport . \"flag\"\n\nfunc main() { String(\"x\", \"\", \"u\") }\n"}, defaultGuards())
	if want := []string{"FLAG_IDIOM_UNSUPPORTED cmd/t"}; !equal(ledgerStrings(res.Ledger), want) {
		t.Fatalf("ledger %v", ledgerStrings(res.Ledger))
	}
}

func TestAliasedFlagLibraryIsStillRecognised(t *testing.T) {
	res := scanFiles(t, map[string]string{"cmd/t/main.go": "package main\n\nimport gf \"flag\"\n\nfunc main() { gf.String(\"renamed\", \"\", \"u\"); gf.Parse() }\n"}, defaultGuards())
	b := binaryByDir(res, "cmd/t")
	if len(res.Ledger) != 0 || !equal(b.Set.Members, []string{"renamed"}) {
		t.Fatalf("ledger %v members %v", ledgerStrings(res.Ledger), b.Set.Members)
	}
}

// ---- member contract ----

func TestMemberCodeBoundaries(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct{ name, want string }{
		{"ab", ""}, {"a1", ""}, {"1a", ""}, {"a.b", ""}, {"a_b", ""}, {"a-b", ""}, {"web.listen-address", ""},
		{long(128), ""}, {long(129), ReasonMemberTooLong}, {long(1000), ReasonMemberTooLong},
		{"a", ReasonNameNotLong}, {"Z", ReasonNameNotLong}, {"-", ReasonNameNotLong}, {"/", ReasonNameNotLong}, {"é", ReasonMemberCharset},
		{"", ReasonMemberCharset}, {"Debug", ReasonNameUppercase}, {"aB", ReasonNameUppercase}, {"web.Listen", ReasonNameUppercase}, {"CamelCase", ReasonNameUppercase},
		{"a/b", ReasonMemberCharset}, {"A/b", ReasonMemberCharset}, {"/ab", ReasonMemberCharset}, {"ab/", ReasonMemberCharset},
		{"-ab", ReasonMemberCharset}, {".ab", ReasonMemberCharset}, {"_ab", ReasonMemberCharset}, {"a b", ReasonMemberCharset},
		{"a=b", ReasonMemberCharset}, {"a\nb", ReasonMemberCharset}, {"日本", ReasonMemberCharset}, {"a\x00", ReasonMemberCharset},
		{"Ab" + long(200), ReasonMemberTooLong},
	}
	for _, c := range cases {
		if got := MemberCode(c.name); got != c.want {
			t.Errorf("MemberCode(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// The pattern cannot admit what it forbids: for random names over an
// alphabet rich in the forbidden bytes, a name is a member only when it is
// lower case, has no "/" and satisfies both the scanner's pattern and the
// constraint engine's.
func TestMemberPatternNeverAdmitsForbidden(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	alphabet := []byte("abcxyz019AZ._-/ =\n\x00\xff")
	for i := 0; i < 20000; i++ {
		n := rng.IntN(6)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.IntN(len(alphabet))]
		}
		name := string(b)
		if MemberCode(name) != "" {
			continue
		}
		if strings.ToLower(name) != name || strings.Contains(name, "/") || len(name) < 2 || !memberRE.MatchString(name) || !constraintengine.ValidSetMember(name) {
			t.Fatalf("%q admitted", name)
		}
	}
	for _, c := range []byte("/ABZ") {
		if memberRE.MatchString("a" + string(c)) {
			t.Errorf("pattern admits %q", c)
		}
	}
}

func TestSetTooLarge(t *testing.T) {
	gen := func(n int) map[string]string {
		var sb strings.Builder
		sb.WriteString("package main\n\nimport \"flag\"\n\nfunc main() {\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "\tflag.Bool(\"flag-%04d\", false, \"u\")\n", i)
		}
		sb.WriteString("}\n")
		return map[string]string{"cmd/t/main.go": sb.String()}
	}
	res := scanFiles(t, gen(constraintengine.MaxSetMembers), defaultGuards())
	if b := binaryByDir(res, "cmd/t"); len(res.Ledger) != 0 || len(b.Set.Members) != constraintengine.MaxSetMembers || !b.Set.Complete {
		t.Fatalf("exactly the cap must be kept whole: ledger %v", ledgerStrings(res.Ledger))
	}
	res = scanFiles(t, gen(constraintengine.MaxSetMembers+1), defaultGuards())
	if want := []string{"MEMBER_SET_TOO_LARGE cmd/t"}; !equal(ledgerStrings(res.Ledger), want) || binaryByDir(res, "cmd/t").Set.Complete || len(binaryByDir(res, "cmd/t").Set.Members) != 0 {
		t.Fatalf("over the cap: %v", ledgerStrings(res.Ledger))
	}
}

// ---- class published per binary ----

func TestClassPerIdiom(t *testing.T) {
	cases := []struct{ name, imports, body, class string }{
		{"stdlib", `"flag"`, `flag.Parse()`, ClassSingleDashLong},
		{"pflag", `"github.com/spf13/pflag"`, `pflag.Parse()`, ClassDoubleDash},
		{"cobra", `"github.com/spf13/cobra"`, `_ = cobra.Command{}`, ClassDoubleDash},
		{"kingpin", `"github.com/alecthomas/kingpin/v2"`, `kingpin.Parse()`, ClassDoubleDash},
		{"urfave", `"github.com/urfave/cli/v2"`, `_ = cli.App{}`, ClassSingleDashLong},
		{"mixed", "\"flag\"\n\t\"github.com/spf13/pflag\"", `pflag.Parse(); flag.Parse()`, ClassSingleDashLong},
		{"none", `"fmt"`, `fmt.Println()`, ""},
	}
	for _, c := range cases {
		res := scanFiles(t, map[string]string{"cmd/t/main.go": fmt.Sprintf("package main\n\nimport (\n\t%s\n)\n\nfunc main() { %s }\n", c.imports, c.body)}, defaultGuards())
		if b := binaryByDir(res, "cmd/t"); b == nil || b.Class != c.class {
			t.Errorf("%s: class %+v, want %q", c.name, b, c.class)
		}
	}
}

// ---- limits ----

func TestLimitsWithholdInsteadOfTruncating(t *testing.T) {
	small := func(f func(*limits)) guards {
		g := defaultGuards()
		f(&g.lim)
		return g
	}
	files := func() map[string]string {
		return map[string]string{
			"cmd/t/main.go":   "package main\n\nimport _ \"example.com/m/internal/a\"\n\nfunc main() {}\n",
			"internal/a/a.go": "package a\n",
			"internal/b/b.go": "package b\n",
			"x/y/z/w/doc.go":  "package w\n",
		}
	}
	cases := []struct {
		name string
		g    guards
		code string
	}{
		{"dirs", small(func(l *limits) { l.dirs = 3 }), "INVENTORY_FAULT_TOO_LARGE"},
		{"depth", small(func(l *limits) { l.depth = 1 }), "INVENTORY_FAULT_TOO_LARGE"},
		{"files per dir", small(func(l *limits) { l.filesPerDir = 0 }), "INVENTORY_FAULT_TOO_LARGE"},
		{"file bytes", small(func(l *limits) { l.fileBytes = 10 }), "INVENTORY_FAULT_TOO_LARGE"},
		{"packages", small(func(l *limits) { l.packages = 1 }), "INVENTORY_FAULT_TOO_LARGE"},
		{"total files", small(func(l *limits) { l.files = 1 }), "INVENTORY_FAULT_TOO_LARGE"},
	}
	for _, c := range cases {
		res := scanFiles(t, files(), c.g)
		found := false
		for _, e := range res.Ledger {
			found = found || e.Code == c.code
		}
		if !found || res.Attestable() {
			t.Errorf("%s: ledger %v attestable=%v", c.name, ledgerStrings(res.Ledger), res.Attestable())
		}
	}
	if res := scanFiles(t, files(), defaultGuards()); len(res.Ledger) != 0 {
		t.Errorf("control: ledger %v", ledgerStrings(res.Ledger))
	}
}

// ---- garbage input ----

func TestGarbageGoDoesNotPanic(t *testing.T) {
	deep := "package main\n\nvar x = " + strings.Repeat("(", 5000) + "1" + strings.Repeat(")", 5000) + "\n"
	deepCall := "package main\n\nfunc main() { " + strings.Repeat("f(", 3000) + strings.Repeat(")", 3000) + " }\n"
	rng := rand.New(rand.NewPCG(3, 5))
	random := make([]byte, 4096)
	for i := range random {
		random[i] = byte(rng.IntN(256))
	}
	inputs := []string{
		"", "package", "package main", "package main\nfunc (", "package main\nimport (", "\x00\xff\xfe",
		"package main\nfunc main() { flag.String( }", "package main\nimport \"flag\"\nfunc main() { flag.String(\"a\"", deep, deepCall,
		"package main\nimport \"flag\"\nvar _ = flag.String(\"a\", \"\", \"\" ...)", "package main\nfunc main() { x.y.z.(", string(random),
		"package main\nimport . \"flag\"\nfunc main() { String() }", "package main\nfunc main() { for { go func() { os.Args = nil }() } }",
		"//go:build\npackage main\nfunc main() {}", "// +build\npackage main", "package \xff",
	}
	for i, in := range inputs {
		for _, where := range []string{"cmd/t/main.go", "internal/lib/lib.go"} {
			files := map[string]string{"cmd/t/main.go": "package main\n\nimport _ \"example.com/m/internal/lib\"\n\nfunc main() {}\n", "internal/lib/lib.go": "package lib\n"}
			files[where] = in
			res := scanFiles(t, files, defaultGuards())
			if _, err := res.Canonical(); err != nil {
				t.Fatalf("input %d in %s: %v", i, where, err)
			}
			if res.Attestable() && where == "cmd/t/main.go" && in != "" && !strings.HasPrefix(in, "package main\nimport . ") {
				// Garbage must not be attestable unless it parsed as a clean main package.
				if f, err := parseSafe(newFset(), "x.go", []byte(in), 0); err != nil || f == nil {
					t.Errorf("input %d attestable although it does not parse", i)
				}
			}
		}
	}
}

// Fuzz-style: byte-range deletions of real fixtures never panic and are
// deterministic.
func TestMutatedSourcesDoNotPanicAndAreDeterministic(t *testing.T) {
	all, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(9, 13))
	for _, fx := range all {
		var paths []string
		for p := range fx.files {
			if strings.HasSuffix(p, ".go") {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			continue
		}
		for i := 0; i < 8; i++ {
			files := map[string]string{}
			for k, v := range fx.files {
				files[k] = v
			}
			p := paths[rng.IntN(len(paths))]
			src := files[p]
			if len(src) > 2 {
				a := rng.IntN(len(src))
				b := a + rng.IntN(len(src)-a)
				src = src[:a] + src[b:]
			}
			files[p] = src
			first := scanFiles(t, files, defaultGuards())
			second := scanFiles(t, files, defaultGuards())
			x, _ := first.Canonical()
			y, _ := second.Canonical()
			if !bytes.Equal(x, y) {
				t.Fatalf("%s: mutated scan is not deterministic", fx.name)
			}
		}
	}
}

// No goroutine is started by a scan.
func TestScanLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	all, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, fx := range all {
		if _, err := fx.scan(defaultGuards(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines %d -> %d", before, after)
	}
}

func TestLedgerItemFaultWhenBinaryDirIsNotAnIdentifier(t *testing.T) {
	res := scanFiles(t, map[string]string{
		"cmd/has space/main.go": "package main\n\nimport _ \"k8s.io/klog/v2\"\n\nfunc main() {}\n",
		"cmd/ok/main.go":        "package main\n\nfunc main() {}\n",
	}, defaultGuards())
	if want := []string{"LEDGER_INVALID ledger"}; !equal(ledgerStrings(res.Ledger), want) {
		t.Fatalf("ledger %v", ledgerStrings(res.Ledger))
	}
	for _, b := range res.Binaries {
		if b.Set.Complete {
			t.Errorf("%s complete under a fault ledger", b.Dir)
		}
	}
}

func TestSourceSetCoversTheScanner(t *testing.T) {
	files, err := extract.CodeFiles(SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}
	for _, want := range []string{"imports.go", "scan.go", "walk.go", "ledger.go", "reasons.go"} {
		found := false
		for p := range got {
			found = found || strings.HasSuffix(p, "/"+want)
		}
		if !found {
			t.Errorf("%s is not in the source set: %v", want, got)
		}
	}
	for p := range got {
		if strings.HasSuffix(p, "_test.go") {
			t.Errorf("test file %s is in the source set", p)
		}
	}
	if _, err := os.Stat("source.go"); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryFaultsInline(t *testing.T) {
	type tc struct {
		name  string
		setup func() *memReader
		tg    Target
		want  []string
	}
	mainSrc := "package main\n\nfunc main() {}\n"
	cases := []tc{
		{"go.mod without module", func() *memReader { return newMem(map[string]string{"go.mod": "go 1.22\n", "cmd/t/main.go": mainSrc}) }, Target{Repo: repo}, []string{"INVENTORY_FAULT_GO_MOD_INVALID ."}},
		{"go.mod bad quoting", func() *memReader {
			return newMem(map[string]string{"go.mod": "module \"example.com/m\ngo 1.22\n", "cmd/t/main.go": mainSrc})
		}, Target{Repo: repo}, []string{"INVENTORY_FAULT_GO_MOD_INVALID ."}},
		{"root listing missing", func() *memReader {
			m := newMem(map[string]string{"go.mod": goMod})
			m.noRoot = true
			return m
		}, Target{Repo: repo}, []string{"INVENTORY_FAULT_TREE_MISSING ."}},
		{"symlinked source", func() *memReader {
			m := newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": mainSrc})
			m.modes = map[string]string{"cmd/t/main.go": "120000"}
			return m
		}, Target{Repo: repo}, []string{"INVENTORY_FAULT_SOURCE_KIND cmd/t"}},
		{"nested module excluded", func() *memReader {
			return newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": mainSrc, "tools/go.mod": "module x\n", "tools/main.go": mainSrc})
		}, Target{Repo: repo, Exclude: []Exclusion{{Dir: "tools", Reason: "separate module, not shipped"}}}, nil},
		{"nested module not excluded", func() *memReader {
			return newMem(map[string]string{"go.mod": goMod, "cmd/t/main.go": mainSrc, "tools/go.mod": "module x\n", "tools/main.go": mainSrc})
		}, Target{Repo: repo}, []string{"INVENTORY_FAULT_NESTED_MODULE tools"}},
		{"root binary excluded leaves nothing", func() *memReader { return newMem(map[string]string{"go.mod": goMod, "main.go": mainSrc}) },
			Target{Repo: repo, Exclude: []Exclusion{{Dir: ".", Reason: "root is a tool"}}}, nil},
	}
	for _, c := range cases {
		res, err := scan(context.Background(), c.setup(), c.tg, commitA, defaultGuards())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := ledgerStrings(res.Ledger); !equal(got, orEmpty(c.want)) {
			t.Errorf("%s: ledger %v, want %v", c.name, got, c.want)
		}
		if len(c.want) > 0 && res.Attestable() {
			t.Errorf("%s: attestable with a ledger", c.name)
		}
	}
}
