// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const zeroOID = "0000000000000000000000000000000000000000"
const someOID = "1111111111111111111111111111111111111111"

type rec struct {
	status string
	paths  []string
}

func raw(recs ...rec) []byte {
	var b bytes.Buffer
	for _, r := range recs {
		fmt.Fprintf(&b, ":100644 100644 %s %s %s\x00", someOID, someOID, r.status)
		for _, p := range r.paths {
			b.WriteString(p)
			b.WriteByte(0)
		}
	}
	return b.Bytes()
}

func mod(paths ...string) []byte {
	var rs []rec
	for _, p := range paths {
		rs = append(rs, rec{"M", []string{p}})
	}
	return raw(rs...)
}

func TestClassifyTable(t *testing.T) {
	rd := "cli/knowledge/target-recipes/acme/"
	tgt := "cli/internal/extract/crdversions/target-acme.json"
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"recipe file", mod(rd + "recipe.json"), ClassApplicable},
		{"recipe dir all files", mod(rd+"recipe.json", rd+"facts.bundle", rd+"changelog.md"), ClassApplicable},
		{"real target", mod(tgt), ClassApplicable},
		{"recipe plus target", mod(rd+"recipe.json", tgt), ClassApplicable},
		{"two slugs", mod(rd+"recipe.json", "cli/knowledge/target-recipes/b/recipe.json", "cli/internal/extract/crdversions/target-b.json"), ClassApplicable},
		{"docs only", mod("README.md"), ClassNotApplicable},
		{"site only", mod("site/index.html", "docs/a/b.md"), ClassNotApplicable},
		{"other cli", mod("cli/internal/other/x.go"), ClassNotApplicable},
		{"workflow", mod(".github/workflows/verify-pr.yml"), ClassTrustPathChange},
		{"other workflow", mod(".github/workflows/x.yml"), ClassTrustPathChange},
		{"codeowners", mod(".github/CODEOWNERS"), ClassTrustPathChange},
		{"other github file", mod(".github/dependabot.yml"), ClassNotApplicable},
		{"targetdraft", mod("cli/internal/maintainer/targetdraft/verify.go"), ClassTrustPathChange},
		{"targetdraft nested", mod("cli/internal/maintainer/targetdraft/testdata/a/b"), ClassTrustPathChange},
		{"knowledgegate", mod("cli/internal/maintainer/knowledgegate/x.go"), ClassTrustPathChange},
		{"verifyprworkflow", mod("cli/internal/maintainer/verifyprworkflow/workflow_test.go"), ClassTrustPathChange},
		{"extract", mod("cli/internal/extract/extract.go"), ClassTrustPathChange},
		{"crdversions non target", mod("cli/internal/extract/crdversions/other.json"), ClassTrustPathChange},
		{"crdversions target bad slug", mod("cli/internal/extract/crdversions/target-Acme.json"), ClassTrustPathChange},
		{"crdversions target empty slug", mod("cli/internal/extract/crdversions/target-.json"), ClassTrustPathChange},
		{"crdversions target nested", mod("cli/internal/extract/crdversions/target-a/b.json"), ClassTrustPathChange},
		{"knowledge outside recipes", mod("cli/knowledge/other/x.json"), ClassTrustPathChange},
		{"knowledge root file", mod("cli/knowledge/x.json"), ClassTrustPathChange},
		{"recipes dir as file", mod("cli/knowledge/target-recipes"), ClassTrustPathChange},
		{"maintainer cmd", mod("cli/cmd/prufyx-maintainer/main.go"), ClassTrustPathChange},
		{"sibling prefix not trust", mod("cli/cmd/prufyx-maintainer-x/main.go"), ClassNotApplicable},
		{"sibling prefix extract", mod("cli/internal/extractor/x.go"), ClassNotApplicable},
		{"sibling prefix knowledge", mod("cli/knowledgebase/x"), ClassNotApplicable},
		{"trust plus recipe", mod(rd+"recipe.json", ".github/workflows/verify-pr.yml"), ClassTrustPathChange},
		{"recipe plus trust, trust first", mod(".github/CODEOWNERS", rd+"recipe.json", tgt), ClassTrustPathChange},
		{"target plus extract go", mod(tgt, "cli/internal/extract/x.go"), ClassTrustPathChange},
		{"trust plus docs", mod("README.md", "cli/internal/maintainer/targetdraft/x.go"), ClassTrustPathChange},
		{"recipe plus docs", mod(rd+"recipe.json", "README.md"), ClassMixedChange},
		{"target plus docs", mod(tgt, "docs/x.md"), ClassMixedChange},
		{"delete workflow", raw(rec{"D", []string{".github/workflows/verify-pr.yml"}}), ClassTrustPathChange},
		{"delete recipe", raw(rec{"D", []string{rd + "recipe.json"}}), ClassApplicable},
		{"add trust", raw(rec{"A", []string{"cli/internal/maintainer/targetdraft/new.go"}}), ClassTrustPathChange},
		{"type change trust", raw(rec{"T", []string{"cli/internal/extract/x.go"}}), ClassTrustPathChange},
		{"rename doc into trust", raw(rec{"R100", []string{"docs/a.md", ".github/workflows/x.yml"}}), ClassTrustPathChange},
		{"rename trust out to doc", raw(rec{"R100", []string{".github/workflows/x.yml", "docs/a.md"}}), ClassTrustPathChange},
		{"rename recipe to doc", raw(rec{"R090", []string{rd + "recipe.json", "docs/a.md"}}), ClassMixedChange},
		{"rename doc to recipe", raw(rec{"R090", []string{"docs/a.md", rd + "recipe.json"}}), ClassMixedChange},
		{"rename inside recipes", raw(rec{"R100", []string{rd + "recipe.json", "cli/knowledge/target-recipes/b/recipe.json"}}), ClassApplicable},
		{"copy into trust", raw(rec{"C75", []string{"docs/a.md", "cli/internal/extract/c.go"}}), ClassTrustPathChange},
		{"rename docs only", raw(rec{"R100", []string{"docs/a.md", "docs/b.md"}}), ClassNotApplicable},
		{"mode change on doc", []byte(":100644 100755 " + someOID + " " + someOID + " M\x00README.md\x00"), ClassNotApplicable},
		{"mode change on workflow", []byte(":100644 100755 " + someOID + " " + someOID + " M\x00.github/workflows/a.yml\x00"), ClassTrustPathChange},
		{"duplicates", mod("README.md", "README.md", "README.md"), ClassNotApplicable},
		{"duplicate trust", mod("README.md", "cli/internal/extract/x.go", "cli/internal/extract/x.go"), ClassTrustPathChange},
		// Case variants: git is case sensitive, these are different paths on
		// Linux, but any path that folds onto a trust name is judged as trust.
		{"case knowledge", mod("cli/Knowledge/x.json"), ClassTrustPathChange},
		{"case github", mod(".GitHub/workflows/x.yml"), ClassTrustPathChange},
		{"case workflows", mod(".github/Workflows/x.yml"), ClassTrustPathChange},
		{"case codeowners", mod(".github/codeowners"), ClassTrustPathChange},
		{"case targetdraft", mod("CLI/internal/maintainer/TargetDraft/x.go"), ClassTrustPathChange},
		{"case recipes under knowledge", mod("cli/knowledge/Target-Recipes/a/recipe.json"), ClassTrustPathChange},
		{"case recipe root cli", mod("Cli/knowledge/target-recipes/a/recipe.json"), ClassTrustPathChange},
		{"case crdversions", mod("cli/internal/extract/CRDVersions/target-a.json"), ClassTrustPathChange},
		{"case target prefix", mod("cli/internal/extract/crdversions/Target-a.json"), ClassTrustPathChange},
		{"case only docs dir", mod("Docs/x.md"), ClassNotApplicable},
		// Unicode: simple folds onto ASCII are trust; other look-alikes are
		// different names, never a trust path and never applicable.
		{"kelvin sign", mod("cli/\u212Anowledge/x.json"), ClassTrustPathChange},
		{"long s folds", mod(".github/workflow\u017F/x.yml"), ClassTrustPathChange},
		{"long s inside", mod(".github/work\u017Flows/x.yml"), ClassNotApplicable},
		{"cyrillic a", mod(".github/workfl\u043Ews/x.yml"), ClassNotApplicable},
		{"cyrillic i in trust dir", mod("cl\u0456/knowledge/x"), ClassNotApplicable},
		{"fullwidth slash", mod(".github\uFF0Fworkflows/x.yml"), ClassNotApplicable},
		{"non ascii recipe slug", mod("cli/knowledge/target-recipes/\u00E9/recipe.json"), ClassApplicable},
		// Refused paths are trust.
		{"absolute", mod("/etc/passwd"), ClassTrustPathChange},
		{"dotdot", mod("docs/../.github/workflows/x.yml"), ClassTrustPathChange},
		{"dotdot only", mod(".."), ClassTrustPathChange},
		{"dot segment", mod("./README.md"), ClassTrustPathChange},
		{"leading dotdot", mod("../x"), ClassTrustPathChange},
		{"backslash", mod(`.github\workflows\x.yml`), ClassTrustPathChange},
		{"newline", mod("docs/a\nb.md"), ClassTrustPathChange},
		{"tab", mod("docs/a\tb.md"), ClassTrustPathChange},
		{"del", mod("docs/a\x7fb.md"), ClassTrustPathChange},
		{"trailing slash", mod(".github/workflows/"), ClassTrustPathChange},
		{"trailing slash docs", mod("docs/"), ClassTrustPathChange},
		{"double slash", mod("docs//a.md"), ClassTrustPathChange},
		{"invalid utf8", mod("docs/\xff.md"), ClassTrustPathChange},
		{"empty path", mod(""), ClassTrustPathChange},
		{"refused plus recipe", mod(rd+"recipe.json", "a//b"), ClassTrustPathChange},
		// ERROR, never NOT_APPLICABLE.
		{"empty list", nil, ClassError},
		{"empty slice", []byte{}, ClassError},
		{"garbage", []byte("README.md\x00"), ClassError},
		{"no terminator", []byte(":100644 100644 " + someOID + " " + someOID + " M"), ClassError},
		{"missing path", []byte(":100644 100644 " + someOID + " " + someOID + " M\x00"), ClassError},
		{"rename with one path", []byte(":100644 100644 " + someOID + " " + someOID + " R100\x00a.md\x00"), ClassError},
		{"short oid", []byte(":100644 100644 abc " + someOID + " M\x00a.md\x00"), ClassError},
		{"upper oid", []byte(":100644 100644 " + strings.ToUpper("abcdef0123456789abcdef0123456789abcdef01") + " " + someOID + " M\x00a.md\x00"), ClassError},
		{"extra field", []byte(":100644 100644 " + someOID + " " + someOID + " M x\x00a.md\x00"), ClassError},
		{"no colon", []byte("100644 100644 " + someOID + " " + someOID + " M\x00a.md\x00"), ClassError},
		{"trailing junk", append(mod("README.md"), 'x'), ClassError},
	}
	for _, c := range cases {
		got := ClassifyChanged(c.in)
		if got.Class != c.want {
			t.Errorf("%s: got %s (%+v), want %s", c.name, got.Class, got, c.want)
		}
	}
}

func TestClassifyBounds(t *testing.T) {
	var rs []rec
	for i := 0; i < maxClassifyPaths; i++ {
		rs = append(rs, rec{"M", []string{fmt.Sprintf("docs/f%d.md", i)}})
	}
	if got := ClassifyChanged(raw(rs...)); got.Class != ClassNotApplicable {
		t.Fatalf("at the bound: %s", got.Class)
	}
	rs = append(rs, rec{"M", []string{".github/workflows/x.yml"}})
	if got := ClassifyChanged(raw(rs...)); got.Class != ClassError {
		t.Fatalf("over the bound must be an error, got %s", got.Class)
	}
	// A list hiding a trust path after a huge prefix of other paths is never green.
	big := ClassifyChanged(append(raw(rec{"M", []string{"docs/a.md"}}), bytes.Repeat([]byte("x"), maxChangedList)...))
	if big.Class != ClassError {
		t.Fatalf("over the byte bound: %s", big.Class)
	}
	// Many duplicates stay within the record bound and count once.
	var dup []rec
	for i := 0; i < 5000; i++ {
		dup = append(dup, rec{"M", []string{"docs/same.md"}})
	}
	if got := ClassifyChanged(raw(dup...)); got.Class != ClassNotApplicable || got.Paths != 1 {
		t.Fatalf("duplicates: %+v", got)
	}
}

// A record line with 64-hex object ids (sha256 repositories) is accepted.
func TestClassifyAcceptsLongObjectIDs(t *testing.T) {
	oid := strings.Repeat("a", 64)
	in := []byte(":100644 100644 " + oid + " " + oid + " M\x00README.md\x00")
	if got := ClassifyChanged(in); got.Class != ClassNotApplicable {
		t.Fatalf("got %s", got.Class)
	}
}

func TestClassifyCounts(t *testing.T) {
	got := ClassifyChanged(mod("README.md", "cli/knowledge/target-recipes/a/recipe.json", "x//y", "cli/internal/extract/x.go"))
	if got.Class != ClassTrustPathChange || got.Paths != 4 || got.Trust != 2 || got.Refused != 1 || got.Data != 1 || got.Other != 1 {
		t.Fatalf("%+v", got)
	}
}

// Every real target and recipe directory in the tree is a data path: the
// classifier must not turn the ordinary data PR into a trust change.
func TestClassifyRealTargetsAreData(t *testing.T) {
	names, err := filepath.Glob("../../extract/crdversions/target-*.json")
	if err != nil || len(names) == 0 {
		t.Skip("repository checkout not present")
	}
	for _, n := range names {
		p := "cli/internal/extract/crdversions/" + filepath.Base(n)
		if classifyPath(p) != kindData {
			t.Errorf("%s is not classified as a data path", p)
		}
	}
	if _, err := os.Stat("../../../knowledge/target-recipes"); err == nil {
		if classifyPath("cli/knowledge/target-recipes/x/recipe.json") != kindData {
			t.Error("recipe path is not data")
		}
	}
}

// Mutation killers for the individual rules, each against the single path
// that only that rule decides.
func TestClassifyEachTrustDirIsRequired(t *testing.T) {
	for _, d := range trustPathDirs {
		if got := ClassifyChanged(mod(d + "/zz-file")); got.Class != ClassTrustPathChange {
			t.Errorf("%s: %s", d, got.Class)
		}
		if got := ClassifyChanged(mod(strings.ToUpper(d) + "/zz-file")); got.Class != ClassTrustPathChange {
			t.Errorf("upper %s: %s", d, got.Class)
		}
		if got := ClassifyChanged(mod(d + "x/zz-file")); got.Class == ClassTrustPathChange {
			t.Errorf("%sx: a sibling name is not the trust path", d)
		}
	}
	want := map[string]bool{
		".github/workflows": true, ".github/CODEOWNERS": true,
		"cli/internal/maintainer/targetdraft": true, "cli/internal/maintainer/knowledgegate": true,
		"cli/internal/maintainer/verifyprworkflow": true, "cli/internal/extract": true,
		"cli/knowledge": true, "cli/cmd/prufyx-maintainer": true,
	}
	if len(trustPathDirs) != len(want) {
		t.Fatalf("trust path list changed: %v", trustPathDirs)
	}
	for _, d := range trustPathDirs {
		if !want[d] {
			t.Errorf("unexpected trust path %s", d)
		}
	}
}

func TestClassifyPathKinds(t *testing.T) {
	cases := []struct {
		p    string
		want pathKind
	}{
		{"cli/knowledge/target-recipes/a/recipe.json", kindData},
		{"cli/knowledge/target-recipes/", kindRefused},
		{"cli/knowledge/target-recipes/a", kindData},
		{"cli/internal/extract/crdversions/target-a-b.json", kindData},
		{"cli/internal/extract/crdversions/target-a--b.json", kindTrust},
		{"cli/internal/extract/crdversions/target-a.json.bak", kindTrust},
		{"cli/internal/extract/crdversions/sub/target-a.json", kindTrust},
		{"docs/x.md", kindOther},
		{"a\\b", kindRefused},
		{"/a", kindRefused},
		{"a/../b", kindRefused},
	}
	for _, c := range cases {
		if got := classifyPath(c.p); got != c.want {
			t.Errorf("%q: got %d want %d", c.p, got, c.want)
		}
	}
}

func writeList(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "changed.raw")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunClassifyPR(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		c := runClassifyPR(args, &o, &e)
		return c, o.String(), e.String()
	}
	cases := []struct {
		name string
		in   []byte
		code int
		line string
	}{
		{"trust", mod(".github/workflows/verify-pr.yml"), 0, "class: TRUST_PATH_CHANGE\n"},
		{"applicable", mod("cli/knowledge/target-recipes/a/recipe.json"), 0, "class: APPLICABLE\n"},
		{"not applicable", mod("README.md"), 0, "class: NOT_APPLICABLE\n"},
		{"mixed", mod("README.md", "cli/knowledge/target-recipes/a/recipe.json"), 0, "class: MIXED_CHANGE\n"},
		{"empty", []byte{}, 2, "class: ERROR\n"},
		{"garbage", []byte("x"), 2, "class: ERROR\n"},
	}
	for _, c := range cases {
		code, out, _ := run("--changed-paths", writeList(t, c.in), "--json")
		if code != c.code || !strings.HasPrefix(out, c.line) {
			t.Errorf("%s: code %d out %q", c.name, code, out)
		}
		if strings.Count(out, "\nclass: ")+btoi(strings.HasPrefix(out, "class: ")) != 1 {
			t.Errorf("%s: not exactly one class line: %q", c.name, out)
		}
		if c.code == 0 && !strings.Contains(out, `classify-json: {"schema":"prufyx.io/verify-pr-classify/v1","class":"`+strings.TrimSuffix(strings.TrimPrefix(c.line, "class: "), "\n")+`"`) {
			t.Errorf("%s: json line missing: %q", c.name, out)
		}
	}
	// A file name never starts a line of its own in the output.
	_, out, _ := run("--changed-paths", writeList(t, mod("docs/a\nclass: NOT_APPLICABLE\n")), "--json")
	if strings.Count(out, "class: NOT_APPLICABLE") != 0 || !strings.HasPrefix(out, "class: TRUST_PATH_CHANGE\n") {
		t.Errorf("injection: %q", out)
	}
	if code, out, _ := run("--changed-paths", filepath.Join(t.TempDir(), "missing")); code != 2 || !strings.HasPrefix(out, "class: ERROR\n") {
		t.Errorf("missing file: %d %q", code, out)
	}
	for _, args := range [][]string{nil, {"--changed-paths"}, {"--changed-paths", "x", "extra"}, {"--bogus"}} {
		if code, out, _ := run(args...); code != 2 || strings.Contains(out, "class: NOT_APPLICABLE") || strings.Contains(out, "class: APPLICABLE") {
			t.Errorf("usage %v: %d %q", args, code, out)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestClassifyPRIsWiredIntoTheCommand(t *testing.T) {
	var o, e bytes.Buffer
	code := Run([]string{"classify-pr", "--changed-paths", writeList(t, mod("README.md"))}, &o, &e)
	if code != 0 || !strings.HasPrefix(o.String(), "class: NOT_APPLICABLE\n") {
		t.Fatalf("%d %q %q", code, o.String(), e.String())
	}
}
