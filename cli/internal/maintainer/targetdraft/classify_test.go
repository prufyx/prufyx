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

func withModes(oldMode, newMode, status string, paths ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, ":%s %s %s %s %s\x00", oldMode, newMode, someOID, someOID, status)
	for _, p := range paths {
		b.WriteString(p)
		b.WriteByte(0)
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
		{"docs only", mod("docs/a/b.md", "changelog.d/x.md", "README-extra.md"), ClassNotApplicable},
		{"site is not allowlisted", mod("site/index.html"), ClassTrustPathChange},
		{"other cli", mod("cli/internal/other/x.go"), ClassTrustPathChange},
		{"workflow", mod(".github/workflows/verify-pr.yml"), ClassTrustPathChange},
		{"other workflow", mod(".github/workflows/x.yml"), ClassTrustPathChange},
		{"codeowners", mod(".github/CODEOWNERS"), ClassTrustPathChange},
		{"dependabot", mod(".github/dependabot.yml"), ClassTrustPathChange},
		{"github actions dir", mod(".github/actions/x/action.yml"), ClassTrustPathChange},
		{"github any file", mod(".github/PULL_REQUEST_TEMPLATE.md"), ClassTrustPathChange},
		{"scripts", mod("scripts/x.sh"), ClassTrustPathChange},
		{"scripts merge policy", mod("scripts/merge-policy-check.sh"), ClassTrustPathChange},
		{"go mod", mod("cli/go.mod"), ClassTrustPathChange},
		{"go sum", mod("cli/go.sum"), ClassTrustPathChange},
		{"vendor", mod("cli/vendor/x/y.go"), ClassTrustPathChange},
		{"maintainer mergepolicy", mod("cli/internal/maintainer/mergepolicy/x.go"), ClassTrustPathChange},
		{"maintainer releasesign", mod("cli/internal/maintainer/releasesign/x.go"), ClassTrustPathChange},
		{"other cmd", mod("cli/cmd/other/x.go"), ClassTrustPathChange},
		{"makefile", mod("Makefile"), ClassTrustPathChange},
		{"cli makefile", mod("cli/Makefile"), ClassTrustPathChange},
		{"tools", mod("tools/x"), ClassTrustPathChange},
		{"root codeowners", mod("CODEOWNERS"), ClassTrustPathChange},
		{"docs codeowners", mod("docs/CODEOWNERS"), ClassTrustPathChange},
		{"docs codeowners md", mod("docs/codeowners/x.md"), ClassTrustPathChange},
		{"action yml", mod("action.yml"), ClassTrustPathChange},
		{"root license", mod("LICENSE"), ClassTrustPathChange},
		{"root gitignore", mod(".gitignore"), ClassTrustPathChange},
		{"cli docs json", mod("cli/docs/data/selected-source-records-v1.json"), ClassTrustPathChange},
		{"cli docs md", mod("cli/docs/x.md"), ClassTrustPathChange},
		{"docs non markdown", mod("docs/x.json"), ClassTrustPathChange},
		{"docs script", mod("docs/run.sh"), ClassTrustPathChange},
		{"changelog.d non markdown", mod("changelog.d/x.json"), ClassTrustPathChange},
		{"readme in subdir", mod("cli/README.md"), ClassTrustPathChange},
		{"readme not markdown", mod("README.txt"), ClassTrustPathChange},
		{"root changelog", mod("CHANGELOG.md"), ClassTrustPathChange},
		{"windows trailing dot", mod(".github/workflows./x.yml"), ClassTrustPathChange},
		{"windows short name", mod("GITHUB~1/WORKFL~1/x.yml"), ClassTrustPathChange},
		{"windows ads", mod(".github/workflows/x.yml::$DATA"), ClassTrustPathChange},
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
		{"sibling prefix is not allowlisted", mod("cli/cmd/prufyx-maintainer-x/main.go"), ClassTrustPathChange},
		{"sibling prefix extract", mod("cli/internal/extractor/x.go"), ClassTrustPathChange},
		{"sibling prefix knowledge", mod("cli/knowledgebase/x"), ClassTrustPathChange},
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
		{"executable doc", withModes("100644", "100755", "M", "README.md"), ClassTrustPathChange},
		{"new executable doc", withModes("000000", "100755", "A", "docs/x.md"), ClassTrustPathChange},
		{"symlink README", withModes("000000", "120000", "A", "README.md"), ClassTrustPathChange},
		{"symlink docs", withModes("000000", "120000", "A", "docs/x.md"), ClassTrustPathChange},
		{"symlink changelog.d", withModes("000000", "120000", "A", "changelog.d/x.md"), ClassTrustPathChange},
		{"file replaced by symlink", withModes("100644", "120000", "T", "docs/x.md"), ClassTrustPathChange},
		{"symlink replaced by file", withModes("120000", "100644", "T", "docs/x.md"), ClassTrustPathChange},
		{"deleted symlink doc", withModes("120000", "000000", "D", "docs/x.md"), ClassTrustPathChange},
		{"gitlink README", withModes("000000", "160000", "A", "README.md"), ClassTrustPathChange},
		{"gitlink docs", withModes("160000", "160000", "M", "docs/x.md"), ClassTrustPathChange},
		{"tree mode", withModes("000000", "040000", "A", "docs/x.md"), ClassTrustPathChange},
		{"unknown mode", withModes("100644", "100664", "M", "docs/x.md"), ClassTrustPathChange},
		{"both modes zero", withModes("000000", "000000", "M", "docs/x.md"), ClassTrustPathChange},
		{"added plain doc", withModes("000000", "100644", "A", "README.md"), ClassNotApplicable},
		{"deleted plain doc", withModes("100644", "000000", "D", "docs/x.md"), ClassNotApplicable},
		{"rename of executable doc", withModes("100755", "100755", "R100", "docs/a.md", "docs/b.md"), ClassTrustPathChange},
		{"rename of symlink doc", withModes("120000", "120000", "R100", "docs/a.md", "docs/b.md"), ClassTrustPathChange},
		{"symlink doc beside plain doc", append(mod("README.md"), withModes("000000", "120000", "A", "docs/x.md")...), ClassTrustPathChange},
		{"same doc plain then symlink", append(mod("docs/x.md"), withModes("000000", "120000", "A", "docs/x.md")...), ClassTrustPathChange},
		{"same doc symlink then plain", append(withModes("000000", "120000", "A", "docs/x.md"), mod("docs/x.md")...), ClassTrustPathChange},
		{"symlink recipe is judged by the verify step", withModes("000000", "120000", "A", "cli/knowledge/target-recipes/a/recipe.json"), ClassApplicable},
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
		{"case docs dir", mod("Docs/x.md"), ClassTrustPathChange},
		{"case readme", mod("readme.md"), ClassTrustPathChange},
		{"case readme ext", mod("README.MD"), ClassTrustPathChange},
		{"case docs ext", mod("docs/x.MD"), ClassTrustPathChange},
		{"case changelog.d", mod("Changelog.d/x.md"), ClassTrustPathChange},
		{"case recipe dir inside allowlist neighbour", mod("docs/x.md", "CLI/knowledge/target-recipes/a/recipe.json"), ClassTrustPathChange},
		// Unicode: simple folds onto ASCII are trust; other look-alikes are
		// different names, never a trust path and never applicable.
		{"kelvin sign", mod("cli/\u212Anowledge/x.json"), ClassTrustPathChange},
		{"long s folds", mod(".github/workflow\u017F/x.yml"), ClassTrustPathChange},
		{"long s inside", mod(".github/work\u017Flows/x.yml"), ClassTrustPathChange},
		{"cyrillic a", mod(".github/workfl\u043Ews/x.yml"), ClassTrustPathChange},
		{"cyrillic readme", mod("READM\u0415.md"), ClassTrustPathChange},
		{"cyrillic docs", mod("d\u043Ecs/x.md"), ClassTrustPathChange},
		{"cyrillic i in trust dir", mod("cl\u0456/knowledge/x"), ClassTrustPathChange},
		{"fullwidth slash", mod(".github\uFF0Fworkflows/x.yml"), ClassTrustPathChange},
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

// Default deny: the allowlist is exactly these shapes, nothing wider.
func TestClassifyAllowlistIsExact(t *testing.T) {
	yes := []string{"README.md", "README-extra.md", "docs/a.md", "docs/a/b/c.md", "changelog.d/a.md", "changelog.d/a/b.md"}
	no := []string{
		"README", "README.txt", "readme.md", "Readme.md", "x/README.md", "docs.md", "docs", "docs/a.txt", "docs/a.md/b",
		"docs/CODEOWNERS", "docs/codeowners", "docs/sub/CODEOWNERS", "docs/CODEOWNERS/x.md", "CODEOWNERS",
		"changelog.d/a.yml", "Changelog.d/a.md", "changelog/a.md", "cli/docs/a.md", "site/a.md", "examples/a.md",
		"contrib/a.md", "testdata/a.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "action.yml",
	}
	for _, p := range yes {
		if !isDocsPath(p) || classifyPath(p) != kindDocs {
			t.Errorf("%q must be allowlisted", p)
		}
	}
	for _, p := range no {
		if isDocsPath(p) || classifyPath(p) != kindTrust {
			t.Errorf("%q must not be allowlisted", p)
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
		{"docs/x.md", kindDocs},
		{"scripts/x.sh", kindTrust},
		{"cli/go.mod", kindTrust},
		{"Docs/x.md", kindTrust},
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
