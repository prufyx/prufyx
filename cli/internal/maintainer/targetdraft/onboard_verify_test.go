// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/pathset"
)

const (
	onbTable   = "cli/data/table.json"
	onbBatch   = "cli/onboarding/b1.json"
	onbOut     = "cli/docs/out.json"
	onbOpt     = "cli/docs/opt.json"
	onbTrustD  = "cli/knowledge/trust/"
	onbBaseSHA = "2222222222222222222222222222222222222222"
	onbHeadSHA = "1111111111111111111111111111111111111111"
	zeros40    = "0000000000000000000000000000000000000000"
)

type onbRec struct{ path, status, old, new string }

type onbFx struct {
	t        *testing.T
	f        *fixture
	fxs      map[string]*fixture
	head     *memTree
	base     *memTree
	recs     []onbRec
	slugs    []string
	policy   OnboardingPolicy
	raw      []byte
	headTree Tree
	baseTree Tree
	runner   *fakeRunner
	noRunner bool
	env      verifyEnv
	baseSHA  string
	headSHA  string
}

func (x *onbFx) put(p string, headB, baseB []byte) {
	x.head.files[p] = headB
	r := onbRec{path: p, status: "A", old: zeros40, new: gitBlobSHA(headB)}
	if baseB != nil {
		x.base.files[p] = baseB
		r.status, r.old = "M", gitBlobSHA(baseB)
	}
	x.recs = append(x.recs, r)
}

func (x *onbFx) idx(p string) int {
	for i, r := range x.recs {
		if r.path == p {
			return i
		}
	}
	x.t.Fatalf("no record for %s", p)
	return -1
}

// setHead changes a head file and keeps the diff record consistent.
func (x *onbFx) setHead(p string, b []byte) {
	x.head.files[p] = b
	x.recs[x.idx(p)].new = gitBlobSHA(b)
}

// setBase changes a base file and keeps the diff record consistent.
func (x *onbFx) setBase(p string, b []byte) {
	x.base.files[p] = b
	x.recs[x.idx(p)].old = gitBlobSHA(b)
}

func (x *onbFx) drop(p string) {
	i := x.idx(p)
	x.recs = append(x.recs[:i:i], x.recs[i+1:]...)
	delete(x.head.files, p)
	delete(x.base.files, p)
}

func (x *onbFx) setRecipe(mutate func(*Recipe)) {
	mutate(&x.f.recipe)
	x.setHead(fxDir+"recipe.json", x.f.recipeBytes())
}

func onbRaw(recs []onbRec) []byte {
	var b bytes.Buffer
	for _, r := range recs {
		om := "100644"
		if r.status == "A" {
			om = "000000"
		}
		fmt.Fprintf(&b, ":%s 100644 %s %s %s\x00%s\x00", om, r.old, r.new, r.status, r.path)
	}
	return b.Bytes()
}

func rawRecord(oldMode, newMode, status, path string) string {
	return fmt.Sprintf(":%s %s %s %s %s\x00%s\x00", oldMode, newMode, zeros40, strings.Repeat("1", 40), status, path)
}

func tableDoc(slugs ...string) []byte {
	var parts []string
	for _, s := range slugs {
		parts = append(parts, `{"slug":"`+s+`"}`)
	}
	return []byte(`{"projects":[` + strings.Join(parts, ",") + `]}`)
}

// buildSlugFixture is newFixture for any slug (same recorded bundle, the
// generator input renamed).
func buildSlugFixture(t *testing.T, slug string) *fixture {
	t.Helper()
	name := strings.ToUpper(slug[:1]) + slug[1:]
	mk := func(s Source) Input {
		in := collapseInputFor(s, true)
		in.Slug, in.Name, in.Repo = slug, name, "github.com/example/"+slug
		return in
	}
	raw, _ := recordBundle(t, collapseSource(nil), mk)
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, mk(FactSource{B: b}))
	rep, _ := marshal(res.Report)
	f := &fixture{t: t, bundle: raw, env: defaultVerifyEnv(), base: map[string][]byte{}, files: map[string][]byte{
		"facts.bundle": raw, "target-" + slug + ".json": res.A, "report.json": rep, "table-row.json": res.TableRow, "changelog.md": res.Changelog,
	}}
	f.recipe = Recipe{Schema: RecipeSchema, Slug: slug, Name: name, Repo: "github.com/example/" + slug, Catalog: "cncf",
		Tags: collapseTags, RangeCheckTags: []string{}, CollapseDirectories: true, Half: "A", Exclude: []string{},
		FactBundleDigest: sha256Of(raw)}
	for _, tag := range b.Tags() {
		c, _ := b.Commit(tag)
		f.recipe.Commits = append(f.recipe.Commits, recipeCommit{Tag: tag, Commit: c})
	}
	f.files["recipe.json"] = f.recipeBytes()
	return f
}

func newOnbFx(t *testing.T) *onbFx { return newOnbFxSlugs(t, "demo") }

func newOnbFxSlugs(t *testing.T, slugs ...string) *onbFx {
	t.Helper()
	x := &onbFx{t: t, head: newMemTree(), base: newMemTree(), slugs: slugs, env: defaultVerifyEnv(), baseSHA: onbBaseSHA, headSHA: onbHeadSHA, fxs: map[string]*fixture{}}
	headRows := []string{"other"}
	for _, s := range slugs {
		f := buildSlugFixture(t, s)
		x.fxs[s] = f
		if x.f == nil {
			x.f = f
		}
		for n, b := range f.files {
			p := RecipesRoot + s + "/" + n
			if n == "target-"+s+".json" {
				p = realTargetPath(s)
			}
			x.put(p, b, nil)
		}
		headRows = append(headRows, s)
	}
	x.put(onbTable, tableDoc(headRows...), tableDoc("other"))
	x.put(onbBatch, []byte(`{"batch":"b1"}`), nil)
	x.put(onbOut, []byte(`{"out":2}`), []byte(`{"out":1}`))
	// Unchanged base content the absence check must read past.
	for _, m := range []*memTree{x.base, x.head} {
		m.files[RecipesRoot+"other/recipe.json"] = []byte("{}")
		m.files[CrdVersionsDir+"/target-other.json"] = []byte(`{"target":{"project":"other"}}`)
		m.files["cli/README.md"] = []byte("readme")
	}
	x.policy = OnboardingPolicy{BatchPath: onbBatch, TablePath: onbTable, Required: []string{onbOut}, Optional: []string{onbOpt}, TrustPaths: []string{onbTrustD}}
	var out []string
	for _, c := range x.f.recipe.Commits {
		out = append(out, c.Commit+"\trefs/tags/"+c.Tag)
	}
	x.runner = &fakeRunner{results: []ExecResult{okRun(lsOut(out...))}}
	return x
}

func (x *onbFx) setRecipeOf(slug string, mutate func(*Recipe)) {
	f := x.fxs[slug]
	mutate(&f.recipe)
	x.setHead(RecipesRoot+slug+"/recipe.json", f.recipeBytes())
}

func (x *onbFx) run() OnboardingVerifyResult {
	x.t.Helper()
	raw := x.raw
	if raw == nil {
		raw = onbRaw(x.recs)
	}
	var ht, bt Tree = x.head, x.base
	if x.headTree != nil {
		ht = x.headTree
	}
	if x.baseTree != nil {
		bt = x.baseTree
	}
	in := OnboardingVerifyInput{Base: bt, Head: ht, ChangedRaw: raw, Slugs: x.slugs, Policy: x.policy,
		BaseSHA: x.baseSHA, HeadSHA: x.headSHA, Sleep: func(time.Duration) {}}
	if !x.noRunner {
		in.Upstream = x.runner
	}
	return verifyOnboarding(in, x.env)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// wantRefusal asserts a fail-closed result: outcome fail, the exact reason
// set, nothing positive in the result, and the network never reached unless
// netCalls says it was.
func (x *onbFx) wantRefusal(res OnboardingVerifyResult, netCalls int, reasons ...string) {
	x.t.Helper()
	sort.Strings(reasons)
	if res.Outcome != "fail" || !reflect.DeepEqual(res.Reasons, reasons) {
		x.t.Fatalf("outcome %s reasons %v (%v), want fail %v", res.Outcome, res.Reasons, res.Details, reasons)
	}
	if res.Mode != OnboardingVerifyMode {
		x.t.Fatalf("mode %q", res.Mode)
	}
	if res.BindingVerified || res.RecipeChange != "" || res.Eligible || res.ChangedPathsSHA256 != "" || res.JudgedPathsSHA256 != "" ||
		res.Slugs != nil || res.BindingDigest != "" || res.TagsCommitsSHA != nil {
		x.t.Fatalf("a failure carries positive data: %+v", res)
	}
	if got := len(x.runner.calls); got != netCalls {
		x.t.Fatalf("%d upstream runs, want %d", got, netCalls)
	}
}

func shaOf(paths []string) string {
	p := append([]string(nil), paths...)
	sort.Strings(p)
	s := sha256.Sum256([]byte(strings.Join(p, "\n")))
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestVerifyOnboardingPositiveFullFixture(t *testing.T) {
	x := newOnbFx(t)
	res := x.run()
	if res.Outcome != "pass" || len(res.Reasons) != 0 || res.Reasons == nil || res.Harness || len(res.Details) != 0 {
		t.Fatalf("%+v", res)
	}
	if res.Mode != "inprocess" || res.BaseSHA != onbBaseSHA || res.HeadSHA != onbHeadSHA {
		t.Fatalf("%+v", res)
	}
	if !res.BindingVerified || res.RecipeChange != "new" || res.Eligible {
		t.Fatalf("%+v", res)
	}
	if !reflect.DeepEqual(res.Slugs, []string{"demo"}) {
		t.Fatalf("slugs %v", res.Slugs)
	}
	var all, judged []string
	for _, r := range x.recs {
		all = append(all, r.path)
		if strings.HasPrefix(r.path, RecipesRoot+"demo/") || r.path == realDemo {
			judged = append(judged, r.path)
		}
	}
	if len(all) != 9 || len(judged) != 6 {
		t.Fatalf("fixture shape %d %d", len(all), len(judged))
	}
	want, err := pathset.Digest(all)
	if err != nil || res.ChangedPathsSHA256 != want || res.ChangedPathsSHA256 != shaOf(all) {
		t.Fatalf("changed digest %s, want %s (%v)", res.ChangedPathsSHA256, want, err)
	}
	wj, err := pathset.Digest(judged)
	if err != nil || res.JudgedPathsSHA256 != wj || res.JudgedPathsSHA256 != shaOf(judged) {
		t.Fatalf("judged digest %s, want %s (%v)", res.JudgedPathsSHA256, wj, err)
	}
	if res.ChangedPathsSHA256 == res.JudgedPathsSHA256 {
		t.Fatal("the full and the judged digest must differ: the table, batch and output are not judged here")
	}
	// The binding digest is bound to the repo, the tags and the commits.
	var tags []BindingTag
	var tc strings.Builder
	tc.WriteString("prufyx.io/onboarding-tags-commits/v1\n")
	cm := append([]recipeCommit(nil), x.f.recipe.Commits...)
	sort.Slice(cm, func(i, j int) bool { return cm[i].Tag < cm[j].Tag })
	for _, c := range cm {
		tags = append(tags, BindingTag{Tag: c.Tag, Commit: c.Commit})
		tc.WriteString(c.Tag + "\t" + c.Commit + "\n")
	}
	sum := sha256.Sum256([]byte("prufyx.io/onboarding-binding/v1\ndemo\t" + bindingDigest("github.com/example/demo", tags) + "\n"))
	if res.BindingDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("binding digest %s", res.BindingDigest)
	}
	tsum := sha256.Sum256([]byte(tc.String()))
	if res.TagsCommitsSHA["demo"] != "sha256:"+hex.EncodeToString(tsum[:]) || len(res.TagsCommitsSHA) != 1 {
		t.Fatalf("%v", res.TagsCommitsSHA)
	}
	if len(x.runner.calls) != 1 {
		t.Fatalf("%d upstream runs", len(x.runner.calls))
	}
	// The one upstream child is the fixed binding command.
	call := x.runner.calls[0]
	if call.Argv[0] != "git" || !contains(call.Argv, "https://github.com/example/demo.git") || strings.Join(call.Env, "|") != strings.Join(bindingEnv(), "|") {
		t.Fatalf("%q %q", call.Argv, call.Env)
	}
}

// The result is the same for any order of the raw records and the slug list,
// and for repeated runs; the optional static path may be present or not.
func TestVerifyOnboardingDeterministicAndOrderFree(t *testing.T) {
	x := newOnbFx(t)
	first := x.run()
	for i := 0; i < 3; i++ {
		if again := x.run(); !reflect.DeepEqual(first, again) {
			t.Fatalf("not deterministic:\n%+v\n%+v", first, again)
		}
	}
	y := newOnbFx(t)
	for i, j := 0, len(y.recs)-1; i < j; i, j = i+1, j-1 {
		y.recs[i], y.recs[j] = y.recs[j], y.recs[i]
	}
	if got := y.run(); !reflect.DeepEqual(first, got) {
		t.Fatalf("record order changed the result:\n%+v\n%+v", first, got)
	}
	z := newOnbFx(t)
	z.put(onbOpt, []byte("o"), nil)
	got := z.run()
	if got.Outcome != "pass" || got.ChangedPathsSHA256 == first.ChangedPathsSHA256 || got.JudgedPathsSHA256 != first.JudgedPathsSHA256 {
		t.Fatalf("an optional path moves the full digest only: %+v", got)
	}
}

func TestVerifyOnboardingBasePresenceConjuncts(t *testing.T) {
	cases := []struct {
		name string
		mut  func(x *onbFx)
	}{
		{"table row exact", func(x *onbFx) { x.setBase(onbTable, tableDoc("other", "demo")) }},
		{"table row case variant", func(x *onbFx) { x.setBase(onbTable, tableDoc("other", "DeMo")) }},
		{"target file exact", func(x *onbFx) { x.base.files[realDemo] = []byte(`{"target":{"project":"zzz"}}`) }},
		{"target file case variant", func(x *onbFx) {
			x.base.files[CrdVersionsDir+"/target-DEMO.json"] = []byte(`{"target":{"project":"zzz"}}`)
		}},
		{"target holds the project", func(x *onbFx) {
			x.base.files[CrdVersionsDir+"/target-other.json"] = []byte(`{"target":{"project":"Demo"}}`)
			x.head.files[CrdVersionsDir+"/target-other.json"] = []byte(`{"target":{"project":"Demo"}}`)
		}},
		{"recipe directory exact", func(x *onbFx) { x.base.files[fxDir+"changelog.md"] = []byte("old") }},
		{"recipe directory case variant", func(x *onbFx) { x.base.files[RecipesRoot+"Demo/recipe.json"] = []byte("{}") }},
		{"recipe entry named like the slug", func(x *onbFx) { x.base.files[RecipesRoot+"DEMO"] = []byte("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			c.mut(x)
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonBasePresent) {
				t.Fatalf("%+v", res)
			}
			if len(x.runner.calls) != 0 {
				t.Fatal("the network ran after a base-presence failure")
			}
		})
	}
	// Each conjunct is the only reason when the rest of the fixture is clean.
	x := newOnbFx(t)
	x.setBase(onbTable, tableDoc("other", "demo"))
	x.wantRefusal(x.run(), 0, OnbReasonBasePresent)
}

func TestVerifyOnboardingBaseAbsenceUnknownFailsClosed(t *testing.T) {
	for name, mut := range map[string]func(x *onbFx){
		"base table garbage": func(x *onbFx) { x.setBase(onbTable, []byte("not json")) },
		"base target garbage": func(x *onbFx) {
			x.base.files[CrdVersionsDir+"/target-other.json"] = []byte("not json")
		},
		"base table unreadable": func(x *onbFx) {
			x.baseTree = &failTree{memTree: x.base, failRead: onbTable}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newOnbFx(t)
			mut(x)
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonBaseUnknown) || !res.Harness {
				t.Fatalf("%+v", res)
			}
			if len(x.runner.calls) != 0 {
				t.Fatal("network ran")
			}
		})
	}
}

func TestVerifyOnboardingHeadTableRows(t *testing.T) {
	for name, rows := range map[string][]string{
		"no row":          {"other"},
		"duplicate row":   {"other", "demo", "demo"},
		"case variant":    {"other", "demo", "Demo"},
		"only case row":   {"other", "DEMO"},
		"empty row table": {},
	} {
		t.Run(name, func(t *testing.T) {
			x := newOnbFx(t)
			x.setHead(onbTable, tableDoc(rows...))
			x.wantRefusal(x.run(), 0, OnbReasonHeadTable)
		})
	}
	x := newOnbFx(t)
	x.setHead(onbTable, []byte("[1"))
	x.wantRefusal(x.run(), 0, OnbReasonHeadTable)
}

func TestVerifyOnboardingPathSetNegatives(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(x *onbFx)
		reason string
	}{
		{"outside the allowlist", func(x *onbFx) { x.put("cli/other/x.json", []byte("x"), nil) }, OnbReasonOutside},
		{"unknown recipe file", func(x *onbFx) { x.put(fxDir+"evil.sh", []byte("x"), nil) }, OnbReasonOutside},
		{"nested recipe file", func(x *onbFx) { x.put(fxDir+"sub/recipe.json", []byte("x"), nil) }, OnbReasonOutside},
		{"target of another slug", func(x *onbFx) { x.put(CrdVersionsDir+"/target-extra.json", []byte("x"), nil) }, OnbReasonSlugSet},
		{"recipe of another slug", func(x *onbFx) { x.put(RecipesRoot+"extra/recipe.json", []byte("x"), nil) }, OnbReasonSlugSet},
		{"other file of crdversions", func(x *onbFx) { x.put(CrdVersionsDir+"/extractor.go", []byte("x"), nil) }, OnbReasonOutside},
		{"trust directory", func(x *onbFx) { x.put(onbTrustD+"root.json", []byte("x"), nil) }, OnbReasonTrust},
		{"approval keys file anywhere", func(x *onbFx) { x.put("cli/x/Approval-Keys.json", []byte("x"), nil) }, OnbReasonTrust},
		{"trust root file anywhere", func(x *onbFx) { x.put("cli/x/trust-root.json", []byte("x"), nil) }, OnbReasonTrust},
		{"workflow", func(x *onbFx) { x.put(".github/workflows/x.yml", []byte("x"), nil) }, OnbReasonForbidden},
		{"upper case github dir", func(x *onbFx) { x.put(".GitHub/x", []byte("x"), nil) }, OnbReasonForbidden},
		{"codeowners", func(x *onbFx) { x.put("docs/CODEOWNERS", []byte("x"), nil) }, OnbReasonForbidden},
		{"dot segment", func(x *onbFx) { x.put("cli/a/../b.json", []byte("x"), nil) }, OnbReasonPathSet},
		{"backslash", func(x *onbFx) { x.put(`cli\b.json`, []byte("x"), nil) }, OnbReasonPathSet},
		{"carriage return", func(x *onbFx) { x.put("cli/b\r.json", []byte("x"), nil) }, OnbReasonPathSet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			c.mut(x)
			x.wantRefusal(x.run(), 0, c.reason)
		})
	}
}

func TestVerifyOnboardingRequiredPaths(t *testing.T) {
	var need []string
	for _, n := range recipeRequired {
		need = append(need, fxDir+n)
	}
	need = append(need, realDemo, onbBatch, onbTable, onbOut)
	for _, p := range need {
		t.Run(p, func(t *testing.T) {
			x := newOnbFx(t)
			x.drop(p)
			x.wantRefusal(x.run(), 0, OnbReasonRequired)
		})
	}
	// A second expected slug that the change does not carry.
	x := newOnbFx(t)
	x.slugs = []string{"demo", "extra"}
	res := x.run()
	if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRequired) || len(x.runner.calls) != 0 {
		t.Fatalf("%+v", res)
	}
	// The batch file must be ADDED.
	x = newOnbFx(t)
	x.drop(onbBatch)
	x.put(onbBatch, []byte("new"), []byte("old"))
	x.wantRefusal(x.run(), 0, "path-status")
}

func TestVerifyOnboardingRawDiffNegatives(t *testing.T) {
	x0 := newOnbFx(t)
	good := onbRaw(x0.recs)
	many := func(n int) []byte {
		var b bytes.Buffer
		for i := 0; i < n; i++ {
			b.WriteString(rawRecord("000000", "100644", "A", "cli/docs/f"+strconv.Itoa(i)+".json"))
		}
		return b.Bytes()
	}
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"empty", nil, "no-changes"},
		{"newline in a path", append(append([]byte(nil), good...), rawRecord("000000", "100644", "A", "cli/docs/a\nb.json")...), OnbReasonPathSet},
		{"NUL inside a path", append(append([]byte(nil), good...), []byte(":000000 100644 "+zeros40+" "+strings.Repeat("1", 40)+" A\x00cli/a\x00b\x00")...), "changed-list-malformed"},
		{"rename", append(append([]byte(nil), good...), rawRecord("100644", "100644", "R100", "cli/docs/new.json")...), "path-status"},
		{"copy", append(append([]byte(nil), good...), rawRecord("100644", "100644", "C100", "cli/docs/new.json")...), "path-status"},
		{"delete", append(append([]byte(nil), good...), rawRecord("100644", "000000", "D", "cli/docs/old.json")...), "path-status"},
		{"mode change to executable", append(append([]byte(nil), good...), rawRecord("100644", "100755", "M", "cli/docs/x.json")...), "path-status"},
		{"added executable", append(append([]byte(nil), good...), rawRecord("000000", "100755", "A", "cli/docs/x.json")...), "path-status"},
		{"symbolic link", append(append([]byte(nil), good...), rawRecord("000000", "120000", "A", "cli/docs/x.json")...), "path-status"},
		{"type change", append(append([]byte(nil), good...), rawRecord("100644", "120000", "T", "cli/docs/x.json")...), "path-status"},
		{"submodule", append(append([]byte(nil), good...), rawRecord("000000", "160000", "A", "cli/docs/x.json")...), "path-status"},
		{"two-path rename record", append(append([]byte(nil), good...), []byte(":100644 100644 "+zeros40+" "+strings.Repeat("1", 40)+" R100\x00cli/docs/old.json\x00cli/docs/new.json\x00")...), "path-status"},
		{"two-path copy record", append(append([]byte(nil), good...), []byte(":100644 100644 "+zeros40+" "+strings.Repeat("1", 40)+" C075\x00cli/docs/old.json\x00cli/docs/new.json\x00")...), "path-status"},
		{"rename as the first record", append([]byte(":100644 100644 "+zeros40+" "+strings.Repeat("1", 40)+" R100\x00cli/docs/old.json\x00cli/docs/new.json\x00"), good...), "path-status"},
		{"stream truncated right after the meta field", append(append([]byte(nil), good...), []byte(":000000 100644 "+zeros40+" "+strings.Repeat("1", 40)+" A\x00")...), "changed-list-malformed"},
		{"trailing NUL", append(append([]byte(nil), good...), 0), "changed-list-malformed"},
		{"leading NUL", append([]byte{0}, good...), "changed-list-malformed"},
		{"listed path as a rename", swapRec(x0.recs, onbOut, func(r onbRec) string {
			return fmt.Sprintf(":100644 100644 %s %s R100\x00%s\x00%s\x00", r.old, r.new, onbOut, onbOpt)
		}), "path-status"},
		{"listed path as a copy", swapRec(x0.recs, onbOut, func(r onbRec) string {
			return fmt.Sprintf(":100644 100644 %s %s C100\x00%s\x00", r.old, r.new, onbOut)
		}), "path-status"},
		{"listed path deleted", swapRec(x0.recs, onbOut, func(r onbRec) string {
			return fmt.Sprintf(":100644 000000 %s %s D\x00%s\x00", r.old, zeros40, onbOut)
		}), "path-status"},
		{"garbage", []byte("garbage\x00x\x00"), "changed-list-malformed"},
		{"short object id", []byte(":000000 100644 abc " + strings.Repeat("1", 40) + " A\x00cli/a\x00"), "changed-list-malformed"},
		{"truncated after the meta", good[:bytes.LastIndexByte(good[:len(good)-1], 0)+1], "changed-list-malformed"},
		{"truncated in the stream", good[:len(good)-2], "changed-list-malformed"},
		{"duplicate path", append(append([]byte(nil), good...), onbRaw(x0.recs[:1])...), "changed-list-malformed"},
		{"too many paths", many(maxChangedPath + 1), "changed-list-too-large"},
		{"list over the byte bound", bytes.Repeat([]byte("x"), maxChangedList+1), "changed-list-too-large"},
		{"invalid UTF-8 path", []byte(":000000 100644 " + zeros40 + " " + strings.Repeat("1", 40) + " A\x00cli/\xff\xfe\x00"), "path-not-allowed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			x.raw = c.raw
			if c.raw == nil {
				x.raw = []byte{}
			}
			x.wantRefusal(x.run(), 0, c.reason)
		})
	}
}

func TestVerifyOnboardingInputNegatives(t *testing.T) {
	long := strings.Repeat("a", 64)
	var sixteen []string
	for i := 0; i < MaxOnboardingSlugs+1; i++ {
		sixteen = append(sixteen, "p"+strconv.Itoa(i))
	}
	cases := []struct {
		name   string
		mut    func(x *onbFx)
		reason string
	}{
		{"no slugs", func(x *onbFx) { x.slugs = nil }, OnbReasonSlugList},
		{"over-bound slug list", func(x *onbFx) { x.slugs = sixteen }, OnbReasonSlugList},
		{"duplicate slug", func(x *onbFx) { x.slugs = []string{"demo", "demo"} }, OnbReasonSlugList},
		{"upper case slug", func(x *onbFx) { x.slugs = []string{"Demo"} }, OnbReasonSlugList},
		{"double hyphen slug", func(x *onbFx) { x.slugs = []string{"de--mo"} }, OnbReasonSlugList},
		{"trailing hyphen slug", func(x *onbFx) { x.slugs = []string{"demo-"} }, OnbReasonSlugList},
		{"slug over 63 bytes", func(x *onbFx) { x.slugs = []string{long} }, OnbReasonSlugList},
		{"slug with a slash", func(x *onbFx) { x.slugs = []string{"a/b"} }, OnbReasonSlugList},
		{"empty slug", func(x *onbFx) { x.slugs = []string{""} }, OnbReasonSlugList},
		{"equal commit ids", func(x *onbFx) { x.baseSHA = x.headSHA }, OnbReasonInput},
		{"upper case head id", func(x *onbFx) { x.headSHA = strings.Repeat("A", 40) }, OnbReasonInput},
		{"short base id", func(x *onbFx) { x.baseSHA = "abc" }, OnbReasonInput},
		{"empty head id", func(x *onbFx) { x.headSHA = "" }, OnbReasonInput},
		{"policy without a batch", func(x *onbFx) { x.policy.BatchPath = "" }, OnbReasonPolicy},
		{"policy without a table", func(x *onbFx) { x.policy.TablePath = "" }, OnbReasonPolicy},
		{"policy path below the recipes", func(x *onbFx) { x.policy.Optional = append(x.policy.Optional, RecipesRoot+"x/recipe.json") }, OnbReasonPolicy},
		{"policy path below crdversions", func(x *onbFx) { x.policy.Required = append(x.policy.Required, CrdVersionsDir+"/target-x.json") }, OnbReasonPolicy},
		{"policy trust path as static", func(x *onbFx) { x.policy.Optional = append(x.policy.Optional, onbTrustD+"k.json") }, OnbReasonPolicy},
		{"policy workflow as static", func(x *onbFx) { x.policy.Optional = append(x.policy.Optional, ".github/workflows/x.yml") }, OnbReasonPolicy},
		{"policy duplicate", func(x *onbFx) { x.policy.Optional = append(x.policy.Optional, onbOut) }, OnbReasonPolicy},
		{"policy unclean", func(x *onbFx) { x.policy.Optional = append(x.policy.Optional, "a//b") }, OnbReasonPolicy},
		{"policy without trust paths", func(x *onbFx) { x.policy.TrustPaths = nil }, OnbReasonPolicy},
		{"policy empty trust entry", func(x *onbFx) { x.policy.TrustPaths = append(x.policy.TrustPaths, "") }, OnbReasonPolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			c.mut(x)
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, c.reason) || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
		})
	}
	t.Run("missing trees", func(t *testing.T) {
		in := OnboardingVerifyInput{ChangedRaw: []byte("x"), Slugs: []string{"demo"}, BaseSHA: onbBaseSHA, HeadSHA: onbHeadSHA}
		res := VerifyOnboarding(in)
		if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonInput) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("no seed kind", func(t *testing.T) {
		x := newOnbFx(t)
		x.env.seedKinds = []string{}
		res := x.run()
		if res.Outcome != "fail" || !res.Harness || !contains(res.Reasons, "seed-cannot-run") {
			t.Fatalf("%+v", res)
		}
	})
}

// failTree wraps a tree and fails selected calls.
type failTree struct {
	*memTree
	failEntries bool
	failRead    string
}

func (f *failTree) Entries() ([]Entry, error) {
	if f.failEntries {
		return nil, errors.New("entries boom")
	}
	return f.memTree.Entries()
}

func (f *failTree) Read(p string) ([]byte, error) {
	if p == f.failRead {
		return nil, errors.New("read boom")
	}
	return f.memTree.Read(p)
}

func TestVerifyOnboardingTreeMustBeTheTreeOfTheDiff(t *testing.T) {
	t.Run("head bytes differ from the new blob", func(t *testing.T) {
		x := newOnbFx(t)
		x.head.files[realDemo] = append(append([]byte(nil), x.head.files[realDemo]...), ' ')
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("listed added but in base", func(t *testing.T) {
		x := newOnbFx(t)
		x.base.files[onbBatch] = []byte("old")
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("listed modified but not in base", func(t *testing.T) {
		x := newOnbFx(t)
		delete(x.base.files, onbOut)
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("base bytes differ from the old blob", func(t *testing.T) {
		x := newOnbFx(t)
		x.base.files[onbOut] = []byte("tampered")
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("listed file is a link in head", func(t *testing.T) {
		x := newOnbFx(t)
		delete(x.head.files, fxDir+"changelog.md")
		x.head.links[fxDir+"changelog.md"] = "../../x"
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("listed file is absent from head", func(t *testing.T) {
		x := newOnbFx(t)
		delete(x.head.files, onbBatch)
		x.wantRefusal(x.run(), 0, OnbReasonTreeDiff)
	})
	t.Run("head carries a recipe file the diff does not list", func(t *testing.T) {
		x := newOnbFx(t)
		x.head.files[fxDir+"rules.json"] = []byte("{}")
		x.wantRefusal(x.run(), 0, OnbReasonHeadExtra)
	})
	t.Run("entries error", func(t *testing.T) {
		x := newOnbFx(t)
		x.headTree = &failTree{memTree: x.head, failEntries: true}
		res := x.run()
		if res.Outcome != "fail" || !res.Harness || !contains(res.Reasons, OnbReasonTreeUnreadable) {
			t.Fatalf("%+v", res)
		}
		x = newOnbFx(t)
		x.baseTree = &failTree{memTree: x.base, failEntries: true}
		if res := x.run(); res.Outcome != "fail" || !res.Harness || !contains(res.Reasons, OnbReasonTreeUnreadable) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("read error", func(t *testing.T) {
		x := newOnbFx(t)
		x.headTree = &failTree{memTree: x.head, failRead: realDemo}
		res := x.run()
		if res.Outcome != "fail" || !res.Harness || len(x.runner.calls) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("duplicate entries", func(t *testing.T) {
		x := newOnbFx(t)
		x.headTree = &dupTree{memTree: x.head}
		res := x.run()
		if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonTreeUnreadable) {
			t.Fatalf("%+v", res)
		}
	})
}

type dupTree struct{ *memTree }

func (d *dupTree) Entries() ([]Entry, error) {
	e, _ := d.memTree.Entries()
	return append(e, e[0]), nil
}

func TestVerifyOnboardingRegenerationAndRecipeNegatives(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(x *onbFx)
		reason string
	}{
		{"target not the regeneration", func(x *onbFx) { x.setHead(realDemo, append(append([]byte(nil), x.head.files[realDemo]...), '\n')) }, ""},
		{"report differs", func(x *onbFx) { x.setHead(fxDir+"report.json", []byte("{}\n")) }, "report-differs"},
		{"table row differs", func(x *onbFx) { x.setHead(fxDir+"table-row.json", []byte("{}\n")) }, "table-row-differs"},
		{"changelog differs", func(x *onbFx) { x.setHead(fxDir+"changelog.md", []byte("x\n")) }, "changelog-differs"},
		{"bundle not the recipe's digest", func(x *onbFx) { x.setHead(fxDir+"facts.bundle", append(append([]byte(nil), x.f.bundle...), '\n')) }, "bundle-digest"},
		{"recipe adds an exclusion", func(x *onbFx) { x.setRecipe(func(r *Recipe) { r.Exclude = []string{"cli/x"} }) }, "recipe-invalid"},
		{"rules with an exclusion", func(x *onbFx) {
			x.setRecipe(func(r *Recipe) { r.Rules = "rules.json" })
			x.put(fxDir+"rules.json", readFile(t, "testdata/knative/rules.json"), nil)
		}, "exclusion-present"},
		{"rules file without the recipe field", func(x *onbFx) { x.put(fxDir+"rules.json", []byte("{}"), nil) }, "recipe-invalid"},
		{"recipe commit differs from the bundle", func(x *onbFx) {
			x.setRecipe(func(r *Recipe) { r.Commits[0].Commit = strings.Repeat("9", 40) })
		}, "bundle-commit"},
		{"recipe names another slug", func(x *onbFx) { x.setRecipe(func(r *Recipe) { r.Slug = "other" }) }, "recipe-slug-mismatch"},
		{"recipe of a bad schema", func(x *onbFx) { x.setHead(fxDir+"recipe.json", []byte("{}")) }, "recipe-invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			c.mut(x)
			res := x.run()
			if res.Outcome != "fail" || len(res.Reasons) != 1 || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
			if c.reason != "" && res.Reasons[0] != c.reason {
				t.Fatalf("reason %v (%v), want %s", res.Reasons, res.Details, c.reason)
			}
			if c.reason == "" && res.Reasons[0] != "target-differs" && res.Reasons[0] != "target-invalid" {
				t.Fatalf("reason %v", res.Reasons)
			}
			if res.BindingVerified || res.ChangedPathsSHA256 != "" {
				t.Fatalf("%+v", res)
			}
		})
	}
	t.Run("generator error", func(t *testing.T) {
		x := newOnbFx(t)
		x.env.generate = func(Input) (*Result, error) { return nil, errors.New("boom") }
		x.wantRefusal(x.run(), 0, "generate-error")
	})
	t.Run("two regenerations differ", func(t *testing.T) {
		x := newOnbFx(t)
		n := 0
		real := x.env.generate
		x.env.generate = func(in Input) (*Result, error) {
			r, err := real(in)
			if err == nil {
				n++
				if n%2 == 0 {
					r.Changelog = append(append([]byte(nil), r.Changelog...), 'x')
				}
			}
			return r, err
		}
		x.wantRefusal(x.run(), 0, "non-deterministic")
	})
}

func TestVerifyOnboardingBindingFailuresFailClosed(t *testing.T) {
	x0 := newOnbFx(t)
	var lines []string
	for _, c := range x0.f.recipe.Commits {
		lines = append(lines, c.Commit+"\trefs/tags/"+c.Tag)
	}
	t1 := x0.f.recipe.Commits[0]
	wrong := append([]string(nil), lines...)
	wrong[0] = strings.Repeat("9", 40) + "\trefs/tags/" + t1.Tag
	cases := []struct {
		name    string
		results []ExecResult
		code    string
		harness bool
		calls   int
	}{
		{"moved tag", []ExecResult{okRun(lsOut(wrong...))}, "binding-mismatch", false, 1},
		{"missing tag", []ExecResult{okRun(lsOut(lines[1:]...))}, "binding-missing", false, 1},
		{"redirect", []ExecResult{errRun(128, "fatal: unable to update url base from redirection: redirect")}, "binding-redirect", false, 1},
		{"empty answer", []ExecResult{okRun("")}, "binding-malformed", false, 1},
		{"unexpected ref", []ExecResult{okRun(lsOut(append(append([]string(nil), lines...), strings.Repeat("1", 40)+"\trefs/tags/zzz")...))}, "binding-malformed", false, 1},
		{"truncated answer", []ExecResult{okRun(strings.TrimSuffix(lsOut(lines...), "\n"))}, "binding-malformed", false, 1},
		{"64 hex object format", []ExecResult{okRun(lsOut(strings.Repeat("a", 64) + "\trefs/tags/" + t1.Tag))}, "binding-hashalgo", false, 1},
		{"not readable", []ExecResult{errRun(128, "fatal: repository not found returned error: 404")}, "binding-unavailable", false, 1},
		{"timeout every attempt", []ExecResult{{TimedOut: true}}, "binding-unavailable", true, 3},
		{"git cannot run", []ExecResult{{Err: errors.New("no git")}}, "binding-unavailable", true, 1},
		{"TLS failure", []ExecResult{errRun(128, "SSL certificate problem")}, "binding-unavailable", true, 1},
		{"other non-zero exit", []ExecResult{errRun(1, "weird")}, "binding-unavailable", true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			x.runner = &fakeRunner{results: c.results}
			res := x.run()
			x.wantRefusal(res, c.calls, c.code)
			if res.Harness != c.harness {
				t.Fatalf("harness %v, want %v", res.Harness, c.harness)
			}
			if !strings.HasPrefix(res.Details[0], "demo: "+c.code) {
				t.Fatalf("%v", res.Details)
			}
		})
	}
	t.Run("no runner", func(t *testing.T) {
		x := newOnbFx(t)
		x.noRunner = true
		res := x.run()
		x.wantRefusal(res, 0, OnbReasonNoRunner)
		if !res.Harness {
			t.Fatal("harness")
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		x := newOnbFx(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		in := OnboardingVerifyInput{Base: x.base, Head: x.head, ChangedRaw: onbRaw(x.recs), Slugs: x.slugs, Policy: x.policy,
			BaseSHA: onbBaseSHA, HeadSHA: onbHeadSHA, Upstream: x.runner, Ctx: ctx}
		res := verifyOnboarding(in, x.env)
		if res.Outcome != "fail" || !contains(res.Reasons, "binding-unavailable") || len(x.runner.calls) != 0 {
			t.Fatalf("%+v", res)
		}
	})
}

// Every accepting path needs ALL conjuncts: a result that passes with one
// removed would be a wrong pass. This walks single-conjunct removals of the
// positive fixture and requires a refusal for each.
func TestVerifyOnboardingEveryConjunctIsNeeded(t *testing.T) {
	removals := map[string]func(x *onbFx){
		"upstream runner":     func(x *onbFx) { x.noRunner = true },
		"base trees":          func(x *onbFx) { x.baseTree = nil; x.base.files[RecipesRoot+"Demo/x"] = []byte("1") },
		"head table row":      func(x *onbFx) { x.setHead(onbTable, tableDoc("other")) },
		"batch in the change": func(x *onbFx) { x.drop(onbBatch) },
		"recipe in the diff":  func(x *onbFx) { x.drop(fxDir + "recipe.json") },
		"target in the diff":  func(x *onbFx) { x.drop(realDemo) },
		"blob binding":        func(x *onbFx) { x.recs[x.idx(realDemo)].new = zeros40 },
		"clean commit ids":    func(x *onbFx) { x.headSHA = "" },
		"slug list":           func(x *onbFx) { x.slugs = nil },
	}
	for name, mut := range removals {
		t.Run(name, func(t *testing.T) {
			x := newOnbFx(t)
			mut(x)
			if res := x.run(); res.Outcome != "fail" {
				t.Fatalf("accepted without the %s: %+v", name, res)
			}
		})
	}
}

// The verifier is a library with one result: the input has no field that
// carries a prior verify-pr result, a path-set digest, or a reason.
func TestOnboardingVerifyInputHasNoExternalResult(t *testing.T) {
	want := []string{"Base", "ChangedRaw", "Ctx", "Head", "BaseSHA", "HeadSHA", "Policy", "Sleep", "Slugs", "Upstream"}
	var got []string
	rt := reflect.TypeOf(OnboardingVerifyInput{})
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, rt.Field(i).Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("input fields %v, want %v", got, want)
	}
}

// Purity pin (as the admission checker's): the file may import only these
// packages, and may not read the environment, the clock, files or the network.
func TestOnboardVerifyIsPure(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "errors": true, "context": true, "crypto/sha1": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true,
		"fmt": true, "path": true, "regexp": true, "sort": true, "strings": true, "time": true,
		"github.com/prufyx/prufyx/cli/internal/pathset": true,
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "onboard_verify.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, im := range file.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !allowed[p] {
			t.Errorf("import %q is not allowed in the pure verifier", p)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch {
		case id.Name == "time" && sel.Sel.Name != "Duration":
			t.Errorf("time.%s: no clock in the verifier", sel.Sel.Name)
		case id.Name == "os" || id.Name == "exec" || id.Name == "http" || id.Name == "net" || id.Name == "ioutil":
			t.Errorf("%s.%s: no file, process or network in the verifier", id.Name, sel.Sel.Name)
		case id.Name == "context" && sel.Sel.Name != "Context":
			t.Errorf("context.%s", sel.Sel.Name)
		}
		return true
	})
}

// A project must not reuse an identity the base already holds: an upstream
// repository (repo, component, upstream repository of any base row or target)
// or a project id (fact project, target project), under any casing.
func TestVerifyOnboardingBaseIdentityCollisions(t *testing.T) {
	row := func(extra string) []byte {
		return []byte(`{"projects":[{"slug":"other"` + extra + `}]}`)
	}
	tgt := func(extra string) []byte { return []byte(`{"target":{"project":"other"` + extra + `}}`) }
	both := func(x *onbFx, p string, b []byte) { x.base.files[p] = b; x.head.files[p] = b }
	cases := []struct {
		name   string
		mut    func(x *onbFx)
		reason string
	}{
		{"base row factProject", func(x *onbFx) { x.setBase(onbTable, row(`,"factProject":"DEMO"`)) }, OnbReasonFactCollision},
		{"base row component", func(x *onbFx) { x.setBase(onbTable, row(`,"component":"pkg:github/Example/Demo"`)) }, OnbReasonRepoCovered},
		{"base row upstream repository", func(x *onbFx) {
			x.setBase(onbTable, row(`,"upstream":{"repository":"https://github.com/example/demo.git"}`))
		}, OnbReasonRepoCovered},
		{"base target factProject", func(x *onbFx) { both(x, CrdVersionsDir+"/target-other.json", tgt(`,"factProject":"Demo"`)) }, OnbReasonFactCollision},
		{"base target repo", func(x *onbFx) { both(x, CrdVersionsDir+"/target-other.json", tgt(`,"repo":"github.com/EXAMPLE/demo"`)) }, OnbReasonRepoCovered},
		{"base target component", func(x *onbFx) {
			both(x, CrdVersionsDir+"/target-other.json", tgt(`,"component":"pkg:github/example/demo"`))
		}, OnbReasonRepoCovered},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newOnbFx(t)
			c.mut(x)
			x.wantRefusal(x.run(), 0, c.reason)
		})
	}
	// Unrelated base identities do not refuse.
	x := newOnbFx(t)
	x.setBase(onbTable, row(`,"factProject":"other","component":"pkg:github/a/b","upstream":{"repository":"https://github.com/a/b"}`))
	both(x, CrdVersionsDir+"/target-other.json", tgt(`,"factProject":"other","repo":"github.com/a/b","component":"pkg:github/a/b"`))
	if res := x.run(); res.Outcome != "pass" {
		t.Fatalf("%+v", res)
	}
}

// With two slugs, every per-project conjunct must hold for the SECOND one too
// (a mutant that judges only slugs[0] fails here).
func TestVerifyOnboardingTwoSlugs(t *testing.T) {
	two := func(t *testing.T) *onbFx { return newOnbFxSlugs(t, "demo", "demo2") }
	t.Run("positive", func(t *testing.T) {
		x := two(t)
		res := x.run()
		if res.Outcome != "pass" || !reflect.DeepEqual(res.Slugs, []string{"demo", "demo2"}) || len(res.TagsCommitsSHA) != 2 {
			t.Fatalf("%+v", res)
		}
		if len(x.runner.calls) != 2 {
			t.Fatalf("%d upstream runs, want one per slug", len(x.runner.calls))
		}
		var all, judged []string
		for _, r := range x.recs {
			all = append(all, r.path)
			if strings.HasPrefix(r.path, RecipesRoot+"demo") || strings.HasPrefix(r.path, CrdVersionsDir+"/target-demo") {
				judged = append(judged, r.path)
			}
		}
		if len(judged) != 12 || res.ChangedPathsSHA256 != shaOf(all) || res.JudgedPathsSHA256 != shaOf(judged) {
			t.Fatalf("digests: %d judged, %+v", len(judged), res)
		}
		var b strings.Builder
		b.WriteString("prufyx.io/onboarding-binding/v1\n")
		for _, s := range []string{"demo", "demo2"} {
			var tags []BindingTag
			for _, c := range x.fxs[s].recipe.Commits {
				tags = append(tags, BindingTag{Tag: c.Tag, Commit: c.Commit})
			}
			b.WriteString(s + "\t" + bindingDigest("github.com/example/"+s, tags) + "\n")
		}
		sum := sha256.Sum256([]byte(b.String()))
		if res.BindingDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("binding digest %s", res.BindingDigest)
		}
		if res.TagsCommitsSHA["demo"] == "" || res.TagsCommitsSHA["demo2"] == "" {
			t.Fatalf("%v", res.TagsCommitsSHA)
		}
		// Any slug order gives the same result.
		y := two(t)
		y.slugs = []string{"demo2", "demo"}
		if got := y.run(); !reflect.DeepEqual(res, got) {
			t.Fatalf("slug order changed the result")
		}
	})
	for name, c := range map[string]struct {
		mut    func(x *onbFx)
		reason string
	}{
		"second in base table": {func(x *onbFx) { x.setBase(onbTable, tableDoc("other", "demo2")) }, OnbReasonBasePresent},
		"second in base target": {func(x *onbFx) {
			x.base.files[CrdVersionsDir+"/target-DEMO2.json"] = []byte(`{"target":{"project":"z"}}`)
		}, OnbReasonBasePresent},
		"second in base recipe":      {func(x *onbFx) { x.base.files[RecipesRoot+"Demo2/recipe.json"] = []byte("{}") }, OnbReasonBasePresent},
		"second report differs":      {func(x *onbFx) { x.setHead(RecipesRoot+"demo2/report.json", []byte("{}\n")) }, "report-differs"},
		"second adds exclusion":      {func(x *onbFx) { x.setRecipeOf("demo2", func(r *Recipe) { r.Exclude = []string{"x"} }) }, "recipe-invalid"},
		"second head row gone":       {func(x *onbFx) { x.setHead(onbTable, tableDoc("other", "demo")) }, OnbReasonHeadTable},
		"second extra head file":     {func(x *onbFx) { x.head.files[RecipesRoot+"demo2/rules.json"] = []byte("{}") }, OnbReasonHeadExtra},
		"second recipe file missing": {func(x *onbFx) { x.drop(RecipesRoot + "demo2/changelog.md") }, OnbReasonRequired},
		"second collides with a base repo": {func(x *onbFx) {
			p := CrdVersionsDir + "/target-other.json"
			b := []byte(`{"target":{"project":"other","repo":"github.com/example/demo2"}}`)
			x.base.files[p], x.head.files[p] = b, b
		}, OnbReasonRepoCovered},
	} {
		t.Run(name, func(t *testing.T) {
			x := two(t)
			c.mut(x)
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, c.reason) || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
			for _, d := range res.Details {
				if strings.Contains(d, "demo: ") && !strings.Contains(d, "demo2") {
					t.Fatalf("the first slug must not fail: %v", res.Details)
				}
			}
		})
	}
	t.Run("second has a wrong tag upstream", func(t *testing.T) {
		x := two(t)
		var good, bad []string
		for i, c := range x.f.recipe.Commits {
			good = append(good, c.Commit+"\trefs/tags/"+c.Tag)
			cm := c.Commit
			if i == 0 {
				cm = strings.Repeat("9", 40)
			}
			bad = append(bad, cm+"\trefs/tags/"+c.Tag)
		}
		x.runner = &fakeRunner{results: []ExecResult{okRun(lsOut(good...)), okRun(lsOut(bad...))}}
		res := x.run()
		x.wantRefusal(res, 2, "binding-mismatch")
		if !strings.HasPrefix(res.Details[0], "demo2: ") {
			t.Fatalf("%v", res.Details)
		}
	})
	t.Run("second binding unavailable", func(t *testing.T) {
		x := two(t)
		x.runner = &fakeRunner{results: []ExecResult{okRun(x.runnerOut()), {Err: errors.New("no git")}}}
		x.wantRefusal(x.run(), 2, "binding-unavailable")
	})
	t.Run("duplicate slug", func(t *testing.T) {
		x := two(t)
		x.slugs = []string{"demo", "demo2", "demo"}
		res := x.run()
		if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonSlugList) || len(x.runner.calls) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("extra expected slug", func(t *testing.T) {
		x := two(t)
		x.slugs = []string{"demo", "demo2", "demo3"}
		res := x.run()
		if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRequired) || len(x.runner.calls) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("diff carries a slug not expected", func(t *testing.T) {
		x := two(t)
		x.slugs = []string{"demo"}
		res := x.run()
		if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonSlugSet) || len(x.runner.calls) != 0 {
			t.Fatalf("%+v", res)
		}
	})
}

func (x *onbFx) runnerOut() string {
	var out []string
	for _, c := range x.f.recipe.Commits {
		out = append(out, c.Commit+"\trefs/tags/"+c.Tag)
	}
	return lsOut(out...)
}

// swapRec builds the raw diff of recs with one record replaced by the text
// the callback returns (a record of a LISTED path with another status).
func swapRec(recs []onbRec, path string, repl func(onbRec) string) []byte {
	var b bytes.Buffer
	for _, r := range recs {
		if r.path == path {
			b.WriteString(repl(r))
			continue
		}
		b.Write(onbRaw([]onbRec{r}))
	}
	return b.Bytes()
}

var demoSpellings = []string{
	"github.com/example/demo", "https://github.com/example/demo", "http://github.com/Example/Demo/",
	"https://github.com/example/demo.git", "git+https://github.com/example/demo", "git+https://github.com/example/demo.git#readme",
	"git@github.com:example/demo.git", "ssh://git@github.com/example/demo.git", "ssh://git@github.com:22/example/demo",
	"git+ssh://git@github.com/example/demo.git", "git://github.com/example/demo", "https://www.github.com/example/demo",
	"https://github.com/example/demo@v1.2.3", "https://github.com/example/demo?tab=readme", "https://github.com/example/demo#readme",
	"pkg:github/example/demo", "pkg:github/example/demo@1.0.0", "pkg:github/example/demo@1.0?a=b#sub/path",
	"https://user:pw@github.com/example/demo", "github.com/example/demo.git.git", " HTTPS://GITHUB.COM/EXAMPLE/DEMO ",
	"git+git+https://github.com/example/demo",
	"https://github.com./example/demo", "ssh://git@ssh.github.com:443/example/demo.git",
	"git@ssh.github.com:example/demo.git", "git@ssh.github.com:443/example/demo.git", "https://WWW.GitHub.com./example/demo.git/",
}

// refusedSpellings never pass: each is unreducible, not a distinct key.
var refusedSpellings = []string{
	"https://gitlab.com/g/r/-/tree/main", "https://gitlab.com/g/-/r", "https://gitlab.com/g/r/tree/main", "https://gitlab.com/g/s/r/blob/main/x",
	"https://gitlab.com/a/b/c/d/e/f/g/h/i/j/k", "github.com:443/example/demo", "//github.com//example/demo", "https://gitlab.com/g/s/r/releases",
	"https://github.com/example/demo/tree/main", "github.com/example/demo/sub", "https://api.github.com/repos/example/demo",
	"https://codeload.github.com/example/demo", "https://raw.githubusercontent.com/example/demo/main/x", "https://gist.github.com/example/demo",
	"https://objects.githubusercontent.com/example/demo", "https://uploads.github.com/example/demo",
	"https://github.com/ex\u00e4mple/demo", "https://github.com/example/demo\u200b", "https://gîthub.com/example/demo",
	"https://xn--gthub-5qa.com/example/demo", "https://github.com:abc/example/demo", "https://github.com/example%2Fdemo",
	"https://github.com/%2e%2e/demo", "https://github.com/example/demo\x01", "https://github.com/example/de~mo",
	"https://bitbucket.org/example/demo/src", "https://api.bitbucket.org/example/demo", "https://x.gitlab.com/example/demo",
	"https://git hub.com/example/demo", "https://github.com/example/demo/\u200d",
}

func TestRepoKeyCanonicalForms(t *testing.T) {
	for _, v := range demoSpellings {
		if k, ok := repoKey(v, false); !ok || k != "github.com/example/demo" {
			t.Errorf("%q -> %q %v", v, k, ok)
		}
	}
	for in, want := range map[string]string{
		"git@gitlab.com:123/sub/r.git":         "gitlab.com/123/sub/r",
		"git@gitlab.com:123/r.git":             "gitlab.com/123/r",
		"ssh://git@gitlab.com:22/g/r":          "gitlab.com/g/r",
		"pkg:gitlab/grp/proj":                  "gitlab.com/grp/proj",
		"https://gitlab.com/grp/proj.git":      "gitlab.com/grp/proj",
		"pkg:bitbucket/o/r":                    "bitbucket.org/o/r",
		"git@bitbucket.org:o/r.git":            "bitbucket.org/o/r",
		"https://gitlab.com/a/b/c":             "gitlab.com/a/b/c",
		"git@gitlab.example.org:grp/sub/p.git": "gitlab.example.org/grp/sub/p",
	} {
		if k, ok := repoKey(in, false); !ok || k != want {
			t.Errorf("%q -> %q %v, want %q", in, k, ok, want)
		}
	}
	if k, ok := repoKey("Kubernetes-Sigs/Cluster-API", true); !ok || k != "github.com/kubernetes-sigs/cluster-api" {
		t.Errorf("bare: %q %v", k, ok)
	}
	if k, ok := repoKey("", false); !ok || k != "" {
		t.Errorf("empty: %q %v", k, ok)
	}
	// Different repositories never share a key.
	seen := map[string]string{}
	for _, v := range []string{"github.com/example/demo", "github.com/example/demox", "github.com/other/demo", "gitlab.com/example/demo",
		"pkg:gitlab/example/demo", "bitbucket.org/example/demo"} {
		k, ok := repoKey(v, false)
		if !ok {
			t.Fatalf("%q", v)
		}
		if p, dup := seen[k]; dup && !(p == "gitlab.com/example/demo" && v == "pkg:gitlab/example/demo") {
			t.Errorf("%q and %q share %q", p, v, k)
		}
		seen[k] = v
	}
	for _, v := range refusedSpellings {
		if k, ok := repoKey(v, false); ok {
			t.Errorf("%q must be unreducible, got %q", v, k)
		}
	}
	for _, v := range []string{"demo", "example/demo", "https://github.com/onlyowner", "pkg:npm/left-pad", "pkg:github/onlyowner",
		"https://github.com//demo", "ftp://github.com/a/b", "https://github.com/a/../b", "https://github.com/a b/c", "https://github.com/a%2fb/c", "git@github.com:onlyowner", "https:/github.com/a/b"} {
		if k, ok := repoKey(v, false); ok {
			t.Errorf("%q must be unreducible, got %q", v, k)
		}
	}
	if k, ok := repoKey("a/b/c", true); ok {
		t.Errorf("bare three segments: %q", k)
	}
}

// Every spelling collides when it is the BASE's value, in every base field
// that names a repository; unrelated repositories do not.
func TestVerifyOnboardingBaseRepoSpellingsCollide(t *testing.T) {
	for _, sp := range demoSpellings {
		for _, field := range []string{"repo", "component"} {
			t.Run(field+" "+sp, func(t *testing.T) {
				x := newOnbFx(t)
				b := []byte(`{"target":{"project":"other","` + field + `":` + jq(sp) + `}}`)
				p := CrdVersionsDir + "/target-other.json"
				x.base.files[p], x.head.files[p] = b, b
				x.wantRefusal(x.run(), 0, OnbReasonRepoCovered)
			})
		}
		t.Run("row upstream "+sp, func(t *testing.T) {
			x := newOnbFx(t)
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other","upstream":{"repository":`+jq(sp)+`}}]}`))
			x.wantRefusal(x.run(), 0, OnbReasonRepoCovered)
		})
		t.Run("row component "+sp, func(t *testing.T) {
			x := newOnbFx(t)
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other","component":`+jq(sp)+`}]}`))
			x.wantRefusal(x.run(), 0, OnbReasonRepoCovered)
		})
		t.Run("reserved "+sp, func(t *testing.T) {
			x := newOnbFx(t)
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other"}],"reserved":[{"repository":`+jq(sp)+`}]}`))
			x.wantRefusal(x.run(), 0, OnbReasonRepoCovered)
		})
	}
	t.Run("reserved bare owner/name", func(t *testing.T) {
		x := newOnbFx(t)
		x.setBase(onbTable, []byte(`{"projects":[{"slug":"other"}],"reserved":[{"repository":"Example/Demo"}]}`))
		x.wantRefusal(x.run(), 0, OnbReasonRepoCovered)
	})
	for _, other := range []string{"github.com/example/demox", "https://github.com/other/demo", "pkg:gitlab/example/demo", "git@github.com:example/other.git"} {
		t.Run("no collision "+other, func(t *testing.T) {
			x := newOnbFx(t)
			b := []byte(`{"target":{"project":"other","repo":` + jq(other) + `}}`)
			p := CrdVersionsDir + "/target-other.json"
			x.base.files[p], x.head.files[p] = b, b
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other"}],"reserved":[{"repository":`+jq(other)+`}]}`))
			if res := x.run(); res.Outcome != "pass" {
				t.Fatalf("%+v", res)
			}
		})
	}
}

// A base value that is not a string, or a repo that cannot be reduced, is a
// refusal and never skipped.
func TestVerifyOnboardingBaseRepoValuesUnreadableRefuse(t *testing.T) {
	p := CrdVersionsDir + "/target-other.json"
	for name, fn := range map[string]func(x *onbFx){
		"target repo number":     func(x *onbFx) { x.base.files[p] = []byte(`{"target":{"project":"other","repo":5}}`) },
		"target repo null":       func(x *onbFx) { x.base.files[p] = []byte(`{"target":{"project":"other","repo":null}}`) },
		"target component array": func(x *onbFx) { x.base.files[p] = []byte(`{"target":{"project":"other","component":["a"]}}`) },
		"target factProject obj": func(x *onbFx) { x.base.files[p] = []byte(`{"target":{"project":"other","factProject":{}}}`) },
		"row component number":   func(x *onbFx) { x.setBase(onbTable, []byte(`{"projects":[{"slug":"other","component":7}]}`)) },
		"row upstream null repo": func(x *onbFx) {
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other","upstream":{"repository":null}}]}`))
		},
		"row factProject null": func(x *onbFx) { x.setBase(onbTable, []byte(`{"projects":[{"slug":"other","factProject":null}]}`)) },
		"reserved repo array": func(x *onbFx) {
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other"}],"reserved":[{"repository":[1]}]}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newOnbFx(t)
			fn(x)
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonBaseUnknown) || !res.Harness || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
		})
	}
	for name, v := range map[string]string{"bare name": "demo", "bare owner/name": "example/demo", "owner only": "https://github.com/onlyowner", "other purl": "pkg:npm/x"} {
		t.Run("unreducible "+name, func(t *testing.T) {
			x := newOnbFx(t)
			b := []byte(`{"target":{"project":"other","repo":` + jq(v) + `}}`)
			x.base.files[p], x.head.files[p] = b, b
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRepoUnparsable) || !res.Harness || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
		})
	}
}

// The head side: every spelling of a covered repository, in the recipe's repo
// or component or the head target's repo or component, collides; an
// undecodable head target and an unreducible head value refuse.
func TestCheckCollisionsHeadSpellings(t *testing.T) {
	mk := func(t *testing.T, target string) (*treeView, *onbRun, *baseFacts) {
		m := newMemTree()
		m.files[realTargetPath("demo")] = []byte(target)
		v, f := newTreeView(m)
		if f != nil {
			t.Fatal(f)
		}
		bf := &baseFacts{ids: map[string]bool{}, repos: map[string]bool{}}
		bf.addRepo("https://github.com/example/demo", false)
		return v, &onbRun{reasons: map[string]bool{}}, bf
	}
	for _, sp := range demoSpellings {
		for name, c := range map[string]struct {
			rc     Recipe
			target string
		}{
			"recipe repo":      {Recipe{Repo: sp}, `{"target":{"project":"demo"}}`},
			"recipe component": {Recipe{Component: sp}, `{"target":{"project":"demo"}}`},
			"target repo":      {Recipe{}, `{"target":{"project":"demo","repo":` + jq(sp) + `}}`},
			"target component": {Recipe{}, `{"target":{"project":"demo","component":` + jq(sp) + `}}`},
		} {
			v, run, bf := mk(t, c.target)
			rc := c.rc
			checkCollisions(run, bf, v, "demo", &rc)
			if !run.reasons[OnbReasonRepoCovered] || len(run.reasons) != 1 {
				t.Errorf("%s %q: %v", name, sp, run.reasons)
			}
		}
	}
	v, run, bf := mk(t, `{"target":{"project":"demo","repo":"github.com/example/other"}}`)
	checkCollisions(run, bf, v, "demo", &Recipe{Repo: "github.com/example/demox", Component: "pkg:github/other/demo"})
	if len(run.reasons) != 0 {
		t.Errorf("unrelated head values: %v", run.reasons)
	}
	for name, c := range map[string]struct {
		rc             Recipe
		target, reason string
	}{
		"undecodable target": {Recipe{}, "not json", OnbReasonHeadTarget},
		"null target repo":   {Recipe{}, `{"target":{"repo":null}}`, OnbReasonHeadTarget},
		"unreducible repo":   {Recipe{Repo: "demo"}, `{"target":{"project":"demo"}}`, OnbReasonRepoUnparsable},
		"unreducible comp":   {Recipe{Component: "pkg:npm/x"}, `{"target":{"project":"demo"}}`, OnbReasonRepoUnparsable},
	} {
		v, run, bf := mk(t, c.target)
		rc := c.rc
		checkCollisions(run, bf, v, "demo", &rc)
		if !run.reasons[c.reason] {
			t.Errorf("%s: %v", name, run.reasons)
		}
	}
	// A missing head target file is a refusal too.
	v, run, bf = mk(t, "{}")
	delete(v.files, realTargetPath("demo"))
	checkCollisions(run, bf, v, "demo", &Recipe{})
	if !run.reasons[OnbReasonHeadTarget] {
		t.Errorf("%v", run.reasons)
	}
}

// The real table and every real target reduce to repository keys: the check
// must not refuse the repository's own data.
func TestRepoKeyReadsTheRealBase(t *testing.T) {
	tbl := readFile(t, "../../customresources/table.json")
	doc, err := onbTableDoc(tbl)
	if err != nil {
		t.Fatal(err)
	}
	bf := &baseFacts{ids: map[string]bool{}, repos: map[string]bool{}}
	for _, r := range doc.Projects {
		bf.addID(r.Slug)
		bf.addRepo(string(r.Component), false)
		if r.Upstream != nil {
			bf.addRepo(string(r.Upstream.Repository), false)
		}
	}
	for _, r := range doc.Reserved {
		if r == nil || r.Repository == nil {
			t.Fatal("a real reserved entry has no repository")
		}
		bf.addRepo(string(*r.Repository), true)
	}
	files, err := filepath.Glob("../../extract/crdversions/target-*.json")
	if err != nil || len(files) < 50 {
		t.Fatalf("%d targets: %v", len(files), err)
	}
	for _, f := range files {
		var d onbTargetDoc
		if err := json.Unmarshal(readFile(t, f), &d); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		bf.addRepo(string(d.Target.Repo), false)
		bf.addRepo(string(d.Target.Component), false)
	}
	if len(bf.bad) != 0 || len(bf.repos) < 50 {
		t.Fatalf("unreducible %q, %d keys", bf.bad, len(bf.repos))
	}
	if !bf.repos["github.com/kubernetes-sigs/cluster-api"] {
		t.Fatal("the reserved repository must be a key")
	}
}

// Reserved entries that name no repository, and spellings that never reduce
// to a key, refuse on the base side and the head side; none passes.
func TestVerifyOnboardingReservedAndRefusedSpellings(t *testing.T) {
	for name, doc := range map[string]string{
		"null entry":    `{"projects":[{"slug":"other"}],"reserved":[null]}`,
		"no repository": `{"projects":[{"slug":"other"}],"reserved":[{"name":"x"}]}`,
		"empty repo":    `{"projects":[{"slug":"other"}],"reserved":[{"repository":""}]}`,
		"null repo":     `{"projects":[{"slug":"other"}],"reserved":[{"repository":null}]}`,
	} {
		t.Run("reserved "+name, func(t *testing.T) {
			x := newOnbFx(t)
			x.setBase(onbTable, []byte(doc))
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRepoUnparsable) || !res.Harness || len(x.runner.calls) != 0 {
				t.Fatalf("%+v", res)
			}
		})
	}
	for _, sp := range refusedSpellings {
		for _, field := range []string{"repo", "component"} {
			t.Run("base "+field+" "+sp, func(t *testing.T) {
				x := newOnbFx(t)
				b := []byte(`{"target":{"project":"other","` + field + `":` + jq(sp) + `}}`)
				p := CrdVersionsDir + "/target-other.json"
				x.base.files[p], x.head.files[p] = b, b
				res := x.run()
				if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRepoUnparsable) {
					t.Fatalf("%+v", res)
				}
			})
		}
		t.Run("base reserved "+sp, func(t *testing.T) {
			x := newOnbFx(t)
			x.setBase(onbTable, []byte(`{"projects":[{"slug":"other"}],"reserved":[{"repository":`+jq(sp)+`}]}`))
			res := x.run()
			if res.Outcome != "fail" || !contains(res.Reasons, OnbReasonRepoUnparsable) {
				t.Fatalf("%+v", res)
			}
		})
		t.Run("head "+sp, func(t *testing.T) {
			m := newMemTree()
			m.files[realTargetPath("demo")] = []byte(`{"target":{"project":"demo"}}`)
			v, f := newTreeView(m)
			if f != nil {
				t.Fatal(f)
			}
			bf := &baseFacts{ids: map[string]bool{}, repos: map[string]bool{}}
			bf.addRepo("https://github.com/example/demo", false)
			for _, rc := range []Recipe{{Repo: sp}, {Component: sp}} {
				run := &onbRun{reasons: map[string]bool{}}
				checkCollisions(run, bf, v, "demo", &rc)
				if !run.reasons[OnbReasonRepoUnparsable] {
					t.Errorf("%q: %v", sp, run.reasons)
				}
			}
		})
	}
}

// jq is a JSON string literal.
func jq(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
