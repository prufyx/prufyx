// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

func newOnbFx(t *testing.T) *onbFx {
	t.Helper()
	f := newFixture(t, nil)
	f.files["recipe.json"] = f.recipeBytes()
	x := &onbFx{t: t, f: f, head: newMemTree(), base: newMemTree(), slugs: []string{"demo"}, env: defaultVerifyEnv(), baseSHA: onbBaseSHA, headSHA: onbHeadSHA}
	for n, b := range f.files {
		x.put(full(n), b, nil)
	}
	x.put(onbTable, tableDoc("other", "demo"), tableDoc("other"))
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
	for _, c := range f.recipe.Commits {
		out = append(out, c.Commit+"\trefs/tags/"+c.Tag)
	}
	x.runner = &fakeRunner{results: []ExecResult{okRun(lsOut(out...))}}
	return x
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
		"context": true, "crypto/sha1": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true,
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
