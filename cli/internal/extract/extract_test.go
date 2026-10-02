// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const (
	testRepo   = "github.com/example/project"
	testCommit = "1111111111111111111111111111111111111111"
	testNext   = "2222222222222222222222222222222222222222"
)

func repoRef(t *testing.T) RepoRef {
	t.Helper()
	r, err := ParseRepo(testRepo)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// writeTree writes files under root/<repo>/commits/<commit>/ and tags.json.
func writeTree(t *testing.T, root string, tags map[string]string, commits map[string]map[string]string) {
	t.Helper()
	base := filepath.Join(root, filepath.FromSlash(testRepo))
	for commit, files := range commits {
		for p, content := range files {
			full := filepath.Join(base, "commits", commit, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var b strings.Builder
	b.WriteString("{")
	names := make([]string, 0, len(tags))
	for n := range tags {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + n + `":"` + tags[n] + `"`)
	}
	b.WriteString("}")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "tags.json"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureReaderComputesGitObjectIDs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	files := map[string]string{"a.txt": "alpha\n", "dir/b.go": "package b\n", "dir/sub/c": "", "dir-x": "x", "dir.y": "y"}
	writeTree(t, root, map[string]string{}, map[string]map[string]string{testCommit: files})
	fr := FixtureReader{Root: root}
	repo := repoRef(t)

	// The same files committed by git yield the same ids.
	work := t.TempDir()
	for p, c := range files {
		full := filepath.Join(work, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	gitRun("init", "-q")
	gitRun("add", "-A")
	tree := gitRun("write-tree")
	want := gitRun("ls-tree", tree)
	entries, err := fr.List(repo, testCommit, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Mode+" "+e.Type+" "+e.SHA+"\t"+e.Path)
	}
	if strings.Join(got, "\n") != want {
		t.Fatalf("listing differs from git:\n%s\nwant\n%s", strings.Join(got, "\n"), want)
	}
	sub, err := fr.List(repo, testCommit, "dir")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 2 || sub[0].Path != "dir/b.go" || sub[1].Path != "dir/sub" {
		t.Fatalf("sub listing %+v", sub)
	}
	if _, err := fr.List(repo, testCommit, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing dir: %v", err)
	}
	if _, err := fr.Read(repo, testCommit, "nope.go"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
	for _, bad := range []string{"../x", "/abs", "a/../b", "dir/"} {
		if _, err := fr.Read(repo, testCommit, bad); err == nil {
			t.Fatalf("path %q accepted", bad)
		}
	}
	if _, err := fr.Read(repo, "HEAD", "a.txt"); err == nil {
		t.Fatal("non-SHA commit accepted")
	}
}

func TestRecorderLogsAndReusesByObjectID(t *testing.T) {
	root := t.TempDir()
	same := "package same\n"
	writeTree(t, root, map[string]string{}, map[string]map[string]string{
		testCommit: {"pkg/same.go": same, "pkg/changed.go": "one\n"},
		testNext:   {"pkg/same.go": same, "pkg/changed.go": "two\n", "other/same.go": same},
	})
	inner := &countingReader{PinnedReader: FixtureReader{Root: root}}
	rec := NewRecorder(inner)
	repo := repoRef(t)

	// Reuse before any listing or read is refused.
	if _, ok := Reuse(rec, repo, testCommit, "pkg/same.go", "x"); ok {
		t.Fatal("reuse without listing")
	}
	first, err := rec.List(repo, testCommit, "")
	if err != nil {
		t.Fatal(err)
	}
	pkg1, err := rec.List(repo, testCommit, "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Read(repo, testCommit, "pkg/same.go"); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.List(repo, testNext, ""); err != nil {
		t.Fatal(err)
	}
	listsBefore := inner.lists
	// pkg/ differs between the commits (changed.go), so it is listed again;
	// a tree id seen before would be served from the cache.
	pkg2, err := rec.List(repo, testNext, "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if inner.lists != listsBefore+1 {
		t.Fatalf("changed tree must be listed by the inner reader")
	}
	var sameOID string
	for _, e := range pkg2 {
		if e.Path == "pkg/same.go" {
			sameOID = e.SHA
		}
	}
	readsBefore := inner.reads
	got, ok := Reuse(rec, repo, testNext, "pkg/same.go", sameOID)
	if !ok || inner.reads != readsBefore {
		t.Fatal("identical blob was not reused")
	}
	sum := sha256.Sum256([]byte(same))
	if got.SHA256 != hex.EncodeToString(sum[:]) || got.Commit != testNext || got.Path != "pkg/same.go" {
		t.Fatalf("reuse record %+v", got)
	}
	if _, ok := Reuse(rec, repo, testNext, "pkg/same.go", strings.Repeat("0", 40)); ok {
		t.Fatal("reuse accepted a wrong object id")
	}
	if _, ok := Reuse(rec, repo, testNext, "pkg/changed.go", pkg2[0].SHA); ok {
		t.Fatal("reuse accepted a blob that was never read")
	}
	if _, ok := Reuse(FixtureReader{Root: root}, repo, testNext, "pkg/same.go", sameOID); ok {
		t.Fatal("reuse without a recorder")
	}
	// Reads are logged per commit, sorted, with their digests.
	reads := rec.CommitReads(repo, testNext)
	if len(reads) != 1 || reads[0].Path != "pkg/same.go" || reads[0].Size != len(same) || reads[0].Lines != 1 {
		t.Fatalf("logged reads %+v", reads)
	}
	if c := rec.Commits(repo); !slices.Equal(c, []string{testCommit, testNext}) {
		t.Fatalf("commits %v", c)
	}
	_ = first
	_ = pkg1

	// A cached tree is served without the inner reader.
	listsBefore = inner.lists
	again, err := rec.List(repo, testCommit, "pkg")
	if err != nil || inner.lists != listsBefore || len(again) != len(pkg1) || again[0].Path != pkg1[0].Path {
		t.Fatalf("cached listing: err=%v lists=%d/%d %+v", err, inner.lists, listsBefore, again)
	}
}

type countingReader struct {
	PinnedReader
	reads, lists int
}

func (c *countingReader) Read(repo RepoRef, commit, p string) ([]byte, error) {
	c.reads++
	return c.PinnedReader.Read(repo, commit, p)
}

func (c *countingReader) List(repo RepoRef, commit, dir string) ([]TreeEntry, error) {
	c.lists++
	return c.PinnedReader.List(repo, commit, dir)
}

func TestRecorderRejectsBytesThatChange(t *testing.T) {
	flip := &flippingReader{}
	rec := NewRecorder(flip)
	repo := repoRef(t)
	if _, err := rec.Read(repo, testCommit, "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Read(repo, testCommit, "f"); err == nil {
		t.Fatal("changed pinned bytes accepted")
	}
}

type flippingReader struct{ n int }

func (f *flippingReader) Read(RepoRef, string, string) ([]byte, error) {
	f.n++
	return []byte{byte(f.n)}, nil
}
func (f *flippingReader) List(RepoRef, string, string) ([]TreeEntry, error) { return nil, nil }

func TestCodeDigestCoversEveryNonTestSourceFile(t *testing.T) {
	files, err := CodeFiles(FrameworkSource())
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range onDisk {
		if !strings.HasSuffix(f, "_test.go") {
			want = append(want, FrameworkDir+"/"+f)
		}
	}
	sort.Strings(want)
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
		data, err := os.ReadFile(strings.TrimPrefix(f.Path, FrameworkDir+"/"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if f.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: embedded digest differs from the file on disk", f.Path)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("digest covers %v, source files are %v", got, want)
	}
	// The digest is sha256 over "path NUL sha LF" lines in path order.
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Path + "\x00" + f.SHA256 + "\n"))
	}
	if CodeDigest(files) != "sha256:"+hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("code digest formula")
	}
	// Any change to any covered file changes the digest; test files do not
	// count.
	a := fstest.MapFS{"x.go": {Data: []byte("package x\n")}, "x_test.go": {Data: []byte("package x\n")}}
	b := fstest.MapFS{"x.go": {Data: []byte("package x \n")}, "x_test.go": {Data: []byte("package y\n")}}
	c := fstest.MapFS{"x.go": {Data: []byte("package x\n")}, "x_test.go": {Data: []byte("package z\n")}}
	da, _ := CodeFiles(SourceSet{Dir: "p", Files: a})
	db, _ := CodeFiles(SourceSet{Dir: "p", Files: b})
	dc, _ := CodeFiles(SourceSet{Dir: "p", Files: c})
	if CodeDigest(da) == CodeDigest(db) || CodeDigest(da) != CodeDigest(dc) {
		t.Fatal("digest must follow non-test sources only")
	}
	if _, err := CodeFiles(SourceSet{Dir: "p", Files: fstest.MapFS{}}); err == nil {
		t.Fatal("empty source set accepted")
	}
	if _, err := CodeFiles(SourceSet{Dir: "p", Files: a}, SourceSet{Dir: "p", Files: a}); err == nil {
		t.Fatal("duplicate source file accepted")
	}
	var _ fs.FS = a
}

func TestCanonicalSortsKeysAndIsStable(t *testing.T) {
	type s struct {
		Z string            `json:"z"`
		A map[string]string `json:"a"`
	}
	got, err := Canonical(s{Z: "a<b>&", A: map[string]string{"y": "1", "b": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": {\n    \"b\": \"2\",\n    \"y\": \"1\"\n  },\n  \"z\": \"a<b>&\"\n}\n"
	if string(got) != want {
		t.Fatalf("got %q", got)
	}
}

// --- a toy extractor exercising Run, stamping, vectors and Verify ---

type toyExtractor struct {
	members   []string
	cite      string
	startLine int
	endLine   int
	withhold  bool
}

func (toyExtractor) ID() string                   { return "toy.removal" }
func (toyExtractor) Version() string              { return "1.0.0" }
func (toyExtractor) Applies(r RepoRef) bool       { return r.Key == testRepo }
func (toyExtractor) SourceFiles() (string, fs.FS) { return "toy", fstest.MapFS{"toy.go": {Data: []byte("package toy\n")}} }
func (toyExtractor) Pairs(ix ReleaseIndex) []VersionPair {
	return []VersionPair{{Repo: ix.Repo, From: "1.0.0", FromTag: "v1.0.0", FromCommit: testCommit, To: "2.0.0", ToTag: "v2.0.0", ToCommit: testNext}}
}

func (x toyExtractor) Extract(_ context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	if _, err := r.Read(p.Repo, p.FromCommit, "decl.go"); err != nil {
		return Extraction{}, err
	}
	if x.withhold {
		return Extraction{}, &Withheld{Reason: "toy registry incomplete"}
	}
	cite := x.cite
	if cite == "" {
		cite = "decl.go"
	}
	return Extraction{Proof: map[string]any{"removed": x.members}, Candidates: []Candidate{{
		Project: "example", Description: "Toy removal.",
		RequiredFacts: []Fact{{Side: "proposed", ID: "component.example.flags_set", Component: "pkg:github/example/project", Type: "set", Description: "Flags."}},
		Rule: Rule{ID: "example.toy.1-0-0-to-2-0-0", Operator: "forbid_set_member",
			Subject:      Subject{Component: "pkg:github/example/project", From: p.From, To: p.To},
			SetCondition: &SetCondition{Side: "proposed", Component: "pkg:github/example/project", FactID: "component.example.flags_set", Members: x.members},
			ReasonCode:   "EXAMPLE_REMOVED", NextAction: "remove the listed flags"},
		Sources:     []SourceRef{{ID: "toy-declaration", Repo: p.Repo, Commit: p.FromCommit, Path: cite, StartLine: x.startLine, EndLine: x.endLine}},
		PassMembers: []string{"kept"},
	}}}, nil
}

func toyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string]string{"v1.0.0": testCommit, "v2.0.0": testNext}, map[string]map[string]string{
		testCommit: {"decl.go": "package decl\n\nconst Old = \"old\"\n", "other.go": "package decl\n"},
		testNext:   {"decl.go": "package decl\n"},
	})
	return root
}

var toyTime = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func runToy(t *testing.T, x toyExtractor, root string) (*Output, error) {
	t.Helper()
	fr := FixtureReader{Root: root}
	return Run(context.Background(), x, fr, fr, Options{Repo: repoRef(t), DerivedAt: toyTime})
}

func TestRunStampsProvenanceAndGeneratesCheckedVectors(t *testing.T) {
	root := toyFixture(t)
	out, err := runToy(t, toyExtractor{members: []string{"old", "older"}, startLine: 3, endLine: 3}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || len(out.Vectors) != 3 {
		t.Fatalf("entries=%d vectors=%d", len(out.Entries), len(out.Vectors))
	}
	ev := out.Entries[0].Rule.Evidence
	data, _ := os.ReadFile(filepath.Join(root, testRepo, "commits", testCommit, "decl.go"))
	sum := sha256.Sum256(data)
	if ev.Basis != "mechanical" || ev.State != "active" || ev.Extractor.ID != "toy.removal" || ev.Extractor.Version != "1.0.0" ||
		!strings.HasPrefix(ev.Extractor.CodeDigest, "sha256:") || ev.DerivedAt != "2026-10-02T00:00:00Z" || ev.ReviewedAt != ev.DerivedAt ||
		ev.ValidUntil != "2026-12-31T00:00:00Z" || len(ev.Sources) != 1 || ev.Sources[0].ContentDigest != "sha256:"+hex.EncodeToString(sum[:]) ||
		ev.Sources[0].URL != "https://github.com/example/project/blob/"+testCommit+"/decl.go" || ev.Sources[0].Revision != testCommit {
		t.Fatalf("evidence %+v", ev)
	}
	kinds := map[string]VectorExpect{}
	for _, v := range out.Vectors {
		kinds[v.Kind] = v.Expect
	}
	if kinds[VectorBlocked].Status != "BLOCKED" || !slices.Equal(kinds[VectorBlocked].MatchedMembers, []string{"old", "older"}) ||
		kinds[VectorPassComplete].Status != "PASS" || kinds[VectorUnknownIncomplete].Status != "UNKNOWN" || kinds[VectorUnknownIncomplete].ReasonCode != "RULE_SET_FACT_INCOMPLETE" {
		t.Fatalf("vectors %+v", kinds)
	}
	// A vector whose expectation is wrong is caught by the engine check.
	bad := append([]Vector(nil), out.Vectors...)
	bad[1].Expect.Status = "BLOCKED"
	if err := CheckVectors(out.Entries, bad, toyTime); err == nil {
		t.Fatal("wrong vector expectation accepted")
	}
	if err := CheckVectors(out.Entries, out.Vectors[:2], toyTime); err == nil {
		t.Fatal("missing vector kind accepted")
	}
	// Whole-file citation.
	out, err = runToy(t, toyExtractor{members: []string{"old"}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if s := out.Entries[0].Rule.Evidence.Sources[0]; s.StartLine != 1 || s.EndLine != 3 {
		t.Fatalf("whole-file span %+v", s)
	}
}

func TestRunRefusesUnprovenCitationsAndBadRules(t *testing.T) {
	root := toyFixture(t)
	for name, x := range map[string]toyExtractor{
		"cites a file it did not read": {members: []string{"old"}, cite: "other.go"},
		"span past the end of file":    {members: []string{"old"}, startLine: 3, endLine: 4},
		"inverted span":                {members: []string{"old"}, startLine: 3, endLine: 2},
		"unsorted members":             {members: []string{"older", "old"}},
		"invalid member":               {members: []string{"bad=member"}},
		"pass member forbidden":        {members: []string{"kept"}},
	} {
		if _, err := runToy(t, x, root); err == nil {
			t.Fatalf("%s: run succeeded", name)
		}
	}
}

func TestWithheldPairYieldsNoRule(t *testing.T) {
	out, err := runToy(t, toyExtractor{members: []string{"old"}, withhold: true}, toyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 || len(out.Vectors) != 0 || out.Manifest.Totals.Withheld != 1 || out.Manifest.Pairs[0].Status != PairWithheld || out.Manifest.Pairs[0].Reason != "toy registry incomplete" {
		t.Fatalf("manifest %+v", out.Manifest)
	}
}

func TestOutputIsReproducibleAndVerifyDetectsEveryChange(t *testing.T) {
	root := toyFixture(t)
	x := toyExtractor{members: []string{"old"}, startLine: 3, endLine: 3}
	a, err := runToy(t, x, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := runToy(t, x, root)
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := a.Files()
	fb, _ := b.Files()
	if len(fa) != len(fb) {
		t.Fatal("file sets differ")
	}
	for name := range fa {
		if string(fa[name]) != string(fb[name]) {
			t.Fatalf("%s differs between runs", name)
		}
	}
	dir := filepath.Join(t.TempDir(), "out")
	if err := a.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := a.Write(dir); err == nil {
		t.Fatal("wrote into a non-empty directory")
	}
	fr := FixtureReader{Root: root}
	problems, err := Verify(context.Background(), x, fr, fr, dir, nil)
	if err != nil || len(problems) != 0 {
		t.Fatalf("verify: %v %v", err, problems)
	}
	// Tamper with each kind of output.
	for _, tc := range []struct {
		name   string
		mutate func()
		want   string
	}{
		{"candidate edited", func() { appendTo(t, filepath.Join(dir, FileCandidates), " ") }, FileCandidates + ": differs"},
		{"extra file", func() { _ = os.WriteFile(filepath.Join(dir, "extra.json"), []byte("{}"), 0o644) }, "extra.json: not produced"},
		{"read log removed", func() { _ = os.Remove(filepath.Join(dir, DirReads, testCommit+".tsv")) }, DirReads + "/" + testCommit + ".tsv: missing"},
	} {
		tc.mutate()
		problems, err := Verify(context.Background(), x, fr, fr, dir, nil)
		if err != nil || !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, tc.want) }) {
			t.Fatalf("%s: problems=%v err=%v", tc.name, problems, err)
		}
	}
	// Upstream bytes that changed under the same commit are detected.
	dir2 := filepath.Join(t.TempDir(), "out")
	if err := a.Write(dir2); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(root, testRepo, "commits", testCommit, "decl.go"), "// changed\n")
	problems, err = Verify(context.Background(), x, fr, fr, dir2, nil)
	if err != nil || len(problems) == 0 {
		t.Fatalf("changed upstream bytes verified: %v %v", problems, err)
	}
	// A different extractor build is reported.
	problems, err = Verify(context.Background(), otherBuild{x}, fr, fr, dir2, nil)
	if err != nil || !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, "extractor identity differs") }) {
		t.Fatalf("other build: %v %v", problems, err)
	}
}

type otherBuild struct{ toyExtractor }

func (otherBuild) SourceFiles() (string, fs.FS) {
	return "toy", fstest.MapFS{"toy.go": {Data: []byte("package toy // v2\n")}}
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsBadOptions(t *testing.T) {
	root := toyFixture(t)
	fr := FixtureReader{Root: root}
	x := toyExtractor{members: []string{"old"}}
	other, _ := ParseRepo("github.com/example/other")
	for name, opts := range map[string]Options{
		"zero time":         {Repo: repoRef(t)},
		"fractional second": {Repo: repoRef(t), DerivedAt: toyTime.Add(time.Millisecond)},
		"other repository":  {Repo: other, DerivedAt: toyTime},
	} {
		if _, err := Run(context.Background(), x, fr, fr, opts); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := Run(context.Background(), noSource{x}, fr, fr, Options{Repo: repoRef(t), DerivedAt: toyTime}); err == nil {
		t.Fatal("extractor without source accepted")
	}
	for _, bad := range []string{"gitlab.com/a/b", "github.com/a", "github.com/a/b/c", ""} {
		if _, err := ParseRepo(bad); err == nil {
			t.Fatalf("repo %q accepted", bad)
		}
	}
}

type noSource struct{ x toyExtractor }

func (n noSource) ID() string                          { return n.x.ID() }
func (n noSource) Version() string                     { return n.x.Version() }
func (n noSource) Applies(r RepoRef) bool              { return n.x.Applies(r) }
func (n noSource) Pairs(ix ReleaseIndex) []VersionPair { return n.x.Pairs(ix) }
func (n noSource) Extract(ctx context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	return n.x.Extract(ctx, r, p)
}
