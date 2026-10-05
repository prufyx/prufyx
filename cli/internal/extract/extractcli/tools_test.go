// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- apply ---------------------------------------------------------------

func TestApplyCommand(t *testing.T) {
	const id, fx = "k8s.feature-gate-removal", "../k8sfeaturegates/testdata/fixture"
	dir := filepath.Join(t.TempDir(), "out")
	if code, _, errs := run("run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", "2026-10-02T00:00:00Z"); code != 0 {
		t.Fatalf("run: %d %s", code, errs)
	}
	pack := filepath.Join(t.TempDir(), "rules.json")
	// A pack the loader does not know cannot be admitted: refused, untouched.
	base := []byte(`{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha1","revision":"r","policyId":"p","policyDigest":"sha256:x","landscapeFileDigest":"sha256:x","registryDigest":"sha256:x","entries":[]}` + "\n")
	if err := os.WriteFile(pack, base, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run("apply", "--out", dir, "--pack", pack)
	if code != 2 || !strings.Contains(errs, "extract apply:") {
		t.Fatalf("apply: %d %s", code, errs)
	}
	if !bytes.Equal(readFile(t, pack), base) {
		t.Fatal("a refused apply changed the pack")
	}
	for _, args := range [][]string{
		{"apply", "--out", dir},
		{"apply", "--pack", pack},
		{"apply", "--out", dir, "--pack", pack, "extra"},
		{"apply", "--out", filepath.Join(t.TempDir(), "nope"), "--pack", pack},
		{"apply", "--out", dir, "--pack", filepath.Join(t.TempDir(), "nope.json")},
	} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}

// ---- inventory -----------------------------------------------------------

func TestInventoryCommand(t *testing.T) {
	const fx = "../k8sfeaturegates/testdata/fixture"
	const commit = "0000000000000000000000000000000000012200"
	args := []string{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "kubernetes/kubernetes", "--commit", commit}
	code, out, errs := run(args...)
	if code != 0 || errs != "" {
		t.Fatalf("inventory: %d %s", code, errs)
	}
	var doc struct {
		Schema, Extractor, Repo, Commit, Kind string
		Declared                              []string
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Kind != "feature-gates" || doc.Commit != commit || doc.Repo != "github.com/kubernetes/kubernetes" || len(doc.Declared) == 0 {
		t.Fatalf("%v %s", err, out)
	}
	if code2, out2, _ := run(append(args[:len(args):len(args)], "--concurrency", "2")...); code2 != 0 || out2 != out {
		t.Fatal("the inventory is not deterministic")
	}
	// The same with the repository spelt out.
	args[6] = "github.com/kubernetes/kubernetes"
	if code2, out2, _ := run(args...); code2 != 0 || out2 != out {
		t.Fatal("repository spelling changes the output")
	}
	// An unknown commit: the fixture reader reports it, no list.
	if code, out, _ := run("inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "kubernetes/kubernetes", "--commit", strings.Repeat("a", 40)); code == 0 || out != "" {
		t.Fatalf("unknown commit: %d %q", code, out)
	}
	for _, bad := range [][]string{
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "kubernetes/kubernetes"},
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--commit", commit},
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--repo", "kubernetes/kubernetes", "--commit", commit},
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "kubernetes/kubernetes", "--commit", "abc"},
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "argoproj/argo-cd", "--commit", commit},
		{"inventory", "--extractor", "k8s.feature-gate-removal", "--fixture", fx, "--repo", "kubernetes/kubernetes", "--commit", commit, "--out", "x"},
	} {
		if code, out, _ := run(bad...); code != 2 || out != "" {
			t.Fatalf("%v: exit %d %q", bad, code, out)
		}
	}
}

// ---- wants-out against a real offline mirror -------------------------------

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// upstream turns a fixture into a bare git repository under root (one git
// commit per fixture commit, tags as in tags.json) and returns the real
// commit of each fixture commit. edit may change a work tree before its
// commit.
func upstream(t *testing.T, fixture, key, root string, edit func(commit, tree string)) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	var tags map[string]string
	if err := json.Unmarshal(readFile(t, filepath.Join(fixture, filepath.FromSlash(key), "tags.json")), &tags); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(root, filepath.FromSlash(key)+".git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, bare, "init", "-q", "--bare", "-b", "main")
	git(t, bare, "config", "uploadpack.allowFilter", "true")
	git(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	work := filepath.Join(t.TempDir(), "work")
	git(t, filepath.Dir(bare), "clone", "-q", bare, work)
	git(t, work, "checkout", "-q", "-b", "main")
	commits := map[string]bool{}
	for _, c := range tags {
		commits[c] = true
	}
	names := make([]string, 0, len(commits))
	for c := range commits {
		names = append(names, c)
	}
	sort.Strings(names)
	real := map[string]string{}
	for _, c := range names {
		src := filepath.Join(fixture, filepath.FromSlash(key), "commits", c)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		items, _ := os.ReadDir(work)
		for _, it := range items {
			if it.Name() != ".git" {
				os.RemoveAll(filepath.Join(work, it.Name()))
			}
		}
		copyDir(t, src, work)
		if edit != nil {
			edit(c, work)
		}
		git(t, work, "add", "-A")
		git(t, work, "commit", "-q", "--allow-empty", "-m", c)
		real[c] = git(t, work, "rev-parse", "HEAD")
	}
	for tag, c := range tags {
		if r, ok := real[c]; ok {
			git(t, work, "tag", "-f", tag, r)
		}
	}
	git(t, work, "push", "-q", "-f", "origin", "main")
	git(t, work, "push", "-q", "-f", "origin", "--tags")
	return real
}

func mirrorMain(t *testing.T, state, remote string, extra ...string) {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(reg, []byte("repos:\n  - "+remote[strings.Index(remote, "|")+1:]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"mirror", "--state", state, "--registry", reg, "--remote-base", "file://" + remote[:strings.Index(remote, "|")] + "/", "--test-allow-file-remote"}, extra...)
	var out, errb bytes.Buffer
	if code := factorymirror.Main(args, nil, func(string) string { return "" }, &out, &errb); code != 0 {
		t.Fatalf("mirror: %d %s %s", code, out.String(), errb.String())
	}
}

type spy struct {
	inner extract.FixtureReader
	lock  *sync.Mutex
	mu    map[string]bool
}

func (s spy) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	s.lock.Lock()
	s.mu[c+"\x00"+p] = true
	s.lock.Unlock()
	return s.inner.Read(r, c, p)
}
func (s spy) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	return s.inner.List(r, c, d)
}
func (s spy) Tags(r extract.RepoRef) ([]extract.Tag, error) { return s.inner.Tags(r) }

// fixtureReads is every (commit, path) the extractor asks its reader for
// over the fixture, as real commit -> paths.
func fixtureReads(t *testing.T, id, fixture string, real map[string]string) map[string][]string {
	t.Helper()
	spec := Catalog()[id]
	repo, _ := extract.ParseRepo(spec.Repo)
	s := spy{inner: extract.FixtureReader{Root: fixture}, lock: &sync.Mutex{}, mu: map[string]bool{}}
	if _, err := extract.Run(context.Background(), spec.New(0), s, s, extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for k := range s.mu {
		parts := strings.SplitN(k, "\x00", 2)
		if r, ok := real[parts[0]]; ok {
			out[r] = append(out[r], parts[1])
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

type wantsDoc struct {
	Wants []struct {
		Repo   string   `json:"repo"`
		Commit string   `json:"commit"`
		Paths  []string `json:"paths"`
	} `json:"wants"`
}

// Acceptance 3: with --wants-out, a run over a mirror that lacks blobs
// lists exactly the files it needs, derives nothing and exits 3; mirroring
// the wants and running again succeeds, and across the rounds the wants are
// exactly the files the extractor reads.
func TestWantsOutAgainstAnOfflineMirror(t *testing.T) {
	for _, tc := range []struct {
		id, fixture, key, summary string
	}{
		{"k8s.feature-gate-removal", "../k8sfeaturegates/testdata/fixture", "github.com/kubernetes/kubernetes", "3 pairs (3 derived, 0 withheld), 15 rules, 45 vectors"},
		{"crd.version-removal.argo-cd", "../crdversions/testdata/fixture", "github.com/argoproj/argo-cd", "2 pairs (2 derived, 0 withheld), 2 rules, 6 vectors"},
		{"k8s.served-api-removal", "../k8sservedapis/testdata/fixture", "github.com/kubernetes/kubernetes", "4 pairs (4 derived, 0 withheld), 6 rules, 18 vectors"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			root := t.TempDir()
			real := upstream(t, tc.fixture, tc.key, root, nil)
			state := filepath.Join(t.TempDir(), "mirror")
			remote := root + "|" + strings.TrimPrefix(tc.key, "github.com/")
			mirrorMain(t, state, remote)
			out := filepath.Join(t.TempDir(), "out")
			wantsFile := filepath.Join(t.TempDir(), "wants.json")

			union := map[string][]string{}
			rounds := 0
			for ; rounds < 6; rounds++ {
				code, stdout, errs := run("run", "--extractor", tc.id, "--mirror-state", state, "--out", out, "--derived-at", "2026-10-02T00:00:00Z", "--wants-out", wantsFile)
				if code == 0 {
					if !strings.Contains(stdout, tc.summary) {
						t.Fatalf("final run: %s", stdout)
					}
					break
				}
				if code != 3 {
					t.Fatalf("round %d: exit %d %s %s", rounds, code, stdout, errs)
				}
				// Nothing was derived or written.
				if items, err := os.ReadDir(out); err == nil && len(items) > 0 {
					t.Fatalf("round %d wrote output: %v", rounds, items)
				}
				var doc wantsDoc
				if err := json.Unmarshal(readFile(t, wantsFile), &doc); err != nil || len(doc.Wants) == 0 {
					t.Fatalf("wants: %v %s", err, readFile(t, wantsFile))
				}
				for _, w := range doc.Wants {
					if w.Repo != tc.key || len(w.Paths) == 0 || !sort.StringsAreSorted(w.Paths) {
						t.Fatalf("bad want %+v", w)
					}
					union[w.Commit] = append(union[w.Commit], w.Paths...)
				}
				mirrorMain(t, state, remote, "--wants", wantsFile)
			}
			if rounds == 0 || rounds >= 6 {
				t.Fatalf("rounds = %d", rounds)
			}
			for _, v := range union {
				sort.Strings(v)
			}
			// Exactly the files the extractor reads, up to files whose bytes
			// another wanted file already supplies (git stores a blob once, so
			// the mirror holds it after fetching the first copy).
			want := fixtureReads(t, tc.id, tc.fixture, real)
			bare := filepath.Join(root, filepath.FromSlash(tc.key)+".git")
			oid := func(commit, path string) string { return git(t, bare, "rev-parse", commit+":"+path) }
			wantOIDs, gotOIDs := map[string]bool{}, map[string]bool{}
			for c, paths := range want {
				for _, p := range paths {
					wantOIDs[oid(c, p)] = true
				}
			}
			for c, paths := range union {
				read := map[string]bool{}
				for _, p := range want[c] {
					read[p] = true
				}
				readNames := map[string]bool{}
				for _, p := range want[c] {
					readNames[path.Base(p)] = true
				}
				for _, p := range paths {
					// A file the extractor lists but never reads may be wanted
					// when a file of the same name is read (see expanded).
					if !read[p] && !readNames[path.Base(p)] {
						t.Fatalf("wanted %s:%s, which the extractor never reads", c, p)
					}
					gotOIDs[oid(c, p)] = true
				}
			}
			if len(wantOIDs) == 0 || len(gotOIDs) < len(wantOIDs) {
				t.Fatalf("wanted %d distinct files, the extractor reads %d", len(gotOIDs), len(wantOIDs))
			}
			for o := range wantOIDs {
				if !gotOIDs[o] {
					t.Fatalf("a file the extractor reads (blob %s) was never wanted", o)
				}
			}
			t.Logf("%s: %d rounds, %d commits, %d files", tc.id, rounds+1, len(union), countAll(union))
			// The run that succeeded is reproducible from the mirror.
			if code, so, _ := run("verify", "--extractor", tc.id, "--mirror-state", state, "--out", out); code != 0 || !strings.Contains(so, "byte-identical") {
				t.Fatalf("verify: %d %s", code, so)
			}
		})
	}
}

func countAll(m map[string][]string) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

// A pair withheld for a reason other than a missing blob is not a "needs
// blobs" result: the run exits 0, says why, and writes no wants file.
func TestWantsOutIsSilentWhenAPairIsWithheldForAReason(t *testing.T) {
	const id, fixture, key = "crd.version-removal.argo-cd", "../crdversions/testdata/fixture", "github.com/argoproj/argo-cd"
	root := t.TempDir()
	real := upstream(t, fixture, key, root, func(commit, tree string) {
		if strings.HasSuffix(commit, "902000") {
			p := filepath.Join(tree, "manifests/crds/widget-crd.yaml")
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, append(b, []byte("# {{ .Values.x }}\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	})
	_ = real
	state := filepath.Join(t.TempDir(), "mirror")
	remote := root + "|argoproj/argo-cd"
	mirrorMain(t, state, remote)
	out := filepath.Join(t.TempDir(), "out")
	wantsFile := filepath.Join(t.TempDir(), "wants.json")
	for i := 0; i < 6; i++ {
		before, _ := os.ReadFile(wantsFile)
		code, stdout, errs := run("run", "--extractor", id, "--mirror-state", state, "--out", out, "--derived-at", "2026-10-02T00:00:00Z", "--wants-out", wantsFile)
		if code == 3 {
			mirrorMain(t, state, remote, "--wants", wantsFile)
			continue
		}
		if code != 0 || !strings.Contains(stdout, "1 withheld") || !strings.Contains(stdout, "withheld ") {
			t.Fatalf("exit %d\n%s\n%s", code, stdout, errs)
		}
		// The last round found nothing missing: the previous round's file
		// is not rewritten (and none appears if there was no earlier round).
		after, _ := os.ReadFile(wantsFile)
		if !bytes.Equal(before, after) {
			t.Fatal("a run that needed nothing touched the wants file")
		}
		return
	}
	t.Fatal("never converged")
}

// Without any missing blob --wants-out writes nothing, and a fixture run
// behaves exactly as without the flag.
func TestWantsOutWithNothingMissing(t *testing.T) {
	const id, fx = "k8s.feature-gate-removal", "../k8sfeaturegates/testdata/fixture"
	plain := filepath.Join(t.TempDir(), "plain")
	flagged := filepath.Join(t.TempDir(), "flagged")
	wantsFile := filepath.Join(t.TempDir(), "wants.json")
	c1, o1, _ := run("run", "--extractor", id, "--fixture", fx, "--out", plain, "--derived-at", "2026-10-02T00:00:00Z")
	c2, o2, _ := run("run", "--extractor", id, "--fixture", fx, "--out", flagged, "--derived-at", "2026-10-02T00:00:00Z", "--wants-out", wantsFile)
	if c1 != 0 || c2 != 0 || strings.ReplaceAll(o1, plain, "X") != strings.ReplaceAll(o2, flagged, "X") {
		t.Fatalf("%d %d\n%s\n%s", c1, c2, o1, o2)
	}
	if _, err := os.Stat(wantsFile); err == nil {
		t.Fatal("a wants file appeared although nothing was missing")
	}
	for _, f := range []string{"candidates.json", "manifest.json", "vectors.json"} {
		if !bytes.Equal(readFile(t, filepath.Join(plain, f)), readFile(t, filepath.Join(flagged, f))) {
			t.Fatalf("%s differs with --wants-out", f)
		}
	}
}

// The command end to end on the real packs: the served-API run without the
// one rule whose fact the engine does not define (and without attestations)
// is merged, listed, admitted; withdrawing a rule the extractor no longer
// produces flips exactly its state.
func TestApplyCommandOnTheShippedPack(t *testing.T) {
	const id, fx = "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"
	const unregistered = "kubernetes.served-api-removal.authentication-k8s-io-v1beta1.1-32-0-to-1-33-0"
	at := "2026-10-02T00:00:00Z"
	mk := func(drop ...string) string {
		dir := filepath.Join(t.TempDir(), "out")
		if code, _, errs := run("run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", at); code != 0 {
			t.Fatalf("run: %d %s", code, errs)
		}
		dropSet := map[string]bool{}
		for _, d := range drop {
			dropSet[d] = true
		}
		var entries []map[string]any
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, "candidates.json")), &entries); err != nil {
			t.Fatal(err)
		}
		kept := entries[:0]
		for _, e := range entries {
			if !dropSet[e["rule"].(map[string]any)["id"].(string)] {
				kept = append(kept, e)
			}
		}
		write := func(name string, v any) []byte {
			raw, err := extract.Canonical(v)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		digest := func(b []byte) string { sum := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(sum[:]) }
		cand := write("candidates.json", kept)
		var m map[string]any
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, "manifest.json")), &m); err != nil {
			t.Fatal(err)
		}
		for _, p := range m["pairs"].([]any) {
			pair := p.(map[string]any)
			rules := []any{}
			for _, r := range pair["rules"].([]any) {
				if !dropSet[r.(string)] {
					rules = append(rules, r)
				}
			}
			pair["rules"] = rules
		}
		outs := m["outputs"].(map[string]any)
		outs["candidates.json"] = digest(cand)
		delete(outs, "attestations.json")
		os.Remove(filepath.Join(dir, "attestations.json"))
		write("manifest.json", m)
		return dir
	}
	// The shipped pack with the reviewed rules this run collides with removed.
	packDir := t.TempDir()
	for _, f := range []string{"rules.json", "landscape-projects.json", "priority-portfolio.json"} {
		if err := os.WriteFile(filepath.Join(packDir, f), readFile(t, "../../cncfcheck/data/"+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pack := filepath.Join(packDir, "rules.json")
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, pack), &doc); err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	var kept []json.RawMessage
	for _, e := range entries {
		var v struct {
			Project string `json:"project"`
			Rule    struct {
				Subject struct{ To string } `json:"subject"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(e, &v); err != nil {
			t.Fatal(err)
		}
		if v.Project == "kubernetes" && (strings.HasPrefix(v.Rule.Subject.To, "1.") && v.Rule.Subject.To != "") {
			continue
		}
		kept = append(kept, e)
	}
	// Re-render through the library the command uses is not the point here:
	// write the pruned pack with plain JSON (the command re-renders it).
	doc["entries"], _ = json.Marshal(kept)
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(pack, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	runDir := mk(unregistered)
	code, out, errs := run("apply", "--out", runDir, "--pack", pack)
	if code != 0 || !strings.Contains(out, "added 5 rule(s), 0 already present") || !strings.Contains(out, "added kubernetes.served-api-removal.autoscaling-v2beta1.1-24-0-to-1-25-0") {
		t.Fatalf("apply: %d\n%s\n%s", code, out, errs)
	}
	merged := readFile(t, pack)
	if code, out, _ := run("apply", "--out", runDir, "--pack", pack); code != 0 || !strings.Contains(out, "added 0 rule(s), 5 already present") || !bytes.Equal(readFile(t, pack), merged) {
		t.Fatalf("second apply: %d %s", code, out)
	}

	// The extractor stops producing one rule: withdraw it.
	later := mk(unregistered, "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0")
	code, out, errs = run("apply", "--withdraw", "--out", later, "--pack", pack)
	if code != 0 || !strings.Contains(out, "withdrawn 1 rule(s)") || !strings.Contains(out, "withdrawn kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0") {
		t.Fatalf("withdraw: %d\n%s\n%s", code, out, errs)
	}
	if now := string(readFile(t, pack)); strings.Count(now, `"state": "withdrawn"`) != strings.Count(string(merged), `"state": "withdrawn"`)+1 {
		t.Fatal("exactly one rule should have changed state")
	}

	// A run older than the rules cannot withdraw anything: exit 3, no write.
	before := readFile(t, pack)
	at = "2026-09-01T00:00:00Z"
	stale := mk(unregistered, "kubernetes.served-api-removal.autoscaling-v2beta1.1-24-0-to-1-25-0")
	code, out, errs = run("apply", "--withdraw", "--out", stale, "--pack", pack)
	if code != 3 || out != "" || !strings.Contains(errs, "before rule") || !bytes.Equal(readFile(t, pack), before) {
		t.Fatalf("stale withdraw: %d\n%s\n%s", code, out, errs)
	}
}

// A commit the mirror does not hold is a mirror gap, not a withheld pair:
// with --wants-out the run says so, derives nothing and exits 3. (The cure is
// "factory mirror" without --wants; a caller's loop stops when the mirror
// exits non-zero.)
func TestWantsOutReportsACommitTheMirrorLacks(t *testing.T) {
	const id, fixture, key = "crd.version-removal.argo-cd", "../crdversions/testdata/fixture", "github.com/argoproj/argo-cd"
	root := t.TempDir()
	upstream(t, fixture, key, root, nil)
	state := filepath.Join(t.TempDir(), "mirror")
	remote := root + "|argoproj/argo-cd"
	mirrorMain(t, state, remote)
	out := filepath.Join(t.TempDir(), "out")
	wantsFile := filepath.Join(t.TempDir(), "wants.json")
	args := []string{"run", "--extractor", id, "--mirror-state", state, "--out", out, "--derived-at", "2026-10-02T00:00:00Z", "--wants-out", wantsFile}
	for i := 0; ; i++ {
		code, _, _ := run(args...)
		if code == 0 {
			break
		}
		if code != 3 || i > 5 {
			t.Fatalf("exit %d after %d rounds", code, i)
		}
		mirrorMain(t, state, remote, "--wants", wantsFile)
		os.RemoveAll(out)
	}
	os.RemoveAll(out)
	// The index now names a release whose commit the mirror never fetched.
	idxPath := filepath.Join(state, "mirror-index.json")
	var idx map[string]any
	if err := json.Unmarshal(readFile(t, idxPath), &idx); err != nil {
		t.Fatal(err)
	}
	tags := idx["repos"].(map[string]any)[key].(map[string]any)["tags"].(map[string]any)
	bogus := strings.Repeat("ab", 20)
	tags["v90.3.0"] = map[string]any{"commit": bogus}
	raw, _ := json.MarshalIndent(idx, "", "  ")
	if err := os.WriteFile(idxPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, errs := run(args...)
	if code != 3 || !strings.Contains(stdout, "needs commit "+key+"@"+bogus) {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, errs)
	}
	if items, err := os.ReadDir(out); err == nil && len(items) > 0 {
		t.Fatalf("output written: %v", items)
	}
	// Without the flag the behaviour is what it was.
	if c, o, _ := run("run", "--extractor", id, "--mirror-state", state, "--out", filepath.Join(t.TempDir(), "o2"), "--derived-at", "2026-10-02T00:00:00Z"); c == 3 || strings.Contains(o, "needs commit") {
		t.Fatalf("the flag-less run changed: %d %s", c, o)
	}
}
