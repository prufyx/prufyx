// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread/gitreadtest"
)

var (
	upCommit1 = strings.Repeat("1", 40)
	upCommit2 = strings.Repeat("2", 40)
)

const upDeep = "pkg/a/b/deep.go"

// upgradeFixture holds a directory tree "pkg" several levels deep, with a
// file and a directory whose git order differs from their name order. In the
// second commit the subtree pkg/a also sits at copy/a, and x/a next to an
// extra file, so one tree id is reachable through different parents.
func upgradeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(commit, p, body string) {
		full := filepath.Join(root, "github.com", "acme", "widget", "commits", commit, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	under := func(commit, dir string) {
		write(commit, dir+"/b/deep.go", "deep\n")
		write(commit, dir+"/b/other.go", "other\n")
		write(commit, dir+"/c/d/leaf.go", "leaf\n")
		write(commit, dir+"/z.go", "z\n")
	}
	under(upCommit1, "pkg/a")
	write(upCommit1, "pkg/a.go", "file before the directory in git order\n")
	write(upCommit1, "pkg/e/f/g/h.go", "h\n")
	write(upCommit1, "pkg/top.go", "top\n")
	write(upCommit1, "README.md", "readme\n")
	under(upCommit2, "copy/a")
	under(upCommit2, "x/a")
	write(upCommit2, "x/extra.go", "extra\n")
	return root
}

func upRepo(t *testing.T) extract.RepoRef {
	t.Helper()
	r, err := extract.ParseRepo("github.com/acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// treeLog counts the tree requests the fake server saw.
type treeLog struct {
	mu             sync.Mutex
	flat, recurses int
}

func (l *treeLog) counts() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flat, l.recurses
}

type treeHook func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool)

func upgradeSource(t *testing.T, root string, hook treeHook) (*GitHubSource, *treeLog) {
	t.Helper()
	log := &treeLog{}
	fake := newFakeGitHub(root)
	fake.realRoot = true
	fake.onTree = func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
		log.mu.Lock()
		if rec {
			log.recurses++
		} else {
			log.flat++
		}
		log.mu.Unlock()
		if hook != nil {
			return hook(id, rec, out)
		}
		return 0, out, false
	}
	return githubSourceFor(t, fake), log
}

// bfs lists dir and every directory below it, breadth first as the scan does,
// and returns the listings by directory.
func bfs(r extract.PinnedReader, repo extract.RepoRef, commit, dir string) (map[string][]extract.TreeEntry, error) {
	out := map[string][]extract.TreeEntry{}
	queue := []string{dir}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		entries, err := r.List(repo, commit, d)
		if err != nil {
			return nil, err
		}
		out[d] = entries
		for _, e := range entries {
			if e.Type == "tree" {
				queue = append(queue, e.Path)
			}
		}
	}
	return out, nil
}

func fixtureBFS(t *testing.T, root, commit, dir string) map[string][]extract.TreeEntry {
	t.Helper()
	m, err := bfs(extract.FixtureReader{Root: root}, upRepo(t), commit, dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func fixtureID(t *testing.T, root, commit, dir string) string {
	t.Helper()
	entries, err := extract.FixtureReader{Root: root}.List(upRepo(t), commit, path.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Path == dir {
			return e.SHA
		}
	}
	t.Fatalf("no directory %s", dir)
	return ""
}

// A file read deep in a tree leaves its ancestors cached one level only. The
// listing of the top directory then costs exactly one recursive request and
// no request for any directory below it, and what the scan sees and records
// is exactly what a run without the earlier read sees and records.
func TestUpgradeFetchesTheSubtreeOnce(t *testing.T) {
	t.Parallel()
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cacheDir=%v", cached), func(t *testing.T) {
			t.Parallel()
			root := upgradeFixture(t)
			repo := upRepo(t)
			run := func(readFirst bool) (map[string][]extract.TreeEntry, []extract.ReadRecord, int, int) {
				src, log := upgradeSource(t, root, nil)
				if cached {
					src.CacheDir = t.TempDir()
				}
				rec := extract.NewRecorder(src)
				if readFirst {
					if _, err := rec.Read(repo, upCommit1, upDeep); err != nil {
						t.Fatal(err)
					}
				}
				flat0, rec0 := log.counts()
				if readFirst && (flat0 != 4 || rec0 != 0) { // root, pkg, pkg/a, pkg/a/b
					t.Fatalf("the read made %d one level and %d recursive requests", flat0, rec0)
				}
				listed, err := bfs(rec, repo, upCommit1, "pkg")
				if err != nil {
					t.Fatal(err)
				}
				if !readFirst {
					if _, err := rec.Read(repo, upCommit1, upDeep); err != nil {
						t.Fatal(err)
					}
				}
				flat1, rec1 := log.counts()
				return listed, rec.CommitReads(repo, upCommit1), flat1 - flat0, rec1 - rec0
			}
			warm, warmReads, flat, recursive := run(true)
			if flat != 0 || recursive != 1 {
				t.Fatalf("listing after the read made %d one level and %d recursive requests, want 0 and 1", flat, recursive)
			}
			cold, coldReads, coldFlat, coldRec := run(false)
			if coldFlat != 1 || coldRec != 1 { // the root, then pkg
				t.Fatalf("cold run made %d one level and %d recursive requests", coldFlat, coldRec)
			}
			if want := fixtureBFS(t, root, upCommit1, "pkg"); !reflect.DeepEqual(warm, want) || !reflect.DeepEqual(cold, want) {
				t.Fatalf("listings differ\nwarm %v\ncold %v\nwant %v", warm, cold, want)
			}
			if len(warmReads) == 0 || !reflect.DeepEqual(warmReads, coldReads) {
				t.Fatalf("read records differ: %v and %v", warmReads, coldReads)
			}
		})
	}
}

// A derivation that follows deep reads yields the bytes the mirror yields.
func TestUpgradeAfterDeepReadsDerivesLikeTheMirror(t *testing.T) {
	t.Parallel()
	want := deriveFiles(t, extract.FixtureReader{Root: servedFixture})
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	repo, err := extract.ParseRepo("github.com/kubernetes/kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	tags, err := src.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for _, tag := range tags {
		var deepest string
		var walk func(dir string)
		walk = func(dir string) {
			es, err := (extract.FixtureReader{Root: servedFixture}).List(repo, tag.Commit, dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range es {
				if e.Type == "tree" {
					walk(e.Path)
				} else if strings.Count(e.Path, "/") > strings.Count(deepest, "/") {
					deepest = e.Path
				}
			}
		}
		walk("")
		if deepest != "" {
			if _, err := src.Read(repo, tag.Commit, deepest); err != nil {
				t.Fatal(err)
			}
			read++
		}
	}
	if read == 0 {
		t.Fatal("no deep file read")
	}
	requireSameFiles(t, want, deriveFiles(t, src))
}

// A one level listing with no directory in it is complete already.
func TestUpgradeSkipsAListingWithoutDirectories(t *testing.T) {
	t.Parallel()
	root := upgradeFixture(t)
	src, log := upgradeSource(t, root, nil)
	repo := upRepo(t)
	if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
		t.Fatal(err)
	}
	flat0, rec0 := log.counts()
	if _, err := src.List(repo, upCommit1, "pkg/a/b"); err != nil {
		t.Fatal(err)
	}
	if flat, rec := log.counts(); flat != flat0 || rec != rec0 {
		t.Fatalf("listing a leaf directory made requests: %d/%d then %d/%d", flat0, rec0, flat, rec)
	}
}

// A truncated upgrade is not used: the one level listing answers, directories
// below are read as before, and the recursive request is not repeated.
func TestUpgradeTruncatedKeepsTheOneLevelListing(t *testing.T) {
	t.Parallel()
	root := upgradeFixture(t)
	pkg := fixtureID(t, root, upCommit1, "pkg")
	src, log := upgradeSource(t, root, func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
		if rec && id == pkg {
			return 0, out[:1], true // a cut answer, which must not be stored
		}
		return 0, out, false
	})
	repo := upRepo(t)
	if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
		t.Fatal(err)
	}
	flat0, rec0 := log.counts()
	first, err := src.List(repo, upCommit1, "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if flat, rec := log.counts(); flat != flat0 || rec != rec0+1 {
		t.Fatalf("truncated upgrade: %d one level, %d recursive requests", flat-flat0, rec-rec0)
	}
	second, err := src.List(repo, upCommit1, "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if flat, rec := log.counts(); flat != flat0 || rec != rec0+1 {
		t.Fatalf("the second listing made requests: %d one level, %d recursive", flat-flat0, rec-rec0)
	}
	want := fixtureBFS(t, root, upCommit1, "pkg")
	if !reflect.DeepEqual(first, want["pkg"]) || !reflect.DeepEqual(second, want["pkg"]) {
		t.Fatalf("listing after truncation: %v, %v", first, second)
	}
	got, err := bfs(src, repo, upCommit1, "pkg")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("scan after truncation: %v %v", got, err)
	}
	if st := src.Stats(); st.TruncatedFallbacks != 1 {
		t.Fatalf("%+v", st)
	}
}

// edit returns a copy of out with the entry at p dropped (change nil) or
// changed.
func edit(out []map[string]string, p string, change func(map[string]string)) []map[string]string {
	var res []map[string]string
	found := false
	for _, e := range out {
		c := map[string]string{}
		for k, v := range e {
			c[k] = v
		}
		if c["path"] == p {
			found = true
			if change == nil {
				continue
			}
			change(c)
		}
		res = append(res, c)
	}
	if !found {
		panic("no entry " + p)
	}
	return res
}

// snapshot is the cached trees and the files of the disk cache.
func snapshot(t *testing.T, g *GitHubSource) string {
	t.Helper()
	g.mu.Lock()
	trees, err := json.Marshal(g.trees)
	shallow, err2 := json.Marshal(g.shallow)
	g.mu.Unlock()
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	var files []string
	if g.CacheDir != "" {
		err := filepath.Walk(g.CacheDir, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			files = append(files, p+"="+string(b))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return string(trees) + "\n" + string(shallow) + "\n" + strings.Join(files, "\n")
}

// An upgrade whose answer leaves out or alters an entry, at any depth, is an
// error: nothing of it is stored, and it never reads as a missing path.
func TestUpgradeRefusesAWrongAnswer(t *testing.T) {
	t.Parallel()
	blob := strings.Repeat("a", 40)
	cases := map[string]struct {
		path   string
		change func(map[string]string)
		want   string
	}{
		// pkg and pkg/a are held one level: the answer must equal them.
		"direct entry missing":  {"top.go", nil, "does not hash"},
		"direct entry changed":  {"top.go", func(e map[string]string) { e["sha"] = blob }, "does not hash"},
		"direct mode changed":   {"top.go", func(e map[string]string) { e["mode"] = "100755" }, "does not hash"},
		"direct entry renamed":  {"top.go", func(e map[string]string) { e["path"] = "tap.go" }, "does not hash"},
		"held ancestor omitted": {"a/z.go", nil, "does not hash"},
		// pkg/e and below were never read: only the hash can catch these.
		"nested omission":          {"e/f/g/h.go", nil, "does not hash"},
		"nested change":            {"e/f/g/h.go", func(e map[string]string) { e["sha"] = blob }, "does not hash"},
		"nested directory missing": {"a/c/d/leaf.go", nil, "does not hash"},
		"non-canonical mode":       {"e/f/g/h.go", func(e map[string]string) { e["mode"] = "100664" }, "does not hash"},
		"mode and type disagree":   {"e/f/g/h.go", func(e map[string]string) { e["type"] = "commit" }, "does not hash"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := upgradeFixture(t)
			pkg := fixtureID(t, root, upCommit1, "pkg")
			src, _ := upgradeSource(t, root, func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
				if rec && id == pkg {
					return 0, edit(out, tc.path, tc.change), false
				}
				return 0, out, false
			})
			src.CacheDir = t.TempDir()
			repo := upRepo(t)
			if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, src)
			got, err := src.List(repo, upCommit1, "pkg")
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("got %v, error %v", got, err)
			}
			if errors.Is(err, extract.ErrNotFound) {
				t.Fatalf("a refused answer reads as a missing path: %v", err)
			}
			if after := snapshot(t, src); after != before {
				t.Fatalf("the refused answer was stored\nbefore %s\nafter %s", before, after)
			}
		})
	}
}

// A tree id already held must be listed the same by a later recursive answer,
// also when the requested tree itself is new, whether the held listing came
// from a one level request or from the disk cache.
func TestRecursiveAnswerMustMatchHeldDescendants(t *testing.T) {
	t.Parallel()
	for _, fromDisk := range []bool{false, true} {
		for name, change := range map[string]func(map[string]string){
			"omitted": nil,
			"changed": func(e map[string]string) { e["sha"] = strings.Repeat("a", 40) },
		} {
			t.Run(fmt.Sprintf("disk=%v %s", fromDisk, name), func(t *testing.T) {
				t.Parallel()
				root := upgradeFixture(t)
				x := fixtureID(t, root, upCommit2, "x")
				var tampering sync.Map
				hook := func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
					if _, on := tampering.Load("on"); on && rec && id == x {
						return 0, edit(out, "a/z.go", change), false
					}
					return 0, out, false
				}
				repo := upRepo(t)
				src, _ := upgradeSource(t, root, hook)
				src.CacheDir = t.TempDir()
				// copy/a is the same tree as x/a: this holds it, not x.
				if _, err := src.Read(repo, upCommit2, "copy/a/b/deep.go"); err != nil {
					t.Fatal(err)
				}
				if fromDisk {
					second, _ := upgradeSource(t, root, hook)
					second.CacheDir = src.CacheDir
					src = second
					if _, err := src.Read(repo, upCommit2, "copy/a/b/deep.go"); err != nil {
						t.Fatal(err)
					}
					if src.Stats().DiskTreeHits == 0 {
						t.Fatal("nothing came from the disk cache")
					}
				}
				tampering.Store("on", true)
				before := snapshot(t, src)
				_, err := src.List(repo, upCommit2, "x")
				// dirTree reads the root, already held, before asking for x.
				if err == nil || !strings.Contains(err.Error(), "differs from the one already read") || errors.Is(err, extract.ErrNotFound) {
					t.Fatalf("error %v", err)
				}
				if after := snapshot(t, src); after != before {
					t.Fatalf("the refused answer was stored\nbefore %s\nafter %s", before, after)
				}
			})
		}
	}
}

// A failed upgrade fails the listing: no fallback to the one level listing,
// and never "not found", which would read as a removed path.
func TestUpgradeFetchFailurePropagates(t *testing.T) {
	t.Parallel()
	for _, status := range []int{404, 500, 502} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			root := upgradeFixture(t)
			pkg := fixtureID(t, root, upCommit1, "pkg")
			src, log := upgradeSource(t, root, func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
				if rec && id == pkg {
					return status, nil, false
				}
				return 0, out, false
			})
			repo := upRepo(t)
			if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
				t.Fatal(err)
			}
			flat0, _ := log.counts()
			got, err := src.List(repo, upCommit1, "pkg")
			if err == nil || got != nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("got %v, error %v", got, err)
			}
			if errors.Is(err, extract.ErrNotFound) {
				t.Fatalf("HTTP %d reads as a missing path: %v", status, err)
			}
			if flat, _ := log.counts(); flat != flat0 {
				t.Fatalf("fell back to %d one level requests", flat-flat0)
			}
			// Still owed: the next listing asks again and fails again.
			if _, err := src.List(repo, upCommit1, "pkg"); err == nil {
				t.Fatal("the second listing answered from the one level one")
			}
		})
	}
}

// The upgrade stays under the source's REST cap: refused, not skipped.
func TestUpgradeRespectsTheRESTCap(t *testing.T) {
	t.Parallel()
	root := upgradeFixture(t)
	src, _ := upgradeSource(t, root, nil)
	src.MaxRESTRequests = 5 // the commit and four trees
	repo := upRepo(t)
	if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
		t.Fatal(err)
	}
	if _, err := src.List(repo, upCommit1, "pkg"); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("listing over the cap: %v", err)
	}
}

// A warm disk cache answers a read and a scan without any tree request, and a
// disk entry is never treated as owing a recursive request.
func TestUpgradeWarmDiskCacheMakesNoTreeRequest(t *testing.T) {
	t.Parallel()
	root := upgradeFixture(t)
	repo := upRepo(t)
	dir := t.TempDir()
	run := func() (map[string][]extract.TreeEntry, *treeLog, *GitHubSource) {
		src, log := upgradeSource(t, root, nil)
		src.CacheDir = dir
		if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
			t.Fatal(err)
		}
		got, err := bfs(src, repo, upCommit1, "pkg")
		if err != nil {
			t.Fatal(err)
		}
		return got, log, src
	}
	first, _, _ := run()
	second, log, src := run()
	if flat, rec := log.counts(); flat != 0 || rec != 0 || src.Stats().TreeCalls != 0 {
		t.Fatalf("warm run made %d one level and %d recursive requests", flat, rec)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("warm run lists differently")
	}
}

// A one level answer that arrives after the recursive one neither replaces
// the listing nor marks the tree as owing a request again; one that disagrees
// is an error.
func TestLateOneLevelAnswerDoesNotUndoTheRecursiveOne(t *testing.T) {
	t.Parallel()
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong=%v", wrong), func(t *testing.T) {
			t.Parallel()
			root := upgradeFixture(t)
			pkg := fixtureID(t, root, upCommit1, "pkg")
			arrived, release := make(chan struct{}), make(chan struct{})
			src, log := upgradeSource(t, root, func(id string, rec bool, out []map[string]string) (int, []map[string]string, bool) {
				if !rec && id == pkg {
					close(arrived)
					<-release
					if wrong {
						return 0, edit(out, "top.go", nil), false
					}
				}
				return 0, out, false
			})
			repo := upRepo(t)
			late := make(chan error, 1)
			go func() {
				_, err := src.Read(repo, upCommit1, upDeep)
				late <- err
			}()
			<-arrived
			if _, err := src.List(repo, upCommit1, "pkg"); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, src)
			close(release)
			err := <-late
			if wrong {
				if err == nil || !strings.Contains(err.Error(), "differs from the one already read") || errors.Is(err, extract.ErrNotFound) {
					t.Fatalf("late wrong answer: %v", err)
				}
				if after := snapshot(t, src); after != before {
					t.Fatalf("the late answer was stored\nbefore %s\nafter %s", before, after)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			src.mu.Lock()
			owed := src.shallow[repo.Key+"\x00"+pkg]
			src.mu.Unlock()
			if owed {
				t.Fatal("the late answer marked the tree again")
			}
			flat0, rec0 := log.counts()
			if _, err := bfs(src, repo, upCommit1, "pkg"); err != nil {
				t.Fatal(err)
			}
			if flat, rec := log.counts(); flat != flat0 || rec != rec0 {
				t.Fatalf("the scan made requests: %d one level, %d recursive", flat-flat0, rec-rec0)
			}
		})
	}
}

// Concurrent reads and listings agree with the fixture (run with -race), and
// the subtree is asked for recursively once.
func TestUpgradeConcurrentReadsAndListings(t *testing.T) {
	t.Parallel()
	root := upgradeFixture(t)
	repo := upRepo(t)
	want := fixtureBFS(t, root, upCommit1, "pkg")
	for round := 0; round < 10; round++ {
		src, log := upgradeSource(t, root, nil)
		src.CacheDir = t.TempDir()
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, err := src.Read(repo, upCommit1, upDeep); err != nil {
					errs <- err
				}
			}()
			go func() {
				defer wg.Done()
				got, err := src.List(repo, upCommit1, "pkg")
				if err != nil {
					errs <- err
				} else if !reflect.DeepEqual(got, want["pkg"]) {
					errs <- fmt.Errorf("listing %v", got)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		if _, rec := log.counts(); rec != 1 {
			t.Fatalf("%d recursive requests", rec)
		}
		got, err := bfs(src, repo, upCommit1, "pkg")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("scan: %v %v", got, err)
		}
	}
}

// Over anonymous git (organisations that refuse REST requests) a one level
// listing is upgraded the same way and its listings pass the hash check.
func TestUpgradeOverGit(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	srv := newIPAllowServer(t)
	g := ipAllowSource(t, srv, repo.Base)
	ref := upRepo(t)
	ctx := context.Background()
	flat, err := g.list(ctx, ref, repo.C1, "docs", false)
	if err != nil {
		t.Fatal(err)
	}
	before := g.Stats().GitReads
	listed, err := g.List(ref, repo.C1, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Stats().GitReads; got != before+1 {
		t.Fatalf("upgrade made %d git reads", got-before)
	}
	if !reflect.DeepEqual(flat, listed) {
		t.Fatalf("listings differ: %v and %v", flat, listed)
	}
	if _, err := g.List(ref, repo.C1, "docs/sub"); err != nil {
		t.Fatal(err)
	}
	if got := g.Stats().GitReads; got != before+1 {
		t.Fatalf("a directory below made %d more git reads", got-before-1)
	}
	if st := g.Stats(); st.RESTCalls != 0 || st.APIRequests != 1 {
		t.Fatalf("%+v", st)
	}
}
