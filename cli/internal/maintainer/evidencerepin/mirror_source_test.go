// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// --- a local upstream: bare repositories served over file:// ---

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z")
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type upstream struct {
	t     *testing.T
	owner string
	name  string
	bare  string
	work  string
	tags  map[string]string // tag -> commit
}

func newUpstream(t *testing.T, root, owner, name string) *upstream {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bare := filepath.Join(root, "github.com", owner, name+".git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, bare, "init", "-q", "--bare", "-b", "main")
	git(t, bare, "config", "uploadpack.allowFilter", "true")
	git(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	work := filepath.Join(t.TempDir(), "work")
	git(t, filepath.Dir(bare), "clone", "-q", bare, work)
	git(t, work, "checkout", "-q", "-b", "main")
	return &upstream{t: t, owner: owner, name: name, bare: bare, work: work, tags: map[string]string{}}
}

// commit replaces the tracked files by exactly the given set (a nil value
// deletes a file) and returns the commit.
func (u *upstream) commit(files map[string]*string) string {
	u.t.Helper()
	for name, content := range files {
		p := filepath.Join(u.work, filepath.FromSlash(name))
		if content == nil {
			_ = os.Remove(p)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			u.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(*content), 0o644); err != nil {
			u.t.Fatal(err)
		}
	}
	git(u.t, u.work, "add", "-A")
	git(u.t, u.work, "commit", "-q", "--allow-empty", "-m", "c")
	git(u.t, u.work, "push", "-q", "-f", "origin", "main")
	return git(u.t, u.work, "rev-parse", "HEAD")
}

func (u *upstream) tag(name string) string {
	u.t.Helper()
	git(u.t, u.work, "tag", "-f", name)
	git(u.t, u.work, "push", "-q", "-f", "origin", "refs/tags/"+name)
	u.tags[name] = git(u.t, u.work, "rev-parse", "HEAD")
	return u.tags[name]
}

func s(v string) *string { return &v }

func (u *upstream) show(commit, path string) ([]byte, bool) {
	cmd := exec.Command("git", "show", commit+":"+path)
	cmd.Dir = u.work
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	return out, err == nil
}

func (u *upstream) key() string { return "github.com/" + u.owner + "/" + u.name }

// --- the same data served as GitHub would serve it (the HTTP source) ---

type fakeRelease struct {
	Tag        string
	Prerelease bool
}

type httpWorld struct {
	ups      map[string]*upstream // owner/repo
	releases map[string][]fakeRelease
	calls    atomic.Int32
}

func (w *httpWorld) Fetch(_ context.Context, path string) ([]byte, int, error) {
	w.calls.Add(1)
	p, rawQuery, _ := strings.Cut(path, "?")
	parts := strings.Split(p, "/") // "", repos, owner, repo, ...
	q, _ := url.ParseQuery(rawQuery)
	key := parts[2] + "/" + parts[3]
	up := w.ups[key]
	if up == nil {
		return nil, 404, nil
	}
	switch {
	case parts[4] == "releases":
		per, _ := strconv.Atoi(q.Get("per_page"))
		page := 1
		if v := q.Get("page"); v != "" {
			page, _ = strconv.Atoi(v)
		}
		list := w.releases[key]
		out := []map[string]any{}
		for i := (page - 1) * per; i < len(list) && i < page*per; i++ {
			out = append(out, map[string]any{"id": 1000 - i, "tag_name": list[i].Tag, "draft": false, "prerelease": list[i].Prerelease})
		}
		raw, _ := json.Marshal(out)
		return raw, 200, nil
	case parts[4] == "tags":
		var names []string
		for name := range up.tags {
			names = append(names, name)
		}
		sort.Strings(names)
		per, _ := strconv.Atoi(q.Get("per_page"))
		page := 1
		if v := q.Get("page"); v != "" {
			page, _ = strconv.Atoi(v)
		}
		out := []map[string]string{}
		for i := (page - 1) * per; i < len(names) && i < page*per; i++ {
			out = append(out, map[string]string{"name": names[i]})
		}
		raw, _ := json.Marshal(out)
		return raw, 200, nil
	case parts[4] == "git" && parts[5] == "ref":
		tag, _ := url.PathUnescape(strings.Join(parts[7:], "/"))
		commit, ok := up.tags[tag]
		if !ok {
			return nil, 404, nil
		}
		raw, _ := json.Marshal(map[string]any{"object": map[string]string{"sha": commit, "type": "commit"}})
		return raw, 200, nil
	}
	return nil, 500, nil
}

// GitRefs serves the repository's refs exactly as "git ls-remote" prints
// them, so the HTTP side derives tag lines from real ls-remote output.
func (w *httpWorld) GitRefs(_ context.Context, owner, repo string) (evidencerepin.RefListing, error) {
	w.calls.Add(1)
	up := w.ups[owner+"/"+repo]
	if up == nil {
		return evidencerepin.RefListing{}, fmt.Errorf("no such repository")
	}
	cmd := exec.Command("git", "ls-remote", up.bare)
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		return evidencerepin.RefListing{}, err
	}
	return evidencerepin.ParseLsRemote(out)
}

func (w *httpWorld) FetchBlob(_ context.Context, path string) sourcecapture.FetchResult {
	w.calls.Add(1)
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	up := w.ups[parts[0]+"/"+parts[1]]
	if up == nil {
		return sourcecapture.FetchResult{Kind: "HTTP_STATUS", StatusCode: 404}
	}
	data, ok := up.show(parts[2], parts[3])
	if !ok {
		return sourcecapture.FetchResult{Kind: "HTTP_STATUS", StatusCode: 404}
	}
	return sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: data}
}

// --- a release client for the mirror ---

type releaseClient struct {
	byRepo    map[string][]fakeRelease
	truncated map[string]bool
}

func (c releaseClient) List(_ context.Context, repo factorymirror.Repo, _ string) (factorymirror.ReleaseResult, error) {
	list, ok := c.byRepo[repo.Key()]
	if !ok {
		return factorymirror.ReleaseResult{}, factorymirror.ErrReleasesNotFound
	}
	res := factorymirror.ReleaseResult{Truncated: c.truncated[repo.Key()]}
	// Newer releases have larger ids, as on GitHub.
	for i, r := range list {
		res.Items = append(res.Items, factorymirror.Release{ID: int64(1000 - i), Tag: r.Tag, Prerelease: r.Prerelease})
	}
	return res, nil
}

// --- the fixture ---

type world struct {
	t       *testing.T
	root    string
	state   string
	widget  *upstream
	gizmo   *upstream
	rel     releaseClient
	c100    string
	c101    string
	c110    string
	cites   []evidencerepin.Citation
	rules   string
	allWant []factorymirror.Want
}

const (
	aOld = "alpha\nbeta\ngamma\n"
	eOld = "e1\ne2\n"
)

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, root: t.TempDir(), state: filepath.Join(t.TempDir(), "state")}
	w.widget = newUpstream(t, w.root, "acme", "widget")
	w.gizmo = newUpstream(t, w.root, "acme", "gizmo")

	w.widget.commit(map[string]*string{"a.txt": s(aOld), "b.txt": s("b\n"), "c.txt": s("c1\nc2\n"), "d.txt": s("d\n"), "e.txt": s(eOld)})
	w.c100 = w.widget.tag("v1.0.0")
	// v1.0.1: a.txt changed outside the cited span, b.txt untouched, c.txt
	// changed inside it, d.txt deleted, e.txt shifted down one line.
	w.c101 = w.widget.commit(map[string]*string{"a.txt": s("ALPHA\nbeta\ngamma\n"), "c.txt": s("c1\nCHANGED\n"), "d.txt": nil, "e.txt": s("new\ne1\ne2\n")})
	w.widget.tag("v1.0.1")
	w.c110 = w.widget.commit(map[string]*string{"b.txt": s("b changed in the next line\n")})
	w.widget.tag("v1.1.0")

	// gizmo publishes no GitHub Releases: only tags.
	g1 := w.gizmo.commit(map[string]*string{"f.txt": s("f1\n")})
	w.gizmo.tag("v0.1.0")
	w.gizmo.commit(map[string]*string{"f.txt": s("f2\n")})
	w.gizmo.tag("v0.2.0")

	w.rel = releaseClient{byRepo: map[string][]fakeRelease{
		"github.com/acme/widget": {{Tag: "v1.1.0"}, {Tag: "v1.0.1"}, {Tag: "v1.0.0"}},
		"github.com/acme/gizmo":  {},
	}, truncated: map[string]bool{}}

	cite := func(id, path, pinned string, commit string, start, end int, up *upstream) evidencerepin.Citation {
		return evidencerepin.Citation{
			RulePack: "p", RuleID: up.name + ".rule-" + id, Project: up.name, SourceID: up.name + "-1-0-0-" + id,
			Owner: up.owner, Repo: up.name, Path: path, OldCommit: commit, OldDigest: sourcecorpus.SHA([]byte(pinned)),
			StartLine: start, EndLine: end,
		}
	}
	w.cites = []evidencerepin.Citation{
		cite("a", "a.txt", aOld, w.c100, 2, 3, w.widget),             // span identical on the line
		cite("b", "b.txt", "b\n", w.c100, 1, 1, w.widget),            // file identical in v1.0.1
		cite("c", "c.txt", "c1\nc2\n", w.c100, 2, 2, w.widget),       // content changed
		cite("d", "d.txt", "d\n", w.c100, 1, 1, w.widget),            // path gone
		cite("e", "e.txt", eOld, w.c100, 1, 2, w.widget),             // span moved
		cite("g", "f.txt", "f1\n", g1, 1, 1, w.gizmo),                // tags-only repository
		cite("z", "a.txt", "wrong digest\n", w.c100, 1, 1, w.widget), // corpus digest mismatch
	}
	return w
}

// wants lists every (commit, path) the citations can need: the pinned
// commit and every commit a baseline could be.
func (w *world) wants() []factorymirror.Want {
	byRepo := map[string]map[string]map[string]bool{}
	add := func(repo, commit, path string) {
		if byRepo[repo] == nil {
			byRepo[repo] = map[string]map[string]bool{}
		}
		if byRepo[repo][commit] == nil {
			byRepo[repo][commit] = map[string]bool{}
		}
		byRepo[repo][commit][path] = true
	}
	for _, c := range w.cites {
		up := w.widget
		if c.Repo == "gizmo" {
			up = w.gizmo
		}
		add(up.key(), c.OldCommit, c.Path)
		for _, commit := range up.tags {
			add(up.key(), commit, c.Path)
		}
	}
	var out []factorymirror.Want
	for repo, commits := range byRepo {
		for commit, paths := range commits {
			want := factorymirror.Want{Repo: repo, Commit: commit}
			for p := range paths {
				want.Paths = append(want.Paths, p)
			}
			sort.Strings(want.Paths)
			out = append(out, want)
		}
	}
	return out
}

func (w *world) mirror(wants []factorymirror.Want) {
	w.t.Helper()
	res, err := factorymirror.Run(context.Background(), factorymirror.Options{
		StateDir: w.state,
		Repos: []factorymirror.Repo{
			{Host: "github.com", Owner: "acme", Name: "widget"},
			{Host: "github.com", Owner: "acme", Name: "gizmo"},
		},
		Wants: wants, RemoteBase: "file://" + w.root + "/", AllowFileRemote: true,
		Releases: w.rel, Concurrency: 2,
	})
	if err != nil {
		w.t.Fatalf("mirror run: %v", err)
	}
	if res.Failed != 0 {
		w.t.Fatalf("mirror run failed: %+v", res)
	}
}

func (w *world) httpWorld() *httpWorld {
	h := &httpWorld{ups: map[string]*upstream{"acme/widget": w.widget, "acme/gizmo": w.gizmo}, releases: map[string][]fakeRelease{}}
	h.releases["acme/widget"] = w.rel.byRepo["github.com/acme/widget"]
	h.releases["acme/gizmo"] = w.rel.byRepo["github.com/acme/gizmo"]
	return h
}

type blobFunc func(context.Context, string) sourcecapture.FetchResult

func (f blobFunc) Fetch(ctx context.Context, p string) sourcecapture.FetchResult { return f(ctx, p) }

func fixedNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

func (w *world) httpWorklist(mode string) evidencerepin.Worklist {
	w.t.Helper()
	h := w.httpWorld()
	wl, err := evidencerepin.BuildWorklistWithBaseline(context.Background(), w.cites, nil, 0, mustState(w.t), h, blobFunc(h.FetchBlob), fixedNow, evidencerepin.DefaultMaxAge, nil, mode)
	if err != nil {
		w.t.Fatal(err)
	}
	return wl
}

func mustState(t *testing.T) *evidencerepin.State {
	t.Helper()
	st, err := evidencerepin.LoadState("")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func (w *world) mirrorWorklist(mode string) (evidencerepin.Worklist, evidencerepin.MirrorWants) {
	w.t.Helper()
	src, err := factorymirror.OpenRepinSource(w.state)
	if err != nil {
		w.t.Fatal(err)
	}
	wl, wants, err := evidencerepin.BuildMirrorWorklist(context.Background(), w.cites, nil, 0, src, fixedNow, evidencerepin.DefaultMaxAge, nil, mode)
	if err != nil {
		w.t.Fatal(err)
	}
	return wl, wants
}

// verdicts is the part of a worklist that must not depend on the source.
func verdicts(wl evidencerepin.Worklist) []string {
	var out []string
	for _, c := range wl.Citations {
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|new=%s %d-%d|%s|%s|%s|%s|%s|%s|%s", c.RuleID, c.SourceID, c.Class, c.Detail, c.NewCommit, c.NewStart, c.NewEnd,
			c.Baseline, c.BaselineTag, c.BaselineLine, c.PinnedTag, c.LineStatus, c.Resolution, c.BaselineNote))
	}
	for _, r := range wl.Repos {
		out = append(out, fmt.Sprintf("repo %s/%s %s %s %s %s", r.Owner, r.Repo, r.Status, r.CurrentTag, r.CurrentCommit, r.Resolution))
	}
	for _, l := range wl.Lines {
		out = append(out, fmt.Sprintf("line %s/%s %s %s %s %s %s", l.Owner, l.Repo, l.Prefix, l.Line, l.Status, l.Tag, l.Commit))
	}
	sort.Strings(out)
	return out
}

func classOf(wl evidencerepin.Worklist, sourceID string) evidencerepin.ClassResult {
	for _, c := range wl.Citations {
		if strings.HasSuffix(c.SourceID, sourceID) {
			return c
		}
	}
	panic("no citation " + sourceID)
}

func TestMirrorAndHTTPClassifyIdentically(t *testing.T) {
	w := newWorld(t)
	w.mirror(w.wants())
	for _, mode := range []string{evidencerepin.BaselineModeReleaseLine, evidencerepin.BaselineModeLatest} {
		fromHTTP := w.httpWorklist(mode)
		fromMirror, wants := w.mirrorWorklist(mode)
		if len(wants.Wants) != 0 {
			t.Fatalf("%s: a warm mirror must miss nothing: %+v", mode, wants)
		}
		a, b := verdicts(fromHTTP), verdicts(fromMirror)
		if strings.Join(a, "\n") != strings.Join(b, "\n") {
			t.Fatalf("%s: mirror and HTTP disagree\nHTTP:\n%s\nMIRROR:\n%s", mode, strings.Join(a, "\n"), strings.Join(b, "\n"))
		}
		if fromMirror.Summary.Pending != 0 {
			t.Fatalf("%s: nothing may be pending: %+v", mode, fromMirror.Summary)
		}
		if fromMirror.Source != "mirror" || fromMirror.Scope.Source != "mirror" || fromMirror.Mirror == nil || fromMirror.Mirror.IndexDigest == "" || fromMirror.Mirror.IndexUpdatedAt == "" {
			t.Fatalf("%s: mirror provenance missing: %+v", mode, fromMirror.Mirror)
		}
		if fromHTTP.Source != "" {
			t.Fatalf("the HTTP source records no source: %q", fromHTTP.Source)
		}
	}
	// The fixture exercises every class.
	wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	for id, class := range map[string]string{"-a": evidencerepin.ClassSpanIdentical, "-b": evidencerepin.ClassFileIdentical, "-c": evidencerepin.ClassContentChanged,
		"-d": evidencerepin.ClassPathGone, "-e": evidencerepin.ClassSpanMoved, "-z": evidencerepin.ClassCorpusDigestMismatch} {
		got := classOf(wl, id)
		if got.Class != class {
			t.Errorf("%s: class %s, want %s (%+v)", id, got.Class, class, got)
		}
		if got.Baseline != evidencerepin.BaselineReleaseLine || got.BaselineTag != "v1.0.1" || got.PinnedTag != "v1.0.0" {
			t.Errorf("%s: unexpected baseline %+v", id, got)
		}
	}
	// A tags-only repository is compared on the line of its pinned tag
	// (v0.1.0, the newest release tag of line 0.1), not with the tags
	// fallback's v0.2.0.
	g := classOf(wl, "-g")
	if g.Baseline != evidencerepin.BaselineTagLine || g.Resolution != "" || g.BaselineTag != "v0.1.0" || g.PinnedTag != "v0.1.0" ||
		g.NewCommit != w.gizmo.tags["v0.1.0"] || g.Class != evidencerepin.ClassNoNewRelease {
		t.Errorf("tags-only repository on its tag line: %+v", g)
	}
	latest, _ := w.mirrorWorklist(evidencerepin.BaselineModeLatest)
	if g := classOf(latest, "-g"); g.Resolution != "tag_fallback" || g.NewCommit != w.gizmo.tags["v0.2.0"] {
		t.Errorf("tags-only repository under --baseline latest: %+v", g)
	}
}

func TestMirrorMakesNoNetworkRequest(t *testing.T) {
	w := newWorld(t)
	w.mirror(w.wants())

	var requests atomic.Int32
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, fmt.Errorf("network is forbidden: %s", r.URL)
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	failing := &failingAPI{}

	rules := filepath.Join(t.TempDir(), "rules.json")
	writeRules(t, rules, w.cites)
	out := filepath.Join(t.TempDir(), "worklist.json")
	wantsOut := filepath.Join(t.TempDir(), "wants.json")
	var stdout, stderr strings.Builder
	code := evidencerepin.RunWith(context.Background(),
		[]string{"repin", "--source", "mirror", "--mirror-state", w.state, "--rules", rules, "--output", out, "--wants-out", wantsOut},
		&stdout, &stderr, evidencerepin.Deps{API: failing, Blobs: failingBlobs{failing}, Now: fixedNow, OpenMirror: factorymirror.OpenRepinSource})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if requests.Load() != 0 || failing.calls.Load() != 0 {
		t.Fatalf("a warm mirror must make no request: http=%d fetchers=%d", requests.Load(), failing.calls.Load())
	}
	var wl evidencerepin.Worklist
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &wl); err != nil || wl.Summary.Classified != len(w.cites) || wl.Source != "mirror" {
		t.Fatalf("bad worklist (%v): %+v", err, wl.Summary)
	}
	rawWants, err := os.ReadFile(wantsOut)
	if err != nil || strings.TrimSpace(string(rawWants)) != "{\n  \"wants\": []\n}" {
		t.Fatalf("a complete run writes an empty wants file: %q %v", rawWants, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingAPI struct{ calls atomic.Int32 }

func (f *failingAPI) Fetch(context.Context, string) ([]byte, int, error) {
	f.calls.Add(1)
	return nil, 0, fmt.Errorf("network is forbidden")
}

type failingBlobs struct{ api *failingAPI }

func (f failingBlobs) Fetch(context.Context, string) sourcecapture.FetchResult {
	f.api.calls.Add(1)
	return sourcecapture.FetchResult{Kind: "TRANSPORT_ERROR"}
}

func writeRules(t *testing.T, path string, cites []evidencerepin.Citation) {
	t.Helper()
	byRule := map[string][]map[string]any{}
	var order []string
	project := map[string]string{}
	for _, c := range cites {
		if _, ok := byRule[c.RuleID]; !ok {
			order = append(order, c.RuleID)
		}
		project[c.RuleID] = c.Project
		byRule[c.RuleID] = append(byRule[c.RuleID], map[string]any{
			"id": c.SourceID, "url": "https://github.com/" + c.Owner + "/" + c.Repo + "/blob/" + c.OldCommit + "/" + c.Path,
			"revision": c.OldCommit, "contentDigest": c.OldDigest, "startLine": c.StartLine, "endLine": c.EndLine,
		})
	}
	var entries []map[string]any
	for _, id := range order {
		entries = append(entries, map[string]any{"project": project[id], "rule": map[string]any{"id": id, "evidence": map[string]any{
			"reviewedAt": "2026-09-12T10:00:00Z", "validUntil": "2026-12-11T10:00:00Z", "state": "active", "sources": byRule[id],
		}}})
	}
	raw, _ := json.Marshal(map[string]any{"schema": "prufyx.io/rule-pack/v1", "revision": "test", "entries": entries})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorMissingBlobIsPendingAndTwoStepFlowConverges(t *testing.T) {
	w := newWorld(t)
	// Refs and release metadata only: no file contents were requested.
	w.mirror(nil)
	wl, wants := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	// A path that does not exist at the baseline needs no file contents,
	// nor does a citation whose pinned tag is its line's newest release.
	if wl.Summary.Pending != len(w.cites)-2 || classOf(wl, "-d").Class != evidencerepin.ClassPathGone || classOf(wl, "-g").Class != evidencerepin.ClassNoNewRelease {
		t.Fatalf("every other citation needs file contents, got %+v", wl.Summary)
	}
	for _, c := range wl.Citations {
		if c.Class == evidencerepin.ClassPending && !strings.Contains(c.Detail, "wants") {
			t.Fatalf("pending without a note naming the wants: %+v", c)
		}
	}
	// The wants cover the baseline AND the pinned commit of every path.
	covered := map[string]bool{}
	for _, want := range wants.Wants {
		for _, p := range want.Paths {
			covered[want.Commit+":"+p] = true
		}
	}
	for _, c := range w.cites {
		if c.Path == "d.txt" || c.Repo == "gizmo" {
			continue // deleted at the baseline, or pinned at its line's newest tag: no contents to read
		}
		if !covered[c.OldCommit+":"+c.Path] {
			t.Errorf("pinned file %s@%s is not in the wants", c.Path, c.OldCommit)
		}
		if c.Repo == "widget" && !covered[w.c101+":"+c.Path] {
			t.Errorf("baseline file %s@%s is not in the wants", c.Path, w.c101)
		}
	}
	// Second step: the mirror materializes them, repin converges.
	var mw []factorymirror.Want
	for _, want := range wants.Wants {
		mw = append(mw, factorymirror.Want{Repo: want.Repo, Commit: want.Commit, Paths: want.Paths})
	}
	w.mirror(mw)
	wl2, wants2 := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	if wl2.Summary.Pending != 0 || len(wants2.Wants) != 0 {
		t.Fatalf("the two-step flow must converge: %+v %+v", wl2.Summary, wants2)
	}
	if strings.Join(verdicts(wl2), "\n") != strings.Join(verdicts(w.httpWorklist(evidencerepin.BaselineModeReleaseLine)), "\n") {
		t.Fatal("converged mirror worklist differs from the HTTP one")
	}
}

func TestMirrorWantsAreDeterministic(t *testing.T) {
	w := newWorld(t)
	w.mirror(nil)
	_, a := w.mirrorWorklist(evidencerepin.BaselineModeLatest)
	_, b := w.mirrorWorklist(evidencerepin.BaselineModeLatest)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) || len(a.Wants) == 0 {
		t.Fatalf("wants must be deterministic and non-empty: %s vs %s", ja, jb)
	}
}

func TestMirrorOnlyOneSideMissingNamesThatFile(t *testing.T) {
	w := newWorld(t)
	// Only the pinned commit's files are materialized; the baseline's are not.
	var pinned []factorymirror.Want
	for _, want := range w.wants() {
		if want.Commit == w.c100 {
			pinned = append(pinned, want)
		}
	}
	w.mirror(pinned)
	wl, wants := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	got := classOf(wl, "-a")
	if got.Class != evidencerepin.ClassPending || !strings.Contains(got.Detail, w.c101) || !strings.Contains(got.Detail, "a.txt") {
		t.Fatalf("the note must name the missing baseline file: %+v", got)
	}
	for _, want := range wants.Wants {
		if want.Commit == w.c100 {
			t.Fatalf("an available pinned file must not be requested again: %+v", want)
		}
	}
}

func TestMirrorFrozenRepositoryIsPending(t *testing.T) {
	w := newWorld(t)
	w.mirror(w.wants())
	// Upstream moves a tag the mirror already recorded.
	git(t, w.widget.work, "tag", "-f", "v1.0.1", w.c110)
	git(t, w.widget.work, "push", "-q", "-f", "origin", "refs/tags/v1.0.1")
	w.mirror(w.wants())

	wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	for _, c := range wl.Citations {
		switch c.Repo {
		case "widget":
			if c.Class != evidencerepin.ClassPending || !strings.Contains(c.Detail, "frozen") {
				t.Fatalf("a frozen repository must be pending with its reason: %+v", c)
			}
		default:
			if c.Class == evidencerepin.ClassPending {
				t.Fatalf("an unrelated repository must still classify: %+v", c)
			}
		}
	}
	for _, r := range wl.Repos {
		if r.Repo == "widget" && r.Status == "RESOLVED" {
			t.Fatalf("a frozen repository must not resolve: %+v", r)
		}
	}
	// After a person acknowledges the alarm the repository classifies again.
	if _, err := factorymirror.Acknowledge(w.state, "acme/widget", "", "reviewed", time.Now); err != nil {
		t.Fatal(err)
	}
	w.mirror(w.wants())
	wl, _ = w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	if wl.Summary.Pending != 0 {
		t.Fatalf("an acknowledged repository classifies again: %+v", wl.Summary)
	}
}

func TestMirrorUnknownOrTruncatedReleases(t *testing.T) {
	t.Run("unknown releases leave the repository pending", func(t *testing.T) {
		w := newWorld(t)
		w.rel.byRepo = map[string][]fakeRelease{} // 404: no metadata, status unknown
		w.mirror(w.wants())
		wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
		for _, c := range wl.Citations {
			if c.Class != evidencerepin.ClassPending || !strings.Contains(c.Detail, "release") {
				t.Fatalf("unknown release metadata is never 'unchanged': %+v", c)
			}
		}
	})
	t.Run("truncated releases derive no line and keep the latest baseline", func(t *testing.T) {
		w := newWorld(t)
		w.rel.truncated["github.com/acme/widget"] = true
		w.mirror(w.wants())
		wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
		got := classOf(wl, "-b")
		if got.Baseline != evidencerepin.BaselineLatest || got.BaselineTag != "v1.1.0" || got.BaselineNote == "" || got.Class != evidencerepin.ClassContentChanged {
			t.Fatalf("a truncated list must not derive a line: %+v", got)
		}
		for _, line := range wl.Lines {
			if line.Owner == "acme" && line.Repo == "widget" {
				t.Fatalf("no release line may be derived for the truncated repository: %+v", line)
			}
		}
	})
	t.Run("stale releases leave the repository pending", func(t *testing.T) {
		w := newWorld(t)
		w.mirror(w.wants())
		editIndex(t, w.state, func(repo map[string]any) {
			repo["releases"].(map[string]any)["fetchedAt"] = time.Now().Add(-(factorymirror.DefaultReleasesTTL + 6*time.Hour)).UTC().Format(time.RFC3339)
		})
		wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeLatest)
		if c := classOf(wl, "-a"); c.Class != evidencerepin.ClassPending {
			t.Fatalf("stale release metadata must not classify: %+v", c)
		}
	})
}

// editIndex rewrites every repository record of the mirror index.
func editIndex(t *testing.T, state string, edit func(repo map[string]any)) {
	t.Helper()
	path := filepath.Join(state, "mirror-index.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["repos"].(map[string]any) {
		edit(r.(map[string]any))
	}
	raw, _ = json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorFreshnessIsTheMirrorsNotTheRuns(t *testing.T) {
	w := newWorld(t)
	w.mirror(w.wants())
	checked := time.Now().Add(-100 * time.Hour).UTC().Truncate(time.Second)
	editIndex(t, w.state, func(repo map[string]any) {
		repo["lastCheckedAt"] = checked.Format(time.RFC3339)
	})
	wl, _ := w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	for _, r := range wl.Repos {
		at, ok := r.EvidenceAt()
		if r.Source != "mirror" || !ok || !at.Equal(checked) || !r.Stale || r.ResolvedAt != checked.Format(time.RFC3339) {
			t.Fatalf("a repository read from an old mirror must carry the mirror's time: %+v", r)
		}
	}
	for _, l := range wl.Lines {
		if at, ok := l.EvidenceAt(); !ok || !at.Equal(checked) || !l.Stale {
			t.Fatalf("a line must carry the mirror's time: %+v", l)
		}
	}
	for _, c := range wl.Citations {
		if !c.Stale {
			t.Fatalf("citations from a stale mirror must be stale: %+v", c)
		}
	}
	if wl.Summary.OldestResolvedAt != checked.Format(time.RFC3339) {
		t.Fatalf("oldest resolution must be the mirror's: %q", wl.Summary.OldestResolvedAt)
	}

	// A fresh check restores freshness.
	w.mirror(nil)
	wl, _ = w.mirrorWorklist(evidencerepin.BaselineModeReleaseLine)
	for _, r := range wl.Repos {
		if r.Stale {
			t.Fatalf("a freshly mirrored repository is not stale: %+v", r)
		}
	}
}

func TestMirrorFlagValidation(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.json")
	w := newWorld(t)
	writeRules(t, rules, w.cites)
	open := factorymirror.OpenRepinSource
	cases := map[string][]string{
		"mirror without a state":   {"--source", "mirror"},
		"state with mirror":        {"--source", "mirror", "--mirror-state", w.state, "--state", filepath.Join(t.TempDir(), "s.json")},
		"mirror-state with http":   {"--mirror-state", w.state},
		"wants-out with http":      {"--wants-out", filepath.Join(t.TempDir(), "w.json")},
		"unknown source":           {"--source", "ftp"},
		"unmirrored state is read": {"--source", "mirror", "--mirror-state", filepath.Join(t.TempDir(), "absent-index-is-empty")},
	}
	for name, extra := range cases {
		args := append([]string{"repin", "--rules", rules, "--output", filepath.Join(t.TempDir(), "o.json")}, extra...)
		var stdout, stderr strings.Builder
		code := evidencerepin.RunWith(context.Background(), args, &stdout, &stderr, evidencerepin.Deps{API: &failingAPI{}, Blobs: failingBlobs{&failingAPI{}}, Now: fixedNow, OpenMirror: open})
		if name == "unmirrored state is read" {
			// An empty mirror is valid input: everything is pending.
			if code != 0 || !strings.Contains(stdout.String(), "0 classified") {
				t.Fatalf("%s: %d %s %s", name, code, stdout.String(), stderr.String())
			}
			continue
		}
		if code != 2 {
			t.Fatalf("%s: expected rejection, got %d", name, code)
		}
	}
	// A build without a mirror opener rejects the source.
	var stdout, stderr strings.Builder
	code := evidencerepin.Run(context.Background(), []string{"repin", "--rules", rules, "--output", filepath.Join(t.TempDir(), "o.json"), "--source", "mirror", "--mirror-state", w.state}, &stdout, &stderr, &failingAPI{}, failingBlobs{&failingAPI{}}, fixedNow, nil)
	if code != 2 {
		t.Fatalf("a build without a mirror must reject --source mirror: %d", code)
	}
}
