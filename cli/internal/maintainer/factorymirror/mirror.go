// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Repo actions reported by Run.
const (
	ActionCloned    = "cloned"
	ActionFetched   = "fetched"
	ActionUnchanged = "unchanged"
	ActionError     = "error"
)

// Options configures one mirror run.
type Options struct {
	StateDir string
	Repos    []Repo
	// Wants lists pinned files to make available offline after the
	// repositories are up to date (see Materialize).
	Wants []Want
	// RemoteBase is prepended to host/owner/name.git; default "https://".
	// With the default git runner only an https:// base is accepted (and
	// file:// when AllowFileRemote is set); anything else, such as a
	// transport helper like "ext::", is rejected.
	RemoteBase string
	// AllowFileRemote additionally permits a file:// RemoteBase. It exists
	// for tests of the command line, not for production runs.
	AllowFileRemote bool
	// Concurrency bounds simultaneous repositories (default 4, max 16).
	Concurrency int
	// Git defaults to ExecGit allowing only the scheme of RemoteBase.
	Git GitRunner
	// OfflineGit is used for read-only probes; default ExecGit{Offline: true}.
	OfflineGit GitRunner
	// Releases supplies release metadata; nil marks releases unknown.
	Releases ReleaseClient
	Now      func() time.Time
	// LsRemoteTimeout and GitTimeout bound single git invocations.
	LsRemoteTimeout time.Duration
	GitTimeout      time.Duration
	LockStaleAfter  time.Duration
	// ReleasesTTL is how long release metadata may be called "known" when
	// it cannot be revalidated (no credential); default 24h.
	ReleasesTTL time.Duration
	// Force fetches even when the remote fingerprint is unchanged.
	Force    bool
	Progress io.Writer
}

// RepoResult is the per-repository outcome of a run.
type RepoResult struct {
	Repo           string `json:"repo"`
	Action         string `json:"action"`
	Error          string `json:"error,omitempty"`
	NewAlarms      int    `json:"newAlarms,omitempty"`
	ReleasesStatus string `json:"releasesStatus,omitempty"`
}

// WantResult is the per-want outcome of Materialize.
type WantResult struct {
	Repo     string   `json:"repo"`
	Commit   string   `json:"commit"`
	Fetched  int      `json:"blobsFetched"`
	Missing  []string `json:"missingPaths,omitempty"`
	Error    string   `json:"error,omitempty"`
	Complete bool     `json:"complete"`
}

// Result summarises a run.
type Result struct {
	Repos      []RepoResult `json:"repos"`
	Wants      []WantResult `json:"wants,omitempty"`
	Cloned     int          `json:"cloned"`
	Fetched    int          `json:"fetched"`
	Unchanged  int          `json:"unchanged"`
	Failed     int          `json:"failed"`
	NewAlarms  int          `json:"newAlarms"`
	OpenAlarms int          `json:"openAlarms"`
}

type run struct {
	opts        Options
	idx         *Index
	mu          sync.Mutex
	rateLimited atomic.Bool
}

func (o *Options) defaults() error {
	if o.StateDir == "" {
		return fmt.Errorf("%w: state directory required", ErrInvalid)
	}
	if o.RemoteBase == "" {
		o.RemoteBase = "https://"
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Concurrency > 16 {
		o.Concurrency = 16
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ReleasesTTL <= 0 {
		o.ReleasesTTL = DefaultReleasesTTL
	}
	if o.LsRemoteTimeout <= 0 {
		o.LsRemoteTimeout = 2 * time.Minute
	}
	if o.GitTimeout <= 0 {
		o.GitTimeout = 45 * time.Minute
	}
	if o.Git == nil {
		var scheme string
		switch {
		case strings.HasPrefix(o.RemoteBase, "https://"):
			scheme = "https"
		case o.AllowFileRemote && strings.HasPrefix(o.RemoteBase, "file://"):
			scheme = "file"
		default:
			return fmt.Errorf("%w: remote base must start with https://", ErrInvalid)
		}
		if strings.ContainsAny(o.RemoteBase, " \t\r\n\x00") {
			return fmt.Errorf("%w: remote base contains whitespace", ErrInvalid)
		}
		o.Git = ExecGit{AllowProtocols: scheme, StateDir: o.StateDir}
	}
	if o.Progress == nil {
		o.Progress = io.Discard
	}
	return nil
}

func (r *run) remoteURL(repo Repo) string {
	base := r.opts.RemoteBase
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + repo.Host + "/" + repo.Owner + "/" + repo.Name + ".git"
}

func (r *run) stamp() string { return r.opts.Now().UTC().Format(time.RFC3339) }

func (r *run) git(ctx context.Context, timeout time.Duration, dir string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.opts.Git.Run(c, dir, args...)
}

// Run mirrors every repository in opts.Repos. It takes the state lock, so
// two runs cannot overlap; a run interrupted at any point can simply be
// started again, because a repository's fingerprint is only recorded after
// its fetch succeeded.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.StateDir, 0o755); err != nil {
		return nil, err
	}
	lock, err := AcquireLock(filepath.Join(opts.StateDir, "locks", "mirror.lock"), opts.LockStaleAfter, opts.Now)
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	idx, err := LoadIndex(opts.StateDir)
	if err != nil {
		return nil, err
	}
	r := &run{opts: opts, idx: idx}
	repos := dedupe(opts.Repos)
	results := make([]RepoResult, len(repos))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = r.processRepo(ctx, repos[i])
				fmt.Fprintf(opts.Progress, "mirror: %s %s\n", repos[i].Key(), results[i].Action)
			}
		}()
	}
loop:
	for i := range repos {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	res := &Result{}
	for i, rr := range results {
		if rr.Repo == "" { // not reached because of cancellation
			rr = RepoResult{Repo: repos[i].Key(), Action: ActionError, Error: "not processed: " + errString(ctx.Err())}
		}
		res.Repos = append(res.Repos, rr)
		switch rr.Action {
		case ActionCloned:
			res.Cloned++
		case ActionFetched:
			res.Fetched++
		case ActionUnchanged:
			res.Unchanged++
		default:
			res.Failed++
		}
		res.NewAlarms += rr.NewAlarms
	}
	if ctx.Err() == nil && len(opts.Wants) > 0 {
		res.Wants = r.materialize(ctx, opts.Wants)
	}
	r.mu.Lock()
	res.OpenAlarms = len(r.idx.OpenAlarms())
	err = r.saveLocked()
	r.mu.Unlock()
	if err != nil {
		return res, err
	}
	return res, ctx.Err()
}

func errString(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

func (r *run) saveLocked() error {
	r.idx.UpdatedAt = r.stamp()
	return r.idx.Save(r.opts.StateDir)
}

func (r *run) info(repo Repo) *RepoInfo {
	info := r.idx.Repos[repo.Key()]
	if info == nil {
		info = &RepoInfo{Host: repo.Host, Owner: repo.Owner, Name: repo.Name, Path: filepath.ToSlash(repo.RelPath()), Status: "pending"}
		r.idx.Repos[repo.Key()] = info
	}
	return info
}

func (r *run) fail(repo Repo, msg string, newAlarms int) RepoResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	info := r.info(repo)
	info.Status, info.Error, info.LastCheckedAt = "error", msg, r.stamp()
	_ = r.saveLocked()
	return RepoResult{Repo: repo.Key(), Action: ActionError, Error: msg, NewAlarms: newAlarms}
}

func (r *run) processRepo(ctx context.Context, repo Repo) RepoResult {
	url := r.remoteURL(repo)
	dest := filepath.Join(r.opts.StateDir, repo.RelPath())

	var out []byte
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		out, err = r.git(ctx, r.opts.LsRemoteTimeout, "", "ls-remote", "--tags", "--heads", url)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return r.fail(repo, "ls-remote: "+scrub(err.Error(), url), 0)
	}
	snap, err := ParseLsRemote(out)
	if err != nil {
		return r.fail(repo, err.Error(), 0)
	}
	fingerprint := snap.Fingerprint()

	r.mu.Lock()
	prev := r.idx.Repos[repo.Key()]
	var prevCopy RepoInfo
	if prev != nil {
		prevCopy = *prev
	}
	newAlarms := 0
	if prev != nil && prev.LastFetchedAt != "" {
		for _, a := range detectTagChanges(repo.Key(), prev.Tags, prev.Tombstones, snap.Tags, r.stamp()) {
			if !r.idx.hasAlarm(a.ID) {
				r.idx.addAlarm(a)
				newAlarms++
				r.preserve(ctx, dest, a.OldCommit)
			}
		}
		if newAlarms > 0 {
			_ = r.saveLocked()
		}
	}
	r.mu.Unlock()

	_, statErr := os.Stat(dest)
	exists := statErr == nil
	changed := r.opts.Force || prev == nil || prevCopy.Status != "ok" || prevCopy.RemoteFingerprint != fingerprint || !exists
	action := ActionUnchanged
	if changed {
		if exists {
			_, err = r.git(ctx, r.opts.GitTimeout, dest, "fetch", "-q", "--filter=blob:none", "--no-tags", "--force", "--prune", "--no-write-fetch-head", "--no-auto-gc", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
			action = ActionFetched
		} else {
			err = r.clone(ctx, url, dest)
			action = ActionCloned
		}
		if err != nil {
			return r.fail(repo, scrub(err.Error(), url), newAlarms)
		}
	}

	r.mu.Lock()
	info := r.info(repo)
	info.Status, info.Error, info.LastCheckedAt = "ok", "", r.stamp()
	if changed {
		info.RemoteFingerprint, info.LastFetchedAt = fingerprint, r.stamp()
		info.Tombstones = nextTombstones(info.Tags, info.Tombstones, snap.Tags)
		info.Heads, info.Tags = snap.Heads, snap.Tags
	}
	relInfo := info.Releases
	r.mu.Unlock()

	rel := r.updateReleases(ctx, repo, relInfo, changed)

	r.mu.Lock()
	r.info(repo).Releases = rel
	_ = r.saveLocked()
	r.mu.Unlock()
	return RepoResult{Repo: repo.Key(), Action: action, NewAlarms: newAlarms, ReleasesStatus: rel.Status}
}

// scrub removes the remote URL from error text.
func scrub(msg, url string) string {
	msg = strings.ReplaceAll(msg, url, "<remote>")
	if i := strings.Index(url, "://"); i >= 0 {
		msg = strings.ReplaceAll(msg, strings.TrimSuffix(url[i+3:], ".git"), "<remote>")
	}
	return msg
}

func (r *run) clone(ctx context.Context, url, dest string) error {
	partial := dest + ".partial"
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if _, err := r.git(ctx, r.opts.GitTimeout, "", "clone", "-q", "--bare", "--filter=blob:none", url, partial); err != nil {
		_ = os.RemoveAll(partial)
		return err
	}
	// Never garbage-collect: commits that rules pin may stop being
	// reachable from any ref after an upstream force-push.
	if _, err := r.git(ctx, r.opts.GitTimeout, partial, "config", "gc.auto", "0"); err != nil {
		_ = os.RemoveAll(partial)
		return err
	}
	if err := os.Rename(partial, dest); err != nil {
		_ = os.RemoveAll(partial)
		return err
	}
	return nil
}

// preserve keeps a commit that a moved or deleted tag used to point to
// reachable, so the bytes of the old release stay readable.
func (r *run) preserve(ctx context.Context, dest, commit string) {
	if !isSHA(commit) {
		return
	}
	if _, err := os.Stat(dest); err != nil {
		return
	}
	if _, err := r.git(ctx, time.Minute, dest, "cat-file", "-e", commit+"^{commit}"); err != nil {
		return
	}
	_, _ = r.git(ctx, time.Minute, dest, "update-ref", "refs/prufyx/preserved/"+commit, commit)
}

// DefaultReleasesTTL bounds how stale "known" release metadata may get.
const DefaultReleasesTTL = 24 * time.Hour

// releasesExpired reports whether known metadata is older than the TTL.
func (r *run) releasesExpired(cur Releases) bool {
	if cur.Status != ReleasesKnown {
		return false
	}
	t, err := time.Parse(time.RFC3339, cur.FetchedAt)
	return err != nil || r.opts.Now().Sub(t) > r.opts.ReleasesTTL
}

func (r *run) updateReleases(ctx context.Context, repo Repo, cur Releases, changed bool) Releases {
	degrade := func(reason string) Releases {
		out := cur
		if len(cur.Items) > 0 || cur.Status == ReleasesKnown || cur.Status == ReleasesStale {
			out.Status = ReleasesStale
		} else {
			out.Status = ReleasesUnknown
		}
		out.Reason = reason
		return out
	}
	if repo.Host != DefaultHost {
		return Releases{Status: ReleasesUnknown, Reason: ReasonUnsupported}
	}
	if r.opts.Releases == nil {
		if cur.Status == "" {
			return Releases{Status: ReleasesUnknown, Reason: ReasonNoToken}
		}
		if changed || r.releasesExpired(cur) {
			return degrade(ReasonNoToken)
		}
		return cur
	}
	// Releases are revalidated on every run, whether or not git refs
	// changed: a release can be published after its tag was pushed, flipped
	// to or from prerelease, or deleted without any ref moving. The listing
	// is conditional (If-None-Match), so an unchanged repository costs a 304.
	if r.rateLimited.Load() {
		return degrade(ReasonRateLimited)
	}
	res, err := r.opts.Releases.List(ctx, repo, cur.ETag)
	switch {
	case errors.Is(err, ErrRateLimited):
		r.rateLimited.Store(true)
		return degrade(ReasonRateLimited)
	case errors.Is(err, ErrReleasesNotFound):
		return Releases{Status: ReleasesUnknown, Reason: ReasonNotFound}
	case err != nil:
		return degrade(ReasonError)
	case res.NotModified:
		cur.Status, cur.Reason, cur.FetchedAt = ReleasesKnown, "", r.stamp()
		return cur
	}
	items := res.Items
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return Releases{Status: ReleasesKnown, ETag: res.ETag, FetchedAt: r.stamp(), Truncated: res.Truncated, Items: items}
}

// Acknowledge marks open alarms of a repository (or one alarm) as reviewed
// by a person, which lifts the repository's freeze. It takes the state lock.
func Acknowledge(stateDir, repoKey, alarmID, note string, now func() time.Time) (int, error) {
	if now == nil {
		now = time.Now
	}
	repo, err := ParseRepo(repoKey)
	if err != nil {
		return 0, err
	}
	lock, err := AcquireLock(filepath.Join(stateDir, "locks", "mirror.lock"), 0, now)
	if err != nil {
		return 0, err
	}
	defer lock.Release()
	idx, err := LoadIndex(stateDir)
	if err != nil {
		return 0, err
	}
	n := 0
	stamp := now().UTC().Format(time.RFC3339)
	for i := range idx.Alarms {
		a := &idx.Alarms[i]
		if a.Repo != repo.Key() || a.Acknowledged || (alarmID != "" && a.ID != alarmID) {
			continue
		}
		a.Acknowledged, a.AcknowledgedAt, a.Note = true, stamp, note
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: no open alarm matches", ErrInvalid)
	}
	idx.UpdatedAt = stamp
	return n, idx.Save(stateDir)
}
