// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

// Reading from a local mirror.
//
// "--source mirror" answers every question repin would otherwise ask GitHub
// from a local mirror of the upstream repositories, and makes no network
// request of any kind. The classification code is unchanged: the mirror is
// presented to it as an APIFetcher (tags, releases, tag resolution) and a
// blob Fetcher (file bytes at a full commit), so the same citations served
// the same way classify identically from either source.
//
// Nothing is guessed. Whatever the mirror cannot answer becomes PENDING:
//
//   - a file that is not materialized locally (the mirror never reads from
//     the network on demand), or a commit it does not hold, is PENDING with a
//     note naming what to add to the mirror's wants; "--wants-out" writes
//     that list;
//   - a repository with an unacknowledged alarm (a tag that moved or
//     vanished) is PENDING: its tags are not trusted, so nothing is compared
//     against them;
//   - release metadata that is unknown, stale or missing leaves the
//     repository PENDING; release metadata the mirror itself marked
//     truncated still gives the newest release, but no release line is
//     derived from it (the line scan is reported incomplete and the citation
//     keeps the latest-release baseline, as with an over-long scan over
//     HTTP).
//
// Freshness is the mirror's, not the run's. A worklist built from a mirror
// that was last refreshed five days ago must not look as fresh as the
// moment it was built, so every repository and line resolution carries the
// OLDEST of the mirror's last successful look at the repository and at its
// release metadata as its ResolvedAt, and the citations of a repository
// older than --max-age are marked stale.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
)

const (
	// SourceHTTP and SourceMirror name the data sources of "evidence
	// repin". A worklist from the HTTP source records no source.
	SourceHTTP   = "http"
	SourceMirror = "mirror"

	mirrorKindBlobNotLocal  = "MIRROR_BLOB_NOT_LOCAL"
	mirrorKindCommitUnknown = "MIRROR_COMMIT_UNKNOWN"
	mirrorKindFrozen        = "MIRROR_REPO_FROZEN"
	mirrorKindNotMirrored   = "MIRROR_REPO_NOT_MIRRORED"
	mirrorKindNotAFile      = "MIRROR_NOT_A_FILE"
	mirrorKindTooLarge      = "MIRROR_FILE_TOO_LARGE"
	mirrorKindReadError     = "MIRROR_READ_ERROR"
)

// Errors a MirrorSource returns. Every one of them means "no evidence".
var (
	ErrMirrorNotMirrored = errors.New("the repository is not in the mirror")
	ErrMirrorFrozen      = errors.New("the repository is frozen by an unacknowledged alarm")
	// ErrMirrorReleasesUnusable: release metadata is unknown, stale or
	// missing.
	ErrMirrorReleasesUnusable = errors.New("the mirror's release metadata is not usable")
	ErrMirrorBlobNotLocal     = errors.New("the file contents are not materialized in the mirror")
	ErrMirrorCommitUnknown    = errors.New("the commit is not in the mirror")
	ErrMirrorPathNotFound     = errors.New("the path does not exist at that commit")
	ErrMirrorNotAFile         = errors.New("the path is not a regular file")
	ErrMirrorTooLarge         = errors.New("the file is too large")
)

// MirrorRelease is one entry of a repository's release list, newest first.
type MirrorRelease struct {
	ID         int64
	Tag        string
	Draft      bool
	Prerelease bool
}

// MirrorReleases is a usable (known and fresh) release list.
type MirrorReleases struct {
	// Items are newest first.
	Items []MirrorRelease
	// Truncated means the mirror cut the list short: its newest entries are
	// present, but it cannot prove which release is newest on a line.
	Truncated bool
}

// MirrorRepoStatus is the mirror's record of when it last looked at a
// repository.
type MirrorRepoStatus struct {
	Status            string
	LastCheckedAt     string
	LastFetchedAt     string
	ReleasesFetchedAt string
}

// MirrorIndex identifies the mirror snapshot a run used.
type MirrorIndex struct {
	UpdatedAt string
	Digest    string
}

// MirrorSource is what repin needs from a local mirror. Implementations
// must be strictly offline.
type MirrorSource interface {
	// Tags returns tag -> peeled commit. It fails with ErrMirrorFrozen
	// while the repository has an unacknowledged alarm.
	Tags(owner, repo string) (map[string]string, error)
	// Releases returns the release list when it is known and fresh, and
	// ErrMirrorReleasesUnusable otherwise.
	Releases(owner, repo string) (MirrorReleases, error)
	// Read returns the file at a full commit SHA. It fails with
	// ErrMirrorFrozen for a frozen repository, ErrMirrorBlobNotLocal when
	// the contents were never fetched and ErrMirrorCommitUnknown when the
	// commit is not in the mirror.
	Read(owner, repo, commit, path string) ([]byte, error)
	RepoStatus(owner, repo string) (MirrorRepoStatus, error)
	Index() MirrorIndex
}

// MirrorProvenance identifies the mirror snapshot a worklist was built from.
type MirrorProvenance struct {
	IndexUpdatedAt string `json:"indexUpdatedAt,omitempty"`
	IndexDigest    string `json:"indexDigest,omitempty"`
}

// MirrorWant asks the mirror to materialize files at a pinned commit. It
// has the shape "factory mirror --wants" reads.
type MirrorWant struct {
	Repo   string   `json:"repo"`
	Commit string   `json:"commit"`
	Paths  []string `json:"paths"`
}

// MirrorWants is the content of a wants file.
type MirrorWants struct {
	Wants []MirrorWant `json:"wants"`
}

// EvidenceAt returns the time the data behind this resolution was last
// known to be current: ResolvedAt, and for a mirror resolution the older of
// that and the mirror's own timestamps. It reports false when a required
// timestamp is missing or unparsable, or the source is not recognised;
// such a resolution must be treated as stale.
func (r RepoResolution) EvidenceAt() (time.Time, bool) {
	return evidenceAt(r.Source, r.ResolvedAt, r.MirrorCheckedAt, r.MirrorReleasesAt)
}

// EvidenceAt is RepoResolution.EvidenceAt for a release-line resolution.
func (l LineResolution) EvidenceAt() (time.Time, bool) {
	return evidenceAt(l.Source, l.ResolvedAt, l.MirrorCheckedAt, l.MirrorReleasesAt)
}

func evidenceAt(source, resolvedAt, checkedAt, releasesAt string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, resolvedAt)
	if err != nil {
		return time.Time{}, false
	}
	switch source {
	case "":
		return t, true
	case SourceMirror:
		for _, stamp := range []string{checkedAt, releasesAt} {
			p, err := time.Parse(time.RFC3339, stamp)
			if err != nil {
				return time.Time{}, false
			}
			if p.Before(t) {
				t = p
			}
		}
		return t, true
	default:
		return time.Time{}, false
	}
}

func checkSourceFlags(source, mirrorState, statePath, wantsOut string, haveMirror bool) string {
	switch source {
	case SourceHTTP:
		if mirrorState != "" || wantsOut != "" {
			return "--mirror-state and --wants-out need --source mirror"
		}
	case SourceMirror:
		switch {
		case !haveMirror:
			return "--source mirror is not available in this build"
		case mirrorState == "":
			return "--source mirror needs --mirror-state"
		case statePath != "":
			return "--state is not used with --source mirror: a mirror run recomputes everything, offline"
		}
	default:
		return "--source must be http or mirror"
	}
	return ""
}

// mirrorRepoOf names a citation's repository in mirror terms.
func mirrorRepoName(owner, repo string) string { return "github.com/" + owner + "/" + repo }

// mirrorNotes remembers why the mirror could not answer for a repository.
type mirrorNotes map[string]string

func (n mirrorNotes) add(owner, repo string, err error) {
	key := owner + "/" + repo
	if _, ok := n[key]; !ok {
		n[key] = err.Error()
	}
}

// mirrorAPIFetcher answers the few GitHub API paths repin uses from a mirror.
type mirrorAPIFetcher struct {
	src   MirrorSource
	notes mirrorNotes

	tags     map[string]map[string]string
	tagsErr  map[string]error
	releases map[string]MirrorReleases
	relErr   map[string]error
}

func newMirrorAPIFetcher(src MirrorSource, notes mirrorNotes) *mirrorAPIFetcher {
	return &mirrorAPIFetcher{
		src: src, notes: notes,
		tags: map[string]map[string]string{}, tagsErr: map[string]error{},
		releases: map[string]MirrorReleases{}, relErr: map[string]error{},
	}
}

func (f *mirrorAPIFetcher) tagMap(owner, repo string) (map[string]string, error) {
	key := owner + "/" + repo
	if m, ok := f.tags[key]; ok {
		return m, nil
	}
	if err, ok := f.tagsErr[key]; ok {
		return nil, err
	}
	m, err := f.src.Tags(owner, repo)
	if err != nil {
		f.tagsErr[key] = err
		f.notes.add(owner, repo, err)
		return nil, err
	}
	f.tags[key] = m
	return m, nil
}

func (f *mirrorAPIFetcher) releaseList(owner, repo string) (MirrorReleases, error) {
	key := owner + "/" + repo
	if m, ok := f.releases[key]; ok {
		return m, nil
	}
	if err, ok := f.relErr[key]; ok {
		return MirrorReleases{}, err
	}
	m, err := f.src.Releases(owner, repo)
	if err != nil {
		f.relErr[key] = err
		f.notes.add(owner, repo, err)
		return MirrorReleases{}, err
	}
	f.releases[key] = m
	return m, nil
}

// CompleteReleaseScan implements releaseScanGate: it is false when the
// release list is truncated, so no release line is derived from it.
func (f *mirrorAPIFetcher) CompleteReleaseScan(owner, repo string) bool {
	m, err := f.releaseList(owner, repo)
	return err == nil && !m.Truncated
}

// GitRefs implements GitRefSource from the mirror's recorded tags (each
// already peeled to its commit). The mirror records no branch heads for
// repin, which only ever explain why a pin has no line.
func (f *mirrorAPIFetcher) GitRefs(_ context.Context, owner, repo string) (RefListing, error) {
	tags, err := f.tagMap(owner, repo)
	if err != nil {
		return RefListing{}, err
	}
	listing := RefListing{Tags: make(map[string]TagRef, len(tags)), Heads: map[string]string{}}
	for name, commit := range tags {
		if !refObjectPattern.MatchString(commit) {
			return RefListing{}, fmt.Errorf("%w: tag %s has no commit", errRefListingMalformed, name)
		}
		listing.Tags[name] = TagRef{Object: commit, Commit: commit}
	}
	return listing, nil
}

// releaseScanGate lets an APIFetcher declare that its release list is cut
// short without the line resolver paging through it.
type releaseScanGate interface {
	CompleteReleaseScan(owner, repo string) bool
}

var errMirrorUnsupported = errors.New("unsupported request")

func (f *mirrorAPIFetcher) Fetch(_ context.Context, path string) ([]byte, int, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	segments := strings.Split(rawPath, "/")
	// "", "repos", owner, repo, kind...
	if len(segments) < 5 || segments[0] != "" || segments[1] != "repos" {
		return nil, 0, errMirrorUnsupported
	}
	owner, repo, kind := segments[2], segments[3], segments[4:]
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, 0, errMirrorUnsupported
	}
	switch {
	case len(kind) == 1 && kind[0] == "releases":
		return f.serveReleases(owner, repo, query)
	case len(kind) == 1 && kind[0] == "tags":
		return f.serveTags(owner, repo, query)
	case len(kind) >= 3 && kind[0] == "git" && kind[1] == "ref" && kind[2] == "tags":
		tag, err := url.PathUnescape(strings.Join(kind[3:], "/"))
		if err != nil {
			return nil, 0, errMirrorUnsupported
		}
		return f.serveTagRef(owner, repo, tag)
	}
	return nil, 0, errMirrorUnsupported
}

func (f *mirrorAPIFetcher) serveReleases(owner, repo string, query url.Values) ([]byte, int, error) {
	list, err := f.releaseList(owner, repo)
	if err != nil {
		return nil, 0, err
	}
	perPage, page := 30, 1
	if v := query.Get("per_page"); v != "" {
		if perPage, err = strconv.Atoi(v); err != nil || perPage < 1 {
			return nil, 0, errMirrorUnsupported
		}
	}
	if v := query.Get("page"); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 {
			return nil, 0, errMirrorUnsupported
		}
	}
	type entry struct {
		ID         int64  `json:"id"`
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	out := []entry{}
	start := (page - 1) * perPage
	for i := start; i < len(list.Items) && i < start+perPage; i++ {
		item := list.Items[i]
		out = append(out, entry{ID: item.ID, TagName: item.Tag, Draft: item.Draft, Prerelease: item.Prerelease})
	}
	body, _ := json.Marshal(out)
	return body, 200, nil
}

// serveTags lists every recorded tag, by name, in pages like the GitHub
// endpoint. Unlike GitHub's arbitrary order, the mirror's is by name, so
// a full scan sees each tag exactly once.
func (f *mirrorAPIFetcher) serveTags(owner, repo string, query url.Values) ([]byte, int, error) {
	perPage, page := 30, 1
	var err error
	if v := query.Get("per_page"); v != "" {
		if perPage, err = strconv.Atoi(v); err != nil || perPage < 1 {
			return nil, 0, errMirrorUnsupported
		}
	}
	if v := query.Get("page"); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 {
			return nil, 0, errMirrorUnsupported
		}
	}
	tags, err := f.tagMap(owner, repo)
	if err != nil {
		return nil, 0, err
	}
	names := make([]string, 0, len(tags))
	for name := range tags {
		names = append(names, name)
	}
	sort.Strings(names)
	type entry struct {
		Name string `json:"name"`
	}
	out := make([]entry, 0, perPage)
	start := (page - 1) * perPage
	for i := start; i < len(names) && i < start+perPage; i++ {
		out = append(out, entry{Name: names[i]})
	}
	body, _ := json.Marshal(out)
	return body, 200, nil
}

func (f *mirrorAPIFetcher) serveTagRef(owner, repo, tag string) ([]byte, int, error) {
	tags, err := f.tagMap(owner, repo)
	if err != nil {
		return nil, 0, err
	}
	commit, ok := tags[tag]
	if !ok {
		return nil, 404, nil
	}
	body, _ := json.Marshal(map[string]any{"object": map[string]string{"sha": commit, "type": "commit"}})
	return body, 200, nil
}

// mirrorWantsCollector gathers the files the mirror was missing.
type mirrorWantsCollector struct {
	// pinned maps repo+path to the pinned commits that cite that path, so
	// that when the baseline file is missing the pinned file that the
	// comparison would need next is requested in the same round.
	pinned map[string]map[string]bool
	wants  map[string]map[string]bool // repo + "@" + commit -> paths
}

func newMirrorWantsCollector(citations []Citation) *mirrorWantsCollector {
	c := &mirrorWantsCollector{pinned: map[string]map[string]bool{}, wants: map[string]map[string]bool{}}
	for _, citation := range citations {
		key := mirrorRepoName(citation.Owner, citation.Repo) + "\x00" + citation.Path
		if c.pinned[key] == nil {
			c.pinned[key] = map[string]bool{}
		}
		c.pinned[key][citation.OldCommit] = true
	}
	return c
}

func (c *mirrorWantsCollector) add(repo, commit, path string) {
	key := repo + "@" + commit
	if c.wants[key] == nil {
		c.wants[key] = map[string]bool{}
	}
	c.wants[key][path] = true
}

// missing records an unavailable file and, so that one more round suffices,
// the pinned files of the same path that are not available either.
// available reports whether a pinned file can already be read.
func (c *mirrorWantsCollector) missing(repo, commit, path string, available func(commit string) bool) {
	c.add(repo, commit, path)
	for old := range c.pinned[repo+"\x00"+path] {
		if old != commit && !available(old) {
			c.add(repo, old, path)
		}
	}
}

func (c *mirrorWantsCollector) render() MirrorWants {
	out := MirrorWants{Wants: []MirrorWant{}}
	keys := make([]string, 0, len(c.wants))
	for key := range c.wants {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		repo, commit, _ := strings.Cut(key, "@")
		want := MirrorWant{Repo: repo, Commit: commit}
		for path := range c.wants[key] {
			want.Paths = append(want.Paths, path)
		}
		sort.Strings(want.Paths)
		out.Wants = append(out.Wants, want)
	}
	return out
}

// mirrorBlobFetcher serves "/owner/repo/commit/path" from the mirror.
type mirrorBlobFetcher struct {
	src   MirrorSource
	notes mirrorNotes
	wants *mirrorWantsCollector
}

func (f *mirrorBlobFetcher) Fetch(_ context.Context, path string) sourcecapture.FetchResult {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	if len(parts) != 4 {
		return sourcecapture.FetchResult{Kind: mirrorKindReadError}
	}
	owner, repo, commit, file := parts[0], parts[1], parts[2], parts[3]
	data, err := f.src.Read(owner, repo, commit, file)
	switch {
	case err == nil:
		return sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: data}
	case errors.Is(err, ErrMirrorPathNotFound):
		return sourcecapture.FetchResult{Kind: "HTTP_STATUS", StatusCode: 404}
	case errors.Is(err, ErrMirrorBlobNotLocal):
		f.wants.missing(mirrorRepoName(owner, repo), commit, file, f.canRead(owner, repo, file))
		return sourcecapture.FetchResult{Kind: mirrorKindBlobNotLocal}
	case errors.Is(err, ErrMirrorCommitUnknown):
		f.wants.missing(mirrorRepoName(owner, repo), commit, file, f.canRead(owner, repo, file))
		return sourcecapture.FetchResult{Kind: mirrorKindCommitUnknown}
	case errors.Is(err, ErrMirrorFrozen):
		f.notes.add(owner, repo, err)
		return sourcecapture.FetchResult{Kind: mirrorKindFrozen}
	case errors.Is(err, ErrMirrorNotMirrored):
		f.notes.add(owner, repo, err)
		return sourcecapture.FetchResult{Kind: mirrorKindNotMirrored}
	case errors.Is(err, ErrMirrorNotAFile):
		return sourcecapture.FetchResult{Kind: mirrorKindNotAFile}
	case errors.Is(err, ErrMirrorTooLarge):
		return sourcecapture.FetchResult{Kind: mirrorKindTooLarge}
	}
	return sourcecapture.FetchResult{Kind: mirrorKindReadError}
}

func (f *mirrorBlobFetcher) canRead(owner, repo, file string) func(commit string) bool {
	return func(commit string) bool {
		_, err := f.src.Read(owner, repo, commit, file)
		return err == nil
	}
}

// BuildMirrorWorklist is BuildWorklistWithBaseline over a local mirror. It
// makes no network request. It keeps no resumable state: everything is
// recomputed from the mirror, which is cheap and always current. The
// returned wants list every file the mirror was missing.
func BuildMirrorWorklist(ctx context.Context, citations []Citation, projects []string, limit int, src MirrorSource, now func() time.Time, maxAge time.Duration, progress io.Writer, baselineMode string) (Worklist, MirrorWants, error) {
	notes := mirrorNotes{}
	filtered := filterCitations(citations, projects, limit)
	wants := newMirrorWantsCollector(filtered)
	api := newMirrorAPIFetcher(src, notes)
	blobs := &mirrorBlobFetcher{src: src, notes: notes, wants: wants}
	worklist, err := BuildWorklistWithBaseline(ctx, citations, projects, limit, newState(), api, blobs, now, maxAge, progress, baselineMode)
	if err != nil {
		return Worklist{}, MirrorWants{}, err
	}
	annotateMirrorWorklist(&worklist, src, notes, now(), maxAge)
	return worklist, wants.render(), nil
}

var mirrorLimitations = []string{
	"this worklist was built from a local mirror and made no network request; every repository and release-line resolution carries, as resolvedAt, the oldest of the mirror's own last successful look at the repository and at its release metadata, and the citations of a repository older than the freshness bound are marked stale",
	"a citation left PENDING by a mirror source says why: a file not materialized in the mirror, a commit the mirror does not hold, a repository frozen by an unacknowledged alarm, or release metadata that is unknown or stale",
	"with a mirror source the tags fallback lists every recorded tag rather than the first page GitHub returns",
}

type repoEvidence struct {
	checkedAt, releasesAt string
	at                    time.Time
	ok                    bool
}

// annotateMirrorWorklist records the mirror as the source, replaces run
// timestamps by the mirror's, marks what is too old as stale and rewrites
// the generic pending details into mirror-specific ones.
func annotateMirrorWorklist(wl *Worklist, src MirrorSource, notes mirrorNotes, now time.Time, maxAge time.Duration) {
	index := src.Index()
	wl.Source = SourceMirror
	wl.Scope.Source = SourceMirror
	wl.Mirror = &MirrorProvenance{IndexUpdatedAt: index.UpdatedAt, IndexDigest: index.Digest}
	wl.Limitations = append(append([]string(nil), wl.Limitations...), mirrorLimitations...)

	evidence := map[string]repoEvidence{}
	for i := range wl.Repos {
		repo := &wl.Repos[i]
		key := repo.Owner + "/" + repo.Repo
		ev := repoEvidence{}
		if st, err := src.RepoStatus(repo.Owner, repo.Repo); err == nil {
			ev.checkedAt = st.LastCheckedAt
			if st.Status != "ok" {
				// The last check failed: the recorded refs are the last good
				// state, as old as the last time they changed.
				ev.checkedAt = st.LastFetchedAt
			}
			ev.releasesAt = st.ReleasesFetchedAt
		}
		repo.Source, repo.MirrorCheckedAt, repo.MirrorReleasesAt = SourceMirror, ev.checkedAt, ev.releasesAt
		repo.ResolvedAt = now.UTC().Format(time.RFC3339)
		ev.at, ev.ok = repo.EvidenceAt()
		switch {
		case !ev.ok:
			repo.ResolvedAt = ""
			repo.Stale = true
		default:
			repo.ResolvedAt = ev.at.UTC().Format(time.RFC3339)
			repo.Stale = now.Sub(ev.at) > maxAge
		}
		evidence[key] = ev
		if repo.Status == repoPendingError {
			repo.Detail = "the mirror cannot answer for this repository: " + noteOr(notes, key, "no usable data")
		}
	}
	for i := range wl.Lines {
		line := &wl.Lines[i]
		ev := evidence[line.Owner+"/"+line.Repo]
		line.Source, line.MirrorCheckedAt, line.MirrorReleasesAt = SourceMirror, ev.checkedAt, ev.releasesAt
		if !ev.ok {
			line.ResolvedAt = ""
			line.Stale = true
			continue
		}
		if at, ok := evidenceAt("", line.ResolvedAt, "", ""); ok && at.After(ev.at) {
			line.ResolvedAt = ev.at.UTC().Format(time.RFC3339)
		}
		line.Stale = now.Sub(ev.at) > maxAge
	}
	for i := range wl.Citations {
		result := &wl.Citations[i]
		ev := evidence[result.Owner+"/"+result.Repo]
		if result.Class != ClassPending {
			if !ev.ok || now.Sub(ev.at) > maxAge {
				result.Stale = true
			}
			continue
		}
		result.Detail = mirrorPendingDetail(*result, notes)
	}
	wl.Summary.OldestResolvedAt = oldestResolvedAt(wl.Repos)
}

func noteOr(notes mirrorNotes, key, fallback string) string {
	if n, ok := notes[key]; ok {
		return n
	}
	return fallback
}

// mirrorPendingDetail turns the generic pending detail into one that says
// what the mirror needs.
func mirrorPendingDetail(result ClassResult, notes mirrorNotes) string {
	repo := mirrorRepoName(result.Owner, result.Repo)
	key := result.Owner + "/" + result.Repo
	detail := result.Detail
	missing := func(commit string) string {
		return fmt.Sprintf("add %s %s %s to the mirror's wants and run the mirror again", repo, commit, result.Path)
	}
	for _, side := range []struct{ prefix, commit string }{
		{"blob fetch ", result.NewCommit},
		{"old blob fetch ", result.OldCommit},
	} {
		if !strings.HasPrefix(detail, side.prefix) {
			continue
		}
		switch strings.TrimPrefix(detail, side.prefix) {
		case mirrorKindBlobNotLocal:
			return "file contents are not in the mirror: " + missing(side.commit)
		case mirrorKindCommitUnknown:
			return "the commit is not in the mirror: " + missing(side.commit)
		case mirrorKindFrozen:
			return "the repository is frozen by an unacknowledged alarm; no file is compared until a person has reviewed it"
		case mirrorKindNotMirrored:
			return "the repository is not in the mirror's registry"
		case mirrorKindNotAFile:
			return "the cited path is not a regular file at that commit"
		case mirrorKindTooLarge:
			return "the cited file is too large to read from the mirror"
		}
		return "the mirror could not read the file"
	}
	if strings.HasPrefix(detail, "baseline unresolved:") || strings.HasPrefix(detail, "repository current commit unresolved:") {
		if note, ok := notes[key]; ok {
			return "baseline unresolved: " + note
		}
	}
	return detail
}

func writeWants(path string, wants MirrorWants) error {
	raw, err := json.MarshalIndent(wants, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
