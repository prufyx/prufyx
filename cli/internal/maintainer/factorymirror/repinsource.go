// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// RepinSource presents a mirror to "evidence repin" (it implements
// evidencerepin.MirrorSource). It reads strictly offline through a Reader
// and maps the Reader's errors onto the ones repin understands.
type RepinSource struct {
	r *Reader
}

// OpenRepinSource opens the mirror in stateDir for "evidence repin".
func OpenRepinSource(stateDir string) (evidencerepin.MirrorSource, error) {
	r, err := OpenReader(stateDir)
	if err != nil {
		return nil, err
	}
	return &RepinSource{r: r}, nil
}

func repoName(owner, repo string) string { return DefaultHost + "/" + owner + "/" + repo }

func mapReadError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRepoNotMirrored):
		return evidencerepin.ErrMirrorNotMirrored
	case errors.Is(err, ErrRepoFrozen):
		return evidencerepin.ErrMirrorFrozen
	case errors.Is(err, ErrReleasesIncomplete):
		return fmt.Errorf("%w: %v", evidencerepin.ErrMirrorReleasesUnusable, err)
	case errors.Is(err, ErrBlobNotLocal):
		return evidencerepin.ErrMirrorBlobNotLocal
	case errors.Is(err, ErrCommitUnknown):
		return evidencerepin.ErrMirrorCommitUnknown
	case errors.Is(err, ErrPathNotFound):
		return evidencerepin.ErrMirrorPathNotFound
	case errors.Is(err, ErrNotAFile):
		return evidencerepin.ErrMirrorNotAFile
	case errors.Is(err, ErrTooLarge):
		return evidencerepin.ErrMirrorTooLarge
	}
	return err
}

// Tags implements evidencerepin.MirrorSource.
func (s *RepinSource) Tags(owner, repo string) (map[string]string, error) {
	tags, err := s.r.Tags(repoName(owner, repo))
	if err != nil {
		return nil, mapReadError(err)
	}
	out := make(map[string]string, len(tags))
	for name, t := range tags {
		out[name] = t.Commit
	}
	return out, nil
}

// Releases implements evidencerepin.MirrorSource. A frozen repository gives
// no releases either: nothing about it is used until a person has looked.
func (s *RepinSource) Releases(owner, repo string) (evidencerepin.MirrorReleases, error) {
	name := repoName(owner, repo)
	if frozen, err := s.r.Frozen(name); err != nil {
		return evidencerepin.MirrorReleases{}, mapReadError(err)
	} else if frozen {
		return evidencerepin.MirrorReleases{}, evidencerepin.ErrMirrorFrozen
	}
	rel, err := s.r.UsableReleases(name)
	if err != nil {
		return evidencerepin.MirrorReleases{}, mapReadError(err)
	}
	out := evidencerepin.MirrorReleases{Truncated: rel.Truncated}
	for _, item := range rel.Items {
		out.Items = append(out.Items, evidencerepin.MirrorRelease{ID: item.ID, Tag: item.Tag, Draft: item.Draft, Prerelease: item.Prerelease})
	}
	return out, nil
}

// Read implements evidencerepin.MirrorSource. A frozen repository's files
// are not read: a tag may have moved, so nothing is compared against it.
func (s *RepinSource) Read(owner, repo, commit, path string) ([]byte, error) {
	name := repoName(owner, repo)
	if frozen, err := s.r.Frozen(name); err != nil {
		return nil, mapReadError(err)
	} else if frozen {
		return nil, evidencerepin.ErrMirrorFrozen
	}
	data, err := s.r.Read(name, commit, path)
	return data, mapReadError(err)
}

// RepoStatus implements evidencerepin.MirrorSource.
func (s *RepinSource) RepoStatus(owner, repo string) (evidencerepin.MirrorRepoStatus, error) {
	st, err := s.r.RepoStatus(repoName(owner, repo))
	if err != nil {
		return evidencerepin.MirrorRepoStatus{}, mapReadError(err)
	}
	return evidencerepin.MirrorRepoStatus{Status: st.Status, LastCheckedAt: st.LastCheckedAt, LastFetchedAt: st.LastFetchedAt, ReleasesFetchedAt: st.ReleasesFetchedAt}, nil
}

// Index implements evidencerepin.MirrorSource.
func (s *RepinSource) Index() evidencerepin.MirrorIndex {
	updated, digest := s.r.IndexInfo()
	return evidencerepin.MirrorIndex{UpdatedAt: updated, Digest: digest}
}
