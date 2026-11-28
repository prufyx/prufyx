// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// The repin source reports a failed check as the error repin classifies, never
// as the reader's own or as an empty tag list.
func TestRepinSourceClassifiesUnavailableRefs(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"README.md": "one\n"})
	u.tag("v1", false)
	e.run()
	repo, err := ParseRepo(k1)
	if err != nil {
		t.Fatal(err)
	}
	src, err := OpenRepinSource(e.state)
	if err != nil {
		t.Fatal(err)
	}
	if tags, err := src.Tags(repo.Owner, repo.Name); err != nil || len(tags) != 1 {
		t.Fatalf("control: %v %v", tags, err)
	}
	idx, err := LoadIndex(e.state)
	if err != nil {
		t.Fatal(err)
	}
	idx.Repos[k1].Status = "error"
	if err := idx.Save(e.state); err != nil {
		t.Fatal(err)
	}
	if src, err = OpenRepinSource(e.state); err != nil {
		t.Fatal(err)
	}
	if tags, err := src.Tags(repo.Owner, repo.Name); !errors.Is(err, evidencerepin.ErrMirrorRefsUnavailable) || tags != nil {
		t.Fatalf("want ErrMirrorRefsUnavailable and no tags, got %v %v", tags, err)
	}
}

// refusesTags asserts that neither tag accessor answers for a repository
// whose last check did not succeed.
func refusesTags(t *testing.T, state, why string) {
	t.Helper()
	r, err := OpenReader(state)
	if err != nil {
		t.Fatal(err)
	}
	if tags, err := r.Tags(k1); err == nil || !strings.Contains(err.Error(), "last check") {
		t.Errorf("%s: Tags answered %v, error %v", why, tags, err)
	}
	if commit, err := r.ResolveTag(k1, "v1"); err == nil || !strings.Contains(err.Error(), "last check") {
		t.Errorf("%s: ResolveTag answered %q, error %v", why, commit, err)
	}
}

func TestReaderRefusesTagsAfterAFailedCheck(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"README.md": "one\n"})
	u.tag("v1", false)
	e.run()

	// Upstream publishes a release, the listing sees it, the fetch fails.
	u.commit("two", map[string]string{"README.md": "two\n"})
	u.tag("v2", false)
	e.git.failFirst = func(args []string) bool { return slices.Contains(args, "fetch") }
	if res := e.run(); res.Failed != 1 {
		t.Fatalf("the run must fail for the repository: %+v", res)
	}
	refusesTags(t, e.state, "failed fetch")

	// The next successful check restores the answers.
	e.run()
	r, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	if tags, err := r.Tags(k1); err != nil || len(tags) != 2 || tags["v1"].Commit != c1 {
		t.Fatalf("after recovery: %v %v", tags, err)
	}
}

func TestReaderRefusesTagsOfANeverFetchedRepository(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"README.md": "one\n"})
	u.tag("v1", false)
	e.git.failFirst = func(args []string) bool { return slices.Contains(args, "clone") }
	if res := e.run(); res.Failed != 1 {
		t.Fatalf("the run must fail for the repository: %+v", res)
	}
	// An empty tag map without an error would read as "upstream has no tags".
	refusesTags(t, e.state, "failed clone")
}

func TestReaderRefusesTagsForAnyStatusButOK(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"README.md": "one\n"})
	u.tag("v1", false)
	e.run()
	for _, status := range []string{"", "pending", "error", "evicted", "OK"} {
		idx, err := LoadIndex(e.state)
		if err != nil {
			t.Fatal(err)
		}
		idx.Repos[k1].Status = status
		if err := idx.Save(e.state); err != nil {
			t.Fatal(err)
		}
		refusesTags(t, e.state, "status "+status)
	}
}
