// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// memReader serves one file per commit and path.
type memReader struct {
	files map[string][]byte
	err   error
	reads int
}

func (m *memReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	m.reads++
	if m.err != nil {
		return nil, m.err
	}
	b, ok := m.files[repo.Key+"@"+commit+":"+p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	return b, nil
}

func (m *memReader) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("List is not used by the reader")
}

var promTarget = Target{
	Component: "prometheus", Repo: extract.RepoRef{Key: "github.com/prometheus/prometheus"},
	Form: FormFile, Path: "CHANGELOG.md",
	HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{
		`^(main|master) / unreleased$`,
		`^[0-9]+\.[0-9]+\.[0-9]+-(rc|beta|alpha)\.[0-9]+ / .*$`,
	},
}

var cortexTarget = Target{
	Component: "cortex", Repo: extract.RepoRef{Key: "github.com/cortexproject/cortex"},
	Form: FormFile, Path: "CHANGELOG.md",
	HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{
		`^master / unreleased$`,
		`^[0-9]+\.[0-9]+\.[0-9]+ in progress$`,
		`^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+ .*$`,
	},
}

var thanosTarget = Target{
	Component: "thanos", Repo: extract.RepoRef{Key: "github.com/thanos-io/thanos"},
	Form: FormFile, Path: "CHANGELOG.md",
	HeadingPattern:   `^\[v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\](?:\([^()\s]*\)|\s\S*\))?(?: - [0-9]{2}\.[0-9]{2}\.[0-9]{4})?$`,
	BoundaryPatterns: []string{`^Unreleased$`},
}

// locateMem runs Locate over an in-memory file at testCommit.
func locateMem(t Target, tagName, file string) (*Entry, error) {
	return locateBytes(t, tagName, []byte(file))
}

func locateBytes(t Target, tagName string, file []byte) (*Entry, error) {
	r := &memReader{files: map[string][]byte{t.Repo.Key + "@" + testCommit + ":" + t.Path: file}}
	return Locate(r, t, extract.Tag{Name: tagName, Commit: testCommit})
}

func wantCode(t *testing.T, err error, want Code) {
	t.Helper()
	got, ok := CodeOf(err)
	if !ok || got != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func mustLocate(t *testing.T, tg Target, tagName, file string) *Entry {
	t.Helper()
	e, err := locateMem(tg, tagName, file)
	if err != nil {
		t.Fatalf("locate: %v", err)
	}
	return e
}

func fixtureRoot(t *testing.T) extract.FixtureReader {
	t.Helper()
	return extract.FixtureReader{Root: filepath.Join("testdata", "fixture")}
}

func fixtureTag(t *testing.T, r extract.FixtureReader, tg Target, name string) extract.Tag {
	t.Helper()
	tags, err := r.Tags(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tags {
		if x.Name == name {
			return x
		}
	}
	t.Fatalf("fixture has no tag %s", name)
	return extract.Tag{}
}
