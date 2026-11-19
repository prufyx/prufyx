// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// gitSource reads tags and files from local clones laid out as
// <root>/<repo key>, with the git command. It is only the generator's source.
type gitSource struct{ root string }

func (g gitSource) git(repo extract.RepoRef, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", filepath.Join(g.root, repo.Key)}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (g gitSource) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	out, err := g.git(repo, "for-each-ref", "--format=%(refname:short) %(objectname) %(*objectname)", "refs/tags")
	if err != nil {
		return nil, err
	}
	var tags []extract.Tag
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		c := f[1]
		if len(f) == 3 {
			c = f[2]
		}
		tags = append(tags, extract.Tag{Name: f[0], Commit: c})
	}
	return tags, nil
}

func (g gitSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if _, err := g.git(repo, "cat-file", "-e", commit+":"+p); err != nil {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	return g.git(repo, "cat-file", "blob", commit+":"+p)
}

func (g gitSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("List is not used by the reader")
}

// TestGenerateRowFixtures writes testdata/rows/<component>.json for every row
// from local clones, and the blobs they pin into a directory. It is a
// maintainer step, off unless PRUFYX_ROW_FIXTURE_GIT (the clones root) and
// PRUFYX_ROW_FIXTURE_OUT (an output directory) are both set.
func TestGenerateRowFixtures(t *testing.T) {
	root, out := os.Getenv("PRUFYX_ROW_FIXTURE_GIT"), os.Getenv("PRUFYX_ROW_FIXTURE_OUT")
	if root == "" || out == "" {
		t.Skip("fixture generation is a maintainer step")
	}
	digests, err := RowDigests()
	if err != nil {
		t.Fatal(err)
	}
	src := gitSource{root: root}
	if err := os.MkdirAll(filepath.Join(out, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, row := range Reviewed {
		fx, err := BuildRowFixture(src, row, digests[row.Component], zeroDigest)
		if err != nil {
			t.Fatalf("%s: %v", row.Component, err)
		}
		for _, tg := range fx.Tags {
			for _, rd := range tg.Reads {
				if rd.BlobID == "" {
					continue
				}
				b, err := src.Read(row.Repo, tg.Commit, rd.Path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(out, "blobs", rd.BlobID), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		b, err := fx.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, row.Component+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
