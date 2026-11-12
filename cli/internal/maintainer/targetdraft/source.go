// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxFileBytes bounds one file read from a tree.
const MaxFileBytes = 8 << 20

// Entry is one regular file or symbolic link of a tree.
type Entry struct {
	Path   string
	IsLink bool
}

// Tree is the read-only content of one tag. Implementations never touch the
// network.
type Tree interface {
	// Entries lists the regular files and symbolic links, sorted by path.
	Entries() ([]Entry, error)
	// Read returns a regular file (never a link) within MaxFileBytes.
	Read(path string) ([]byte, error)
	// Link returns the target text of a symbolic link.
	Link(path string) (string, error)
}

// Source opens the tree of a tag and names its commit.
type Source interface {
	Open(tag string) (Tree, string, error)
}

var tagNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// GitSource reads tags of a local git checkout with the git command line.
// Every command is local; nothing is fetched.
type GitSource struct{ Dir string }

func (g GitSource) git(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", g.Dir}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=/nonexistent", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_NO_REPLACE_OBJECTS=1"}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, msg)
	}
	return out.Bytes(), nil
}

// Open implements Source.
func (g GitSource) Open(tag string) (Tree, string, error) {
	if !tagNameRE.MatchString(tag) {
		return nil, "", fmt.Errorf("tag %q is not a plain tag name", tag)
	}
	ref := "refs/tags/" + tag
	raw, err := g.git("rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return nil, "", err
	}
	commit := strings.TrimSpace(string(raw))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return nil, "", errors.New("unexpected commit id from git")
	}
	listing, err := g.git("ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, "", err
	}
	t := &gitTree{g: g, sha: map[string]string{}, link: map[string]bool{}}
	for _, rec := range bytes.Split(listing, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, "", errors.New("unexpected ls-tree record")
		}
		f := strings.Fields(string(rec[:tab]))
		if len(f) != 3 || f[1] != "blob" {
			continue // submodule commits are not files
		}
		p := string(rec[tab+1:])
		switch f[0] {
		case "100644", "100755":
		case "120000":
			t.link[p] = true
		default:
			continue
		}
		t.sha[p] = f[2]
	}
	return t, commit, nil
}

type gitTree struct {
	g    GitSource
	sha  map[string]string
	link map[string]bool
}

func (t *gitTree) Entries() ([]Entry, error) {
	out := make([]Entry, 0, len(t.sha))
	for p := range t.sha {
		out = append(out, Entry{Path: p, IsLink: t.link[p]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (t *gitTree) blob(p string, wantLink bool) ([]byte, error) {
	sha, ok := t.sha[p]
	if !ok || t.link[p] != wantLink {
		return nil, fmt.Errorf("%s: not found as expected type", p)
	}
	size, err := t.g.git("cat-file", "-s", sha)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(size)))
	if err != nil || n < 0 || n > MaxFileBytes {
		return nil, fmt.Errorf("%s: size over the %d byte bound", p, MaxFileBytes)
	}
	return t.g.git("cat-file", "blob", sha)
}

func (t *gitTree) Read(p string) ([]byte, error) { return t.blob(p, false) }

func (t *gitTree) Link(p string) (string, error) {
	b, err := t.blob(p, true)
	return string(b), err
}
