// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const maxBlobBytes = 32 << 20

// gitSource reads one local clone offline: pinned trees and blobs, and its
// tags. Replace refs and lazy object fetching are off.
type gitSource struct {
	ctx  context.Context
	dir  string
	repo extract.RepoRef

	batch *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Reader
	// commit is the commit whose tree is loaded; one is held at a time.
	commit  string
	dirs    map[string][]extract.TreeEntry
	entries map[string]extract.TreeEntry
}

func (g *gitSource) command(args ...string) *exec.Cmd {
	cmd := exec.CommandContext(g.ctx, "git", append([]string{"-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull}, args...)...)
	cmd.Dir = g.dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none", "GIT_TERMINAL_PROMPT=0"}
	return cmd
}

func (g *gitSource) Close() {
	if g.batch != nil {
		g.in.Close()
		_ = g.batch.Wait()
		g.batch = nil
	}
}

// object returns the type and bytes of an object by full id.
func (g *gitSource) object(id string) (string, []byte, error) {
	if !extract.IsCommitSHA(id) {
		return "", nil, errors.New("not a full object id")
	}
	if g.batch == nil {
		cmd := g.command("cat-file", "--batch")
		in, err := cmd.StdinPipe()
		if err != nil {
			return "", nil, err
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			return "", nil, err
		}
		if err := cmd.Start(); err != nil {
			return "", nil, err
		}
		g.batch, g.in, g.out = cmd, in, bufio.NewReader(out)
	}
	if _, err := io.WriteString(g.in, id+"\n"); err != nil {
		return "", nil, err
	}
	head, err := g.out.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	f := strings.Fields(head)
	if len(f) != 3 || f[0] != id {
		return "", nil, fmt.Errorf("object %s is not in the clone", id)
	}
	size, err := strconv.Atoi(f[2])
	if err != nil || size < 0 || size > maxBlobBytes {
		g.Close()
		return "", nil, fmt.Errorf("object %s: unusable size", id)
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(g.out, data); err != nil || data[size] != '\n' {
		return "", nil, fmt.Errorf("object %s: short read", id)
	}
	return f[1], data[:size], nil
}

func (g *gitSource) load(repo extract.RepoRef, commit string) error {
	if repo != g.repo {
		return fmt.Errorf("repository %s is not the clone's", repo.Key)
	}
	if commit == g.commit {
		return nil
	}
	kind, _, err := g.object(commit)
	if err != nil {
		return err
	}
	if kind != "commit" {
		return fmt.Errorf("%s is not a commit", commit)
	}
	raw, err := g.command("ls-tree", "-r", "-t", "-z", "--full-tree", commit).Output()
	if err != nil {
		return fmt.Errorf("ls-tree %s: %w", commit, err)
	}
	dirs := map[string][]extract.TreeEntry{"": {}}
	entries := map[string]extract.TreeEntry{}
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, p, ok := strings.Cut(string(rec), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || p == "" {
			return fmt.Errorf("ls-tree %s: unreadable record", commit)
		}
		e := extract.TreeEntry{Mode: f[0], Type: f[1], SHA: f[2], Path: p}
		parent := path.Dir(p)
		if parent == "." {
			parent = ""
		}
		entries[p] = e
		dirs[parent] = append(dirs[parent], e)
		if e.Type == "tree" && dirs[p] == nil {
			dirs[p] = []extract.TreeEntry{}
		}
	}
	g.commit, g.dirs, g.entries = commit, dirs, entries
	return nil
}

// Read implements extract.PinnedReader.
func (g *gitSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if err := g.load(repo, commit); err != nil {
		return nil, err
	}
	e, ok := g.entries[p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	if e.Type != "blob" || e.Mode == "120000" {
		return nil, fmt.Errorf("not a regular file: %s", p)
	}
	kind, data, err := g.object(e.SHA)
	if err != nil {
		return nil, err
	}
	if kind != "blob" {
		return nil, fmt.Errorf("not a blob: %s", p)
	}
	return data, nil
}

// List implements extract.PinnedReader.
func (g *gitSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	if err := g.load(repo, commit); err != nil {
		return nil, err
	}
	l, ok := g.dirs[dir]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	return append([]extract.TreeEntry(nil), l...), nil
}

// Tags implements extract.TagSource. A tag that does not lead to a commit has
// an empty commit.
func (g *gitSource) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	if repo != g.repo {
		return nil, fmt.Errorf("repository %s is not the clone's", repo.Key)
	}
	raw, err := g.command("for-each-ref", "--format=%(refname)%09%(objecttype)%09%(objectname)%09%(*objecttype)%09%(*objectname)", "refs/tags").Output()
	if err != nil {
		return nil, fmt.Errorf("for-each-ref: %w", err)
	}
	var out []extract.Tag
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return nil, errors.New("for-each-ref: unreadable line")
		}
		t := extract.Tag{Name: strings.TrimPrefix(f[0], "refs/tags/")}
		switch {
		case f[1] == "commit":
			t.Commit = f[2]
		case f[1] == "tag" && f[3] == "commit":
			t.Commit = f[4]
		}
		out = append(out, t)
	}
	return out, nil
}

// ParsePins reads the output of git ls-remote --tags: "<id>\trefs/tags/<name>"
// lines, where a "^{}" line gives the commit of an annotated tag.
func ParsePins(raw []byte) (map[string]string, error) {
	plain, peeled := map[string]string{}, map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		id, ref, ok := strings.Cut(line, "\t")
		name, tag := strings.CutPrefix(ref, "refs/tags/")
		if !ok || !tag || !extract.IsCommitSHA(id) || name == "" {
			return nil, errors.New("removalproof: pins: unreadable line")
		}
		m := plain
		if n, is := strings.CutSuffix(name, "^{}"); is {
			m, name = peeled, n
		}
		if _, dup := m[name]; dup {
			return nil, errors.New("removalproof: pins: tag listed twice: " + name)
		}
		m[name] = id
	}
	for name, id := range peeled {
		if _, ok := plain[name]; !ok {
			return nil, errors.New("removalproof: pins: peeled line without its tag: " + name)
		}
		plain[name] = id
	}
	if len(plain) == 0 {
		return nil, errors.New("removalproof: pins: no tags")
	}
	return plain, nil
}
