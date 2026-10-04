// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Export limits. The repository holds about two thousand files, the
// largest about one MiB.
const (
	maxExportEntries   = 100000
	maxExportBlobBytes = 64 << 20
	maxExportBytes     = 2 << 30
	maxLinkTargetBytes = 4096
)

// ExportOptions names a commit to export.
type ExportOptions struct {
	// Git is the git executable; empty means "git" on PATH.
	Git string
	// GitDir is a repository (usually bare) holding the commit.
	GitDir string
	// Commit is the full 40-hex commit id.
	Commit string
	// Out is the directory to create; it must not exist.
	Out string
	// Only, when set, limits what is written to these repository paths: a
	// file, or a directory (everything below it). Every path of the commit
	// is still checked, written or not.
	Only []string
}

func (o ExportOptions) wanted(p string) bool {
	if len(o.Only) == 0 {
		return true
	}
	for _, w := range o.Only {
		if p == w || strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
			return true
		}
	}
	return false
}

type treeEntry struct {
	mode, kind, object string
	size               int64
	path               string
}

// Export writes the tree of one commit into a new directory with the
// exact bytes of every blob. It never checks the commit out: a checkout
// would apply the commit's own .gitattributes (ident, eol and encoding
// conversions, filters), so the files the gate checks could differ from
// the blobs that merge. Blobs are read from the object store with git
// cat-file, which applies no attributes. Regular files and symbolic links
// are written (links last, as links, never followed); a submodule, a path
// component "." or ".." or ".git", or any limit exceeded fails the export.
func Export(ctx context.Context, opts ExportOptions) error {
	if !shaRE.MatchString(opts.Commit) {
		return fmt.Errorf("commit %q is not a full commit id", logSafe(opts.Commit))
	}
	if opts.Git == "" {
		opts.Git = "git"
	}
	if _, err := os.Lstat(opts.Out); err == nil {
		return fmt.Errorf("%s already exists", opts.Out)
	}
	listing, err := gitOutput(ctx, opts, "ls-tree", "-r", "-z", "-l", "--full-tree", opts.Commit)
	if err != nil {
		return fmt.Errorf("list commit tree: %w", err)
	}
	entries, err := parseLsTree(listing)
	if err != nil {
		return err
	}
	if len(opts.Only) > 0 {
		kept := entries[:0]
		for _, e := range entries {
			if opts.wanted(e.path) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	if err := os.Mkdir(opts.Out, 0o755); err != nil {
		return err
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	if total > maxExportBytes {
		return fmt.Errorf("the commit holds more than %d bytes", int64(maxExportBytes))
	}
	cmd := gitCommand(ctx, opts, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	exportErr := exportBlobs(opts.Out, entries, stdin, bufio.NewReader(stdout))
	stdin.Close()
	if err := cmd.Wait(); err != nil && exportErr == nil {
		exportErr = fmt.Errorf("git cat-file: %v: %s", err, logSafe(stderr.String()))
	}
	return exportErr
}

func exportBlobs(out string, entries []treeEntry, stdin io.Writer, stdout *bufio.Reader) error {
	read := func(e treeEntry) ([]byte, error) {
		if _, err := io.WriteString(stdin, e.object+"\n"); err != nil {
			return nil, err
		}
		header, err := stdout.ReadString('\n')
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != e.object || fields[1] != "blob" {
			return nil, fmt.Errorf("unexpected object for %s", logSafe(e.path))
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size != e.size || size > maxExportBlobBytes {
			return nil, fmt.Errorf("unexpected size for %s", logSafe(e.path))
		}
		raw := make([]byte, size+1)
		if _, err := io.ReadFull(stdout, raw); err != nil {
			return nil, err
		}
		if raw[size] != '\n' {
			return nil, fmt.Errorf("unexpected blob framing for %s", logSafe(e.path))
		}
		return raw[:size], nil
	}
	var links []treeEntry
	for _, e := range entries {
		if e.mode == "120000" {
			links = append(links, e)
			continue
		}
		raw, err := read(e)
		if err != nil {
			return err
		}
		full := filepath.Join(out, filepath.FromSlash(e.path))
		if err := mkdirPlain(out, filepath.Dir(full)); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if e.mode == "100755" {
			perm = 0o755
		}
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return err
		}
		_, werr := f.Write(raw)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	for _, e := range links {
		raw, err := read(e)
		if err != nil {
			return err
		}
		if len(raw) == 0 || len(raw) > maxLinkTargetBytes || bytes.IndexByte(raw, 0) >= 0 {
			return fmt.Errorf("link %s has an invalid target", logSafe(e.path))
		}
		full := filepath.Join(out, filepath.FromSlash(e.path))
		if err := mkdirPlain(out, filepath.Dir(full)); err != nil {
			return err
		}
		if err := os.Symlink(string(raw), full); err != nil {
			return err
		}
	}
	return nil
}

// mkdirPlain creates dir (inside root) and its parents, refusing to pass
// through anything that is not a plain directory.
func mkdirPlain(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !info.IsDir():
			return fmt.Errorf("%s is not a plain directory", cur)
		}
	}
	return nil
}

// parseLsTree parses "git ls-tree -r -z -l" output and checks every entry.
func parseLsTree(raw []byte) ([]treeEntry, error) {
	var out []treeEntry
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		if len(out) >= maxExportEntries {
			return nil, fmt.Errorf("the commit holds more than %d files", maxExportEntries)
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, errors.New("malformed tree listing")
		}
		fields := strings.Fields(string(rec[:tab]))
		p := string(rec[tab+1:])
		if len(fields) != 4 {
			return nil, errors.New("malformed tree listing")
		}
		if err := checkExportPath(p); err != nil {
			return nil, err
		}
		e := treeEntry{mode: fields[0], kind: fields[1], object: fields[2], path: p}
		switch {
		case e.kind == "blob" && (e.mode == "100644" || e.mode == "100755" || e.mode == "120000"):
		case e.kind == "commit":
			return nil, fmt.Errorf("%s is a submodule; submodules are not supported", logSafe(p))
		default:
			return nil, fmt.Errorf("%s has unsupported mode %s %s", logSafe(p), logSafe(e.mode), logSafe(e.kind))
		}
		if !shaRE.MatchString(e.object) {
			return nil, fmt.Errorf("%s: unexpected object id", logSafe(p))
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > maxExportBlobBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes", logSafe(p), maxExportBlobBytes)
		}
		e.size = size
		out = append(out, e)
	}
	return out, nil
}

func checkExportPath(p string) error {
	if _, err := cleanRel(p); err != nil {
		return fmt.Errorf("path %q is not a plain repository path", logSafe(p))
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.EqualFold(strings.TrimRight(part, ". "), ".git") {
			return fmt.Errorf("path %q is not a plain repository path", logSafe(p))
		}
	}
	return nil
}

func gitCommand(ctx context.Context, opts ExportOptions, args ...string) *exec.Cmd {
	full := append([]string{
		"--git-dir=" + opts.GitDir,
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.autocrlf=false",
		"-c", "core.safecrlf=false",
	}, args...)
	cmd := exec.CommandContext(ctx, opts.Git, full...)
	// Only this repository's own configuration applies: no system or
	// global configuration, no environment overrides of git's paths.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1",
		"LC_ALL=C",
	}
	return cmd
}

func gitOutput(ctx context.Context, opts ExportOptions, args ...string) ([]byte, error) {
	cmd := gitCommand(ctx, opts, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, logSafe(stderr.String()))
	}
	return out, nil
}
