// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package fix

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/prufyx/prufyx/cli/internal/validation"
)

// Target is one file to write: its path on disk and the plan made on its
// bytes.
type Target struct {
	Path string
	Plan FilePlan
}

// ApplyOptions configures Apply.
type ApplyOptions struct {
	// Roots are the directories files may be written in. A file outside
	// every root is refused; no roots refuse every file.
	Roots []string
	Options
}

// FileResult reports one target. Err is a *Refusal when the file was not
// written; Written is false when the plan changes nothing.
type FileResult struct {
	Path    string
	Display string
	Written bool
	Diff    string
	Err     error
}

// prepared is a validated target, holding the descriptors it was checked on.
type prepared struct {
	index    int
	dir      *os.File
	file     *os.File
	base     string
	identity validation.FileIdentity
	perm     os.FileMode
	digest   string
	after    []byte
}

// beforeRename runs after the temporary file is written and before the final
// checks; tests replace it to inject failures and races.
var beforeRename = func(dir *os.File, tempName string) error { return nil }

// Apply writes the planned edits to disk. Every target is validated first;
// only then is each valid target written, one file at a time, through a
// temporary file in the same directory and a rename. A target that fails
// any check is left untouched and reported; the others are still written.
func Apply(targets []Target, opts ApplyOptions) []FileResult {
	results := make([]FileResult, len(targets))
	roots, rootsErr := cleanRoots(opts.Roots)
	seen := map[string]int{}
	for i, target := range targets {
		results[i] = FileResult{Path: target.Path, Display: target.Plan.Display, Diff: target.Plan.Diff}
		if abs, err := filepath.Abs(target.Path); err == nil {
			seen[abs]++
		}
	}
	var ready []*prepared
	identities := map[validation.FileIdentity]int{}
	for i, target := range targets {
		if rootsErr != nil {
			results[i].Err = rootsErr
			continue
		}
		if abs, err := filepath.Abs(target.Path); err == nil && seen[abs] > 1 {
			results[i].Err = refuse(ReasonConflictingEdits, "the same file appears more than once in the batch")
			continue
		}
		p, err := prepare(i, target, roots, opts.Options)
		if err != nil {
			results[i].Err = err
			continue
		}
		if p == nil {
			continue
		}
		key := validation.FileIdentity{Dev: p.identity.Dev, Ino: p.identity.Ino}
		if other, duplicate := identities[key]; duplicate {
			results[i].Err = refuse(ReasonConflictingEdits, "the same file appears more than once in the batch")
			results[other].Err = results[i].Err
			p.close()
			continue
		}
		identities[key] = i
		ready = append(ready, p)
	}
	for _, p := range ready {
		if results[p.index].Err != nil {
			p.close()
			continue
		}
		if err := p.write(); err != nil {
			results[p.index].Err = err
		} else {
			results[p.index].Written = true
		}
		p.close()
	}
	return results
}

func cleanRoots(roots []string) ([]string, error) {
	cleaned := make([]string, 0, len(roots))
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil || root == "" {
			return nil, refuse(ReasonOutsideRoots, "a declared root is not a usable path")
		}
		cleaned = append(cleaned, filepath.Clean(abs))
	}
	return cleaned, nil
}

func inside(path string, roots []string) bool {
	for _, root := range roots {
		if root == string(filepath.Separator) || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// prepare validates one target. It returns nil, nil when the plan changes
// nothing.
func prepare(index int, target Target, roots []string, opts Options) (*prepared, error) {
	abs, err := filepath.Abs(target.Path)
	if err != nil || target.Path == "" {
		return nil, refuse(ReasonUnsafeFile, "the file path is not usable")
	}
	abs = filepath.Clean(abs)
	if !inside(abs, roots) {
		return nil, refuse(ReasonOutsideRoots, "the file is not inside a declared root")
	}
	dir, err := validation.OpenInputDirectory(filepath.Dir(abs))
	if err != nil {
		return nil, refuse(ReasonUnsafeFile, "the file's directory cannot be reached without following a symlink")
	}
	p := &prepared{index: index, dir: dir, base: filepath.Base(abs), digest: target.Plan.Digest}
	if err := p.open(); err != nil {
		p.close()
		return nil, err
	}
	src, err := io.ReadAll(io.LimitReader(p.file, int64(MaxFileBytes)+1))
	if err != nil {
		p.close()
		return nil, refuse(ReasonUnsafeFile, "the file cannot be read")
	}
	if len(src) > MaxFileBytes {
		p.close()
		return nil, refuse(ReasonLimit, "the file is larger than the per-file limit")
	}
	if digestOf(src) != target.Plan.Digest {
		p.close()
		return nil, refuse(ReasonFileChanged, "the file changed since the fix was planned")
	}
	after, err := ApplyInMemory(src, target.Plan, opts)
	if err != nil {
		p.close()
		return nil, err
	}
	if bytes.Equal(after, src) {
		p.close()
		return nil, nil
	}
	p.after = after
	return p, nil
}

// open opens the file without following a symlink and checks its type,
// permissions, owner and link count on the open descriptor.
func (p *prepared) open() error {
	kind, err := validation.StatEntry(p.dir, p.base)
	if err != nil {
		return refuse(ReasonUnsafeFile, "the file cannot be inspected")
	}
	if kind == validation.EntrySymlink {
		return refuse(ReasonUnsafeFile, "the file is a symlink; symlinks are never followed")
	}
	if kind != validation.EntryRegular {
		return refuse(ReasonUnsafeFile, "the file is not a regular file")
	}
	file, err := validation.OpenEntryFile(p.dir, p.base)
	if err != nil {
		return refuse(ReasonUnsafeFile, "the file cannot be opened without following a symlink")
	}
	p.file = file
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return refuse(ReasonUnsafeFile, "the file is not a regular file")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return refuse(ReasonUnsafeFile, "the file has special mode bits")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return refuse(ReasonUnsafeFile, "the file is group or other writable")
	}
	identity, ok := validation.IdentityOf(info)
	if !ok || identity.Nlink != 1 {
		return refuse(ReasonUnsafeFile, "the file has more than one link")
	}
	if identity.Uid != uint64(os.Geteuid()) {
		return refuse(ReasonUnsafeFile, "the file is owned by another user")
	}
	p.identity, p.perm = identity, info.Mode().Perm()
	return nil
}

func (p *prepared) close() {
	if p.file != nil {
		_ = p.file.Close()
	}
	if p.dir != nil {
		_ = p.dir.Close()
	}
}

// write replaces the file through a temporary sibling. Right before the
// rename it checks again that the name still refers to the checked file and
// that the file still has the planned digest.
func (p *prepared) write() (err error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return refuse(ReasonWriteFailed, "no random name for the temporary file")
	}
	tempName := "." + p.base + ".prufyx-" + hex.EncodeToString(random) + ".tmp"
	if len(tempName) > 255 {
		tempName = ".prufyx-" + hex.EncodeToString(random) + ".tmp"
	}
	dirFD := int(p.dir.Fd())
	fd, err := unix.Openat(dirFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return refuse(ReasonWriteFailed, "the temporary file cannot be created")
	}
	temp := os.NewFile(uintptr(fd), tempName)
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dirFD, tempName, 0)
		}
	}()
	if _, err := temp.Write(p.after); err != nil {
		_ = temp.Close()
		return refuse(ReasonWriteFailed, "the temporary file cannot be written")
	}
	if err := unix.Fchmod(fd, uint32(p.perm)); err != nil {
		_ = temp.Close()
		return refuse(ReasonWriteFailed, "the permission bits cannot be kept")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return refuse(ReasonWriteFailed, "the temporary file cannot be synced")
	}
	if err := temp.Close(); err != nil {
		return refuse(ReasonWriteFailed, "the temporary file cannot be closed")
	}
	if err := beforeRename(p.dir, tempName); err != nil {
		return refuse(ReasonWriteFailed, "the file cannot be replaced")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, p.base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		uint64(st.Dev) != p.identity.Dev || uint64(st.Ino) != p.identity.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return refuse(ReasonFileChanged, "the file was replaced since it was checked")
	}
	current, err := io.ReadAll(io.NewSectionReader(p.file, 0, int64(MaxFileBytes)+1))
	if err != nil || digestOf(current) != p.digest {
		return refuse(ReasonFileChanged, "the file changed since the fix was planned")
	}
	if err := unix.Renameat(dirFD, tempName, dirFD, p.base); err != nil {
		return refuse(ReasonWriteFailed, "the file cannot be replaced")
	}
	renamed = true
	_ = p.dir.Sync()
	return nil
}
