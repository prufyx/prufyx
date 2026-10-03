// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package fix

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
// written; Written is false when the plan changes nothing. Diff is the diff
// of the edits that were actually applied, computed again at apply time (never
// copied from the plan); it is empty when the file was refused or unchanged.
// One case has both Written and a non-nil Err: the file was replaced but the
// replacement could not be made durable (WRITE_FAILED).
type FileResult struct {
	Path    string
	Display string
	Written bool
	Diff    string
	Err     error
}

// prepared is a validated target. It holds no descriptors: the file is
// opened again, and checked against the recorded identity, when it is
// written, so a large batch never holds more than a few descriptors.
type prepared struct {
	index    int
	abs      string
	identity validation.FileIdentity
	digest   string
}

// handles are the open descriptors of one checked file and its directory.
type handles struct {
	dir      *os.File
	file     *os.File
	base     string
	identity validation.FileIdentity
	perm     os.FileMode
	gid      uint32
}

func (h *handles) close() {
	if h.file != nil {
		_ = h.file.Close()
	}
	if h.dir != nil {
		_ = h.dir.Close()
	}
}

// Test seams. Production values are the real calls.
var (
	// beforeRename runs after the temporary file is written and before the
	// final checks; tests replace it to inject failures and races.
	beforeRename = func(dir *os.File, tempName string) error { return nil }
	// effectiveUID is the user files must belong to.
	effectiveUID = os.Geteuid
	// tempSuffix returns the random part of the temporary file name.
	tempSuffix = func() (string, error) {
		random := make([]byte, 8)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		return hex.EncodeToString(random), nil
	}
	// fchownGroup sets the group of the temporary file.
	fchownGroup = func(fd int, gid uint32) error { return unix.Fchown(fd, -1, int(gid)) }
	// syncFile and syncDir make a file or directory durable; see syncDescriptor.
	syncFile = syncDescriptor
	syncDir  = syncDescriptor
)

// Apply writes the planned edits to disk. Every target is validated first;
// only then is each valid target written, one file at a time, through a
// temporary file in the same directory and a rename. A target that fails
// any check is left untouched and reported; the others are still written.
//
// A plan is not trusted: the requested kinds are run again on the bytes read
// from disk, and must produce exactly the plan's edits and diff.
//
// The new file keeps the permission bits, the owner and the group of the old
// one. Anything else attached to a file that a replacement cannot carry over
// makes the file refused: extended attributes (on Linux, where POSIX ACLs and
// file capabilities are extended attributes, and on macOS), and BSD file
// flags on macOS. The only exceptions are attributes that are provenance or
// labelling data the system re-creates (com.apple.provenance on macOS,
// security.selinux on Linux). macOS ACLs are not extended attributes and
// cannot be read without cgo, so they are not detected: a replacement drops
// them. Parent directories that are group or other writable and not sticky
// are refused, because another user could swap the name under the rename.
//
// Durability: the temporary file and the directory are synced after the
// write. On macOS fsync does not reach stable storage, so F_FULLFSYNC is
// used; where a file system does not support it, plain fsync is the best
// available. A sync error is reported, not ignored.
func Apply(targets []Target, opts ApplyOptions) []FileResult {
	results := make([]FileResult, len(targets))
	roots, rootsErr := cleanRoots(opts.Roots)
	seen := map[string]int{}
	for i, target := range targets {
		results[i] = FileResult{Path: target.Path, Display: target.Plan.Display}
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
			continue
		}
		identities[key] = i
		ready = append(ready, p)
	}
	for _, p := range ready {
		if results[p.index].Err != nil {
			continue
		}
		diff, written, err := p.write(targets[p.index].Plan, opts.Options)
		results[p.index].Err = err
		results[p.index].Written = written
		if written {
			results[p.index].Diff = diff
		}
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

// descriptorsExhausted reports EMFILE or ENFILE.
func descriptorsExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// openRefusal names why a file or directory could not be opened: no
// descriptors left, or the given explanation.
func openRefusal(err error, detail string) *Refusal {
	if descriptorsExhausted(err) {
		return refuse(ReasonDescriptorLimit, "the process has no file descriptors left; apply fewer files at a time")
	}
	return refuse(ReasonUnsafeFile, detail)
}

// readChecked reads the open file in full, bounded.
func readChecked(file *os.File) ([]byte, error) {
	src, err := io.ReadAll(io.NewSectionReader(file, 0, int64(MaxFileBytes)+1))
	if err != nil {
		return nil, refuse(ReasonUnsafeFile, "the file cannot be read")
	}
	if len(src) > MaxFileBytes {
		return nil, refuse(ReasonLimit, "the file is larger than the per-file limit")
	}
	return src, nil
}

// prepare validates one target, holding descriptors only while it does. It
// returns nil, nil when the plan changes nothing.
func prepare(index int, target Target, roots []string, opts Options) (*prepared, error) {
	abs, err := filepath.Abs(target.Path)
	if err != nil || target.Path == "" {
		return nil, refuse(ReasonUnsafeFile, "the file path is not usable")
	}
	abs = filepath.Clean(abs)
	if !inside(abs, roots) {
		return nil, refuse(ReasonOutsideRoots, "the file is not inside a declared root")
	}
	h, err := openChecked(abs)
	if err != nil {
		return nil, err
	}
	defer h.close()
	src, err := readChecked(h.file)
	if err != nil {
		return nil, err
	}
	if digestOf(src) != target.Plan.Digest {
		return nil, refuse(ReasonFileChanged, "the file changed since the fix was planned")
	}
	after, _, err := applyPlan(src, target.Plan, opts)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(after, src) {
		return nil, nil
	}
	return &prepared{index: index, abs: abs, identity: h.identity, digest: target.Plan.Digest}, nil
}

// openChecked opens the directory and the file without following a symlink
// and checks type, permissions, owner, link count and attached data on the
// open descriptors.
func openChecked(abs string) (*handles, error) {
	dir, err := validation.OpenInputDirectory(filepath.Dir(abs))
	if err != nil {
		return nil, openRefusal(err, "the file's directory cannot be reached without following a symlink")
	}
	h := &handles{dir: dir, base: filepath.Base(abs)}
	ok := false
	defer func() {
		if !ok {
			h.close()
		}
	}()
	dirInfo, err := dir.Stat()
	if err != nil {
		return nil, refuse(ReasonUnsafeFile, "the file's directory cannot be inspected")
	}
	if dirInfo.Mode().Perm()&0o022 != 0 && dirInfo.Mode()&os.ModeSticky == 0 {
		return nil, refuse(ReasonUnsafeFile, "the file's directory is group or other writable without the sticky bit")
	}
	kind, err := validation.StatEntry(dir, h.base)
	if err != nil {
		return nil, refuse(ReasonUnsafeFile, "the file cannot be inspected")
	}
	if kind == validation.EntrySymlink {
		return nil, refuse(ReasonUnsafeFile, "the file is a symlink; symlinks are never followed")
	}
	if kind != validation.EntryRegular {
		return nil, refuse(ReasonUnsafeFile, "the file is not a regular file")
	}
	file, err := validation.OpenEntryFile(dir, h.base)
	if err != nil {
		return nil, openRefusal(err, "the file cannot be opened without following a symlink")
	}
	h.file = file
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, refuse(ReasonUnsafeFile, "the file is not a regular file")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, refuse(ReasonUnsafeFile, "the file has special mode bits")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, refuse(ReasonUnsafeFile, "the file is group or other writable")
	}
	identity, found := validation.IdentityOf(info)
	if !found || identity.Nlink != 1 {
		return nil, refuse(ReasonUnsafeFile, "the file has more than one link")
	}
	if identity.Uid != uint64(effectiveUID()) {
		return nil, refuse(ReasonUnsafeFile, "the file is owned by another user")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, refuse(ReasonUnsafeFile, "the file cannot be inspected")
	}
	if r := unpreservable(int(file.Fd()), &st); r != nil {
		return nil, r
	}
	h.identity, h.perm, h.gid = identity, info.Mode().Perm(), st.Gid
	ok = true
	return h, nil
}

// write replaces the file through a temporary sibling. The file is opened
// again and must be the one that was validated, with the planned digest.
// Right before the rename it checks once more that the name still refers to
// that file and that the file still has the planned digest. It returns the
// diff of the applied edits and whether the file was replaced.
func (p *prepared) write(plan FilePlan, opts Options) (diff string, written bool, err error) {
	h, err := openChecked(p.abs)
	if err != nil {
		return "", false, err
	}
	defer h.close()
	if h.identity.Dev != p.identity.Dev || h.identity.Ino != p.identity.Ino {
		return "", false, refuse(ReasonFileChanged, "the file was replaced since it was checked")
	}
	src, err := readChecked(h.file)
	if err != nil {
		return "", false, err
	}
	if digestOf(src) != p.digest {
		return "", false, refuse(ReasonFileChanged, "the file changed since the fix was planned")
	}
	after, diff, err := applyPlan(src, plan, opts)
	if err != nil {
		return "", false, err
	}
	suffix, err := tempSuffix()
	if err != nil {
		return "", false, refuse(ReasonWriteFailed, "no random name for the temporary file")
	}
	tempName := "." + h.base + ".prufyx-" + suffix + ".tmp"
	if len(tempName) > 255 {
		tempName = ".prufyx-" + suffix + ".tmp"
	}
	dirFD := int(h.dir.Fd())
	fd, err := unix.Openat(dirFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if descriptorsExhausted(err) {
			return "", false, openRefusal(err, "")
		}
		return "", false, refuse(ReasonWriteFailed, "the temporary file cannot be created")
	}
	temp := os.NewFile(uintptr(fd), tempName)
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dirFD, tempName, 0)
		}
	}()
	if _, err := temp.Write(after); err != nil {
		_ = temp.Close()
		return "", false, refuse(ReasonWriteFailed, "the temporary file cannot be written")
	}
	// The owner is this user already; the group must be the old file's, or a
	// different group would gain access. Change it before the mode.
	if err := fchownGroup(fd, h.gid); err != nil {
		_ = temp.Close()
		return "", false, refuse(ReasonWriteFailed, "the group of the file cannot be kept")
	}
	if err := unix.Fchmod(fd, uint32(h.perm)); err != nil {
		_ = temp.Close()
		return "", false, refuse(ReasonWriteFailed, "the permission bits cannot be kept")
	}
	if err := syncFile(fd); err != nil {
		_ = temp.Close()
		return "", false, refuse(ReasonWriteFailed, "the temporary file cannot be synced")
	}
	if err := temp.Close(); err != nil {
		return "", false, refuse(ReasonWriteFailed, "the temporary file cannot be closed")
	}
	if err := beforeRename(h.dir, tempName); err != nil {
		return "", false, refuse(ReasonWriteFailed, "the file cannot be replaced")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, h.base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		uint64(st.Dev) != h.identity.Dev || uint64(st.Ino) != h.identity.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", false, refuse(ReasonFileChanged, "the file was replaced since it was checked")
	}
	current, err := readChecked(h.file)
	if err != nil || digestOf(current) != p.digest {
		return "", false, refuse(ReasonFileChanged, "the file changed since the fix was planned")
	}
	if err := unix.Renameat(dirFD, tempName, dirFD, h.base); err != nil {
		return "", false, refuse(ReasonWriteFailed, "the file cannot be replaced")
	}
	renamed = true
	if err := syncDir(dirFD); err != nil {
		return diff, true, refuse(ReasonWriteFailed, "the file was replaced but the directory could not be synced; the change may not survive a crash")
	}
	return diff, true, nil
}
