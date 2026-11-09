// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const (
	approvalStagePrefix = ".approval-stage-"
	// staleStageAge is how old a staging directory must be before the next
	// signing removes it: a run killed half way leaves one behind.
	staleStageAge = time.Hour
)

type fileID struct{ dev, ino uint64 }

func fileIDOf(st *unix.Stat_t) fileID { return fileID{uint64(st.Dev), uint64(st.Ino)} } //nolint:unconvert

// writeApprovalFiles writes <ids[i]>.json with raws[i] into dir, all or
// none. dir's parent must exist and is opened without following a link in
// any component; every later step is relative to that descriptor. The files
// are written (exclusive, no-follow) to a staging directory in the parent;
// the staging directory is renamed to dir when dir does not exist, else each
// file is hard-linked into dir (a link never replaces a file) and, if one
// link fails, the links made are removed again, each only if it is still the
// file this run linked (device and inode). The remainder that cannot be
// closed: between that check and the unlink another process can swap the
// file again. The staging directory is removed in every case, and one left by
// a killed run is removed by the next (same owner, older than an hour).
func writeApprovalFiles(dir string, ids []string, raws [][]byte) error {
	if len(ids) != len(raws) || len(ids) == 0 {
		return errors.New("no approvals to write")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	parent, pack := filepath.Dir(abs), filepath.Base(abs)
	pf, err := currentbundle.OpenDirectoryNoFollow(parent)
	if err != nil {
		return fmt.Errorf("cannot create %s: its parent directory is missing, a symbolic link or cannot be opened", logSafe(dir))
	}
	defer func() { _ = pf.Close() }()
	pfd := int(pf.Fd())
	removeStaleStages(pf)

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := approvalStagePrefix + hex.EncodeToString(nonce[:])
	if err := unix.Mkdirat(pfd, stage, 0o755); err != nil {
		return fmt.Errorf("cannot stage the approvals: %w", err)
	}
	defer removeStageDir(pf, stage)
	sfd, err := unix.Openat(pfd, stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot stage the approvals: %w", err)
	}
	sf := os.NewFile(uintptr(sfd), stage)
	defer func() { _ = sf.Close() }()

	staged := make([]fileID, len(ids))
	for i, id := range ids {
		fd, err := unix.Openat(sfd, id+".json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, approvalFileMode)
		if err != nil {
			return fmt.Errorf("cannot stage %s: %w", logSafe(id), err)
		}
		f := os.NewFile(uintptr(fd), id)
		werr := unix.Fchmod(fd, approvalFileMode)
		if werr == nil {
			_, werr = f.Write(raws[i])
		}
		if werr == nil {
			werr = f.Sync()
		}
		var st unix.Stat_t
		if werr == nil {
			werr = unix.Fstat(fd, &st)
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("cannot stage %s: %w", logSafe(id), werr)
		}
		staged[i] = fileIDOf(&st)
	}

	var st unix.Stat_t
	switch err := unix.Fstatat(pfd, pack, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
		if err := unix.Renameat(pfd, stage, pfd, pack); err != nil {
			return fmt.Errorf("cannot create %s: %w", logSafe(dir), err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("cannot write %s: %w", logSafe(dir), err)
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%s is not a directory (a symbolic link is refused)", logSafe(dir))
	}
	dfd, err := unix.Openat(pfd, pack, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot write %s: a symbolic link or not a directory", logSafe(dir))
	}
	df := os.NewFile(uintptr(dfd), pack)
	defer func() { _ = df.Close() }()

	for i, id := range ids {
		name := id + ".json"
		if err := unix.Linkat(sfd, name, dfd, name, 0); err != nil {
			for j := 0; j < i; j++ {
				var cur unix.Stat_t
				n := ids[j] + ".json"
				if unix.Fstatat(dfd, n, &cur, unix.AT_SYMLINK_NOFOLLOW) == nil && fileIDOf(&cur) == staged[j] {
					_ = unix.Unlinkat(dfd, n, 0)
				}
			}
			return fmt.Errorf("cannot create %s: %w; no approval was written", logSafe(filepath.Join(dir, name)), err)
		}
		afterApprovalLink(name)
	}
	return nil
}

// removeStageDir removes a staging directory of regular files, relative to
// the parent descriptor. It follows nothing and removes nothing else.
func removeStageDir(parent *os.File, name string) {
	pfd := int(parent.Fd())
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	d := os.NewFile(uintptr(fd), name)
	names, _ := d.Readdirnames(-1)
	for _, n := range names {
		var st unix.Stat_t
		if unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			_ = unix.Unlinkat(fd, n, 0)
		}
	}
	_ = d.Close()
	_ = unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
}

// removeStaleStages removes the staging directories a killed run left in the
// parent: a real directory (not a link) named like ours, owned by this user,
// not modified within staleStageAge.
func removeStaleStages(parent *os.File) {
	names, err := parent.Readdirnames(-1)
	if err != nil {
		return
	}
	for _, n := range names {
		if !strings.HasPrefix(n, approvalStagePrefix) {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(int(parent.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != syscall.Getuid() {
			continue
		}
		fd, err := unix.Openat(int(parent.Fd()), n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		d := os.NewFile(uintptr(fd), n)
		info, err := d.Stat()
		_ = d.Close()
		if err != nil || time.Since(info.ModTime()) < staleStageAge {
			continue
		}
		removeStageDir(parent, n)
	}
}

// approvalSigningSupported is checked before any confirmation or key read.
var approvalSigningSupported = true
