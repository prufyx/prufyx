// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"golang.org/x/sys/unix"
)

// currentUID is the user a key file must belong to; tests replace it.
var currentUID = os.Getuid

// readApprovalKeyFile reads a private key file. It refuses a symbolic link
// (at any path component), anything but a regular file with one link, a
// file not owned by the current user, and any mode with a group or other
// permission bit or a setuid, setgid or sticky bit. Errors never contain
// any of the file's content.
func readApprovalKeyFile(path string) ([]byte, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("the key file is a symbolic link; give the file itself")
	}
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, MaxApprovalKeyBytes)
	if err != nil || info == nil {
		if raw != nil {
			wipe(raw)
		}
		return nil, errors.New("the key file cannot be read: it must be a regular file with one link, no symbolic link in its path, at most 4 KiB")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		wipe(raw)
		return nil, errors.New("the key file mode gives group or others access or sets a special bit; run chmod 600 on it")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != currentUID() {
		wipe(raw)
		return nil, errors.New("the key file is not owned by the current user")
	}
	return raw, nil
}

// approvalFileMode is the mode of a written approval: a public record.
const approvalFileMode = 0o644

// writeApprovalFile creates path with the approval's bytes. It never
// replaces a file and never writes through a symbolic link: the deepest
// existing directory of the path is opened without following a link in any
// component, missing directories are created below it one by one and opened
// the same way, and the file is created relative to that descriptor with
// O_EXCL and O_NOFOLLOW, then set to mode 0644 whatever the umask.
func writeApprovalFile(path string, raw []byte) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, name := filepath.Dir(abs), filepath.Base(abs)
	var missing []string
	for {
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("cannot create %s: no existing directory", path)
		}
		missing = append([]string{filepath.Base(dir)}, missing...)
		dir = parent
	}
	d, err := currentbundle.OpenDirectoryNoFollow(dir)
	if err != nil {
		return fmt.Errorf("cannot create %s: a directory in the path is a symbolic link or cannot be opened", path)
	}
	defer func() { _ = d.Close() }()
	for _, part := range missing {
		if err := unix.Mkdirat(int(d.Fd()), part, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("cannot create %s: %w", path, err)
		}
		fd, err := unix.Openat(int(d.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("cannot create %s: a directory in the path is a symbolic link or cannot be opened", path)
		}
		_ = d.Close()
		d = os.NewFile(uintptr(fd), part)
	}
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, approvalFileMode)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), name)
	werr := unix.Fchmod(fd, approvalFileMode)
	if werr == nil {
		_, werr = f.Write(raw)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = unix.Unlinkat(int(d.Fd()), name, 0)
		return fmt.Errorf("cannot write %s: %w", path, werr)
	}
	return nil
}
