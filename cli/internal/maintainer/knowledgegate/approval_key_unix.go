// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"errors"
	"os"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
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
