// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package knowledge

import (
	"errors"
	"os"
)

// The knowledge store is anchored on directory descriptors, no-follow opens,
// owner and link-count checks and flock(2). None of these exist on Windows, so
// every store operation refuses instead of running with weaker guarantees.
var errUnsupportedPlatform = errors.New("knowledge store is not supported on Windows")

func platformCanonicalPath(path string) string { return path }

func fdOpenRoot() (*os.File, error) { return nil, errUnsupportedPlatform }

func fdOpenDir(*os.File, string) (*os.File, error) { return nil, errUnsupportedPlatform }

func fdMkdir(*os.File, string, uint32) error { return errUnsupportedPlatform }

func fdOpenFile(*os.File, string, int, uint32) (*os.File, error) {
	return nil, errUnsupportedPlatform
}

func fdRename(*os.File, string, string) error { return errUnsupportedPlatform }

func fdRenameNoReplace(*os.File, string, string) error { return errUnsupportedPlatform }

func fdUnlink(*os.File, string) error { return errUnsupportedPlatform }

func fdSync(*os.File) error { return errUnsupportedPlatform }

func fileNlink(os.FileInfo) uint64 { return 0 }

func lockFileExclusiveNonBlocking(*os.File) error { return errUnsupportedPlatform }

func lockWouldBlock(error) bool { return false }

func unlockFile(*os.File) error { return errUnsupportedPlatform }
