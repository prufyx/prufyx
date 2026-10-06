// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package currentbundle

import (
	"errors"
	"os"
)

// Descriptor-relative, no-follow artifact I/O is not available on Windows.
// Every opener refuses, and the metadata probes report values that fail the
// callers' single-link, owner and change-time checks, so a bundle file is
// never read or written with weaker guarantees than on Linux and macOS.
var errUnsupportedPlatform = errors.New("secure artifact I/O is not supported on Windows")

func openArtifactFile(string, int, os.FileMode) (*os.File, error) {
	return nil, errUnsupportedPlatform
}

func artifactLinkCount(os.FileInfo) uint64 { return 0 }

func artifactChangeTimesMatch(_, _ os.FileInfo) bool { return false }

func artifactOwnedByCurrentUser(os.FileInfo) bool { return false }

func openDirectoryNoFollow(string) (*os.File, error) { return nil, errUnsupportedPlatform }

func openRelativeFile(*os.File, string) (*os.File, error) { return nil, errUnsupportedPlatform }

func readBoundedRelative(*os.File, string, int) ([]byte, error) {
	return nil, errUnsupportedPlatform
}
