// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package validation

import (
	"errors"
	"os"
)

// ErrUnsupportedPlatform is returned by every descriptor-relative primitive on
// Windows. Prufyx's input admission rests on openat/no-follow semantics and on
// POSIX owner, link-count and mode bits; Windows has none of these in a form
// that can be checked here, so file and directory input is refused rather than
// opened with weaker guarantees. Standard input is unaffected.
var ErrUnsupportedPlatform = errors.New("secure file input is not supported on Windows; pipe the manifest on standard input")

func atomicBatchPublicationSupported() bool { return false }

func openRootDirectory() (*os.File, error) { return nil, ErrUnsupportedPlatform }

func openRelativeFile(*os.File, string, int, uint32) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func openRelativeDirectory(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func mkdirRelative(*os.File, string, uint32) error { return ErrUnsupportedPlatform }

func openRelativeExclusive(*os.File, string, uint32) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func syncDirectory(*os.File) error { return ErrUnsupportedPlatform }

func renameNoReplaceRelative(*os.File, string, string) error { return ErrUnsupportedPlatform }

func removeRelative(*os.File, string) error { return ErrUnsupportedPlatform }

func removeDirectoryRelative(*os.File, string) error { return ErrUnsupportedPlatform }
