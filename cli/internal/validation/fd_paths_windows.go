// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package validation

import (
	"os"
)

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

func renameRelative(*os.File, string, string) error { return ErrUnsupportedPlatform }
