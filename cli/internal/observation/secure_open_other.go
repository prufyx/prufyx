// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package observation

import "os"

// Descriptor-relative observation I/O exists only on Linux and macOS. On every
// other platform each constructor refuses with ErrUnsupportedPlatform before
// any of these functions is reached; they exist so the package compiles.

func observationPlatformSupported() bool { return false }

func observationDupFile(*os.File) (*os.File, error) { return nil, ErrUnsupportedPlatform }

func observationOpenRoot(string) (*os.File, string, error) {
	return nil, "", ErrUnsupportedPlatform
}

func observationOpenDirectory(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func observationOpenFile(*os.File, string) (*os.File, error) { return nil, ErrUnsupportedPlatform }

func observationStableIdentity(*os.File) (stableIdentity, error) {
	return stableIdentity{}, ErrUnsupportedPlatform
}

func observationStatAt(*os.File, string) (stableIdentity, error) {
	return stableIdentity{}, ErrUnsupportedPlatform
}
