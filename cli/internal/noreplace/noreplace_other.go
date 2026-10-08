// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !(linux && (amd64 || arm64))

package noreplace

import "os"

// Rename is unsupported on this platform; it always returns ErrUnsupported.
func Rename(*os.File, string, string) error { return ErrUnsupported }
