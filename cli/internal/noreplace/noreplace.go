// SPDX-License-Identifier: AGPL-3.0-only

// Package noreplace renames a directory entry without ever replacing an
// existing destination: renameat2(RENAME_NOREPLACE) on Linux and
// renameatx_np(RENAME_EXCL) on macOS, issued as direct syscalls so CGO-free
// builds keep the guarantee. Both names are relative to one directory
// descriptor. It is shared by the validation package and the extract safefs
// package; it holds no policy of its own.
package noreplace

import "errors"

// ErrUnsupported is returned where the platform has no no-replace rename.
// Callers decide whether to fail closed or to fall back.
var ErrUnsupported = errors.New("no-replace rename is not supported on this platform")
