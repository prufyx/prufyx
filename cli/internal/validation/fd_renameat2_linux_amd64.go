// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux && amd64

package validation

// Linux syscall numbers are architecture-specific; keep the no-replace
// primitive explicit so CGO-free cross builds do not depend on syscall's
// deprecated constant set.
const linuxSYSRenameat2 = 316
