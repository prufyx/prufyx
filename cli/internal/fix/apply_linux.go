// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fix

import "golang.org/x/sys/unix"

// allowedAttribute: the security label is assigned by policy to the new
// file in the same directory, so it is not carried over by hand. Everything
// else, including POSIX ACLs (system.posix_acl_*) and file capabilities
// (security.capability), would be dropped and makes the file refused.
func allowedAttribute(name string) bool { return name == "security.selinux" }

// unpreservable refuses a file with extended attributes a replacement would
// drop. Linux inode attribute flags (chattr) are not inspected: the ones
// that matter (immutable, append-only) make the rename fail, which is
// reported as WRITE_FAILED, and the rest are not access controls.
func unpreservable(fd int, _ *unix.Stat_t) *Refusal { return unpreservableAttributes(fd) }

// syncDescriptor flushes to stable storage.
func syncDescriptor(fd int) error { return unix.Fsync(fd) }
