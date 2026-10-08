// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package offlineboundary

import (
	"os"
	"syscall"
)

// ownedByCurrentUser reports whether info is owned by the effective user. A
// 0700 directory owned by someone else can still be renamed away and replaced
// by its owner, so it is not private to this process.
func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
