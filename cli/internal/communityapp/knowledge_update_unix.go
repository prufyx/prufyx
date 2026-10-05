// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux || darwin

package communityapp

import (
	"os"
	"syscall"
)

const openNoFollowNonblock = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func singleLinkOwnedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid())
}
