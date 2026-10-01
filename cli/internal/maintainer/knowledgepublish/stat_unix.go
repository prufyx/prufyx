// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgepublish

import (
	"os"
	"syscall"
)

func fileUID(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
