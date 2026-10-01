// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package localcollector

import (
	"os"
	"path/filepath"
	"syscall"
)

func kubeconfigTimesMatch(before, after os.FileInfo) bool {
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	return bok && aok && before.ModTime().Equal(after.ModTime()) && b.Ctim.Sec == a.Ctim.Sec && b.Ctim.Nsec == a.Ctim.Nsec
}

func canonicalKubeconfigTempPath(path string) string { return filepath.Clean(path) }
