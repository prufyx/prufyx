// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package localcollector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func kubeconfigTimesMatch(before, after os.FileInfo) bool {
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	return bok && aok && before.ModTime().Equal(after.ModTime()) && b.Ctimespec.Sec == a.Ctimespec.Sec && b.Ctimespec.Nsec == a.Ctimespec.Nsec
}

func canonicalKubeconfigTempPath(path string) string {
	path = filepath.Clean(path)
	for _, pair := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if path == pair[0] {
			return pair[1]
		}
		if strings.HasPrefix(path, pair[0]+string(filepath.Separator)) {
			return pair[1] + strings.TrimPrefix(path, pair[0])
		}
	}
	return path
}
