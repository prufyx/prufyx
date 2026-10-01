// SPDX-License-Identifier: AGPL-3.0-only

//go:build (darwin && (amd64 || arm64)) || (linux && (amd64 || arm64))

package observation

import (
	"fmt"
	"syscall"
)

// countOpenDescriptors uses the kernel's descriptor table directly instead of
// reading /dev/fd. macOS may expose /dev/fd as a devfs view which fails
// fstatat/read-dir under the Go test process; F_GETFD is available on both
// supported Unix hosts and does not open any descriptor itself.
func countOpenDescriptors() (int, error) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, fmt.Errorf("getrlimit nofile: %w", err)
	}
	if limit.Cur == 0 || limit.Cur > 1<<20 {
		return 0, fmt.Errorf("unexpected nofile limit %d", limit.Cur)
	}
	count := 0
	for fd := uintptr(0); fd < uintptr(limit.Cur); fd++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno == 0 {
			count++
			continue
		}
		if errno != syscall.EBADF {
			return 0, fmt.Errorf("fcntl descriptor %d: %w", fd, errno)
		}
	}
	return count, nil
}
