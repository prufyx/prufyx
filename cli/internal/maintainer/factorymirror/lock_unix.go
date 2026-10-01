// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package factorymirror

import (
	"errors"
	"syscall"
)

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
