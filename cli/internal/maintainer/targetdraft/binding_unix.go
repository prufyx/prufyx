// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package targetdraft

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel puts the command in its own process group and kills the
// whole group when the context ends, so a child of git cannot outlive the
// deadline.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
