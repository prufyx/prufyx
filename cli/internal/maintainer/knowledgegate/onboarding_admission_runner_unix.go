// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"os/exec"
	"syscall"
)

// runnerKillGroup puts the command in its own process group and kills the
// whole group when the context ends, so a child of git cannot outlive the
// deadline.
func runnerKillGroup(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return nil
}
