// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package localcollector

import "os/exec"

func configureProcessGroup(cmd *exec.Cmd) {}
func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
