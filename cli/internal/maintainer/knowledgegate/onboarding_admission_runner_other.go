// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import "os/exec"

// runnerKillGroup keeps the default kill of the process on cancel.
func runnerKillGroup(cmd *exec.Cmd) {}
