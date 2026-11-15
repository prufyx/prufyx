// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package targetdraft

import "os/exec"

// killGroupOnCancel keeps the default kill of the process on cancel.
func killGroupOnCancel(cmd *exec.Cmd) {}
