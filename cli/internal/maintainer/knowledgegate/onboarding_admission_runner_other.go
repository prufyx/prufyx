// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import (
	"errors"
	"os/exec"
)

// runnerKillGroup refuses: without a process group the deadline cannot kill
// a child of git, so on this platform no upstream command is run at all
// (fail closed; the supported platforms are linux and darwin).
func runnerKillGroup(_ *exec.Cmd) error {
	return errors.New("upstream runner unsupported on this platform: no process group kill")
}
