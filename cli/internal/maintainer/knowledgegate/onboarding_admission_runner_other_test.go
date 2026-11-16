// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import (
	"context"
	"os/exec"
	"testing"
)

// On a platform without the process-group kill the runner refuses: no command
// is started and a typed error comes back.
func TestRunnerRefusesWithoutGroupKill(t *testing.T) {
	cmd := exec.Command("git")
	if err := runnerKillGroup(cmd); err == nil || cmd.Cancel != nil || cmd.SysProcAttr != nil {
		t.Fatalf("group kill unsupported but not refused: %v", err)
	}
	res := runnerExec(context.Background(), "git", []string{"--version"}, nil, t.TempDir())
	if res.Err == nil || res.Exit != 0 || len(res.Stdout) != 0 || res.TimedOut {
		t.Fatalf("a command ran or was not refused: %+v", res)
	}
}
