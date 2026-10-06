// SPDX-License-Identifier: AGPL-3.0-only

// Package actionscript runs the script-level tests of the composite GitHub
// Action (action.yml, scripts/action) as part of the Go test suite.
package actionscript

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionScripts runs scripts/action/test.sh, which exercises install.sh
// and run.sh with a fake binary and a fake download tool, including inputs
// with quotes, command substitutions, flags and newlines.
func TestActionScripts(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "action", "test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("test script missing: %v", err)
	}
	// The scripts must behave the same whatever umask the runner has.
	for _, umask := range []string{"022", "0002"} {
		t.Run("umask-"+umask, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", `umask "$1"; exec "$2" "$3"`, "sh", umask, bash, script)
			cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("scripts/action/test.sh failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), " 0 failed") {
				t.Fatalf("unexpected output:\n%s", out)
			}
		})
	}
}
