// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestChangelogFragmentsAreValid runs the same check the release cut runs, so a
// malformed changelog.d fragment fails in the pull request that adds it.
func TestChangelogFragmentsAreValid(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	script := filepath.Join(repo, "scripts", "changelog-assemble.sh")
	if _, err := os.Stat(script); os.IsNotExist(err) {
		t.Skip("no scripts directory: staged release source tree")
	}
	out, err := exec.Command("sh", script, "--check").CombinedOutput()
	if err != nil {
		t.Fatalf("changelog fragments invalid: %v\n%s", err, out)
	}
}
