// SPDX-License-Identifier: AGPL-3.0-only

package gitops_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestFrozenPackagesNotShipped guards the freeze of internal/fix and
// internal/gitops: neither may be wired into the community binary before an
// explicit decision (FIX4/GIT3).
func TestFrozenPackagesNotShipped(t *testing.T) {
	out, err := exec.Command("go", "list", "-buildvcs=false", "-deps", "../../cmd/prufyx-community").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasSuffix(dep, "/cli/internal/fix") || strings.HasSuffix(dep, "/cli/internal/gitops") {
			t.Errorf("frozen package %s is a dependency of prufyx-community", dep)
		}
	}
}
