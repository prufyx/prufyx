// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

// assess --to accepts only a strict X.Y.Z; everything else is a usage error
// raised before any cluster access.
func TestAssessRejectsMalformedTarget(t *testing.T) {
	for _, to := range []string{"1.25", "v1.25.1", "1.25.1-gke.100", "1.25.1-rc.0", "garbage"} {
		code, stdout, stderr := runCommunity(t, "assess", "--kubeconfig", "/nonexistent", "--acknowledge-kubeconfig-exec-risk", "--to", to, "ctx")
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid --to") {
			t.Errorf("to=%q: code=%d stdout=%q stderr=%q", to, code, stdout, stderr)
		}
	}
}
