// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package changelogcli

import "testing"

func specialTargets(t *testing.T, dir, dirLink string) map[string]string {
	return map[string]string{"symlink to dir": dirLink}
}
