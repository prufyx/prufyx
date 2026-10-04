// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"os"
	"testing"
)

// A key file owned by another user is refused even with mode 0600.
func TestApprovalSignKeyFileOwner(t *testing.T) {
	f := newRuleFixture(t)
	path := f.key.keyFile(t, 0o600)
	defer func(orig func() int) { currentUID = orig }(currentUID)
	currentUID = func() int { return os.Getuid() + 1 }
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", path)...), 2, "not owned by the current user")
}
