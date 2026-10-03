// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package fix

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyRefusesFileFlags(t *testing.T) {
	root, file, plan := workspace(t, 0o644)
	const hidden = 0x8000 // UF_HIDDEN
	if err := unix.Chflags(file, hidden); err != nil {
		t.Skip(err)
	}
	before := listing(t, root)
	result := applyOne(root, file, plan)
	if ReasonOf(result.Err) != ReasonUnsafeFile || result.Written {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed")
	}
}
