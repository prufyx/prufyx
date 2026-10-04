// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The approval commands are wired in; a repeated option is refused before
// anything is read.
func TestApprovalCommandDispatch(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"approval", "help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "approval <sign|verify|public-key|keys-digest>") {
		t.Fatalf("help: %v %q", err, out.String())
	}
	err := run([]string{"approval", "sign", "--rule", "a", "--rule", "b"}, &out, &errOut)
	var ce *commandError
	if !errors.As(err, &ce) || ce.code != 2 || !strings.Contains(ce.message, "duplicate option") {
		t.Fatalf("duplicate option: %v", err)
	}
	err = run([]string{"approval", "sign"}, &out, &errOut)
	if !errors.As(err, &ce) || ce.code != 2 {
		t.Fatalf("missing options: %v", err)
	}
}
