// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/validation"
)

// A refused file input on Windows names the platform and the way out, even
// when the paths are redacted (18-m2).
func TestInputErrorNamesTheWindowsLimitation(t *testing.T) {
	cause := fmt.Errorf("%w: manifest.yaml: %w", intake.ErrInput, validation.ErrUnsupportedPlatform)
	for _, redact := range []bool{false, true} {
		err := inputError(cause, Request{Redact: redact})
		if err == nil || !strings.Contains(err.Error(), "not supported on Windows") || !strings.Contains(err.Error(), "standard input") {
			t.Fatalf("redact=%v: want the Windows message, got %v", redact, err)
		}
		if redact && strings.Contains(err.Error(), "manifest.yaml") {
			t.Fatalf("a redacted message names the path: %v", err)
		}
	}
	if err := inputError(fmt.Errorf("%w: x", intake.ErrInput), Request{}); strings.Contains(err.Error(), "Windows") {
		t.Fatalf("an ordinary failure must not mention Windows: %v", err)
	}
}
