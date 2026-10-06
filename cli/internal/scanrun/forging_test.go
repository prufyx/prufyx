// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"testing"
	"unicode"
)

// TestUsageErrorsNeverCarryTerminalControls: a command line, a path or a
// component name from the scanned input never reaches the error text as a
// terminal escape, a line break or a bidirectional control.
func TestUsageErrorsNeverCarryTerminalControls(t *testing.T) {
	hostile := []string{"\x1b[2J", "\x1b]0;x\x07", "\u009b2J", "a\nPASS forged", "a\rb", "\u202eevil", "\u2028x", "\x7f"}
	for _, value := range hostile {
		for _, args := range [][]string{
			{"--" + value},
			{"--format=" + value},
			{"--format", value},
			{"--current=kubernetes=" + value},
			{"--current", value},
			{"--target=" + value},
			{"--permissions=" + value},
			{"--now=" + value},
		} {
			_, err := ParseArgs(args)
			if err == nil {
				continue
			}
			var usageErr *UsageError
			if !errors.As(err, &usageErr) {
				t.Fatalf("%q: error is %T", args, err)
			}
			for _, r := range err.Error() {
				if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar {
					t.Errorf("%q: error carries %U: %q", args, r, err.Error())
					break
				}
			}
		}
	}
}
