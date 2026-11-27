// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"

	"github.com/prufyx/prufyx/cli/internal/maintainer/removalproof"
)

// runFlagRemovalVerify wires the report-only check of removed command line
// flags. It writes no rule and no fact.
func runFlagRemovalVerify(args []string, stdout, stderr io.Writer) error {
	if code := removalproof.Main(args, stdout, stderr); code != 0 {
		return &commandError{code: code, message: "flag-removal-verify did not pass", printed: true}
	}
	return nil
}
