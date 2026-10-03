// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"os"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
)

// runGate wires the knowledge gate subcommands (classify, limits, verify).
// Only "verify --source github" uses the network.
func runGate(args []string, stdout, stderr io.Writer) error {
	if code := knowledgegate.Main(args, os.Getenv, stdout, stderr); code != 0 {
		return &commandError{code: code, message: "gate failed", printed: true}
	}
	return nil
}
