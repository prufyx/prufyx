// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// runFactory wires the factory subcommands (mirror, registry derive, ack,
// status). Only "factory mirror" uses the network.
func runFactory(args []string, stdout, stderr io.Writer) error {
	var packs []string
	if root, err := cliRoot(); err == nil {
		packs = []string{
			filepath.Join(root, "internal/cncfcheck/data/rules.json"),
			filepath.Join(root, "internal/projectcheck/data/rules.json"),
		}
	}
	if code := factorymirror.Main(args, packs, os.Getenv, stdout, stderr); code != 0 {
		return &commandError{code: code, message: "factory failed", printed: true}
	}
	return nil
}
