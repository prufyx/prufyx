// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
)

// runExtract wires the extract subcommands (run, verify, oracle, list).
// They read only the offline mirror or a fixture tree and never publish.
func runExtract(args []string, stdout, stderr io.Writer) error {
	var packs []string
	if root, err := cliRoot(); err == nil {
		for _, p := range []string{"internal/cncfcheck/data/rules.json", "internal/projectcheck/data/rules.json"} {
			if info, err := os.Stat(filepath.Join(root, p)); err == nil && info.Mode().IsRegular() {
				packs = append(packs, filepath.Join(root, p))
			}
		}
	}
	if code := extractcli.Main(args, packs, time.Now, stdout, stderr); code != 0 {
		return &commandError{code: code, message: "extract failed", printed: true}
	}
	return nil
}
