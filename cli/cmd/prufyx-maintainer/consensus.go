// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"

	"github.com/prufyx/prufyx/cli/internal/consensus"
)

// runConsensus wires the consensus subcommands (normalise, verify). They
// read only the offline mirror or a fixture tree, never call a model or
// the network, and publish nothing.
func runConsensus(args []string, stdout, stderr io.Writer) error {
	if code := consensus.Main(args, stdout, stderr); code != 0 {
		return &commandError{code: code, message: "consensus failed", printed: true}
	}
	return nil
}
