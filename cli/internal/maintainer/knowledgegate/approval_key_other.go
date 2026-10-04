// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import "errors"

// readApprovalKeyFile refuses key files where their permissions cannot be
// checked; pipe the key on standard input instead.
func readApprovalKeyFile(string) ([]byte, error) {
	return nil, errors.New("key files are supported on Linux and macOS only; use --key-stdin")
}
