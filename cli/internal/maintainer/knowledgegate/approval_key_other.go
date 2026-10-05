// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import (
	"errors"
	"os"
	"path/filepath"
)

// readApprovalKeyFile refuses key files where their permissions cannot be
// checked; pipe the key on standard input instead.
func readApprovalKeyFile(string) ([]byte, error) {
	return nil, errors.New("key files are supported on Linux and macOS only; use --key-stdin")
}

// writeApprovalFile creates path with the approval's bytes, never
// replacing a file (O_EXCL). Parent directories are not checked for links
// on these platforms.
func writeApprovalFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(raw)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
	}
	return werr
}
