// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/validation"
)

// ReadFile reads one regular file named directly, under the same rules Open
// applies to a file named on the command line: the path is not a symlink
// and not standard input, the file is opened without following symlinks,
// the permission policy applies, and the file holds at most the per-file
// byte bound (DefaultFileBytes when opts.Limits.FileBytes is zero). The
// bytes are returned undecoded: the caller reads them in its own format.
// The file never joins a manifest workspace, and its digest is not part of
// a workspace digest.
func ReadFile(path string, opts Options) (FileRecord, []byte, error) {
	if path == "" || path == "-" || strings.IndexByte(path, 0) >= 0 {
		return FileRecord{}, nil, fmt.Errorf("%w: empty or invalid path", ErrInput)
	}
	limits := opts.Limits.withDefaults()
	info, err := os.Lstat(path)
	if err != nil {
		return FileRecord{}, nil, fmt.Errorf("%w: %s", ErrInput, path)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return FileRecord{}, nil, fmt.Errorf("%w: %s is a symlink, which is not followed", ErrInput, path)
	case !info.Mode().IsRegular():
		return FileRecord{}, nil, fmt.Errorf("%w: %s is not a regular file", ErrInput, path)
	}
	file, err := validation.OpenInputRegularFile(path)
	if err != nil {
		return FileRecord{}, nil, openFailure(path, err)
	}
	defer file.Close()
	display := filepath.Clean(path)
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return FileRecord{}, nil, fmt.Errorf("%w: %s is not a regular file", ErrInput, display)
	}
	result, err := permit(opts.Permissions, opened, display)
	if err != nil {
		return FileRecord{}, nil, err
	}
	if opened.Size() > limits.FileBytes {
		return FileRecord{}, nil, limitError("bytes per file", limits.FileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limits.FileBytes+1))
	if err != nil {
		return FileRecord{}, nil, fmt.Errorf("%w: %s", ErrInput, display)
	}
	if int64(len(raw)) > limits.FileBytes {
		return FileRecord{}, nil, limitError("bytes per file", limits.FileBytes)
	}
	sum := sha256.Sum256(raw)
	record := FileRecord{Display: display, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(raw)), Mode: opened.Mode().Perm(), Policy: result}
	return record, raw, nil
}
