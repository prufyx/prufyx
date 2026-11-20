// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package changelogcli

import (
	"bytes"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A FIFO or a device is not a regular file: it is refused, never read.
func TestUpstreamTagsNotRegularFileRefused(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	fifo := filepath.Join(t.TempDir(), "up.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	for name, p := range map[string]string{"fifo": fifo, "device": "/dev/null", "directory": t.TempDir()} {
		var o, e bytes.Buffer
		code := run([]string{"rows-check", "--fixture", fx, "--upstream-tags", p}, floorTable(""), &o, &e)
		if code != 2 || o.Len() != 0 || !strings.Contains(e.String(), "regular file") && name != "directory" {
			t.Errorf("%s: %d out=%q err=%q", name, code, o.String(), e.String())
		}
	}
}
