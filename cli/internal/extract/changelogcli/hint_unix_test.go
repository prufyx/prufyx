// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package changelogcli

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProposeHintFileNotFollowedOrBlocking(t *testing.T) {
	fx := hintFixture(t)
	dir := t.TempDir()
	real := writeHint(t, goodHint)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var o, e bytes.Buffer
	if code := run(hintArgs(fx, link), nil, &o, &e); code != 2 || o.Len() != 0 {
		t.Fatalf("symlinked hint accepted: %d %q", code, o.String())
	}
	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no fifo here")
	}
	o.Reset()
	if code := run(hintArgs(fx, fifo), nil, &o, &e); code != 2 || o.Len() != 0 {
		t.Fatalf("fifo hint accepted: %d %q", code, o.String())
	}
}
