// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package extractcli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// SEC-B F6a: modes are explicit, not derived from the umask.
func TestRunOutputModesIgnoreUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "out")
	if code, _, errs := run(secbArgs(dir)...); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("dir mode %v err %v, want 0755", st.Mode().Perm(), err)
	}
	st, err = os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("file mode %v err %v, want 0644", st.Mode().Perm(), err)
	}
}
