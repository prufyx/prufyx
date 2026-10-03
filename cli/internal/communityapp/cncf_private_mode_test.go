// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadCNCFPrivateAcceptsOwnerOnlyModes(t *testing.T) {
	for mode, want := range map[os.FileMode]bool{0o600: true, 0o400: true, 0o640: false, 0o644: false, 0o660: false, 0o666: false} {
		path := filepath.Join(t.TempDir(), "in.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := readCNCFPrivate(path, 1024)
		if (err == nil) != want || (err != nil && !errors.Is(err, ErrInsecurePermissions)) {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}
