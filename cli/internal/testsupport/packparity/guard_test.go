// SPDX-License-Identifier: AGPL-3.0-only

package packparity

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoProductionFileImportsPackparity: the table is test support. A
// non-test Go file anywhere in the module that imports it would link test
// data into a command.
func TestNoProductionFileImportsPackparity(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	const path = `"github.com/prufyx/prufyx/cli/internal/testsupport/packparity"`
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "vendor" || entry.Name() == "packparity") {
			return fs.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), path) {
			t.Errorf("%s imports the test-only parity table", file)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
