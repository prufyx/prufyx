// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestListedFloorSeamOnlyInTests: the setter that swaps out the shared
// admission floor check is referenced by no non-test Go file outside its own
// declaration, so no command or release path can turn the guard off.
func TestListedFloorSeamOnlyInTests(t *testing.T) {
	root := filepath.Join("..", "..", "..") // cli/
	var offenders []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), "SetListedFloorCheckForTest") {
			return nil
		}
		if filepath.Base(p) == "knowledgepublish.go" && filepath.Base(filepath.Dir(p)) == "knowledgepublish" {
			return nil // the declaration itself
		}
		offenders = append(offenders, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("non-test files reference SetListedFloorCheckForTest: %v", offenders)
	}
}
