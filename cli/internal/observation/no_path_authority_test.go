// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNoPathnameObservationAuthorityInProductionSources(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	internal := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	forbidden := []string{
		"func ImportRoot(", "func BuildWithOptions(", "func ImportWithOptions(",
		"func Build(root string", "func Read(root string", "/proc/self/fd", "/dev/fd",
	}
	err := filepath.Walk(internal, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, token := range forbidden {
			if strings.Contains(string(data), token) {
				t.Errorf("forbidden pathname authority token %q in %s", token, filepath.Base(path))
			}
		}
		if strings.Contains(path, string(filepath.Separator)+"syntheticsnapshot"+string(filepath.Separator)) {
			for _, token := range []string{"filepath.Walk(", "filepath.WalkDir(", "os.RemoveAll("} {
				if strings.Contains(string(data), token) {
					t.Errorf("forbidden synthetic lifecycle token %q in %s", token, filepath.Base(path))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
