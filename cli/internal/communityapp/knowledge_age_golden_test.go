// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var updateAgeGoldens = flag.Bool("update-age", false, "rewrite the knowledge age golden files")

// ageClocks are evaluation instants before, inside and after the last
// 30 days of the embedded knowledge's rules.
var ageClocks = []struct{ name, now string }{
	{"before", "2026-10-04T00:00:00Z"},
	{"inside", "2026-11-20T00:00:00Z"},
	{"after", "2026-12-10T00:00:00Z"},
}

func ageGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "knowledge-age", name)
	if *updateAgeGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file:\n%s", name, got)
	}
}

// TestCheckOutputUnchangedNearExpiry: stdout and the exit code of check cncf
// and check batch with embedded knowledge do not depend on how close the
// knowledge is to its end. The golden files were written before the age note
// existed; only the clock they record differs between them.
func TestCheckOutputUnchangedNearExpiry(t *testing.T) {
	input := writeCNCFFile(t, "input.json", []byte(kyvernoInputTrue), 0o600)
	root, plan := writeEmbeddedCLIBatch(t)
	for _, clock := range ageClocks {
		for _, format := range []string{"human", "json"} {
			code, stdout, _ := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", input, "--now", clock.now, "--format", format)
			ageGolden(t, fmt.Sprintf("check-cncf-%s.%s", clock.name, format), []byte(fmt.Sprintf("%s\nexit %d\n", stdout, code)))
			code, stdout, _ = runCNCFCLI(t, "check", "batch", "--plan", plan, "--root", root, "--now", clock.now, "--format", format)
			ageGolden(t, fmt.Sprintf("check-batch-%s.%s", clock.name, format), []byte(fmt.Sprintf("%s\nexit %d\n", stdout, code)))
		}
	}
}
