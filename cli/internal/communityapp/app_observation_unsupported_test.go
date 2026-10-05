// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/observation"
)

// TestPrometheusModeObservationUnsupportedPlatform proves the refusal used on
// platforms without descriptor-relative observation I/O (Windows): exit 2 and
// a fixed message, for both the check route and the legacy alias.
func TestPrometheusModeObservationUnsupportedPlatform(t *testing.T) {
	original := openObservationRoot
	openObservationRoot = func(string) (*observation.Root, error) { return nil, observation.ErrUnsupportedPlatform }
	t.Cleanup(func() { openObservationRoot = original })

	dir := t.TempDir()
	raw := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[]}}}}`)
	proposed := filepath.Join(dir, "proposed.json")
	if err := os.WriteFile(proposed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(proposed, 0o600); err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	for _, prefix := range [][]string{{"check", "prometheus-mode"}, {"community-preview", "validate-prometheus-mode"}} {
		args := append(append([]string{}, prefix...), "--observation-root", dir, "--captured-at", "2026-09-07T10:00:00Z", "--now", "2026-09-07T10:01:00Z", "--max-age", "1h", "--proposed-workload", proposed, "--proposed-digest", pin)
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), args, &stdout, &stderr, "test")
		if code != ExitUsage || stdout.Len() != 0 || stderr.String() != "prufyx: real observation is not supported on this platform\n" {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", prefix, code, stdout.String(), stderr.String())
		}
	}
}
