// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"fmt"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// openFailure is what OpenStore returns for a failed open: the fallback reason
// and the minimum version, and no fallback when a hard failure is part of the
// error.
func TestOpenFailureFallbackMapping(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		fallback string
		min      string
	}{
		{"too new, version known", fmt.Errorf("open: %w", &knowledge.UnsupportedError{Reason: "r", MinVersion: "v0.3.0"}), "store-too-new", "v0.3.0"},
		{"too new, version unknown", &knowledge.UnsupportedError{Reason: "r"}, "store-too-new", ""},
		{"trust advanced", fmt.Errorf("open: %w", knowledge.ErrTrustAdvanced), "store-trust-advanced", ""},
		{"expired", knowledge.ErrExpired, "store-expired", ""},
		{"too new and integrity", errors.Join(&knowledge.UnsupportedError{Reason: "r", MinVersion: "v0.3.0"}, knowledge.ErrIntegrity), "", "v0.3.0"},
		{"trust advanced and rollback", errors.Join(knowledge.ErrTrustAdvanced, knowledge.ErrRollback), "", ""},
		{"integrity", knowledge.ErrIntegrity, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := openFailure(c.err)
			if got.Fallback != c.fallback || got.FallbackMin != c.min {
				t.Fatalf("fallback %q min %q, want %q %q", got.Fallback, got.FallbackMin, c.fallback, c.min)
			}
			if !errors.Is(got, ErrIntegrity) {
				t.Fatal("a StoreError stays an integrity failure")
			}
		})
	}
}
