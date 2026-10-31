// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// importTooNewStore imports, with a dev build (which meets every minimum), a
// store whose index names minClientVersion v0.2.0.
func importTooNewStore(t *testing.T) (*projectsFixture, string) {
	t.Helper()
	withBuildVersion(t, "dev")
	base := projectsTargets(t, "5", nil)
	base[ConstraintsProjectsIndexTargetPath] = indexWithExtra(t, base[ConstraintsProjectsIndexTargetPath], `"minClientVersion":"v0.2.0"`)
	f := newProjectsFixture(t)
	if r, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base})); err != nil || r.Status != "IMPORTED" {
		t.Fatalf("dev import: %+v err=%v", r, err)
	}
	first, _ := firstProjects(base)
	return f, projectOf(t, first)
}

// A store imported by a dev build whose minClientVersion is above a
// release-stamped build must surface the unsupported error (with its minimum
// version) through the real open path, not a bare integrity failure.
func TestOpenRealTooNewStoreIsUnsupportedNotIntegrity(t *testing.T) {
	f, project := importTooNewStore(t)
	withBuildVersion(t, "v0.1.0-beta.0")
	_, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{project})
	if !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("err=%v", err)
	}
	if got := UnsupportedMinVersion(err); got != "v0.2.0" {
		t.Fatalf("min version %q", got)
	}
	// A build that meets the minimum still opens it.
	withBuildVersion(t, "v0.2.0")
	if _, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{project}); err != nil {
		t.Fatalf("readable build: %v", err)
	}
}

// Tampering with a too-new store stays an integrity failure: the unsupported
// answer is given only after the stored bundle is revalidated.
func TestOpenRealTooNewStoreTamperStaysIntegrity(t *testing.T) {
	for _, tc := range []string{"index target", "project target", "trust state"} {
		t.Run(tc, func(t *testing.T) {
			f, project := importTooNewStore(t)
			withBuildVersion(t, "v0.1.0-beta.0")
			var victim string
			err := filepath.WalkDir(f.store, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				slash := filepath.ToSlash(p)
				switch {
				case tc == "index target" && strings.HasSuffix(slash, "/target.json"):
					victim = p
				case tc == "project target" && strings.HasSuffix(slash, "/projects/"+project+".json"):
					victim = p
				case tc == "trust state" && strings.Contains(slash, "/trust/states/") && strings.HasSuffix(slash, "/state.json"):
					victim = p
				}
				return nil
			})
			if err != nil || victim == "" {
				t.Fatalf("victim not found: %v", err)
			}
			raw, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(victim, flipByte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{project})
			if err == nil || errors.Is(err, ErrUnsupportedKnowledge) {
				t.Fatalf("tampered %s opened or reported unsupported: %v", tc, err)
			}
		})
	}
}
