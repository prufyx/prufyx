// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func TestProducerDefaultsAndRetiredSingleRejection(t *testing.T) {
	defaultOptions := Options{Revision: "73", FirstRelease: true, OldestClient: cncfcheck.BoundaryCoveredFloor}
	a, err := ComputeDigests(defaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	defaultOptions.Profile = ProfileCNCFProjects
	b, err := ComputeDigests(defaultOptions)
	if err != nil || a != b {
		t.Fatalf("producer default differs: %+v %+v %v", a, b, err)
	}
	if _, err := ComputeDigests(Options{Revision: "73", OldestClient: cncfcheck.BoundaryCoveredFloor}); !errors.Is(err, ErrRejected) || errors.Is(err, cncfcheck.ErrOptInBelowFloor) {
		t.Fatalf("omitted previous index silently initialized: %v", err)
	}
	if _, err := ComputeDigests(Options{Revision: "73", Profile: ProfileCNCF, OldestClient: cncfcheck.BoundaryCoveredFloor}); !errors.Is(err, ErrRejected) || errors.Is(err, cncfcheck.ErrOptInBelowFloor) {
		t.Fatalf("single digests accepted: %v", err)
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent")
	output := filepath.Join(dir, "output")
	_, err = Run(Options{Profile: ProfileCNCF, Revision: "73", Version: 1, Root: missing, RootDigest: "missing", TargetsKey: missing, SnapshotKey: missing, TimestampKey: missing, PassphraseFile: missing, OutputDir: output, Now: time.Now().UTC()})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "single-target publication retired") {
		t.Fatalf("profile rejection must precede root/key access: %v", err)
	}
	_, err = Refresh(RefreshOptions{Profile: ProfileCNCF, OutputDir: output})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "single-target publication retired") {
		t.Fatalf("refresh rejection must precede key access: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired producer created output: %v", err)
	}
}
