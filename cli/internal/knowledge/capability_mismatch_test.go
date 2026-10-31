// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// An index of another engine capability is unsupported knowledge with its own
// sentinel: it is never an integrity failure and never says which side is newer.
func TestCapabilityMismatchIsUnsupportedNotIntegrity(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	foreign := regexp.MustCompile(`"engineCapabilityDigest":"sha256:[0-9a-f]{64}"`)
	index := foreign.ReplaceAll(base[ConstraintsProjectsIndexTargetPath], []byte(`"engineCapabilityDigest":"sha256:`+strings.Repeat("cd", 32)+`"`))
	if string(index) == string(base[ConstraintsProjectsIndexTargetPath]) {
		t.Fatal("capability digest not found in the index")
	}
	base[ConstraintsProjectsIndexTargetPath] = index
	f := newProjectsFixture(t)
	_, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	if err == nil || !errors.Is(err, ErrUnsupportedKnowledge) || !errors.Is(err, ErrCapabilityMismatch) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("err=%v", err)
	}
	if got := UnsupportedMinVersion(err); got != "" {
		t.Fatalf("a capability mismatch names no minimum version: %q", got)
	}
}

// Other unsupported reasons are not capability mismatches.
func TestTooNewIsNotCapabilityMismatch(t *testing.T) {
	err := unsupportedFailure("v0.2.0", "the package requires prufyx %s or newer", "v0.2.0")
	if !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrCapabilityMismatch) {
		t.Fatalf("err=%v", err)
	}
}
