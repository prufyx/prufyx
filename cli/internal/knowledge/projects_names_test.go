// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func hexOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func TestSplitPackageMemberNamesAreStrict(t *testing.T) {
	sha := hexOf("x")
	valid := []string{
		"targets/knowledge/cncf/" + sha + ".index.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".argo-cd.v1.json",
		"metadata/timestamp.json",
	}
	for _, name := range valid {
		if !packageMemberName(name, ConstraintsProjectsIndexTargetPath) {
			t.Fatalf("valid member %q rejected", name)
		}
	}
	invalid := []string{
		"targets/knowledge/cncf/projects/" + sha + ".Kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".KYVERNO.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".kyvernö.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".кyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + "...v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".../x.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".-kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".kyverno-.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".kyv--erno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".kyverno_x.v1.json",
		"targets/knowledge/cncf/projects/x/" + sha + ".p.v1.json",
		"targets/knowledge/cncf/projects/../" + sha + ".kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + strings.ToUpper(sha) + ".kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha[:63] + ".kyverno.v1.json",
		"targets/knowledge/cncf/projects/.kyverno.v1.json",
		"targets/knowledge/constraints/" + sha + ".constraints.v1.json",
		"targets/knowledge/" + sha + ".constraints.v1.json",
		"targets/other/cncf/projects/" + sha + ".kyverno.v1.json",
	}
	for _, name := range invalid {
		if packageMemberName(name, ConstraintsProjectsIndexTargetPath) {
			t.Fatalf("odd member %q accepted", name)
		}
	}
}

// Non-ASCII names cannot be written by the ustar fixture; the table test
// above covers them.
func TestConstraintsProjectsRejectOddMemberNamesInThePackage(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	first, _ := firstProjects(base)
	sha := hexOf("odd")
	for _, name := range []string{
		"targets/knowledge/cncf/projects/" + sha + ".Kyverno.v1.json",
		"targets/knowledge/cncf/projects/" + sha + ".../x.v1.json",
		"targets/knowledge/cncf/projects/../" + sha + ".kyverno.v1.json",
		"targets/knowledge/cncf/projects/x/" + sha + ".p.v1.json",
	} {
		t.Run(name, func(t *testing.T) {
			f := newProjectsFixture(t)
			pkg := knowledgefixture.ProjectsPackage{Targets: base, Extra: map[string][]byte{name: base[first]}}
			_, err := f.importPackage(f.write(t, pkg))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "package path") {
				t.Fatalf("odd member name not rejected by name: %v", err)
			}
		})
	}
}

// TestConstraintsProjectsRejectPackageOverTheMemberTotalBeforeStoreUse builds
// a package between the 7 MiB member total and the 8 MiB file bound, so only
// the member total can reject it.
func TestConstraintsProjectsRejectPackageOverTheMemberTotalBeforeStoreUse(t *testing.T) {
	f := newProjectsFixture(t)
	base := projectsTargets(t, "5", nil)
	extra := map[string][]byte{}
	for i := 0; i < 8; i++ {
		name := "targets/knowledge/cncf/projects/" + hexOf(strings.Repeat("m", i+1)) + ".filler.v1.json"
		extra[name] = []byte(strings.Repeat(" ", 880000))
	}
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: base, Extra: extra})
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 7<<20 || info.Size() >= 8<<20 {
		t.Fatalf("test package size %v is not between the member total and the file bound: %v", info, err)
	}
	_, err = f.importPackage(path)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "package total size") {
		t.Fatalf("package over the member total: %v", err)
	}
	if _, statErr := os.Stat(f.store); statErr == nil {
		if _, err := loadSelectionAt(f.store); err == nil {
			t.Fatal("rejected package created a selection")
		}
	}
}

func TestStoredTrustStateValidatesProjectFloors(t *testing.T) {
	f := newProjectsFixture(t)
	targets := projectsTargets(t, "5", nil)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targets})); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(f.store, "*", "trust", "states", "*", "state.json"))
	if err != nil || len(matches) == 0 {
		matches, err = filepath.Glob(filepath.Join(f.store, "trust", "states", "*", "state.json"))
	}
	if err != nil || len(matches) == 0 {
		t.Fatalf("no stored trust state found under %s: %v", f.store, err)
	}
	var state trustState
	for _, name := range matches {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var candidate trustState
		if err := json.Unmarshal(raw, &candidate); err != nil {
			t.Fatal(err)
		}
		if len(candidate.ProjectFloors) > len(state.ProjectFloors) {
			state = candidate
		}
	}
	if err := validateTrustState(state); err != nil || len(state.ProjectFloors) < 2 {
		t.Fatalf("stored state invalid or without floors: floors=%d err=%v", len(state.ProjectFloors), err)
	}
	mutate := func(change func(*trustState)) trustState {
		copy := state
		copy.ProjectFloors = append([]projectFloor(nil), state.ProjectFloors...)
		change(&copy)
		return copy
	}
	cases := map[string]trustState{
		"unsorted": mutate(func(s *trustState) {
			s.ProjectFloors[0], s.ProjectFloors[1] = s.ProjectFloors[1], s.ProjectFloors[0]
		}),
		"duplicate":           mutate(func(s *trustState) { s.ProjectFloors[1] = s.ProjectFloors[0] }),
		"invalid slug":        mutate(func(s *trustState) { s.ProjectFloors[0].Project = "Not A Slug" }),
		"bad revision":        mutate(func(s *trustState) { s.ProjectFloors[0].Revision = "x" }),
		"bad digest":          mutate(func(s *trustState) { s.ProjectFloors[0].Digest = "sha256:zz" }),
		"without index floor": mutate(func(s *trustState) { s.RevisionFloor, s.RevisionFloorBundleDigest = "", "" }),
	}
	for name, bad := range cases {
		if err := validateTrustState(bad); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: invalid project floors accepted: %v", name, err)
		}
	}
}
