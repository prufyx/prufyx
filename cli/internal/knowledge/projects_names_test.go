// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
// packageMemberBytes sums member sizes exactly as readImportPackageForProfile does.
func packageMemberBytes(t *testing.T, path string) int64 {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	r := tar.NewReader(fh)
	var total int64
	for {
		h, err := r.Next()
		if err == io.EOF {
			return total
		}
		if err != nil {
			t.Fatal(err)
		}
		total += h.Size
	}
}

func TestConstraintsProjectsRejectPackageOverTheMemberTotalBeforeStoreUse(t *testing.T) {
	f := newProjectsFixture(t)
	base := projectsTargets(t, "5", nil)
	// The limit counts member bytes (no tar headers, padding or trailer), so the
	// fillers are sized from the member bytes of the real base package.
	_, maxFiles, limitTotal := constraintsProjectsProfile().packageLimits()
	maxFileBytes, _, _ := constraintsProjectsProfile().packageLimits()
	const margin = 64 << 10
	const step = 440000
	baseMembers := packageMemberBytes(t, f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	need := limitTotal + margin - baseMembers
	if need <= 0 {
		t.Fatalf("base members %d already exceed the member total %d", baseMembers, limitTotal)
	}
	extra := map[string][]byte{}
	for i, left := 0, need; left > 0; i++ {
		n := int64(step)
		if left < n {
			n = left
		}
		name := "targets/knowledge/cncf/projects/" + hexOf(strings.Repeat("m", i+1)) + ".filler.v1.json"
		extra[name] = []byte(strings.Repeat(" ", int(n)))
		left -= n
	}
	if len(extra)+len(base)+8 > maxFiles {
		t.Fatalf("test package needs %d members, over the file-count limit %d", len(extra)+len(base)+8, maxFiles)
	}
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: base, Extra: extra})
	members := packageMemberBytes(t, path)
	if members < limitTotal+margin {
		t.Fatalf("precondition: member bytes %d are not at least %d above the member total %d", members, margin, limitTotal)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() >= int64(maxFileBytes) {
		t.Fatalf("precondition: package file %v must stay below the file bound %d so only the member total can reject it: %v", info, maxFileBytes, err)
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
