// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// foreignCapabilityTargets is a package whose index names another engine
// capability, so a client that reads the capability refuses it.
func foreignCapabilityTargets(t *testing.T) map[string][]byte {
	t.Helper()
	base := projectsTargets(t, "5", nil)
	index := regexp.MustCompile(`"engineCapabilityDigest":"sha256:[0-9a-f]{64}"`).ReplaceAll(base[ConstraintsProjectsIndexTargetPath], []byte(`"engineCapabilityDigest":"sha256:`+strings.Repeat("cd", 32)+`"`))
	index = regexp.MustCompile(`"baseCapabilityDigest":"sha256:[0-9a-f]{64}"`).ReplaceAll(index, []byte(`"baseCapabilityDigest":"sha256:`+strings.Repeat("ef", 32)+`"`))
	base[ConstraintsProjectsIndexTargetPath] = index
	return base
}

func (f *projectsFixture) verifyPackage(path string) error {
	_, err := VerifyConstraintsProjects(VerifyRequest{PackagePath: path, BootstrapRootPath: f.root, BootstrapRootDigest: f.repo.RootDigest})
	return err
}

func assertIntegrityNotCapability(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrCapabilityMismatch) || errors.Is(err, ErrUnsupportedKnowledge) {
		t.Fatalf("want integrity failure, not capability mismatch: %v", err)
	}
}

// A project target flipped after signing, in a package that would also be a
// capability mismatch, is reported as tampering on verify and import.
func TestFlippedTargetInCapabilityMismatchIsIntegrity(t *testing.T) {
	targets := foreignCapabilityTargets(t)
	name, _ := firstProjects(targets)
	flipped := append([]byte(nil), targets[name]...)
	flipped[len(flipped)/2] ^= 1
	f := newProjectsFixture(t)
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: targets, Replace: map[string][]byte{name: flipped}})
	assertIntegrityNotCapability(t, f.verifyPackage(path))
	_, err := f.importPackage(path)
	assertIntegrityNotCapability(t, err)
}

// An index flipped after signing is an integrity failure as well.
func TestFlippedIndexInCapabilityMismatchIsIntegrity(t *testing.T) {
	targets := foreignCapabilityTargets(t)
	flipped := append([]byte(nil), targets[ConstraintsProjectsIndexTargetPath]...)
	flipped[len(flipped)/2] ^= 1
	f := newProjectsFixture(t)
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: targets, Replace: map[string][]byte{ConstraintsProjectsIndexTargetPath: flipped}})
	assertIntegrityNotCapability(t, f.verifyPackage(path))
	_, err := f.importPackage(path)
	assertIntegrityNotCapability(t, err)
}

// A correctly signed package of another capability is still refused as one.
func TestSignedCapabilityMismatchStillRefusedOnVerify(t *testing.T) {
	f := newProjectsFixture(t)
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: foreignCapabilityTargets(t)})
	err := f.verifyPackage(path)
	if err == nil || !errors.Is(err, ErrCapabilityMismatch) || !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("err=%v", err)
	}
}

// A valid package verifies.
func TestValidPackageStillVerifies(t *testing.T) {
	f := newProjectsFixture(t)
	path := f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "5", nil)})
	if err := f.verifyPackage(path); err != nil {
		t.Fatal(err)
	}
}
