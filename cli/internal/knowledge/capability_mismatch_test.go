// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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
	// Another engine, not only another registry: the base marker moves too.
	index = regexp.MustCompile(`"baseCapabilityDigest":"sha256:[0-9a-f]{64}"`).ReplaceAll(index, []byte(`"baseCapabilityDigest":"sha256:`+strings.Repeat("ef", 32)+`"`))
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

// futureProjectsTargets turns the embedded per-project feed into a feed of a
// later release: another engine capability (a wider fact registry and
// project table) with this build's base capability, and one project this
// build does not know.
func futureProjectsTargets(t *testing.T, revision string) map[string][]byte {
	t.Helper()
	targets := projectsTargets(t, revision, nil)
	var index struct {
		Schema                 string                         `json:"schema"`
		Revision               string                         `json:"revision"`
		Purpose                string                         `json:"purpose"`
		EngineCapabilityDigest string                         `json:"engineCapabilityDigest"`
		BaseCapabilityDigest   string                         `json:"baseCapabilityDigest,omitempty"`
		Projects               []cncfcheck.ExternalIndexEntry `json:"projects"`
		MinClientVersion       string                         `json:"minClientVersion,omitempty"`
	}
	if err := json.Unmarshal(targets[ConstraintsProjectsIndexTargetPath], &index); err != nil {
		t.Fatal(err)
	}
	if index.BaseCapabilityDigest == "" {
		t.Fatal("the publisher wrote no base capability")
	}
	old := index.EngineCapabilityDigest
	index.EngineCapabilityDigest = "sha256:" + strings.Repeat("ab", 32)
	for i, entry := range index.Projects {
		raw := bytes.ReplaceAll(targets[entry.TargetPath], []byte(old), []byte(index.EngineCapabilityDigest))
		targets[entry.TargetPath] = raw
		index.Projects[i].Length, index.Projects[i].Digest = int64(len(raw)), cncfcheck.TargetDigest(raw)
	}
	unknown := []byte(`{"a":"project of a later release"}`)
	path := cncfcheck.ProjectTargetPath("zz-future-project")
	targets[path] = unknown
	index.Projects = append(index.Projects, cncfcheck.ExternalIndexEntry{Project: "zz-future-project", TargetPath: path, Revision: revision, Length: int64(len(unknown)), Digest: cncfcheck.TargetDigest(unknown), RuleDigest: cncfcheck.TargetDigest([]byte("r")), EvidenceExpiresAt: "2027-01-01T00:00:00Z"})
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	targets[ConstraintsProjectsIndexTargetPath] = raw
	return targets
}

// A signed feed of a later release is imported, not refused: the project it
// adds is verified as an index entry and kept out of the store.
func TestFutureFeedImportsInCompatMode(t *testing.T) {
	f := newProjectsFixture(t)
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: futureProjectsTargets(t, "5")}))
	if err != nil {
		t.Fatalf("future feed: %v", err)
	}
	listed := false
	for _, project := range receipt.ProjectTargets {
		listed = listed || project.Project == "zz-future-project"
	}
	if !listed {
		t.Fatal("the receipt does not list the project of the later release")
	}
	if found, _ := filepath.Glob(filepath.Join(f.store, "*", "*", "projects", "zz-future-project.json")); len(found) != 0 {
		t.Fatalf("the unknown project target was stored: %v", found)
	}
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: futureProjectsTargets(t, "6")})); err != nil {
		t.Fatalf("second future feed: %v", err)
	}
}

// A compat index whose targets do not carry the index capability is not a
// feed of a later release but a mismatch, and it is an integrity failure.
func TestFutureIndexWithForeignTargetsIsRefused(t *testing.T) {
	targets := futureProjectsTargets(t, "5")
	plain := projectsTargets(t, "5", nil)
	swapped := false
	for path, raw := range plain {
		if !swapped && path != ConstraintsProjectsIndexTargetPath {
			targets[path], swapped = raw, true
		}
	}
	f := newProjectsFixture(t)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targets})); err == nil {
		t.Fatal("imported a feed whose index and targets disagree")
	}
}
