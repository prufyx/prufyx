// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// listedPack is the embedded rule pack plus one listed-entries attestation.
func listedPack(t *testing.T) []byte {
	t.Helper()
	embedded, err := cncfcheck.EmbeddedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(embedded, &pack); err != nil {
		t.Fatal(err)
	}
	var atts []lineattest.LineAttestation
	if raw, ok := pack["lineAttestations"]; ok {
		if atts, err = lineattest.Parse(raw); err != nil {
			t.Fatal(err)
		}
	}
	atts = append(atts, lineattest.LineAttestation{
		Component: "pkg:github/prometheus/prometheus", Line: "0.51", FactFamily: lineattest.FamilyChangelogListedEntries, Completeness: lineattest.Completeness,
		RuleIDs: []string{},
		Releases: &lineattest.Releases{
			From: []lineattest.Release{{Version: "0.50.0", Commit: strings.Repeat("1", 40)}},
			To:   []lineattest.Release{{Version: "0.51.0", Commit: strings.Repeat("2", 40)}},
		},
		Evidence: lineattest.Evidence{
			Basis: constraintengine.BasisMechanical, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z", DerivedAt: "2026-10-01T00:00:00Z",
			Extractor: &constraintengine.Extractor{ID: "changelog.listed-entries", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)},
			Sources:   []constraintengine.SourceEvidence{{ID: "changelog", URL: "https://github.com/prometheus/prometheus/blob/" + strings.Repeat("2", 40) + "/CHANGELOG.md", Revision: strings.Repeat("2", 40), ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
		},
	})
	if pack["lineAttestations"], err = lineattest.Marshal(atts); err != nil {
		t.Fatal(err)
	}
	if pack["schema"], err = json.Marshal(mustSchema(t, pack)); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustSchema(t *testing.T, pack map[string]json.RawMessage) string {
	t.Helper()
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := cncfcheck.RequiredPackSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

// withListedPack makes the release build from listedPack.
func withListedPack(t *testing.T, edit func(index cncfcheck.ExternalTarget) cncfcheck.ExternalTarget) {
	t.Helper()
	pack := listedPack(t)
	original := buildPinned
	t.Cleanup(func() { buildPinned = original })
	buildPinned = func(revision string, _ []byte, oldest string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, int, error) {
		index, targets, n, err := cncfcheck.BuildExternalTargetsFromPackPinned(pack, revision, oldest)
		if err == nil && edit != nil {
			index = edit(index)
		}
		return index, targets, n, err
	}
}

func writtenIndex(t *testing.T, o Options) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(o.OutputDir, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Below the floor the signed package carries no listed record and no floor,
// and the receipt counts what was left out.
func TestReleaseBelowTheFloorLeavesTheFamilyOutAndCountsIt(t *testing.T) {
	withListedPack(t, nil)
	o := projectsFixture(t)
	o.OldestClient = "v0.1.0-beta.0"
	result, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if result.ListedAttestationsExcluded != 1 {
		t.Fatalf("receipt counts %d excluded, want 1", result.ListedAttestationsExcluded)
	}
	index := writtenIndex(t, o)
	if min, ok := cncfcheck.ExternalIndexMinClient(index); ok {
		t.Fatalf("an index without the family names minClientVersion %q", min)
	}
	raw, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(raw), `"listedAttestationsExcluded":1`) {
		t.Fatalf("receipt output %s: %v", raw, err)
	}
	// An unknown pin leaves it out as well.
	o2 := projectsFixture(t)
	o2.OldestClient = ""
	if result, err = Run(o2); err != nil || result.ListedAttestationsExcluded != 1 {
		t.Fatalf("unknown pin: %+v %v", result, err)
	}
}

// From the floor the family ships, and the final signed index carries the floor.
func TestReleaseFromTheFloorShipsTheFamilyWithMinClientVersion(t *testing.T) {
	withListedPack(t, nil)
	o := projectsFixture(t)
	o.OldestClient = cncfcheck.ListedFamilyFloor
	result, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if result.ListedAttestationsExcluded != 0 {
		t.Fatalf("excluded %d at the floor", result.ListedAttestationsExcluded)
	}
	index := writtenIndex(t, o)
	if min, ok := cncfcheck.ExternalIndexMinClient(index); !ok || min != cncfcheck.ListedFamilyFloor {
		t.Fatalf("signed index minClientVersion %q, want %s", min, cncfcheck.ListedFamilyFloor)
	}
	// The written index is the one the signed targets role binds.
	sum := sha256.Sum256(index)
	if result.Receipt.TargetDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("receipt target digest %s is not the written index", result.Receipt.TargetDigest)
	}
	if _, err := knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{
		PackagePath: filepath.Join(o.OutputDir, "cncf-projects-"+o.Revision+".tar"), BootstrapRootPath: o.Root, BootstrapRootDigest: o.RootDigest,
		ExpectedRevision: o.Revision, ExpectedBundleDigest: result.Receipt.TargetDigest, Now: o.Now,
	}); err != nil {
		t.Fatalf("the signed package does not verify: %v", err)
	}
}

// Fail closed: a package that carries the family without the floor, or while
// the pin is below it, is refused and nothing is written.
func TestReleaseRefusesTheFamilyWithoutTheFloor(t *testing.T) {
	// The floor is the last member of the index, so the edits keep the index
	// canonical and only the floor changes.
	member := []byte(`,"minClientVersion":"` + cncfcheck.ListedFamilyFloor + `"`)
	dropFloor := func(index cncfcheck.ExternalTarget) cncfcheck.ExternalTarget {
		if !bytes.Contains(index.Bytes, member) {
			t.Fatal("the index does not carry the floor")
		}
		index.Bytes = bytes.Replace(index.Bytes, member, nil, 1)
		return index
	}
	lowFloor := func(index cncfcheck.ExternalTarget) cncfcheck.ExternalTarget {
		index.Bytes = bytes.Replace(index.Bytes, member, []byte(`,"minClientVersion":"v0.1.0-beta.0"`), 1)
		return index
	}
	for name, edit := range map[string]func(cncfcheck.ExternalTarget) cncfcheck.ExternalTarget{"floor absent": dropFloor, "floor too low": lowFloor} {
		t.Run(name, func(t *testing.T) {
			withListedPack(t, edit)
			o := projectsFixture(t)
			o.OldestClient = cncfcheck.ListedFamilyFloor
			if _, err := Run(o); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "listed family") {
				t.Fatalf("err=%v", err)
			}
			if _, err := os.Stat(o.OutputDir); err == nil {
				t.Fatal("output written for a refused release")
			}
		})
	}
	t.Run("builder that did not exclude below the floor", func(t *testing.T) {
		pack := listedPack(t)
		original := buildPinned
		defer func() { buildPinned = original }()
		// A builder that ignores the pin: the family ships to a pin below the floor.
		buildPinned = func(revision string, _ []byte, _ string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, int, error) {
			return cncfcheck.BuildExternalTargetsFromPackPinned(pack, revision, cncfcheck.ListedFamilyFloor)
		}
		o := projectsFixture(t)
		o.OldestClient = "v0.1.0-beta.0"
		if _, err := Run(o); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "listed family") {
			t.Fatalf("err=%v", err)
		}
		if _, err := os.Stat(o.OutputDir); err == nil {
			t.Fatal("output written for a refused release")
		}
	})
	t.Run("pin that is not a version", func(t *testing.T) {
		o := projectsFixture(t)
		o.OldestClient = "latest"
		if _, err := Run(o); !errors.Is(err, ErrRejected) {
			t.Fatalf("err=%v", err)
		}
	})
}

// After the pin moves to the floor, a release from the previous index ships
// the family: the projects that carry it advance, the others keep their
// revision.
func TestReleaseFromPreviousIndexAfterThePinMoves(t *testing.T) {
	pack := listedPack(t)
	original := buildPinned
	t.Cleanup(func() { buildPinned = original })
	buildPinned = func(revision string, previous []byte, oldest string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, int, error) {
		return cncfcheck.BuildExternalTargetsFromPackPinnedFrom(pack, revision, previous, oldest)
	}
	first := projectsFixture(t)
	first.OldestClient = "v0.1.0-beta.0"
	if _, err := Run(first); err != nil {
		t.Fatal(err)
	}
	before, err := cncfcheck.ParseExternalIndex(writtenIndex(t, first))
	if err != nil {
		t.Fatal(err)
	}
	next := first
	next.FirstRelease = false
	next.PreviousIndex = filepath.Join(first.OutputDir, "knowledge", "cncf", "index.v1.json")
	next.Revision, next.Version = "92", 2
	next.OldestClient = cncfcheck.ListedFamilyFloor
	next.OutputDir = filepath.Join(filepath.Dir(first.OutputDir), "after-bump")
	result, err := Run(next)
	if err != nil {
		t.Fatal(err)
	}
	if result.ListedAttestationsExcluded != 0 {
		t.Fatalf("excluded %d after the pin moved", result.ListedAttestationsExcluded)
	}
	after, err := cncfcheck.ParseExternalIndex(writtenIndex(t, next))
	if err != nil {
		t.Fatal(err)
	}
	if min, _ := cncfcheck.ExternalIndexMinClient(writtenIndex(t, next)); min != cncfcheck.ListedFamilyFloor {
		t.Fatalf("minClientVersion %q after the bump", min)
	}
	if len(before.Entries()) != len(after.Entries()) {
		t.Fatalf("projects %d -> %d", len(before.Entries()), len(after.Entries()))
	}
	advanced := 0
	for _, entry := range after.Entries() {
		was, ok := before.Entry(entry.Project)
		if !ok {
			t.Fatalf("project %s is new", entry.Project)
		}
		switch {
		case entry.Revision == next.Revision && entry.Digest != was.Digest:
			advanced++
		case entry.Revision == was.Revision && entry.Digest == was.Digest:
		default:
			t.Fatalf("project %s: revision %s digest changed=%v", entry.Project, entry.Revision, entry.Digest != was.Digest)
		}
	}
	if advanced != 1 {
		t.Fatalf("%d projects advanced, want only the one that gained the family", advanced)
	}
}
