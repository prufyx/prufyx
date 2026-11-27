// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// optInPack is the shipped pack, with the given sections, declaring the
// opt-in level.
func optInPack(t *testing.T, sections recordSections) []byte {
	t.Helper()
	var pack rulePack
	if err := strictJSON(recordsPack(t, sections), &pack); err != nil {
		t.Fatal(err)
	}
	pack.Schema = packSchemaBoundaryCovered
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A package that carries the level names the floor, on every builder.
func TestOptInIndexNamesTheFloor(t *testing.T) {
	t.Parallel()
	pack := optInPack(t, recordSections{})
	index, targets, err := BuildExternalTargetsFromPack(pack, "5")
	if err != nil {
		t.Fatal(err)
	}
	if carries, err := targetsCarryOptIn(rawTargets(targets)); err != nil || !carries {
		t.Fatalf("carries=%v err=%v", carries, err)
	}
	if got := minClientOf(t, index); got != BoundaryCoveredFloor {
		t.Fatalf("minClientVersion %q", got)
	}
	for _, oldest := range []string{BoundaryCoveredFloor, "v9.9.9"} {
		index, targets, _, err := BuildExternalTargetsFromPackPinned(pack, "5", oldest)
		if err != nil || minClientOf(t, index) != BoundaryCoveredFloor {
			t.Fatalf("oldest %q: floor=%q err=%v", oldest, minClientOf(t, index), err)
		}
		if err := CheckOptInShipping(index.Bytes, rawTargets(targets), oldest); err != nil {
			t.Fatalf("oldest %q refused: %v", oldest, err)
		}
	}
	// A package without the level is not constrained.
	index, targets, _, err = BuildExternalTargetsFromPackPinned(plainRecordsPack(t, recordSections{}), "5", "")
	if err != nil || minClientOf(t, index) != "" {
		t.Fatalf("no level: floor=%q err=%v", minClientOf(t, index), err)
	}
	if err := CheckOptInShipping(index.Bytes, rawTargets(targets), ""); err != nil {
		t.Fatal(err)
	}
}

// The shipped pack itself is refused for an oldest client below the floor and
// for an unstated one, and built from the floor.
func TestShippedPackRefusedBelowTheOptInFloor(t *testing.T) {
	t.Parallel()
	for _, oldest := range []string{"v0.1.0-beta.0", ""} {
		index, targets, _, err := BuildEmbeddedExternalTargetsPinned("5", nil, oldest)
		if !errors.Is(err, ErrOptInBelowFloor) || !errors.Is(err, ErrIntegrity) || index.Bytes != nil || targets != nil {
			t.Fatalf("oldest %q: %v", oldest, err)
		}
	}
	index, _, _, err := BuildEmbeddedExternalTargetsPinned("5", nil, BoundaryCoveredFloor)
	if err != nil || minClientOf(t, index) != BoundaryCoveredFloor {
		t.Fatalf("at the floor: floor=%q err=%v", minClientOf(t, index), err)
	}
}

// With the listed family in the same package its floor, never above the
// opt-in floor, is not lowered.
func TestOptInKeepsTheHigherFloor(t *testing.T) {
	t.Parallel()
	index, _, _, err := BuildExternalTargetsFromPackPinned(optInPack(t, recordSections{LineAttestations: mixedSection(t)}), "5", ListedFamilyFloor)
	if err != nil || minClientOf(t, index) != ListedFamilyFloor {
		t.Fatalf("floor=%q err=%v", minClientOf(t, index), err)
	}
}

// No publication build carries the level below the floor.
func TestOptInExportRefusedBelowTheFloor(t *testing.T) {
	t.Parallel()
	pack := optInPack(t, recordSections{})
	for _, oldest := range []string{"", "v0.0.1-alpha.1", "v0.1.0-beta.0", "v0.1.0-beta.1", "v0.1.0-beta.2"} {
		index, targets, _, err := BuildExternalTargetsFromPackPinned(pack, "5", oldest)
		if !errors.Is(err, ErrOptInBelowFloor) || !errors.Is(err, ErrIntegrity) || index.Bytes != nil || targets != nil {
			t.Fatalf("oldest %q: %v", oldest, err)
		}
	}
	if _, _, _, err := BuildExternalTargetsFromPackPinned(pack, "5", "latest"); err == nil {
		t.Fatal("an oldest client that is not a version was accepted")
	}
}

// A target set is refused without a usable floor, and on any doubt.
func TestCheckOptInFloorRefusals(t *testing.T) {
	t.Parallel()
	index, targets, err := BuildExternalTargetsFromPack(optInPack(t, recordSections{}), "5")
	if err != nil {
		t.Fatal(err)
	}
	raws := rawTargets(targets)
	if err := CheckOptInFloor(index.Bytes, raws); err != nil {
		t.Fatal(err)
	}
	if err := CheckOptInShipping(index.Bytes, raws, "v0.1.0-beta.0"); !errors.Is(err, ErrOptInBelowFloor) {
		t.Fatalf("old client: %v", err)
	}
	member := []byte(`,"minClientVersion":"` + BoundaryCoveredFloor + `"`)
	if !bytes.Contains(index.Bytes, member) {
		t.Fatal("no floor member")
	}
	for _, replacement := range []string{"", `,"minClientVersion":"v0.1.0-beta.0"`, `,"minClientVersion":"v0.1.0-beta.2"`, `,"minClientVersion":"latest"`} {
		if err := CheckOptInFloor(bytes.Replace(index.Bytes, member, []byte(replacement), 1), raws); err == nil {
			t.Fatalf("floor %q accepted", replacement)
		}
	}
	for _, bad := range []string{"{", `{}`, `{"pack":{}}`} {
		if err := CheckOptInFloor(index.Bytes, [][]byte{[]byte(bad)}); err == nil {
			t.Fatalf("target %q accepted", bad)
		}
	}
}

// The floor is a version above the releases published before the level, and
// never below the listed-family floor.
func TestBoundaryCoveredFloorIsAboveEarlierReleases(t *testing.T) {
	t.Parallel()
	if !atLeastVersion(BoundaryCoveredFloor, ListedFamilyFloor) {
		t.Fatalf("the floor %s is below the listed-family floor %s", BoundaryCoveredFloor, ListedFamilyFloor)
	}
	for _, earlier := range []string{"v0.0.1-alpha.1", "v0.1.0-beta.0", "v0.1.0-beta.1", "v0.1.0-beta.2"} {
		if atLeastVersion(earlier, BoundaryCoveredFloor) {
			t.Fatalf("%s is not below the floor %s", earlier, BoundaryCoveredFloor)
		}
	}
	if !atLeastVersion(BoundaryCoveredFloor, BoundaryCoveredFloor) {
		t.Fatalf("floor %q is not a version", BoundaryCoveredFloor)
	}
}

// optInFloorProblems lists every release tag that does not know the level and
// is not below the floor: a client at it would pass the floor and fail the
// package as an integrity error. A tag that knows the level may be on either
// side, because a floor above it only refuses more.
func optInFloorProblems(floor string, tags []releaseTag) []string {
	var problems []string
	for _, tag := range tags {
		switch {
		case !buildidentity.ValidVersion(tag.name):
			problems = append(problems, tag.name+" is not a version")
		case !tag.hasFamily && buildidentity.AtLeast(tag.name, floor):
			problems = append(problems, tag.name+" predates the level but is not below the floor "+floor)
		}
	}
	return problems
}

func TestOptInFloorProblems(t *testing.T) {
	t.Parallel()
	before := []releaseTag{{"v0.0.1-alpha.1", false}, {"v0.1.0-beta.0", false}}
	later := append(append([]releaseTag(nil), before...), releaseTag{"v0.1.0-beta.1", true}, releaseTag{BoundaryCoveredFloor, true}, releaseTag{"v0.2.0", true})
	if p := optInFloorProblems(BoundaryCoveredFloor, later); len(p) != 0 {
		t.Fatalf("floor %s: %v", BoundaryCoveredFloor, p)
	}
	if p := optInFloorProblems("v0.1.0-beta.0", before); len(p) != 1 {
		t.Fatalf("a floor lowered to the last released tag: %v", p)
	}
	for _, tag := range []releaseTag{{BoundaryCoveredFloor, false}, {"v0.2.0", false}, {"latest", true}} {
		if p := optInFloorProblems(BoundaryCoveredFloor, []releaseTag{tag}); len(p) != 1 {
			t.Fatalf("tag %+v: %v", tag, p)
		}
	}
}

// The floor is above every real release tag that does not hold the level. On
// CI an unreadable tag list is a failure, never a pass; elsewhere the test is
// skipped with the reason.
func TestBoundaryCoveredFloorAgainstTheRealTags(t *testing.T) {
	tags, reason := gitReleaseTags(t, "optinfloor.go")
	if reason != "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI cannot read the release tags: %s", reason)
		}
		t.Skip(reason)
	}
	if p := optInFloorProblems(BoundaryCoveredFloor, tags); len(p) != 0 {
		t.Fatalf("floor %s: %v", BoundaryCoveredFloor, p)
	}
}

// No level may follow the opt-in level without carrying the opt-in: a pack
// that declares the highest feature's schema would otherwise lose it.
func TestNoLevelAfterTheOptInDropsIt(t *testing.T) {
	t.Parallel()
	first := -1
	for i, feature := range packFeatureLevels {
		if feature.schema == packSchemaBoundaryCovered {
			first = i
		}
	}
	if first < 0 {
		t.Fatal("the opt-in level is not a pack level")
	}
	b := recordsBase(t, recordSections{})
	var rules []json.RawMessage
	for _, entry := range b.pack.Entries {
		ranged, err := constraintengine.AnyRanged([]json.RawMessage{entry.Rule})
		if err != nil {
			t.Fatal(err)
		}
		if ranged {
			rules = append(rules, entry.Rule)
			break
		}
	}
	if len(rules) == 0 {
		t.Fatal("no ranged rule")
	}
	for _, feature := range packFeatureLevels[first:] {
		if !PackSchemaIsOptIn(feature.schema) {
			t.Fatalf("%s follows the opt-in level without carrying the opt-in", feature.schema)
		}
		b.pack.Schema = feature.schema
		raw, err := b.ruleDocumentBytes(rules, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"`+constraintengine.RulesSchemaBoundaryCovered+`"`)) {
			t.Fatalf("%s does not select the boundary-covered contract", feature.schema)
		}
	}
}
