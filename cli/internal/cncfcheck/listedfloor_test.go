// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const listedTestComponent = "pkg:github/prometheus/prometheus"

func listedTestAttestation() lineattest.LineAttestation {
	a := testAttestation("0.51", nil)
	a.Component, a.FactFamily = listedTestComponent, lineattest.FamilyChangelogListedEntries
	a.Evidence.Basis = constraintengine.BasisMechanical
	a.Evidence.Extractor = &constraintengine.Extractor{ID: "changelog.listed-entries", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
	a.Evidence.DerivedAt = a.Evidence.ReviewedAt
	a.Releases = &lineattest.Releases{
		From: []lineattest.Release{{Version: "0.50.0", Commit: strings.Repeat("1", 40)}},
		To:   []lineattest.Release{{Version: "0.51.0", Commit: strings.Repeat("2", 40)}},
	}
	return a
}

// mixedSection holds one attestation of another family and one listed.
func mixedSection(t *testing.T) []byte {
	return section(t, testAttestation("1.30", nil), listedTestAttestation())
}

func listedOnlySection(t *testing.T) []byte { return section(t, listedTestAttestation()) }

func carriesListed(t *testing.T, targets []ExternalTarget) bool {
	t.Helper()
	for _, target := range targets {
		var envelope struct {
			Pack struct {
				LineAttestations json.RawMessage `json:"lineAttestations"`
			} `json:"pack"`
		}
		if err := json.Unmarshal(target.Bytes, &envelope); err != nil {
			t.Fatal(err)
		}
		if SectionCarriesListedFamily(envelope.Pack.LineAttestations) {
			return true
		}
	}
	return false
}

func minClientOf(t *testing.T, index ExternalTarget) string {
	t.Helper()
	v, _ := ExternalIndexMinClient(index.Bytes)
	return v
}

func rawTargets(targets []ExternalTarget) [][]byte {
	out := make([][]byte, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.Bytes)
	}
	return out
}

func listedBuild(t *testing.T, sec []byte, pin string) (ExternalTarget, []ExternalTarget) {
	t.Helper()
	index, targets, _, err := BuildExternalTargetsFromPackPinned(recordsPack(t, recordSections{LineAttestations: sec}), "5", pin)
	if err != nil {
		t.Fatal(err)
	}
	return index, targets
}

// The listed section is removed below the floor and kept at it; the count is
// returned; nothing else in the section changes.
func TestExcludeListedAttestations(t *testing.T) {
	mixed := mixedSection(t)
	for _, pin := range []string{"", "v0.1.0-beta.0", "v0.0.1-alpha.1", "v0.1.0-beta.1", "v0.1.0-beta.1.1"} {
		kept, n, err := ExcludeListedAttestations(mixed, pin)
		if err != nil || n != 1 || SectionCarriesListedFamily(kept) || len(kept) == 0 {
			t.Fatalf("pin %q: kept=%s n=%d err=%v", pin, kept, n, err)
		}
		atts, err := lineattest.Parse(kept)
		if err != nil || len(atts) != 1 || atts[0].FactFamily != lineattest.FamilyKubernetesRemovedServedGVK {
			t.Fatalf("the other family did not survive: %v %v", atts, err)
		}
	}
	for _, pin := range []string{ListedFamilyFloor, "v9.9.9"} {
		kept, n, err := ExcludeListedAttestations(mixed, pin)
		if err != nil || n != 0 || !bytes.Equal(kept, mixed) {
			t.Fatalf("pin %q at or above the floor changed the section: n=%d err=%v", pin, n, err)
		}
	}
	// A section of only listed records is gone, not empty.
	kept, n, err := ExcludeListedAttestations(listedOnlySection(t), "v0.1.0-beta.0")
	if err != nil || n != 1 || kept != nil {
		t.Fatalf("emptied section must be absent: %q n=%d err=%v", kept, n, err)
	}
	// An absent section stays absent whatever the pin.
	if kept, n, err := ExcludeListedAttestations(nil, "v0.1.0-beta.0"); err != nil || n != 0 || kept != nil {
		t.Fatalf("absent: %q %d %v", kept, n, err)
	}
	// A pin that is not a version, and a section that does not parse, refuse.
	for _, bad := range []string{"latest", "0.1", "v1", "v0.1.0-", " v0.1.0"} {
		if _, _, err := ExcludeListedAttestations(mixed, bad); !errors.Is(err, ErrListedFloorInvalid) {
			t.Errorf("pin %q: %v", bad, err)
		}
	}
	if _, _, err := ExcludeListedAttestations(json.RawMessage(`[{"factFamily":"nope"}]`), ""); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a section that does not parse was accepted: %v", err)
	}
}

// A malformed floor is refused on every path that reads it.
func TestMalformedListedFloorIsRefused(t *testing.T) {
	for _, floor := range []string{"", "latest", "1.0", "v1.0", "v0.1.0-"} {
		if _, err := listedFamilyShips("v9.9.9", floor); !errors.Is(err, ErrListedFloorInvalid) {
			t.Errorf("floor %q: ships: %v", floor, err)
		}
		if _, _, err := excludeListed(mixedSection(t), "v9.9.9", floor); !errors.Is(err, ErrListedFloorInvalid) {
			t.Errorf("floor %q: exclude: %v", floor, err)
		}
		_, _, _, err := buildExternalTargetsPolicy(syntheticBaseBundle(t), "5", "operator_provided", func(string, func(string) ([]byte, error)) (string, error) { return "5", nil }, &listedPolicy{oldestClient: "v9.9.9", floor: floor})
		if floor != "" && !errors.Is(err, ErrListedFloorInvalid) {
			t.Errorf("floor %q: build: %v", floor, err)
		}
	}
	// An index whose floor is not a version does not parse.
	index, _ := listedBuild(t, mixedSection(t), "v9.9.9")
	var doc map[string]any
	if err := json.Unmarshal(index.Bytes, &doc); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"latest", "1.2", "v1", "v0.1.0-", "V0.1.0"} {
		doc["minClientVersion"] = bad
		raw, _ := json.Marshal(doc)
		if _, err := ParseExternalIndex(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("minClientVersion %q parsed: %v", bad, err)
		}
	}
}

// The writer: a package that carries the family names the floor; one that
// does not leaves the field unset.
func TestIndexMinClientFollowsTheFamily(t *testing.T) {
	pack := recordsPack(t, recordSections{LineAttestations: mixedSection(t)})
	index, targets, err := BuildExternalTargetsFromPack(pack, "5")
	if err != nil {
		t.Fatal(err)
	}
	if !carriesListed(t, targets) || minClientOf(t, index) != ListedFamilyFloor {
		t.Fatalf("family shipped=%v minClientVersion=%q", carriesListed(t, targets), minClientOf(t, index))
	}
	if _, err := ParseExternalIndex(index.Bytes); err != nil {
		t.Fatalf("the index with the floor does not parse: %v", err)
	}
	// No family: unset.
	index, targets, err = BuildExternalTargetsFromPack(recordsPack(t, recordSections{LineAttestations: validAttestations(t)}), "5")
	if err != nil || carriesListed(t, targets) || minClientOf(t, index) != "" || bytes.Contains(index.Bytes, []byte("minClientVersion")) {
		t.Fatalf("no family: minClientVersion=%q err=%v", minClientOf(t, index), err)
	}
}

// Pin below the floor: nothing listed ships and the index carries no floor; at
// the floor the family ships with the floor.
func TestPinnedBuildShipsTheFamilyOnlyFromTheFloor(t *testing.T) {
	pack := recordsPack(t, recordSections{LineAttestations: mixedSection(t)})
	for _, pin := range []string{"", "v0.1.0-beta.0"} {
		index, targets, n, err := BuildExternalTargetsFromPackPinned(pack, "5", pin)
		if err != nil || n != 1 || carriesListed(t, targets) || minClientOf(t, index) != "" {
			t.Fatalf("pin %q: excluded=%d shipped=%v floor=%q err=%v", pin, n, carriesListed(t, targets), minClientOf(t, index), err)
		}
	}
	index, targets, n, err := BuildExternalTargetsFromPackPinned(pack, "5", ListedFamilyFloor)
	if err != nil || n != 0 || !carriesListed(t, targets) || minClientOf(t, index) != ListedFamilyFloor {
		t.Fatalf("pin at the floor: excluded=%d shipped=%v floor=%q err=%v", n, carriesListed(t, targets), minClientOf(t, index), err)
	}
	if err := CheckListedFamilyShipping(index.Bytes, rawTargets(targets), ListedFamilyFloor); err != nil {
		t.Fatalf("the publish check refused a correct package: %v", err)
	}
	if _, _, _, err := BuildExternalTargetsFromPackPinned(pack, "5", "latest"); !errors.Is(err, ErrListedFloorInvalid) {
		t.Fatalf("a pin that is not a version was accepted: %v", err)
	}
}

// Same input, same digest: the exclusion depends on nothing but its input.
func TestListedExclusionIsDeterministic(t *testing.T) {
	pack := recordsPack(t, recordSections{LineAttestations: mixedSection(t)})
	a, at, _, err := BuildExternalTargetsFromPackPinned(pack, "5", "v0.1.0-beta.0")
	if err != nil {
		t.Fatal(err)
	}
	b, bt, _, err := BuildExternalTargetsFromPackPinned(pack, "5", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes, b.Bytes) || len(at) != len(bt) {
		t.Fatal("two pins below the floor gave different indexes")
	}
	for i := range at {
		if !bytes.Equal(at[i].Bytes, bt[i].Bytes) {
			t.Fatalf("target %s differs", at[i].Path)
		}
	}
	// A pack that never held the family gives the same bytes as the pack with
	// the family excluded, so the digest does not depend on what was left out.
	without := recordsPack(t, recordSections{LineAttestations: section(t, testAttestation("1.30", nil))})
	c, ct, n, err := BuildExternalTargetsFromPackPinned(without, "5", "v0.1.0-beta.0")
	if err != nil || n != 0 || !bytes.Equal(a.Bytes, c.Bytes) || len(ct) != len(at) {
		t.Fatalf("excluded pack differs from a pack without the family: n=%d err=%v", n, err)
	}
	// The unpinned builder is untouched: it still ships what the pack holds.
	x, _, err := BuildExternalTargetsFromPack(pack, "5")
	if err != nil || bytes.Equal(x.Bytes, a.Bytes) {
		t.Fatalf("the unpinned build equals the excluded one: %v", err)
	}
}

// A section that is present but empty is refused by the pack admission; an
// emptied section must therefore be absent, and an absent one admitted.
func TestEmptyVersusAbsentAttestationSection(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.PathPolicies, pack.ServedAPIs = nil, nil
	pack.LineAttestations = json.RawMessage(`[]`)
	var encodeErr error
	if pack.Schema, encodeErr = requiredPackSchema(pack); encodeErr != nil {
		t.Fatal(encodeErr)
	}
	emptyPack, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assembleSynthetic(emptyPack, nil); err == nil {
		t.Fatal("a present but empty attestation section was admitted")
	}
	if _, err := admitAttestations(json.RawMessage(`[]`), true, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("admitAttestations accepted an empty present section: %v", err)
	}
	if _, err := admitAttestations(nil, false, nil); err != nil {
		t.Fatalf("an absent section was refused: %v", err)
	}
	// What the exclusion leaves of a listed-only pack is absent, and the
	// resulting targets pass the whole admission, including the rule that the
	// package holds no unused member (the index lists exactly the targets).
	index, targets, n, err := BuildExternalTargetsFromPackPinned(recordsPack(t, recordSections{LineAttestations: listedOnlySection(t)}), "5", "v0.1.0-beta.0")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	parsed, err := ParseExternalIndex(index.Bytes)
	if err != nil || len(parsed.Entries()) != len(targets) {
		t.Fatalf("index lists %d entries for %d targets: %v", len(parsed.Entries()), len(targets), err)
	}
	for _, entry := range parsed.Entries() {
		if entry.Records {
			t.Fatalf("project %s is flagged as holding records after the exclusion", entry.Project)
		}
	}
	for _, target := range targets {
		project, _ := ProjectFromTargetPath(target.Path)
		if _, err := AdmitExternalProjectTarget(parsed, project, target.Bytes); err != nil {
			t.Fatalf("%s: %v", target.Path, err)
		}
	}
}

// The publish check refuses on every way the floor can be missing.
func TestCheckListedFamilyShipping(t *testing.T) {
	pack := recordsPack(t, recordSections{LineAttestations: mixedSection(t)})
	good, goodTargets, _, err := BuildExternalTargetsFromPackPinned(pack, "5", ListedFamilyFloor)
	if err != nil {
		t.Fatal(err)
	}
	raws := rawTargets(goodTargets)
	if err := CheckListedFamilyShipping(good.Bytes, raws, ListedFamilyFloor); err != nil {
		t.Fatal(err)
	}
	withFloor := func(value string, remove bool) []byte {
		var doc map[string]any
		if err := json.Unmarshal(good.Bytes, &doc); err != nil {
			t.Fatal(err)
		}
		if remove {
			delete(doc, "minClientVersion")
		} else {
			doc["minClientVersion"] = value
		}
		out, _ := json.Marshal(doc)
		return out
	}
	refused := map[string][]byte{
		"absent":          withFloor("", true),
		"below the floor": withFloor("v0.1.0-beta.1", false),
		"the pin version": withFloor("v0.1.0-beta.0", false),
		"malformed":       withFloor("latest", false),
		"empty":           withFloor("", false),
		"not JSON":        []byte("x"),
	}
	for name, index := range refused {
		if err := CheckListedFamilyShipping(index, raws, ListedFamilyFloor); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, pin := range []string{"", "v0.1.0-beta.0", "v0.1.0-beta.1", "v0.1.0-beta.1.1", "latest"} {
		if err := CheckListedFamilyShipping(good.Bytes, raws, pin); err == nil {
			t.Errorf("a package with the family accepted for pin %q", pin)
		}
	}
	if err := CheckListedFamilyShipping(good.Bytes, [][]byte{[]byte("{")}, ListedFamilyFloor); err == nil {
		t.Error("an unreadable project target was accepted")
	}
	// No family: no constraint, whatever the index says.
	_, plain, _, err := BuildExternalTargetsFromPackPinned(pack, "5", "v0.1.0-beta.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckListedFamilyShipping(withFloor("", true), rawTargets(plain), "v0.1.0-beta.0"); err != nil {
		t.Fatalf("a package without the family was refused: %v", err)
	}
}

// releaseTag is a release tag and whether the commit it points at already
// holds the listed family.
type releaseTag struct {
	name      string
	hasFamily bool
}

// earlyFamilyRelease is the one release name below ListedFamilyFloor that may
// hold the family. A client at it refuses a package that carries the family as
// too new (exit 15), because the package names the floor. The exception is for
// this exact tag name against ListedFamilyFloor only; it changes no floor and
// no publish check. Do not add names to it.
const earlyFamilyRelease = "v0.1.0-beta.1"

// floorProblems lists every way the floor fails to separate clients that know
// the family from clients that do not: a tag that predates the family must be
// below the floor (a client at it would pass the floor and fail the package
// as an integrity error, exit 3), and a tag that holds the family must be at
// or above it (otherwise that release would be refused as too new, or the
// floor would be too high to be the first release that knows the family). The
// only tag excused from the second condition is earlyFamilyRelease, and only
// when floor is ListedFamilyFloor.
func floorProblems(floor string, tags []releaseTag) []string {
	var problems []string
	for _, tag := range tags {
		switch {
		case !buildidentity.ValidVersion(tag.name):
			problems = append(problems, tag.name+" is not a version")
		case !tag.hasFamily && buildidentity.AtLeast(tag.name, floor):
			problems = append(problems, tag.name+" predates the family but is not below the floor "+floor)
		case tag.hasFamily && !buildidentity.AtLeast(tag.name, floor) && !(floor == ListedFamilyFloor && tag.name == earlyFamilyRelease):
			problems = append(problems, tag.name+" holds the family but is below the floor "+floor)
		}
	}
	return problems
}

func TestFloorProblems(t *testing.T) {
	before := []releaseTag{{"v0.0.1-alpha.1", false}, {"v0.1.0-beta.0", false}}
	if p := floorProblems(ListedFamilyFloor, before); len(p) != 0 {
		t.Fatalf("the floor %s is refused for the tags before the family: %v", ListedFamilyFloor, p)
	}
	// Tags cut later do not break the check: a release at the floor or above
	// holds the family.
	later := append(append([]releaseTag(nil), before...), releaseTag{ListedFamilyFloor, true}, releaseTag{"v0.1.0-beta.4", true}, releaseTag{"v0.2.0", true})
	if p := floorProblems(ListedFamilyFloor, later); len(p) != 0 {
		t.Fatalf("a later tag broke the check: %v", p)
	}
	// Negative cases.
	if p := floorProblems("v0.1.0-beta.0", before); len(p) == 0 {
		t.Fatal("a floor lowered to the last released tag was accepted")
	}
	if p := floorProblems("v0.0.1-alpha.1", before); len(p) != 2 {
		t.Fatalf("a floor at the first tag: %v", p)
	}
	if p := floorProblems(ListedFamilyFloor, append(append([]releaseTag(nil), before...), releaseTag{"v0.1.0-beta.1.1", true})); len(p) != 1 {
		t.Fatalf("a release below the floor that holds the family: %v", p)
	}
	if p := floorProblems(ListedFamilyFloor, []releaseTag{{ListedFamilyFloor, false}}); len(p) != 1 {
		t.Fatalf("a release at the floor that predates the family: %v", p)
	}
	if p := floorProblems(ListedFamilyFloor, []releaseTag{{"latest", false}}); len(p) != 1 {
		t.Fatalf("a tag that is not a version: %v", p)
	}
	// The one named exception. Its literal is held here, so changing the
	// constant fails this test.
	if earlyFamilyRelease != "v0.1.0-beta.1" {
		t.Fatalf("the early release exception names %q", earlyFamilyRelease)
	}
	early := releaseTag{"v0.1.0-beta.1", true}
	if p := floorProblems(ListedFamilyFloor, append(append([]releaseTag(nil), before...), early)); len(p) != 0 {
		t.Fatalf("the named early release is refused: %v", p)
	}
	// No other name below the floor is excused, alone or next to the named one.
	for _, name := range []string{"v0.1.0-beta.0", "v0.0.2", "v0.1.0-beta.1.1", "v0.1.0-beta.1+1", "0.1.0-beta.1", "v0.1.0-alpha.1"} {
		if p := floorProblems(ListedFamilyFloor, []releaseTag{early, {name, true}}); len(p) != 1 || !strings.HasPrefix(p[0], name+" ") {
			t.Errorf("%s holding the family below the floor: %v", name, p)
		}
	}
	// A lowered floor is still refused with the named release among the tags.
	if p := floorProblems("v0.1.0-beta.0", append(append([]releaseTag(nil), before...), early)); len(p) == 0 {
		t.Fatal("a floor lowered to the last released tag was accepted with the early release")
	}
	// The exception holds against ListedFamilyFloor only.
	for _, floor := range []string{"v0.1.0-beta.3", "v0.1.0-beta.4", "v0.2.0"} {
		if p := floorProblems(floor, []releaseTag{early}); len(p) != 1 {
			t.Errorf("floor %s: the early release was excused: %v", floor, p)
		}
	}
	// The name excuses only holding the family below the floor: without the
	// family it still counts as a tag that predates it against a lower floor.
	if p := floorProblems("v0.1.0-beta.0", []releaseTag{{earlyFamilyRelease, false}}); len(p) != 1 {
		t.Fatalf("the early name without the family at a lowered floor: %v", p)
	}
}

// gitReleaseTags reads the release tags of the checkout and whether each holds
// the commit that added file (the floor of a feature). ok is false (with a
// reason) when the checkout cannot say: no git, no tags, or no history back to
// that commit.
func gitReleaseTags(t *testing.T, file string) (tags []releaseTag, reason string) {
	t.Helper()
	git := func(args ...string) (string, error) {
		out, err := exec.Command("git", args...).Output()
		return strings.TrimSpace(string(out)), err
	}
	out, err := git("tag", "--list", "v*")
	if err != nil {
		return nil, "git is not usable here: " + err.Error()
	}
	names := strings.Fields(out)
	if len(names) == 0 {
		return nil, "the checkout has no release tags (fetch them: fetch-depth 0)"
	}
	added, err := git("log", "--diff-filter=A", "--format=%H", "--", file)
	lines := strings.Fields(added)
	if err != nil || len(lines) == 0 {
		return nil, "the checkout has no history back to the commit that added " + file
	}
	family := lines[len(lines)-1]
	for _, name := range names {
		has := exec.Command("git", "merge-base", "--is-ancestor", family, name).Run() == nil
		tags = append(tags, releaseTag{name, has})
	}
	return tags, ""
}

// The floor must separate the releases that predate the family from the ones
// that hold it, in this checkout's real tags. On CI an unreadable tag list is
// a failure, never a pass; elsewhere the test is skipped with the reason.
func TestListedFamilyFloorAgainstTheRealTags(t *testing.T) {
	tags, reason := gitReleaseTags(t, "listedfloor.go")
	if reason != "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI cannot read the release tags: %s", reason)
		}
		t.Skip(reason)
	}
	if p := floorProblems(ListedFamilyFloor, tags); len(p) != 0 {
		t.Fatalf("floor %s: %v", ListedFamilyFloor, p)
	}
}

// The floor is a version above the provider-facts floor and the releases that
// predate the family, and not below the pinned-lease floor (the two may be the
// same release). The oldest supported client is either the legacy one below it
// or a proved release: the family would otherwise ship to a client that does
// not know it.
func TestListedFamilyFloorIsAboveTheOtherFloorsAndThePin(t *testing.T) {
	if !buildidentity.ValidVersion(ListedFamilyFloor) {
		t.Fatalf("floor %q is not a version", ListedFamilyFloor)
	}
	if buildidentity.AtLeast(ProviderFactsMinClientVersion, ListedFamilyFloor) {
		t.Errorf("the provider facts floor %s is not below the floor %s", ProviderFactsMinClientVersion, ListedFamilyFloor)
	}
	if !buildidentity.ValidVersion(PinnedLeaseMinClientVersion) || !buildidentity.AtLeast(ListedFamilyFloor, PinnedLeaseMinClientVersion) {
		t.Errorf("the floor %s is below the pinned lease floor %s", ListedFamilyFloor, PinnedLeaseMinClientVersion)
	}
	for _, earlier := range []string{"v0.0.1-alpha.1", "v0.1.0-beta.0", earlyFamilyRelease} {
		if buildidentity.AtLeast(earlier, ListedFamilyFloor) {
			t.Errorf("%s is not below the floor %s", earlier, ListedFamilyFloor)
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "version=") {
		t.Fatalf("pin file %q", raw)
	}
	// A pin at or above the floor ships the family to it, so it must be a
	// proved release that holds the family (pinproof_test.go).
	if p := pinProblems(clientFloors(), raw, pinRepoRoot); len(p) != 0 {
		t.Fatalf("pin %q: %s", raw, strings.Join(p, "; "))
	}
}
