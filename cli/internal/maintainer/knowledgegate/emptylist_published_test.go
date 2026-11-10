// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const publishedComp = "pkg:github/example/published"

func publishedTarget() crdversions.Target {
	return crdversions.Target{Project: "x", Component: publishedComp, TagPrefixes: []string{"v"}}
}

func publishedAttestation(line string, from, to []lineattest.Release) *lineattest.LineAttestation {
	return &lineattest.LineAttestation{Component: publishedComp, Line: line, Releases: &lineattest.Releases{From: from, To: to}}
}

func TestPublishedHopAgainstLiveTags(t *testing.T) {
	defer lineattest.SetPublishedLineComponentsForTest(publishedComp)()
	base := []string{"v25.8.0", "v25.10.1", "v25.10.2", "v26.3.0", "v26.6.0"}
	tags := calverTags(base...)
	r := func(name, version string) lineattest.Release { return releaseAt(tags, name, version) }
	from := []lineattest.Release{r("v25.10.1", "25.10.1"), r("v25.10.2", "25.10.2")}
	to := []lineattest.Release{r("v26.3.0", "26.3.0")}
	if err := crdReleasesMatch(publishedTarget(), publishedAttestation("26.3", from, to), tags); err != nil {
		t.Fatalf("25.10 -> 26.3 with no line between: %v", err)
	}

	// 26.3 -> 26.6 needs the from-line 26.3; 25.10 -> 26.6 skips a published line.
	skipped := publishedAttestation("26.6", from, []lineattest.Release{r("v26.6.0", "26.6.0")})
	if err := crdReleasesMatch(publishedTarget(), skipped, tags); err == nil || !strings.Contains(err.Error(), "just below") {
		t.Fatalf("25.10 -> 26.6 skips 26.3: %v", err)
	}
	if err := crdReleasesMatch(publishedTarget(), publishedAttestation("26.6", to, []lineattest.Release{r("v26.6.0", "26.6.0")}), tags); err != nil {
		t.Fatalf("26.3 -> 26.6: %v", err)
	}

	// A prerelease-only line between does not break the hop; an alias tag
	// never forms a line.
	for _, extra := range [][]string{{"v26.1.0-rc1"}, {"v26.1.0~1"}, {"v26.1.0-rc1", "v26.1.0~1", "v26.2.0-beta.1"}} {
		withExtra := calverTags(append(append([]string{}, base...), extra...)...)
		// Commits are position-based: re-read the releases from the new list.
		f := []lineattest.Release{releaseAt(withExtra, "v25.10.1", "25.10.1"), releaseAt(withExtra, "v25.10.2", "25.10.2")}
		tt := []lineattest.Release{releaseAt(withExtra, "v26.3.0", "26.3.0")}
		if err := crdReleasesMatch(publishedTarget(), publishedAttestation("26.3", f, tt), withExtra); err != nil {
			t.Errorf("%v between: %v", extra, err)
		}
	}

	// A final release of a line between makes the old pair stale.
	between := calverTags(append(append([]string{}, base...), "v26.1.0")...)
	f := []lineattest.Release{releaseAt(between, "v25.10.1", "25.10.1"), releaseAt(between, "v25.10.2", "25.10.2")}
	tt := []lineattest.Release{releaseAt(between, "v26.3.0", "26.3.0")}
	if err := crdReleasesMatch(publishedTarget(), publishedAttestation("26.3", f, tt), between); err == nil {
		t.Error("a late-inserted published line must stale the 25.10 -> 26.3 record")
	}
	// A middle line the tags cannot read (padded beside canonical) is still a
	// line: it blocks both neighbours.
	ambiguous := calverTags(append(append([]string{}, base...), "v26.02.0", "v26.2.1")...)
	f = []lineattest.Release{releaseAt(ambiguous, "v25.10.1", "25.10.1"), releaseAt(ambiguous, "v25.10.2", "25.10.2")}
	tt = []lineattest.Release{releaseAt(ambiguous, "v26.3.0", "26.3.0")}
	if err := crdReleasesMatch(publishedTarget(), publishedAttestation("26.3", f, tt), ambiguous); err == nil {
		t.Error("an ambiguous middle line must block the hop")
	}

	// An attested line with no live tags: the from-line was removed upstream.
	gone := publishedAttestation("26.3", []lineattest.Release{r("v25.10.1", "25.10.1")}, to)
	gone.Releases.From[0] = lineattest.Release{Version: "26.1.0", Commit: tags[0].Commit}
	if err := crdReleasesMatch(publishedTarget(), gone, tags); err == nil {
		t.Error("a from-line with no live final tags was accepted")
	}

	// Cross era and a skipped semver minor are not hops.
	semver := calverTags("v0.37.0", "v0.38.0", "v25.0.0", "v0.34.0", "v0.36.0")
	cross := publishedAttestation("25.0", []lineattest.Release{releaseAt(semver, "v0.38.0", "0.38.0")}, []lineattest.Release{releaseAt(semver, "v25.0.0", "25.0.0")})
	if err := crdReleasesMatch(publishedTarget(), cross, semver); err == nil {
		t.Error("0.38 -> 25.0 crosses the era boundary")
	}
	skip := publishedAttestation("0.36", []lineattest.Release{releaseAt(semver, "v0.34.0", "0.34.0")}, []lineattest.Release{releaseAt(semver, "v0.36.0", "0.36.0")})
	if err := crdReleasesMatch(publishedTarget(), skip, semver); err == nil {
		t.Error("0.34 -> 0.36 is not strict m-1")
	}
}

// An unregistered component is unchanged: the from-line is M.(m-1).
func TestPublishedHopUnregisteredUnchanged(t *testing.T) {
	tags := calverTags("v25.10.1", "v26.3.0")
	a := publishedAttestation("26.3", []lineattest.Release{releaseAt(tags, "v25.10.1", "25.10.1")}, []lineattest.Release{releaseAt(tags, "v26.3.0", "26.3.0")})
	if err := crdReleasesMatch(publishedTarget(), a, tags); err == nil {
		t.Fatal("an unregistered component read a skipped line as previous")
	}
}

// A line a current or prior record names that has no live final tag any more
// is an unknown line and refuses the record.
func TestPublishedRecordLinesLive(t *testing.T) {
	defer lineattest.SetPublishedLineComponentsForTest(publishedComp)()
	tags := calverTags("v25.10.1", "v26.3.0")
	rec := func(line string, from, to string) *record {
		return &record{attestation: publishedAttestation(line,
			[]lineattest.Release{{Version: from, Commit: strings.Repeat("a", 40)}},
			[]lineattest.Release{{Version: to, Commit: strings.Repeat("b", 40)}})}
	}
	head := rec("26.3", "25.10.1", "26.3.0")
	if err := publishedRecordLinesLive(publishedTarget(), &Change{rhead: head}, tags); err != nil {
		t.Fatalf("live lines refused: %v", err)
	}
	prior := rec("26.1", "25.10.1", "26.1.0")
	err := publishedRecordLinesLive(publishedTarget(), &Change{rhead: head, rbase: prior}, tags)
	if err == nil || !strings.Contains(err.Error(), "26.1") {
		t.Fatalf("a prior record naming the vanished line 26.1 was accepted: %v", err)
	}
	if err := publishedRecordLinesLive(publishedTarget(), &Change{rhead: prior}, tags); err == nil {
		t.Fatal("a record naming a line with no live tags was accepted")
	}
	// A record whose from-line is unreadable fails closed.
	bad := &record{attestation: &lineattest.LineAttestation{Component: publishedComp, Line: "26.3"}}
	if err := publishedRecordLinesLive(publishedTarget(), &Change{rhead: bad}, tags); err == nil {
		t.Fatal("a record with no from-line was accepted")
	}
}

// An unchanged record of the same component and family in the head pack,
// whose line has no live tag, blocks a first record of another line.
func TestPublishedRecordLinesLiveHeadPack(t *testing.T) {
	defer lineattest.SetPublishedLineComponentsForTest(publishedComp)()
	tags := calverTags("v25.10.1", "v26.3.0")
	rec := func(line, from, to string) *record {
		a := publishedAttestation(line,
			[]lineattest.Release{{Version: from, Commit: strings.Repeat("a", 40)}},
			[]lineattest.Release{{Version: to, Commit: strings.Repeat("b", 40)}})
		a.FactFamily = lineattest.FamilyCustomResourceVersions
		return &record{attestation: a}
	}
	head := rec("26.3", "25.10.1", "26.3.0")
	unchanged := rec("26.1", "25.10.1", "26.1.0")
	other := rec("26.3", "25.10.1", "26.3.0")
	other.attestation.Component = "pkg:github/example/other"
	c := &Change{rhead: head, headRecords: map[string]*record{"a": head, "b": other}}
	if err := publishedRecordLinesLive(publishedTarget(), c, tags); err != nil {
		t.Fatalf("live head pack refused: %v", err)
	}
	c = &Change{rhead: head, headRecords: map[string]*record{"a": head, "b": unchanged}}
	err := publishedRecordLinesLive(publishedTarget(), c, tags)
	if err == nil || !strings.Contains(err.Error(), "26.1") {
		t.Fatalf("an unchanged head-pack 26.1 record with vanished tags did not block the 25.10 -> 26.3 record: %v", err)
	}
	// A record of another family or component does not count.
	unchanged.attestation.FactFamily = lineattest.FamilyKubernetesRemovedServedGVK
	if err := publishedRecordLinesLive(publishedTarget(), c, tags); err != nil {
		t.Fatalf("a record of another family blocked: %v", err)
	}
}

func TestPublishedLinesReadOnlyFinalTags(t *testing.T) {
	tags := calverTags("v25.10.1", "v26.1.0-rc1", "v26.1.0~1", "v26.3.0", "v26.02.0", "v19.02.0", "edge-26.4.0")
	got := strings.Join(publishedLines(tags, []string{"v"}, ""), " ")
	if got != "25.10 26.2 26.3" {
		t.Fatalf("published lines = %q", got)
	}
}
