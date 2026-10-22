// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const calverComponent = "pkg:github/argoproj/argo-cd"

func calverTags(names ...string) []extract.Tag {
	var out []extract.Tag
	for _, n := range names {
		out = append(out, extract.Tag{Name: n, Commit: strings.Repeat(string(rune('a'+len(out)%6)), 40)})
	}
	return out
}

func releaseAt(tags []extract.Tag, name, version string) lineattest.Release {
	for _, t := range tags {
		if t.Name == name {
			return lineattest.Release{Version: version, Commit: t.Commit}
		}
	}
	panic("no tag " + name)
}

func TestFinalReleasesCalver(t *testing.T) {
	tags := calverTags("edge-25.12.1", "25.12.2-edge", "edge-25.03.1", "edge-26.1.1-rc1", "26.1.1-edge", "v26.1.2-edge", "edge-26.2.1")
	got, err := finalReleases(tags, nil, crdversions.SchemeCalverEdge, "25.12")
	if err != nil || len(got) != 2 || got[0].Version != "25.12.1" || got[1].Version != "25.12.2" {
		t.Fatalf("25.12: %+v, %v", got, err)
	}
	if got, err := finalReleases(tags, nil, crdversions.SchemeCalverEdge, "26.1"); err != nil || len(got) != 1 || got[0].Version != "26.1.1" {
		t.Fatalf("26.1: %+v, %v", got, err)
	}
	// The non-canonical spelling is no release, so its line has none.
	if got, _ := finalReleases(tags, nil, crdversions.SchemeCalverEdge, "25.3"); len(got) != 0 {
		t.Fatalf("25.3: %+v", got)
	}
	// A semver target does not read these tags.
	if got, _ := finalReleases(tags, []string{"v", ""}, "", "25.12"); len(got) != 0 {
		t.Fatalf("semver target read edge tags: %+v", got)
	}
	// One version under both spellings at two commits is refused.
	both := []extract.Tag{{Name: "edge-26.1.1", Commit: strings.Repeat("a", 40)}, {Name: "26.1.1-edge", Commit: strings.Repeat("b", 40)}}
	if _, err := finalReleases(both, nil, crdversions.SchemeCalverEdge, "26.1"); err == nil || !strings.Contains(err.Error(), "two commits") {
		t.Fatalf("two commits: %v", err)
	}
}

// The releases of an attested line across a year change are compared with
// the tags of the previous calendar month, and only with a calendar component.
func TestReleasesCompleteAcrossNewYear(t *testing.T) {
	defer lineattest.SetCalverComponentsForTest(calverComponent)()
	tags := calverTags("edge-25.12.1", "25.12.2-edge", "26.1.1-edge", "26.1.2-edge", "edge-26.0.9")
	target := crdversions.Target{Project: "x", ReleaseScheme: crdversions.SchemeCalverEdge}
	att := func(from, to []lineattest.Release) *lineattest.LineAttestation {
		return &lineattest.LineAttestation{Component: calverComponent, Line: "26.1", Releases: &lineattest.Releases{From: from, To: to}}
	}
	from := []lineattest.Release{releaseAt(tags, "edge-25.12.1", "25.12.1"), releaseAt(tags, "25.12.2-edge", "25.12.2")}
	to := []lineattest.Release{releaseAt(tags, "26.1.1-edge", "26.1.1"), releaseAt(tags, "26.1.2-edge", "26.1.2")}
	if err := crdReleasesMatch(target, att(from, to), tags); err != nil {
		t.Fatalf("complete record refused: %v", err)
	}
	for name, a := range map[string]*lineattest.LineAttestation{
		"missing a release of the previous month": att(from[:1], to),
		"missing a release of the line":           att(from, to[:1]),
		"no releases":                             {Component: calverComponent, Line: "26.1"},
	} {
		if err := crdReleasesMatch(target, a, tags); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The same record for an ordinary component reads 26.0 as the previous
	// line and finds no release of it.
	ordinary := att(from, to)
	ordinary.Component = "pkg:github/example/ordinary"
	if err := crdReleasesMatch(crdversions.Target{Project: "x", TagPrefixes: []string{""}}, ordinary, tags); err == nil {
		t.Error("an ordinary component was compared with the previous calendar month")
	}
}
