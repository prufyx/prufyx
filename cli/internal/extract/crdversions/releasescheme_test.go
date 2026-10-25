// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestCalverEdgeGrammar(t *testing.T) {
	for _, c := range []struct {
		tag      string
		version  string
		spelling int
		ok       bool
	}{
		{"edge-24.7.1", "24.7.1", 0, true},
		{"edge-26.2.5", "26.2.5", 0, true},
		{"26.3.2-edge", "26.3.2", 1, true},
		{"26.10.4-edge", "26.10.4", 1, true},
		{"edge-25.12.100", "25.12.100", 0, true},
		{"edge-25.03.1", "25.3.1", 2, true},
		{"25.03.1-edge", "25.3.1", 3, true},
		{"edge-25.10.1", "25.10.1", 0, true},
		{"edge-25.00.1", "", 0, false},
		{"edge-25.013.1", "", 0, false},
		{"edge-25.003.1", "", 0, false},
		{"edge-26.3.2-rc1", "", 0, false},
		{"v26.3.2-edge", "", 0, false},
		{"026.3.2-edge", "", 0, false},
		{"26.13.1-edge", "", 0, false},
		{"26.0.1-edge", "", 0, false},
		{"26.3.2", "", 0, false},
		{"26.3.0-edge", "", 0, false},
		{"26.3.1000-edge", "", 0, false},
		{"26.3.01-edge", "", 0, false},
		{"edge-26.3.2-edge", "", 0, false},
		{"05.3.2-edge", "", 0, false},
		{"edge-26.3", "", 0, false},
		{"xedge-26.3.2", "", 0, false},
		{"26.3.2-edge\n", "", 0, false},
		{"", "", 0, false},
	} {
		t.Run(c.tag, func(t *testing.T) {
			v, s, ok := CalverEdgeRelease(c.tag)
			if v != c.version || s != c.spelling || ok != c.ok {
				t.Fatalf("CalverEdgeRelease(%q) = %q, %d, %v; want %q, %d, %v", c.tag, v, s, ok, c.version, c.spelling, c.ok)
			}
		})
	}
}

func schemeTargetJSON(extra string) []byte {
	return []byte(fmt.Sprintf(`{"schema":%q,"target":{"project":"kamaji","name":"Kamaji","repo":"github.com/clastix/kamaji","component":"pkg:github/clastix/kamaji","factProject":"kamaji",%s"minFrom":"24.7","paths":[{"path":"crds/a.yaml"}],"exclude":[]}}`, TargetSchema, extra))
}

func TestReleaseSchemeTarget(t *testing.T) {
	tg, err := LoadTarget("target-kamaji.json", schemeTargetJSON(`"releaseScheme":"calver-edge",`))
	if err != nil || tg.ReleaseScheme != SchemeCalverEdge || len(tg.TagPrefixes) != 0 {
		t.Fatalf("target %+v: %v", tg, err)
	}
	for _, c := range []struct {
		name, extra, want string
	}{
		{"both", `"releaseScheme":"calver-edge","tagPrefixes":["v"],`, "mutually exclusive"},
		{"both, empty prefixes", `"releaseScheme":"calver-edge","tagPrefixes":[],`, "mutually exclusive"},
		{"neither", ``, "tagPrefixes"},
		{"unknown scheme", `"releaseScheme":"calver",`, "releaseScheme"},
		{"empty scheme, no prefixes", `"releaseScheme":"",`, "tagPrefixes"},
		{"unknown field", `"releaseScheme":"calver-edge","releaseSchemes":["calver-edge"],`, "unknown field"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadTarget("target-kamaji.json", schemeTargetJSON(c.extra)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
	// The scheme is for the components registered with calendar lines.
	other := strings.NewReplacer("clastix/kamaji", "example/other", `"kamaji"`, `"other"`, "target-kamaji", "target-other").Replace(string(schemeTargetJSON(`"releaseScheme":"calver-edge",`)))
	if _, err := LoadTarget("target-other.json", []byte(other)); err == nil || !strings.Contains(err.Error(), "calendar") {
		t.Fatalf("scheme on an unregistered component: %v", err)
	}
	// A semver target is read as before.
	if tg, err := LoadTarget("target-kamaji.json", schemeTargetJSON(`"tagPrefixes":["v"],`)); err != nil || tg.ReleaseScheme != "" || !slices.Equal(tg.TagPrefixes, []string{"v"}) {
		t.Fatalf("semver target %+v: %v", tg, err)
	}
}

func tagsAt(names ...string) extract.ReleaseIndex {
	var tags []extract.Tag
	for _, n := range names {
		tags = append(tags, extract.Tag{Name: n, Commit: commitOf(n)})
	}
	return extract.ReleaseIndex{Tags: tags}
}

// A tag with the shape of a release that the grammar does not read is
// reported with its line; a tag that is no release shape is not.
func TestCalverEdgeUnread(t *testing.T) {
	for _, c := range []struct {
		tag, line string
		unread    bool
	}{
		{"edge-26.3.0", "26.3", true},
		{"26.3.1000-edge", "26.3", true},
		{"26.3.01-edge", "26.3", true},
		{"edge-26.13.1", "26.13", true},
		{"26.00.1-edge", "26.0", true},
		{"edge-05.3.1", "5.3", true},
		{"edge-26.3.1", "", false},
		{"edge-26.03.1", "", false},
		{"26.3.2-edge", "", false},
		{"edge-26.3.2-rc1", "", false},
		{"v26.3.2-edge", "", false},
		{"26.3.2", "", false},
		{"edge-26.3", "", false},
		{"edge-26.3.2\n", "", false},
	} {
		line, unread := CalverEdgeUnread(c.tag)
		if line != c.line || unread != c.unread {
			t.Errorf("CalverEdgeUnread(%q) = %q, %v; want %q, %v", c.tag, line, unread, c.line, c.unread)
		}
	}
}

// Both spellings form lines by calendar month; a skipped month is skipped,
// numeric order puts 26.9 before 26.10, and tags of any other shape are not
// releases.
func TestCalverReleaseLinesAndPairs(t *testing.T) {
	x := New(Target{ReleaseScheme: SchemeCalverEdge, MinFrom: [2]int{24, 7}})
	idx := tagsAt(
		"edge-24.7.1", "edge-24.7.2", "edge-24.9.1", "edge-25.3.2", "edge-25.03.1", "edge-25.12.5",
		"edge-26.1.1", "edge-26.2.5", "26.3.2-edge", "26.3.3-edge", "26.9.1-edge", "26.10.4-edge",
		"26.10.5-rc1-edge", "edge-26.3.2-rc1", "v26.3.2-edge", "26.3.2", "v1.2.3", "26.11.1-edge-1",
	)
	lines := x.releaseLines(idx)
	var keys []string
	versions := map[string][]string{}
	for _, l := range lines {
		keys = append(keys, l.key())
		versions[l.key()] = l.Versions
		if l.Problem != "" {
			t.Fatalf("line %s: %s", l.key(), l.Problem)
		}
	}
	if want := []string{"24.7", "24.9", "25.3", "25.12", "26.1", "26.2", "26.3", "26.9", "26.10"}; !slices.Equal(keys, want) {
		t.Fatalf("lines %v, want %v", keys, want)
	}
	if !slices.Equal(versions["24.7"], []string{"24.7.1", "24.7.2"}) || !slices.Equal(versions["25.3"], []string{"25.3.1", "25.3.2"}) || !slices.Equal(versions["26.3"], []string{"26.3.2", "26.3.3"}) {
		t.Fatalf("versions %v", versions)
	}
	var pairs []string
	for _, p := range x.Pairs(idx) {
		pairs = append(pairs, p.From+">"+p.To+" "+p.FromTag+">"+p.ToTag)
	}
	if len(pairs) != 8 || pairs[3] != "25.12.5>26.1.1 edge-25.12.5>edge-26.1.1" || pairs[5] != "26.2.5>26.3.2 edge-26.2.5>26.3.2-edge" || pairs[7] != "26.9.1>26.10.4 26.9.1-edge>26.10.4-edge" {
		t.Fatalf("pairs %v", pairs)
	}
	// MinFrom applies to the calendar line.
	late := New(Target{ReleaseScheme: SchemeCalverEdge, MinFrom: [2]int{26, 2}})
	if got := late.Pairs(idx); len(got) != 3 || got[0].From != "26.2.5" {
		t.Fatalf("pairs from 26.2: %+v", got)
	}
}

// A zero-padded month is the same release as the canonical spelling: at
// one commit it counts once and the canonical tag is the recorded one; at
// two commits it spoils the line.
func TestCalverPaddedMonth(t *testing.T) {
	x := New(Target{ReleaseScheme: SchemeCalverEdge})
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	same := extract.ReleaseIndex{Tags: []extract.Tag{{Name: "edge-25.03.1", Commit: a}, {Name: "edge-25.3.1", Commit: a}}}
	if lines := x.releaseLines(same); len(lines) != 1 || lines[0].Problem != "" || len(lines[0].Tags) != 1 || lines[0].Tags[0].Name != "edge-25.3.1" {
		t.Fatalf("same commit: %+v", lines)
	}
	apart := extract.ReleaseIndex{Tags: []extract.Tag{{Name: "edge-25.03.1", Commit: a}, {Name: "edge-25.3.1", Commit: b}}}
	if lines := x.releaseLines(apart); len(lines) != 1 || !strings.Contains(lines[0].Problem, "tagged twice") {
		t.Fatalf("two commits: %+v", lines)
	}
	only := extract.ReleaseIndex{Tags: []extract.Tag{{Name: "edge-25.03.1", Commit: a}}}
	if lines := x.releaseLines(only); len(lines) != 1 || lines[0].key() != "25.3" || lines[0].Versions[0] != "25.3.1" || lines[0].Tags[0].Name != "edge-25.03.1" {
		t.Fatalf("padded only: %+v", lines)
	}
}

// A tag shaped like a release that the grammar cannot read spoils its line
// (and no other line), so the line is never attested as complete.
func TestCalverUnreadReleaseSpoilsLine(t *testing.T) {
	x := New(Target{ReleaseScheme: SchemeCalverEdge})
	c := func(n string) extract.Tag { return extract.Tag{Name: n, Commit: strings.Repeat("a", 40)} }
	idx := extract.ReleaseIndex{Tags: []extract.Tag{c("edge-26.2.1"), c("edge-26.3.1"), c("26.3.1000-edge"), c("edge-26.4.1"), c("edge-26.4.2-rc1")}}
	got := map[string]string{}
	for _, l := range x.releaseLines(idx) {
		got[l.key()] = l.Problem
	}
	if got["26.2"] != "" || got["26.4"] != "" || !strings.Contains(got["26.3"], "release grammar") || len(got) != 3 {
		t.Fatalf("problems %v", got)
	}
	// A semver target does not read these tags at all.
	if lines := New(Target{TagPrefixes: []string{""}}).releaseLines(idx); len(lines) != 0 {
		t.Fatalf("semver target: %+v", lines)
	}
}

// ReleaseTags names every tag the scheme reads by its engine version, for
// the framework's recorded-tag check, and leaves other targets alone.
func TestReleaseTags(t *testing.T) {
	a := strings.Repeat("a", 40)
	src := fixedTags{{Name: "26.3.2-edge", Commit: a}, {Name: "edge-25.03.1", Commit: a}, {Name: "edge-26.1.1", Commit: a}, {Name: "26.3.3-rc1", Commit: a}, {Name: "27.1.1-edge", Commit: a}}
	got, err := ReleaseTags(New(Target{ReleaseScheme: SchemeCalverEdge}), src).Tags(extract.RepoRef{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tg := range got {
		names = append(names, tg.Name)
	}
	if want := []string{"26.3.2-edge", "edge-25.03.1", "edge-26.1.1", "26.3.3-rc1", "27.1.1-edge", "26.3.2", "25.3.1", "26.1.1", "27.1.1"}; !slices.Equal(names, want) {
		t.Fatalf("tags %v, want %v", names, want)
	}
	if got, _ := ReleaseTags(New(Target{TagPrefixes: []string{"v"}}), src).Tags(extract.RepoRef{}); len(got) != len(src) {
		t.Fatalf("a semver target got %d tags, want %d", len(got), len(src))
	}
	// The aliases are no release tags of the scheme.
	if lines := New(Target{ReleaseScheme: SchemeCalverEdge}).releaseLines(extract.ReleaseIndex{Tags: []extract.Tag{{Name: "26.3.2", Commit: a}}}); len(lines) != 0 {
		t.Fatalf("an alias is a release: %+v", lines)
	}
}

type fixedTags []extract.Tag

func (f fixedTags) Tags(extract.RepoRef) ([]extract.Tag, error) { return f, nil }

// One version under both spellings counts once at one commit and spoils its
// line at two (as a version under two prefixes does).
func TestCalverBothSpellings(t *testing.T) {
	x := New(Target{ReleaseScheme: SchemeCalverEdge})
	same := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "26.3.2-edge", Commit: strings.Repeat("a", 40)},
		{Name: "edge-26.3.2", Commit: strings.Repeat("a", 40)},
	}}
	lines := x.releaseLines(same)
	if len(lines) != 1 || lines[0].Problem != "" || len(lines[0].Tags) != 1 || lines[0].Tags[0].Name != "edge-26.3.2" {
		t.Fatalf("same commit: %+v", lines)
	}
	apart := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "26.3.2-edge", Commit: strings.Repeat("a", 40)},
		{Name: "edge-26.3.2", Commit: strings.Repeat("b", 40)},
	}}
	if lines := x.releaseLines(apart); len(lines) != 1 || !strings.Contains(lines[0].Problem, "tagged twice") {
		t.Fatalf("two commits: %+v", lines)
	}
}

func calverSynthTarget() Target {
	tg := attestingTarget()
	tg.TagPrefixes, tg.ReleaseScheme, tg.MinFrom = nil, SchemeCalverEdge, [2]int{24, 0}
	return tg
}

// A synthetic calendar project, end to end: the December -> January pair
// is a previous-line hop and is attested with the releases of 25.12 and
// 26.1; a skipped month gives a derived pair without an attestation; the
// records carry the engine version, not the tag's decoration.
func TestCalverDeriveAndAttest(t *testing.T) {
	defer lineattest.SetCalverComponentsForTest(calverSynthTarget().Component)()
	alpha := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
	out := runSynth(t, calverSynthTarget(), newSynth(
		release{"edge-25.11.1", alpha}, release{"edge-25.12.1", alpha}, release{"edge-25.12.2", alpha},
		release{"26.1.1-edge", alpha}, release{"26.2.1-edge", alpha}, release{"26.4.1-edge", alpha},
	))
	// A zero-padded month attests too, with its version as the release.
	padded := runSynth(t, calverSynthTarget(), newSynth(release{"edge-25.03.1", alpha}, release{"edge-25.04.1", alpha}))
	if r := attestationFor(t, padded, "25.4"); r == nil || r.Releases.To[0].Version != "25.4.1" || r.Releases.From[0].Version != "25.3.1" {
		t.Fatalf("padded months: %+v", padded.Attestations)
	}
	for _, c := range []struct {
		from, to, status string
		line             string
		reason           string
	}{
		{"25.11.1", "25.12.1", extract.PairAttested, "25.12", ""},
		{"25.12.1", "26.1.1", extract.PairAttested, "26.1", ""},
		{"26.1.1", "26.2.1", extract.PairAttested, "26.2", ""},
		{"26.2.1", "26.4.1", extract.PairNotAttested, "", "skipped-minor hop"},
	} {
		a := pairAttestation(t, out, c.from, c.to)
		if a.Status != c.status || !strings.Contains(a.Reason, c.reason) {
			t.Fatalf("%s -> %s: %+v", c.from, c.to, a)
		}
		if c.line != "" && attestationFor(t, out, c.line) == nil {
			t.Fatalf("no attestation of line %s in %+v", c.line, out.Attestations)
		}
	}
	if len(out.Attestations) != 3 {
		t.Fatalf("%d attestations", len(out.Attestations))
	}
	rollover := attestationFor(t, out, "26.1")
	var from, to []string
	for _, r := range rollover.Releases.From {
		from = append(from, r.Version)
	}
	for _, r := range rollover.Releases.To {
		to = append(to, r.Version)
	}
	if !slices.Equal(from, []string{"25.12.1", "25.12.2"}) || !slices.Equal(to, []string{"26.1.1"}) || len(rollover.RuleIDs) != 0 || rollover.RuleIDs == nil {
		t.Fatalf("rollover attestation from %v to %v rules %v", from, to, rollover.RuleIDs)
	}
	if _, err := lineattest.Marshal(out.Attestations); err != nil {
		t.Fatalf("attestations do not validate: %v", err)
	}
	// Without the component in the calendar set the same January line would
	// have no previous line 25.12, and the extractor would see a skipped hop.
}

// A removal under the scheme is withheld: rule bounds are about minor lines
// of one major, which a calendar line has not (fail closed).
func TestCalverRemovalIsWithheld(t *testing.T) {
	defer lineattest.SetCalverComponentsForTest(calverSynthTarget().Component)()
	out := runSynth(t, calverSynthTarget(), newSynth(
		release{"edge-25.12.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"26.1.1-edge", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	))
	p, _ := pairOf(t, out, "25.12.1", "26.1.1")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "calver-edge") || len(out.Entries) != 0 || len(out.Attestations) != 0 {
		t.Fatalf("pair %s %q, %d rules, %d attestations", p.Status, p.Reason, len(out.Entries), len(out.Attestations))
	}
}

// Existing semver targets read their tags exactly as before: the scheme's
// shapes are not releases for them, and their prefix order still prefers the
// first prefix.
func TestSemverTargetIgnoresCalverTags(t *testing.T) {
	x := New(Target{TagPrefixes: []string{"v", ""}})
	idx := tagsAt("edge-26.3.2", "26.3.2-edge", "v1.2.3")
	idx.Tags = append(idx.Tags, extract.Tag{Name: "1.2.3", Commit: idx.Tags[2].Commit})
	lines := x.releaseLines(idx)
	if len(lines) != 1 || lines[0].key() != "1.2" || lines[0].Tags[0].Name != "v1.2.3" || lines[0].Problem != "" {
		t.Fatalf("lines %+v", lines)
	}
}
