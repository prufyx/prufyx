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
		{"edge-25.03.1", "", 0, false},
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
	if !slices.Equal(versions["24.7"], []string{"24.7.1", "24.7.2"}) || !slices.Equal(versions["25.3"], []string{"25.3.2"}) || !slices.Equal(versions["26.3"], []string{"26.3.2", "26.3.3"}) {
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
