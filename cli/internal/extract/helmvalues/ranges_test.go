// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

const (
	c001 = "0000000000000000000000000000000000b90001"
	c011 = "0000000000000000000000000000000000b91001"
	c021 = "0000000000000000000000000000000000b92001"
)

// rangeFixture is a copy of the fixture whose tags are edited by edit
// (tag -> commit, "" removes the tag).
func rangeFixture(t *testing.T, edit map[string]string) string {
	t.Helper()
	root := copyFixture(t)
	p := filepath.Join(root, "github.com/kedacore/charts/tags.json")
	raw, err := os.ReadFile(p)
	must(t, err)
	tags := map[string]string{}
	must(t, json.Unmarshal(raw, &tags))
	for tag, commit := range edit {
		if commit == "" {
			delete(tags, tag)
			continue
		}
		tags[tag] = commit
	}
	raw, err = json.Marshal(tags)
	must(t, err)
	must(t, os.WriteFile(p, raw, 0o644))
	return root
}

// patchRelease writes commit as a copy of the chart at src that declares
// version, then applies edit to its files (relative to the chart).
func patchRelease(t *testing.T, root, src, commit, version string, edit func(dir string)) {
	t.Helper()
	commits := filepath.Join(root, "github.com/kedacore/charts/commits")
	must(t, os.RemoveAll(filepath.Join(commits, commit)))
	must(t, filepath.WalkDir(filepath.Join(commits, src), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(commits, src), p)
		dst := filepath.Join(commits, commit, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	}))
	dir := filepath.Join(commits, commit, "keda")
	chart, err := os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	must(t, err)
	var out []string
	for _, line := range strings.Split(string(chart), "\n") {
		if strings.HasPrefix(line, "version: ") {
			line = "version: " + version
		}
		out = append(out, line)
	}
	must(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte(strings.Join(out, "\n")), 0o644))
	if edit != nil {
		edit(dir)
	}
}

// rangeOf returns the first pair's proof and the run's entries by id.
func rangeRun(t *testing.T, root string) (*chartrun.Output, PairProof) {
	t.Helper()
	out, err := runFixture(t, root)
	must(t, err)
	if err := chartrun.CheckVectors(out.Entries, out.Vectors, derivedAt); err != nil {
		t.Fatal(err)
	}
	return out, pairProof(t, out.Manifest.Pairs[0])
}

func rangeProofOf(t *testing.T, p PairProof, kind string) RangeProof {
	t.Helper()
	for _, r := range p.Lines.Ranges {
		if r.Kind == kind {
			return r
		}
	}
	t.Fatalf("no range proof for %s in %+v", kind, p.Lines)
	return RangeProof{}
}

// identicalPatches: v90.0.1 and v90.1.1 are copies of their lines' first
// releases.
func identicalPatches(t *testing.T) string {
	t.Helper()
	root := rangeFixture(t, map[string]string{"v90.0.1": c001, "v90.1.1": c011})
	patchRelease(t, root, c0, c001, "90.0.1", nil)
	patchRelease(t, root, c1, c011, "90.1.1", nil)
	return root
}

// Identical patches: every rule of the first pair is ranged with the
// consecutive-line shape, its bounds cite the rule's own sources, and the
// texts name the whole later line.
func TestRangeConsecutiveLines(t *testing.T) {
	out, proof := rangeRun(t, identicalPatches(t))
	if proof.Lines.RangeOutcome != rangeChecked {
		t.Fatalf("range outcome %q", proof.Lines.RangeOutcome)
	}
	rules := byID(out)
	for kind, release := range map[string]string{kindKube: constraintengine.BasisChangedInRelease, kindRequired: constraintengine.BasisChangedInRelease, kindRemoved: constraintengine.BasisRemovedInRelease} {
		rp := rangeProofOf(t, proof, kind)
		if rp.Outcome != rangeConsecutive || rp.PairsChecked != 4 || rp.Divergence != nil {
			t.Fatalf("%s: %+v", kind, rp)
		}
		e, ok := rules[prefix01+kind]
		if !ok || e.Rule.Range == nil {
			t.Fatalf("%s: not ranged: %+v", kind, e.Rule)
		}
		r := e.Rule.Range
		if r.From != (constraintengine.VersionBound{Gte: "90.0.0", Lt: "90.1.0"}) || r.To != (constraintengine.VersionBound{Gte: "90.1.0", Lt: "90.2.0"}) {
			t.Fatalf("%s: range %+v", kind, r)
		}
		wantBases := []string{constraintengine.BasisPreviousMinorLine, release, release, constraintengine.BasisTargetSeries}
		sources := map[string]bool{}
		for _, s := range e.Rule.Evidence.Sources {
			sources[s.ID] = true
		}
		for i, b := range r.Bounds {
			if b.Basis != wantBases[i] || !sources[b.SourceID] {
				t.Fatalf("%s: bound %+v (sources %v)", kind, b, sources)
			}
		}
		if e.Rule.Subject.From != "90.0.0" || e.Rule.Subject.To != "90.1.0" || !strings.Contains(e.Rule.NextAction, "keda chart 90.1.x") && !strings.Contains(e.Rule.NextAction, "keda chart to 90.1.x") || !strings.Contains(e.Description, "each of the 2 x 2 tagged final releases of lines 90.0 and 90.1; the range also applies to other patches of those lines.") {
			t.Fatalf("%s: texts %q / %q", kind, e.Rule.NextAction, e.Description)
		}
		if !constraintengine.ValidChartRangeShape(e.Rule.Operator, *r) {
			t.Fatalf("%s: not a chart line shape", kind)
		}
	}
	// Notices stay anchor-only, and the second pair (a single-release
	// later line) derives nothing ranged.
	for _, e := range out.Entries {
		if constraintengine.IsSetNoticeOperator(e.Rule.Operator) && e.Rule.Range != nil {
			t.Fatalf("notice %s ranged", e.Rule.ID)
		}
	}
	if p2 := pairProof(t, out.Manifest.Pairs[1]); p2.Lines.RangeOutcome != "anchor-only: line 90.2 has a single final release" {
		t.Fatalf("second pair %q", p2.Lines.RangeOutcome)
	}
	// Every hop inside the range evaluates as the anchor pair does, and a
	// hop that skips the earlier line across the boundary is undetermined.
	var extra []chartrun.Vector
	for _, v := range out.Vectors {
		for _, hop := range [][2]string{{"90.0.1", "90.1.1"}, {"90.0.7", "90.1.0"}, {"90.0.0", "90.1.9"}} {
			nv := v
			nv.Name, nv.Kind, nv.Input = v.Name+"/range-"+hop[0]+"-"+hop[1], "range-hop", retarget(t, v.Input, hop[0], hop[1])
			extra = append(extra, nv)
		}
		nv := v
		nv.Name, nv.Kind, nv.Input = v.Name+"/boundary", "boundary-hop", retarget(t, v.Input, "89.9.0", "90.1.1")
		nv.Expect = chartrun.VectorExpect{Status: "UNKNOWN", ReasonCode: constraintengine.ReasonReleaseBoundaryNotReviewed}
		if rules[v.RuleID].Rule.Range == nil {
			nv.Expect = chartrun.VectorExpect{Status: "UNKNOWN", ReasonCode: "RULE_TRANSITION_NOT_REVIEWED"}
		}
		extra = append(extra, nv)
	}
	if err := chartrun.CheckVectors(out.Entries, append(append([]chartrun.Vector{}, out.Vectors...), extra...), derivedAt); err != nil {
		t.Fatal(err)
	}
}

// retarget sets the chart component's versions of a vector input.
func retarget(t *testing.T, input json.RawMessage, from, to string) json.RawMessage {
	t.Helper()
	var doc map[string]any
	must(t, json.Unmarshal(input, &doc))
	for side, version := range map[string]string{"current": from, "proposed": to} {
		for _, c := range doc[side].(map[string]any)["components"].([]any) {
			if m := c.(map[string]any); m["chart"] != nil {
				m["version"] = version
			}
		}
	}
	raw, err := json.Marshal(doc)
	must(t, err)
	return raw
}

// A later patch whose schema requires one more key keeps the required
// rule anchor-only, with the divergence recorded; the other kinds still
// range.
func TestRangeDivergentPatchStaysAnchorOnly(t *testing.T) {
	root := identicalPatches(t)
	p := filepath.Join(root, "github.com/kedacore/charts/commits", c011, "keda/values.schema.json")
	schema, err := os.ReadFile(p)
	must(t, err)
	edited := bytes.Replace(schema, []byte(`"required": [
    "rootKey"
  ],
  "properties": {`), []byte(`"required": [
    "rootKey", "extraKey"
  ],
  "properties": {"extraKey": {"type": "string"},`), 1)
	if bytes.Equal(edited, schema) {
		t.Fatal("schema not edited")
	}
	must(t, os.WriteFile(p, edited, 0o644))
	out, proof := rangeRun(t, root)
	rules := byID(out)
	rp := rangeProofOf(t, proof, kindRequired)
	if rp.Outcome != "anchor-only: required-values differs at 90.0.0 -> 90.1.1" || rp.Divergence == nil || rp.Divergence.From != "v90.0.0" || rp.Divergence.To != "v90.1.1" || !strings.Contains(rp.Divergence.What, "extraKey") || rp.PairsChecked != 2 {
		t.Fatalf("required proof %+v %+v", rp, rp.Divergence)
	}
	if r := rules[prefix01+kindRequired].Rule; r.Range != nil || strings.Contains(r.NextAction, "90.1.x") || strings.Contains(rules[prefix01+kindRequired].Description, "tagged final releases") {
		t.Fatalf("required rule ranged: %+v", r)
	}
	for _, kind := range []string{kindKube, kindRemoved} {
		if rangeProofOf(t, proof, kind).Outcome != rangeConsecutive || rules[prefix01+kind].Rule.Range == nil {
			t.Fatalf("%s not ranged", kind)
		}
	}
}

// An earlier patch that does not read keeps every kind anchor-only.
func TestRangeUnreadablePatchStaysAnchorOnly(t *testing.T) {
	root := rangeFixture(t, map[string]string{"v90.1.1": c011})
	patchRelease(t, root, c1, c011, "90.1.1", nil)
	out, proof := rangeRun(t, root)
	const want = "anchor-only: release v90.0.1 of line 90.0 does not read completely"
	if proof.Lines.RangeOutcome != want {
		t.Fatalf("outcome %q", proof.Lines.RangeOutcome)
	}
	for _, kind := range rangedKinds {
		if rp := rangeProofOf(t, proof, kind); rp.Outcome != want || rp.PairsChecked != 0 {
			t.Fatalf("%s: %+v", kind, rp)
		}
	}
	for _, e := range out.Entries {
		if e.Rule.Range != nil {
			t.Fatalf("%s ranged", e.Rule.ID)
		}
	}
	// The anchor-only output is the fixture's own: only the proof differs.
	base := fixtureOutput(t)
	if len(base.Entries) != len(out.Entries) {
		t.Fatal("entries differ")
	}
	for i := range base.Entries {
		a, _ := json.Marshal(base.Entries[i])
		b, _ := json.Marshal(out.Entries[i])
		if !bytes.Equal(a, b) {
			t.Fatalf("entry %d differs:\n%s\n%s", i, a, b)
		}
	}
}

// Lines that are not consecutive (a line with no final release between
// them) range over each whole line, without a release boundary.
func TestRangeLineGapTakesWholeLines(t *testing.T) {
	root := rangeFixture(t, map[string]string{"v90.1.0": "", "v90.0.1": c001, "v90.2.1": c021})
	patchRelease(t, root, c0, c001, "90.0.1", nil)
	patchRelease(t, root, c2, c021, "90.2.1", nil)
	out, proof := rangeRun(t, root)
	if pair := out.Manifest.Pairs[0]; pair.FromTag != "v90.0.0" || pair.ToTag != "v90.2.0" {
		t.Fatalf("pair %+v", pair)
	}
	rules := byID(out)
	const prefix = "keda.helm-values.keda.90-0-0-to-90-2-0."
	ranged := 0
	for _, kind := range rangedKinds {
		rp := rangeProofOf(t, proof, kind)
		e, ok := rules[prefix+kind]
		if !ok {
			if rp.Outcome != rangeNoAnchorRule {
				t.Fatalf("%s: %+v", kind, rp)
			}
			continue
		}
		ranged++
		r := e.Rule.Range
		if rp.Outcome != rangeWholeLines || r == nil || r.From != (constraintengine.VersionBound{Gte: "90.0.0", Lt: "90.1.0"}) || r.To != (constraintengine.VersionBound{Gte: "90.2.0", Lt: "90.3.0"}) {
			t.Fatalf("%s: %+v %+v", kind, rp, r)
		}
		for i, want := range []string{constraintengine.BasisUpgradeFromSeries, constraintengine.BasisUpgradeFromSeries, constraintengine.BasisTargetSeries, constraintengine.BasisTargetSeries} {
			if r.Bounds[i].Basis != want {
				t.Fatalf("%s: bounds %+v", kind, r.Bounds)
			}
		}
		// No boundary is known: a hop from outside the earlier line is
		// outside the rule.
		if _, ok := (constraintengine.RuleTransition{From: e.Rule.Subject.From, To: e.Rule.Subject.To, Range: r}).ChangeVersion(); ok {
			t.Fatalf("%s: whole-line range pins a boundary", kind)
		}
	}
	if ranged != 2 {
		t.Fatalf("%d ranged rules, want the required and removed rules", ranged)
	}
}

// A single-release line keeps every rule anchor-only (the unmodified
// fixture's later line 90.1 has one release once v90.0.1 reads).
func TestRangeSingleReleaseLineStaysAnchorOnly(t *testing.T) {
	root := rangeFixture(t, map[string]string{"v90.0.1": c001})
	patchRelease(t, root, c0, c001, "90.0.1", nil)
	out, proof := rangeRun(t, root)
	if proof.Lines.RangeOutcome != "anchor-only: line 90.1 has a single final release" {
		t.Fatalf("outcome %q", proof.Lines.RangeOutcome)
	}
	for _, e := range out.Entries {
		if e.Rule.Range != nil {
			t.Fatalf("%s ranged", e.Rule.ID)
		}
	}
}

// An anchor that is not its line's first release M.m.0 keeps the rules
// anchor-only: a ranged chart rule names its lines by their first release.
func TestRangeAnchorNotLineStart(t *testing.T) {
	lines := &pairLines{
		from: &releaseLine{Major: 2, Minor: 15, Tags: []extract.Tag{{Name: "v2.15.1"}, {Name: "v2.15.2"}}, Versions: []string{"2.15.1", "2.15.2"}},
		to:   &releaseLine{Major: 2, Minor: 16, Tags: []extract.Tag{{Name: "v2.16.0"}, {Name: "v2.16.1"}}, Versions: []string{"2.16.0", "2.16.1"}},
	}
	lines.fromSides, lines.toSides = []*side{{}, {}}, []*side{{}, {}}
	if got := lines.anchorOnly(); got != "anchor-only: the anchor 2.15.1 is not the first release 2.15.0 of line 2.15" {
		t.Fatalf("%q", got)
	}
	lines.from.Problem = "too many"
	if got := lines.anchorOnly(); !strings.HasPrefix(got, "anchor-only: line 2.15: too many") {
		t.Fatalf("%q", got)
	}
}

// noneRanged fails when any entry of the run carries a range.
func noneRanged(t *testing.T, out *chartrun.Output) {
	t.Helper()
	for _, e := range out.Entries {
		if e.Rule.Range != nil {
			t.Fatalf("%s ranged", e.Rule.ID)
		}
	}
}

// A tag outside the tag scheme that names a version of either line keeps
// every rule of the pair anchor-only: the range would cover that release,
// but the proof never read it.
func TestRangeTagOutsideTheSchemeStaysAnchorOnly(t *testing.T) {
	for _, tc := range []struct{ tag, commit, want string }{
		{"keda-90.0.5", c001, "anchor-only: line 90.0 has 1 tag(s) outside the tag scheme naming one of its versions, first keda-90.0.5"},
		{"90.1.3", c011, "anchor-only: line 90.1 has 1 tag(s) outside the tag scheme naming one of its versions, first 90.1.3"},
		{"v90.1.10000", c011, "anchor-only: line 90.1 has 1 tag(s) outside the tag scheme naming one of its versions, first v90.1.10000"},
		{"v90.0.01", c001, "anchor-only: line 90.0 has 1 tag(s) outside the tag scheme naming one of its versions, first v90.0.01"},
	} {
		root := identicalPatches(t)
		raw, err := os.ReadFile(filepath.Join(root, "github.com/kedacore/charts/tags.json"))
		must(t, err)
		tags := map[string]string{}
		must(t, json.Unmarshal(raw, &tags))
		tags[tc.tag] = tc.commit
		raw, err = json.Marshal(tags)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(root, "github.com/kedacore/charts/tags.json"), raw, 0o644))
		out, proof := rangeRun(t, root)
		if proof.Lines.RangeOutcome != tc.want {
			t.Fatalf("%s: outcome %q", tc.tag, proof.Lines.RangeOutcome)
		}
		for _, kind := range rangedKinds {
			if rp := rangeProofOf(t, proof, kind); rp.Outcome != tc.want && rp.Outcome != rangeNoAnchorRule || rp.PairsChecked != 0 {
				t.Fatalf("%s: %s: %+v", tc.tag, kind, rp)
			}
		}
		noneRanged(t, out)
	}
	// A tag in the scheme whose commit is not a commit id is outside too.
	x := &Extractor{target: Target{TagPrefix: "v"}}
	lines := x.releaseLines(extract.ReleaseIndex{Tags: []extract.Tag{{Name: "v2.15.0", Commit: c0}, {Name: "v2.15.1", Commit: "main"}, {Name: "v2.16.0", Commit: c1}}})
	if len(lines) != 2 || len(lines[0].Tags) != 1 || len(lines[0].Outside) != 1 || lines[0].Outside[0] != "v2.15.1" || len(lines[1].Outside) != 0 {
		t.Fatalf("%+v %+v", lines[0], lines[1])
	}
}

// A pre-release tag inside a line is neither a release of the line nor a
// tag outside the scheme: the range is still checked.
func TestRangePreReleaseTagIgnored(t *testing.T) {
	root := rangeFixture(t, map[string]string{"v90.0.1": c001, "v90.1.1": c011, "v90.1.1-rc.1": c011, "v90.0.1+build.2": c001})
	patchRelease(t, root, c0, c001, "90.0.1", nil)
	patchRelease(t, root, c1, c011, "90.1.1", nil)
	out, proof := rangeRun(t, root)
	if proof.Lines.RangeOutcome != rangeChecked {
		t.Fatalf("outcome %q", proof.Lines.RangeOutcome)
	}
	for _, kind := range rangedKinds {
		if rp := rangeProofOf(t, proof, kind); rp.PairsChecked != 4 {
			t.Fatalf("%s: %+v", kind, rp)
		}
	}
	if len(proof.Lines.From.Releases) != 2 || len(proof.Lines.To.Releases) != 2 {
		t.Fatalf("lines %+v", proof.Lines)
	}
	if byID(out)[prefix01+kindKube].Rule.Range == nil {
		t.Fatal("kube rule not ranged")
	}
}

// A line with more release tags than the per-line bound keeps the rules
// anchor-only.
func TestRangeLineOverTheTagBound(t *testing.T) {
	x := &Extractor{target: Target{TagPrefix: "v"}}
	var tags []extract.Tag
	for i := 0; i <= maxTagsPerLine; i++ {
		tags = append(tags, extract.Tag{Name: fmt.Sprintf("v2.15.%d", i), Commit: c0})
	}
	tags = append(tags, extract.Tag{Name: "v2.16.0", Commit: c1}, extract.Tag{Name: "v2.16.1", Commit: c1})
	lines := x.releaseLines(extract.ReleaseIndex{Tags: tags})
	if len(lines) != 2 || len(lines[0].Tags) != maxTagsPerLine+1 || lines[0].Problem == "" || lines[1].Problem != "" {
		t.Fatalf("%+v", lines)
	}
	l := &pairLines{from: lines[0], to: lines[1], fromSides: make([]*side, len(lines[0].Tags)), toSides: []*side{{}, {}}}
	want := fmt.Sprintf("anchor-only: line 2.15: the line has %d release tags, over the bound of %d", maxTagsPerLine+1, maxTagsPerLine)
	if got := l.anchorOnly(); got != want {
		t.Fatalf("%q", got)
	}
	// At the bound the line is fine.
	lines = x.releaseLines(extract.ReleaseIndex{Tags: tags[1:]})
	if lines[0].Problem != "" || len(lines[0].Tags) != maxTagsPerLine {
		t.Fatalf("%+v", lines[0])
	}
}

// An earlier patch already at the later Kubernetes minimum derives no
// kube-version rule against the later anchor: the kind diverges and stays
// anchor-only, the other kinds still range.
func TestRangeKubeEarlierPatchAtTheBound(t *testing.T) {
	root := rangeFixture(t, map[string]string{"v90.0.1": c001, "v90.1.1": c011})
	patchRelease(t, root, c0, c001, "90.0.1", func(dir string) {
		p := filepath.Join(dir, "Chart.yaml")
		chart, err := os.ReadFile(p)
		must(t, err)
		edited := bytes.Replace(chart, []byte(`kubeVersion: ">=1.20.0-0"`), []byte(`kubeVersion: ">= 1.23-0"`), 1)
		if bytes.Equal(edited, chart) {
			t.Fatal("Chart.yaml not edited")
		}
		must(t, os.WriteFile(p, edited, 0o644))
	})
	patchRelease(t, root, c1, c011, "90.1.1", nil)
	out, proof := rangeRun(t, root)
	rp := rangeProofOf(t, proof, kindKube)
	if rp.Outcome != "anchor-only: kube-version differs at 90.0.1 -> 90.1.0" || rp.Divergence == nil || rp.Divergence.From != "v90.0.1" || !strings.Contains(rp.Divergence.What, noRuleSignature+" here") || rp.PairsChecked != 3 {
		t.Fatalf("kube proof %+v %+v", rp, rp.Divergence)
	}
	rules := byID(out)
	if rules[prefix01+kindKube].Rule.Range != nil {
		t.Fatal("kube rule ranged")
	}
	for _, kind := range []string{kindRequired, kindRemoved} {
		if rules[prefix01+kind].Rule.Range == nil {
			t.Fatalf("%s not ranged", kind)
		}
	}
}

// Lines across a new major range over each whole line.
func TestRangeNewMajorTakesWholeLines(t *testing.T) {
	const (
		c910 = "0000000000000000000000000000000000b91000"
		c911 = "0000000000000000000000000000000000b91100"
	)
	root := rangeFixture(t, map[string]string{"v90.1.0": "", "v90.2.0": "", "v90.3.0": "", "v90.0.1": c001, "v91.0.0": c910, "v91.0.1": c911})
	patchRelease(t, root, c0, c001, "90.0.1", nil)
	patchRelease(t, root, c1, c910, "91.0.0", nil)
	patchRelease(t, root, c1, c911, "91.0.1", nil)
	out, _ := rangeRun(t, root)
	var pair *extract.PairRecord
	for i := range out.Manifest.Pairs {
		if p := &out.Manifest.Pairs[i]; p.FromTag == "v90.0.0" && p.ToTag == "v91.0.0" {
			pair = p
		}
	}
	if pair == nil {
		t.Fatalf("no 90.0 -> 91.0 pair in %+v", out.Manifest.Pairs)
	}
	proof := pairProof(t, *pair)
	if proof.Lines.RangeOutcome != rangeChecked {
		t.Fatalf("outcome %q", proof.Lines.RangeOutcome)
	}
	ranged := 0
	for _, e := range out.Entries {
		r := e.Rule.Range
		if r == nil || e.Rule.Subject.From != "90.0.0" {
			continue
		}
		ranged++
		if r.From != (constraintengine.VersionBound{Gte: "90.0.0", Lt: "90.1.0"}) || r.To != (constraintengine.VersionBound{Gte: "91.0.0", Lt: "91.1.0"}) || !constraintengine.ValidChartRangeShape(e.Rule.Operator, *r) {
			t.Fatalf("%s: %+v", e.Rule.ID, r)
		}
		for i, want := range []string{constraintengine.BasisUpgradeFromSeries, constraintengine.BasisUpgradeFromSeries, constraintengine.BasisTargetSeries, constraintengine.BasisTargetSeries} {
			if r.Bounds[i].Basis != want {
				t.Fatalf("%s: bounds %+v", e.Rule.ID, r.Bounds)
			}
		}
	}
	if ranged != len(rangedKinds) {
		t.Fatalf("%d ranged rules across the new major: %+v", ranged, proof.Lines.Ranges)
	}
	for _, rp := range proof.Lines.Ranges {
		if rp.Outcome != rangeWholeLines && rp.Outcome != rangeNoAnchorRule {
			t.Fatalf("%+v", rp)
		}
	}
}
