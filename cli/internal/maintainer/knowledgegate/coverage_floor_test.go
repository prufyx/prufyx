// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

func floorPath(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(coveragereport.BaselinePath))
}

func readFloor(t *testing.T, tr Tree) coveragereport.Baseline {
	t.Helper()
	raw, err := os.ReadFile(floorPath(tr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := coveragereport.ParseBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFloor(t *testing.T, tr Tree, b coveragereport.Baseline) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, floorPath(tr), raw)
}

// floorTrees returns identical trees whose baseline is seeded and whose first
// project (in order) with decided pairs is returned.
func floorTrees(t *testing.T) (Tree, Tree, string) {
	t.Helper()
	base, head := trees(t)
	seedBaseline(t, Options{Base: base, Head: head})
	b := readFloor(t, base)
	var project string
	for p := range b.ProjectPairs {
		if project == "" || p < project {
			project = p
		}
	}
	if project == "" {
		t.Fatal("the fixture has no project with decided pairs")
	}
	return base, head, project
}

func floorCheck(t *testing.T, r *Report) Check {
	t.Helper()
	c, ok := check(r, CheckCoverageFloor)
	if !ok {
		t.Fatal("the gate did not run the coverage floor check")
	}
	return c
}

func TestCoverageFloorHolds(t *testing.T) {
	t.Parallel()
	base, head, _ := floorTrees(t)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); !c.OK {
		t.Fatalf("unchanged numbers fail: %s", c.Detail)
	}
}

// A re-derive that drops the decided pairs of one project fails: the floor is
// the base's, the head's own file is not consulted for the drop.
func TestCoverageFloorRefusesDroppedProject(t *testing.T) {
	t.Parallel()
	base, head, project := floorTrees(t)
	// The base promises one more pair than the head's data yields.
	b := readFloor(t, base)
	b.ProjectPairs[project]++
	b.DecidedPairs++
	writeFloor(t, base, b)
	writeFloor(t, head, b)
	c := floorCheck(t, runGate(t, Options{Base: base, Head: head}))
	if c.OK || !strings.Contains(c.Detail, "decided pairs fell to") || strings.Contains(c.Detail, project+":") {
		t.Fatalf("a fleet-wide drop is not refused with the fleet message: %+v", c)
	}
}

// The fleet total holds but one project's floor alone is raised: the
// per-project path trips, with its own message.
func TestCoverageFloorRefusesOneProjectAlone(t *testing.T) {
	t.Parallel()
	base, head, project := floorTrees(t)
	b := readFloor(t, base)
	b.ProjectPairs[project]++
	writeFloor(t, base, b)
	writeFloor(t, head, b)
	c := floorCheck(t, runGate(t, Options{Base: base, Head: head}))
	if c.OK || !strings.Contains(c.Detail, project+": decided pairs fell to") {
		t.Fatalf("a single dropped project is not refused per project: %+v", c)
	}
}

// A layout without generated blocks does not skip the floor when the base
// carries a baseline.
func TestCoverageFloorNoBlocksWithBaselineFails(t *testing.T) {
	t.Parallel()
	base, head, _ := floorTrees(t)
	r := &Report{}
	r.coverageFloorCheck(Options{Base: base, Head: head})
	if len(r.Checks) != 1 || r.Checks[0].OK {
		t.Fatalf("%+v", r.Checks)
	}
	empty := &Report{}
	empty.coverageFloorCheck(Options{Base: Tree{Root: t.TempDir()}, Head: head})
	if len(empty.Checks) != 0 {
		t.Fatalf("a base without a baseline and a layout without blocks: %+v", empty.Checks)
	}
}

// A change that lowers the floor in its own baseline file fails, whatever the
// data yields.
func TestCoverageFloorRefusesLoweredFloor(t *testing.T) {
	t.Parallel()
	base, head, project := floorTrees(t)
	b := readFloor(t, base)
	b.ProjectPairs[project]++
	b.DecidedPairs++
	writeFloor(t, base, b)
	low := readFloor(t, base)
	low.ProjectPairs[project]--
	low.DecidedPairs--
	writeFloor(t, head, low)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); c.OK {
		t.Fatalf("a lowered floor passes: %+v", c)
	}
}

// A change that lowers the floor and names its own withdrawal fails: a
// withdrawal excuses a drop only when the base already has it.
func TestCoverageFloorRefusesSelfApprovedWithdrawal(t *testing.T) {
	t.Parallel()
	base, head, project := floorTrees(t)
	b := readFloor(t, base)
	b.ProjectPairs[project]++
	b.DecidedPairs++
	writeFloor(t, base, b)
	own := b
	own.Withdrawals = []coveragereport.Withdrawal{{Project: project, DecidedPairs: 1, Reason: "dropped in this change"}}
	writeFloor(t, head, own)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); c.OK {
		t.Fatalf("a self-approved withdrawal passes: %+v", c)
	}
	// The same head with floors lowered as well fails too.
	low := own
	low.ProjectPairs = map[string]int{}
	for k, v := range b.ProjectPairs {
		low.ProjectPairs[k] = v
	}
	low.ProjectPairs[project]--
	low.DecidedPairs--
	writeFloor(t, head, low)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); c.OK {
		t.Fatalf("a lowered floor with its own withdrawal passes: %+v", c)
	}
}

// A withdrawal that the base already carries excuses the drop it names.
func TestCoverageFloorAcceptsBaseWithdrawal(t *testing.T) {
	t.Parallel()
	base, head, project := floorTrees(t)
	b := readFloor(t, base)
	b.ProjectPairs[project]++
	b.DecidedPairs++
	b.Withdrawals = []coveragereport.Withdrawal{{Project: project, DecidedPairs: 1, Reason: "reviewed on the base branch"}}
	writeFloor(t, base, b)
	writeFloor(t, head, b)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); !c.OK {
		t.Fatalf("a base withdrawal is refused: %+v", c)
	}
	// It excuses one pair only.
	b.ProjectPairs[project]++
	b.DecidedPairs++
	writeFloor(t, base, b)
	writeFloor(t, head, b)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); c.OK {
		t.Fatalf("a withdrawal excuses more than it names: %+v", c)
	}
}

func TestCoverageFloorRefusesDroppedProjectCount(t *testing.T) {
	t.Parallel()
	base, head, _ := floorTrees(t)
	b := readFloor(t, base)
	b.CRDProjects++
	writeFloor(t, base, b)
	writeFloor(t, head, b)
	if c := floorCheck(t, runGate(t, Options{Base: base, Head: head})); c.OK {
		t.Fatalf("fewer covered projects pass: %+v", c)
	}
}

// Missing or unreadable baselines fail closed, on either side.
func TestCoverageFloorFailsClosed(t *testing.T) {
	t.Parallel()
	run := func(base, head Tree) Check {
		t.Helper()
		r, err := Verify(context.Background(), Options{Layout: DefaultLayout(), Base: base, Head: head, Now: gateNow, Citations: passingCitations{}})
		if err != nil {
			t.Fatal(err)
		}
		return floorCheck(t, r)
	}
	t.Run("base has none", func(t *testing.T) {
		t.Parallel()
		base, head, _ := floorTrees(t)
		if err := os.Remove(floorPath(base)); err != nil {
			t.Fatal(err)
		}
		if c := run(base, head); c.OK {
			t.Fatalf("passes: %+v", c)
		}
	})
	t.Run("head has none", func(t *testing.T) {
		t.Parallel()
		base, head, _ := floorTrees(t)
		if err := os.Remove(floorPath(head)); err != nil {
			t.Fatal(err)
		}
		if c := run(base, head); c.OK {
			t.Fatalf("passes: %+v", c)
		}
	})
	t.Run("base invalid", func(t *testing.T) {
		t.Parallel()
		base, head, _ := floorTrees(t)
		writeFile(t, floorPath(base), []byte(`{"decidedPairs":1,"x":1}`))
		if c := run(base, head); c.OK {
			t.Fatalf("passes: %+v", c)
		}
	})
	t.Run("head invalid", func(t *testing.T) {
		t.Parallel()
		base, head, _ := floorTrees(t)
		writeFile(t, floorPath(head), []byte(`not json`))
		if c := run(base, head); c.OK {
			t.Fatalf("passes: %+v", c)
		}
	})
	t.Run("head data unreadable", func(t *testing.T) {
		t.Parallel()
		base, head, _ := floorTrees(t)
		if err := os.Remove(filepath.Join(head.Root, filepath.FromSlash(cncfRulesPath))); err != nil {
			t.Fatal(err)
		}
		if c := run(base, head); c.OK {
			t.Fatalf("passes: %+v", c)
		}
	})
}

// The baseline file is not a mechanical path: a change to it is never
// re-derived or admitted as an automatic change.
func TestBaselinePathIsNotMechanical(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	for _, g := range layout.GeneratedBlocks {
		if g.Path == coveragereport.BaselinePath {
			t.Fatal("the baseline file is a generated block")
		}
	}
	base, head, project := floorTrees(t)
	b := readFloor(t, head)
	b.ProjectPairs[project] += 5
	b.DecidedPairs += 5
	writeFloor(t, head, b)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	if r.AutoMerge.Eligible {
		t.Fatal("a change to the baseline file is eligible for automatic merging")
	}
}

// The shipped data satisfies the committed baseline, with the real layout:
// base and head are the repository itself.
func TestCoverageFloorShippedData(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	tree := Tree{Root: root}
	if len(DefaultLayout().GeneratedBlocks) == 0 {
		t.Fatal("the shipped layout has no generated blocks, so the floor would be skipped")
	}
	if err := coverageFloor(tree, tree); err != nil {
		t.Fatal(err)
	}
	report, _, _, err := coverageReportOf(tree)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decided pairs %d, CRD projects %d", report.Fleet.A+report.Fleet.B, report.CRDPublishedProjects)
	r := &Report{}
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: tree, Head: tree})
	if len(r.Checks) != 1 || !r.Checks[0].OK {
		t.Fatalf("%+v", r.Checks)
	}
}

// shippedSlice copies, into a new tree, the shipped files the published
// coverage numbers are computed from. The synthetic fixture packs carry no
// line attestations, so the re-derive is played on the shipped data.
func shippedSlice(t *testing.T) Tree {
	t.Helper()
	tr := Tree{Root: t.TempDir()}
	ol := DefaultLayout().Onboarding
	rels := []string{cncfRulesPath, commRulesPath, coveragereport.PinnedLinesPath, inventoryJSON, coveragereport.BaselinePath}
	names, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(ol.TargetsDir), "target-*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("targets: %v", err)
	}
	for _, n := range names {
		rels = append(rels, ol.TargetsDir+"/"+filepath.Base(n))
	}
	for _, rel := range rels {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), raw)
	}
	return tr
}

func shippedFloorCheck(base, head Tree) Check {
	r := &Report{}
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: base, Head: head})
	return r.Checks[0]
}

// rederiveLineAttestations plays a data-only re-derive: every line
// attestation of the CNCF pack is replaced by one whose derivedAt and
// reviewedAt are newer than the evaluation clock of the README block (noon of
// pinnedOn, or of capturedOn when there is no pin). The README clock does not
// move with the data, so an attestation reviewed after it is not yet in force
// and its pair stops being decided. It returns the clock the block is
// evaluated on.
func rederiveLineAttestations(t *testing.T, tr Tree) time.Time {
	t.Helper()
	_, _, clock, err := coverageReportOf(tr)
	if err != nil {
		t.Fatal(err)
	}
	newer := clock.Add(24 * time.Hour).Format(time.RFC3339)
	until := clock.Add(24 * time.Hour * 89).Format(time.RFC3339)
	p := readPack(t, tr, cncfRulesPath)
	var atts []map[string]any
	if err := json.Unmarshal(p.fields["lineAttestations"], &atts); err != nil {
		t.Fatal(err)
	}
	if len(atts) == 0 {
		t.Fatal("the fixture pack has no line attestations")
	}
	for _, a := range atts {
		ev, ok := a["evidence"].(map[string]any)
		if !ok {
			t.Fatal("a line attestation has no evidence")
		}
		ev["derivedAt"] = newer
		ev["reviewedAt"] = newer
		ev["validUntil"] = until
	}
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.write(t, tr, cncfRulesPath)
	return clock
}

func decidedPairs(t *testing.T, tr Tree) int {
	t.Helper()
	report, _, _, err := coverageReportOf(tr)
	if err != nil {
		t.Fatal(err)
	}
	return report.Fleet.A + report.Fleet.B
}

// Regression for the dapr incident class (decided pairs 46 -> 41 after a
// re-derive): a data PR that replaces line attestations with newer
// reviewedAt/derivedAt dates while the pinned README clock stays put lowers
// the published decided pairs, and the coverage floor of the BASE branch
// refuses that PR with the decided-pairs message. The floor, not the
// generator, is the protection: the generator is deterministic and would
// publish the lower number.
//
// The fix route for a re-derive is a deliberate pinnedOn bump in the same PR
// (lines file), which moves the clock past the new reviewedAt dates so the
// pairs stay decided; see the second half of the test. The floor is never
// edited to excuse a drop.
func TestCoverageFloorRefusesRederiveWithNewerDatesUnderOldClock(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	before := decidedPairs(t, base)
	if before == 0 {
		t.Fatal("the fixture has no decided pairs")
	}
	clock := rederiveLineAttestations(t, head)
	after := decidedPairs(t, head)
	if after >= before {
		t.Fatalf("the re-derive under the old clock did not lower decided pairs (%d -> %d): the fixture no longer reproduces the incident", before, after)
	}
	c := shippedFloorCheck(base, head)
	if c.OK || !strings.Contains(c.Detail, "decided pairs fell to") {
		t.Fatalf("a re-derive that lowers decided pairs %d -> %d is not refused by the floor: %+v", before, after, c)
	}

	// Fix route: the same data with the pinned clock advanced in the same
	// change keeps the pairs decided, and the floor holds.
	linesPath := filepath.Join(head.Root, filepath.FromSlash(coveragereport.PinnedLinesPath))
	raw, err := os.ReadFile(linesPath)
	if err != nil {
		t.Fatal(err)
	}
	var lines map[string]any
	if err := json.Unmarshal(raw, &lines); err != nil {
		t.Fatal(err)
	}
	lines["pinnedOn"] = clock.Add(48 * time.Hour).Format("2006-01-02")
	raw, err = json.Marshal(lines)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, linesPath, raw)
	if got := decidedPairs(t, head); got < before {
		t.Fatalf("advancing pinnedOn did not restore decided pairs (%d, floor %d)", got, before)
	}
	if c := shippedFloorCheck(base, head); !c.OK {
		t.Fatalf("the floor refuses a re-derive with a deliberate pinnedOn bump: %s", c.Detail)
	}
}
