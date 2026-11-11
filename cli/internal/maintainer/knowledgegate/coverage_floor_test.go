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
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: tree, Head: tree, Now: gateDate})
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
	rels := []string{cncfRulesPath, commRulesPath, coveragereport.PinnedLinesPath, inventoryJSON}
	names, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(ol.TargetsDir), "target-*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("targets: %v", err)
	}
	for _, n := range names {
		rels = append(rels, ol.TargetsDir+"/"+filepath.Base(n))
	}
	// The slice never carries the repository's additions or tag files (see
	// shippedSliceWithAdditions for the real ones).
	for _, rel := range rels {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), raw)
	}
	// The slice is stripped of the repository's additions, so the repository's
	// floors do not describe it: its baseline is made of its own numbers.
	floor, err := floorOf(tr)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(coveragereport.BaselinePath)), floor)
	return tr
}

// gateDate is the fixed gate clock of the shipped-tree tests: after the capture
// date of any addition the repository holds or these tests build.
var gateDate = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// shippedSliceWithAdditions is shippedSlice plus the repository's own
// additions file and tag files, when it has them.
func shippedSliceWithAdditions(t *testing.T) Tree {
	t.Helper()
	tr := shippedSlice(t)
	extra, err := additionFiles()
	if err != nil {
		t.Fatal(err)
	}
	// With the real additions the real baseline applies too.
	for _, rel := range append(extra, coveragereport.BaselinePath) {
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
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: base, Head: head, Now: gateDate})
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

// A data PR that replaces line attestations with newer reviewedAt/derivedAt
// dates (a renewal: the factory stamps the real derive time, after the pin)
// no longer lowers the published decided pairs: the evaluation clock of the
// tree follows its newest attestation, so the renewal is in force at it and
// the coverage floor of the BASE branch holds. This replaces the old
// regression, where the frozen pinned clock made the same re-derive lose
// pairs (dapr 46 -> 41, cert-manager 49 -> 47, istio 49 -> 46).
//
// The bound that keeps this honest is the gate's clock: an attestation dated
// after it is refused, so no attestation makes itself current. The pinned
// snapshot stays byte-identical between base and head, so a data change
// cannot move the pin either.
func TestCoverageFloorAcceptsRederiveWithNewerDatesAtTheTreeClock(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	before := decidedPairs(t, base)
	if before == 0 {
		t.Fatal("the fixture has no decided pairs")
	}
	clock := rederiveLineAttestations(t, head)
	after := decidedPairs(t, head)
	if after < before {
		t.Fatalf("a re-derive lowered the decided pairs by the clock alone (%d -> %d)", before, after)
	}
	_, _, headClock, err := coverageReportOf(head)
	if err != nil {
		t.Fatal(err)
	}
	if !headClock.Equal(clock.Add(24 * time.Hour)) {
		t.Fatalf("the head clock %s is not the newest attestation time %s", headClock, clock.Add(24*time.Hour))
	}
	if c := shippedFloorCheck(base, head); !c.OK {
		t.Fatalf("a renewal at the tree clock is refused: %+v", c)
	}
	// Negative: the same head under a gate whose clock is before its newest
	// attestation is refused with the named reason, in the floor check itself.
	for _, gate := range []time.Time{clock, headClock.Add(-time.Second)} {
		r := &Report{}
		r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: base, Head: head, Now: gate})
		if c := r.Checks[0]; c.OK || !strings.Contains(c.Detail, "after the gate's clock") {
			t.Fatalf("an attestation dated after the gate clock %s is not refused: %+v", gate, c)
		}
	}
	// The gate clock equal to the newest attestation is the boundary that holds.
	r := &Report{}
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: base, Head: head, Now: headClock})
	if c := r.Checks[0]; !c.OK {
		t.Fatalf("the boundary is refused: %+v", c)
	}
	// An attestation far in the future never makes itself current.
	future := shippedSlice(t)
	rederiveLineAttestations(t, future)
	p := readPack(t, future, cncfRulesPath)
	var atts []map[string]any
	if err := json.Unmarshal(p.fields["lineAttestations"], &atts); err != nil {
		t.Fatal(err)
	}
	ev := atts[0]["evidence"].(map[string]any)
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "2027-02-01T00:00:00Z"
	atts[0]["evidence"] = ev
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.write(t, future, cncfRulesPath)
	if c := shippedFloorCheck(base, future); c.OK || !strings.Contains(c.Detail, "after the gate's clock") {
		t.Fatalf("a future-dated attestation is not refused: %+v", c)
	}
	// An unreadable attestation section fails closed.
	if err := attestationsNotFuture(Tree{Root: t.TempDir()}, gateDate); err == nil {
		t.Fatal("a tree without a rule pack passed the attestation time bound")
	}

	// A data change that advances the pinned clock to restore the pairs is not
	// a fix route any more: the pinned snapshot must stay byte-identical.
	linesPath := filepath.Join(head.Root, filepath.FromSlash(coveragereport.PinnedLinesPath))
	raw, err = os.ReadFile(linesPath)
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
	if c := shippedFloorCheck(base, head); c.OK || !strings.Contains(c.Detail, "differs from the base branch") {
		t.Fatalf("a data change of the pinned snapshot is not refused: %+v", c)
	}
}

func withoutAttestations(t *testing.T, tr Tree) {
	t.Helper()
	p := readPack(t, tr, cncfRulesPath)
	delete(p.fields, "lineAttestations")
	p.write(t, tr, cncfRulesPath)
}

// The clock follows the newest attestation, so a head that removes or
// backdates it would roll the clock back and revive attestations that
// expired at the base's clock. The gate refuses a head whose tree clock is
// earlier than the base's, so the tree clock is monotone over admitted
// history; equal and later clocks are accepted.
func TestCoverageFloorRefusesClockRollback(t *testing.T) {
	t.Parallel()
	newer := func() Tree { tr := shippedSlice(t); rederiveLineAttestations(t, tr); return tr }
	base := newer()
	baseClock, err := treeEvalClock(base)
	if err != nil {
		t.Fatal(err)
	}
	refused := func(name string, b, h Tree) {
		t.Helper()
		if c := shippedFloorCheck(b, h); c.OK || !strings.Contains(c.Detail, "earlier than the base branch's") {
			t.Fatalf("%s is not refused for its clock: %+v", name, c)
		}
	}
	// Backdated: attestations ending soon after the head's own (earlier)
	// clock, which would count there and not at the base's clock.
	back := shippedSlice(t)
	backClock, err := treeEvalClock(back)
	if err != nil || !backClock.Before(baseClock) {
		t.Fatalf("the backdated head is not earlier: %v %v", backClock, err)
	}
	p := readPack(t, back, cncfRulesPath)
	var atts []map[string]any
	if err := json.Unmarshal(p.fields["lineAttestations"], &atts); err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		a["evidence"].(map[string]any)["validUntil"] = backClock.Add(time.Hour).Format(time.RFC3339)
	}
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.write(t, back, cncfRulesPath)
	refused("a backdated head", base, back)
	// Removed: the head holds no attestation at all.
	removed := newer()
	withoutAttestations(t, removed)
	refused("a head without its attestations", base, removed)
	// Equal clock.
	if c := shippedFloorCheck(base, newer()); !c.OK {
		t.Fatalf("an equal clock is refused: %+v", c)
	}
	// Later clock: the head renews on top of the base.
	later := newer()
	rederiveLineAttestations(t, later)
	laterClock, err := treeEvalClock(later)
	if err != nil || !laterClock.After(baseClock) {
		t.Fatalf("the later head is not later: %v %v", laterClock, err)
	}
	if c := shippedFloorCheck(base, later); !c.OK {
		t.Fatalf("a later clock is refused: %+v", c)
	}
	// Chain: the lower tree is refused against the base, so the next
	// admission still starts from the base's clock (or higher): the later
	// head is admitted, and then the lower tree is refused against it too.
	refused("the lower tree against the base", base, back)
	if c := shippedFloorCheck(base, later); !c.OK {
		t.Fatalf("the later head is refused: %+v", c)
	}
	refused("the lower tree after the later head", later, back)
	refused("the base after the later head", later, base)
	// Publication: the block is rendered with the clock the gate uses, also
	// for the rolled-back tree (which the gate refuses above).
	for _, tr := range []Tree{base, back, later} {
		want, err := treeEvalClock(tr)
		_, _, got, err2 := coverageReportOf(tr)
		if err != nil || err2 != nil || !got.Equal(want) {
			t.Fatalf("render clock %v, gate clock %v (%v %v)", got, want, err2, err)
		}
	}
}

// The gate's time bound never falls back to the host clock: a zero clock
// refuses, for the attestations and for the additions. A community-pack
// attestation dated after the gate's clock is refused like a CNCF one and
// moves the tree's clock.
func TestAttestationBoundFailsClosedAndCoversCommunity(t *testing.T) {
	t.Parallel()
	tr := shippedSlice(t)
	if err := attestationsNotFuture(tr, time.Time{}); err == nil || !strings.Contains(err.Error(), "no clock") {
		t.Fatalf("a zero gate clock was accepted: %v", err)
	}
	if err := additionsNotFuture(tr, time.Time{}); err == nil || !strings.Contains(err.Error(), "no clock") {
		t.Fatalf("a zero gate clock was accepted for the additions: %v", err)
	}
	r := &Report{}
	r.coverageFloorCheck(Options{Layout: DefaultLayout(), Base: tr, Head: tr})
	if c := r.Checks[0]; c.OK || !strings.Contains(c.Detail, "no clock") {
		t.Fatalf("the floor check ran without a gate clock: %+v", c)
	}
	before, err := treeEvalClock(tr)
	if err != nil {
		t.Fatal(err)
	}
	cn := readPack(t, tr, cncfRulesPath)
	var atts []map[string]any
	if err := json.Unmarshal(cn.fields["lineAttestations"], &atts); err != nil || len(atts) == 0 {
		t.Fatalf("no attestation to copy: %v", err)
	}
	ev := atts[0]["evidence"].(map[string]any)
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "2027-02-01T00:00:00Z"
	raw, err := json.Marshal(atts[:1])
	if err != nil {
		t.Fatal(err)
	}
	cm := readPack(t, tr, commRulesPath)
	cm.fields["lineAttestations"] = raw
	cm.write(t, tr, commRulesPath)
	if err := attestationsNotFuture(tr, gateDate); err == nil || !strings.Contains(err.Error(), "after the gate's clock") {
		t.Fatalf("a future community attestation was accepted: %v", err)
	}
	after, err := treeEvalClock(tr)
	if err != nil || !after.After(before) {
		t.Fatalf("a community attestation did not move the clock: %v -> %v %v", before, after, err)
	}
}

func TestTreeEvalClockIsTheReportClock(t *testing.T) {
	t.Parallel()
	for _, tr := range []Tree{shippedSlice(t), shippedSliceWithAdditions(t)} {
		got, err := treeEvalClock(tr)
		_, _, want, err2 := coverageReportOf(tr)
		if err != nil || err2 != nil || !got.Equal(want) {
			t.Fatalf("%v %v %v %v", got, want, err, err2)
		}
	}
}
