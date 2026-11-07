// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if c.OK || !(strings.Contains(c.Detail, project) || strings.Contains(c.Detail, "decided pairs fell")) {
		t.Fatalf("a dropped project passes: %+v", c)
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
