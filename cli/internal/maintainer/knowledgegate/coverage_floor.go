// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// CheckCoverageFloor is the name of the check that holds the published
// coverage numbers of the head at or above the floor of the base branch.
const CheckCoverageFloor = "coverage-floor"

// coverageFloorCheck compares the decided pairs, the covered projects and the
// decided pairs of every project that the head's data yields with the
// baseline file of the BASE tree. The floor and the withdrawals that excuse a
// drop are those of the base: a change cannot lower the floor or add its own
// withdrawal and have it count. The baseline file of the head must parse and
// may not move below the base's (CheckBaselineMove). A missing or unreadable
// baseline on the base, an unreadable head baseline or head data that cannot
// be evaluated fails the check; nothing is skipped.
//
// The floors count decided pairs, not which pairs: new coverage in a project
// can offset expired coverage there (stated residual, not checked per pair).
//
// Floors and withdrawals are ratchet-only: a floor can rise, a withdrawal
// can be added by a change that the base then carries, and a deliberate
// re-baseline path does not exist yet (follow-up).
//
// The check belongs to the README coverage block: a layout without generated
// blocks (the synthetic layouts of the tests) publishes no numbers and has
// nothing to compare. The shipped layout always has them.
func (r *Report) coverageFloorCheck(opts Options) {
	if len(opts.Layout.GeneratedBlocks) == 0 {
		// Nothing is published by this layout; but a base that carries a
		// baseline file expects the floor to be held, so it is not skipped.
		if raw, err := opts.Base.ReadOptional(coveragereport.BaselinePath, MaxFileBytes); err != nil || len(raw) > 0 {
			r.add(CheckCoverageFloor, false, "the layout has no generated blocks but the base branch carries a coverage baseline")
		}
		return
	}
	// An invalid addition speaks first: it is checked before the numbers are
	// evaluated with it (coverageFloor runs the integrity checks before the
	// floor).
	if err := additionsNotFuture(opts.Head, opts.Now); err != nil {
		r.add(CheckCoverageFloor, false, "%s", logSafe(err.Error()))
		return
	}
	if err := attestationsNotFuture(opts.Head, opts.Now); err != nil {
		r.add(CheckCoverageFloor, false, "%s", logSafe(err.Error()))
		return
	}
	if err := coverageFloor(opts.Base, opts.Head); err != nil {
		r.add(CheckCoverageFloor, false, "%s", logSafe(err.Error()))
		return
	}
	r.add(CheckCoverageFloor, true, "the published coverage numbers of the change are not below the baseline of the base branch")
}

func coverageFloor(base, head Tree) error {
	// What the numbers are measured against is held first: the pinned
	// snapshot byte-identical, the additions file append-only and
	// regenerated from its tag files.
	if err := linesIntegrity(base, head); err != nil {
		return err
	}
	// The evaluation clock follows the newest attestation, so removing or
	// backdating the newest one would roll the head's clock back and revive
	// attestations that have expired at the later clock. The tree clock must
	// therefore be monotone over admitted history: a head whose clock is
	// earlier than the base's is refused (the same function for both, and the
	// one the published block is rendered with), so no admitted tree carries
	// a lower clock for the next admission to start from.
	baseClock, err := treeEvalClock(base)
	if err != nil {
		return fmt.Errorf("cannot compute the evaluation clock of the base branch: %w", err)
	}
	headClock, err := treeEvalClock(head)
	if err != nil {
		return fmt.Errorf("cannot compute the evaluation clock of the change: %w", err)
	}
	if headClock.Before(baseClock) {
		return fmt.Errorf("the evaluation clock of the change %s is earlier than the base branch's %s: its newest line attestation was removed or backdated", headClock.UTC().Format(time.RFC3339), baseClock.UTC().Format(time.RFC3339))
	}
	baseRaw, err := base.Read(coveragereport.BaselinePath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the base branch has no readable coverage baseline: %w", err)
	}
	floor, err := coveragereport.ParseBaseline(baseRaw)
	if err != nil {
		return fmt.Errorf("the base coverage baseline is invalid: %w", err)
	}
	headRaw, err := head.Read(coveragereport.BaselinePath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the change has no readable coverage baseline: %w", err)
	}
	proposed, err := coveragereport.ParseBaseline(headRaw)
	if err != nil {
		return fmt.Errorf("the change's coverage baseline is invalid: %w", err)
	}
	if err := coveragereport.CheckBaselineMove(floor, proposed); err != nil {
		return err
	}
	report, _, _, err := coverageReportOf(head)
	if err != nil {
		return fmt.Errorf("cannot compute the published coverage numbers: %w", err)
	}
	pp := map[string]int{}
	for _, p := range report.Projects {
		if p.A+p.B > 0 {
			pp[p.Project] = p.A + p.B
		}
	}
	if err := coveragereport.CheckBaseline(floor, report.Fleet.A+report.Fleet.B, report.CRDPublishedProjects, pp); err != nil {
		return err
	}
	return nil
}
