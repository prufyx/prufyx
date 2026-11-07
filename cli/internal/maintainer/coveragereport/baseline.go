// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// BaselinePath is the repository path of the committed coverage floor.
const BaselinePath = "cli/internal/maintainer/coveragereport/testdata/readme-baseline.json"

// Baseline is the committed floor of the published README numbers: the
// decided-pair count and the covered-project count may not fall below it
// unless a named withdrawal accounts for the drop. The floor is moved only
// by editing this file in the pull request that changes the numbers.
type Baseline struct {
	DecidedPairs int `json:"decidedPairs"`
	CRDProjects  int `json:"crdPublishedProjects"`
	// ProjectPairs is the floor of decided pairs (A+B) per project, for the
	// projects that have any.
	ProjectPairs map[string]int `json:"projectPairs"`
	Withdrawals  []Withdrawal   `json:"withdrawals"`
}

// Withdrawal names one deliberate removal of coverage and what it costs.
type Withdrawal struct {
	Project      string `json:"project"`
	DecidedPairs int    `json:"decidedPairs"`
	CRDProjects  int    `json:"crdPublishedProjects"`
	Reason       string `json:"reason"`
}

// ParseBaseline reads a baseline strictly: unknown fields, negative counts
// and withdrawals without a project or a reason are refused.
func ParseBaseline(raw []byte) (Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Baseline{}, fmt.Errorf("%w: baseline: %v", ErrInvalid, err)
	}
	if b.DecidedPairs < 0 || b.CRDProjects < 0 {
		return Baseline{}, fmt.Errorf("%w: baseline: negative count", ErrInvalid)
	}
	for p, n := range b.ProjectPairs {
		if p == "" || n <= 0 {
			return Baseline{}, fmt.Errorf("%w: baseline: a project floor needs a project and a positive count", ErrInvalid)
		}
	}
	seen := map[string]bool{}
	for _, w := range b.Withdrawals {
		if seen[w.Project] {
			return Baseline{}, fmt.Errorf("%w: baseline: withdrawal for %q is listed twice", ErrInvalid, w.Project)
		}
		seen[w.Project] = true
		if w.Project == "" || w.Reason == "" || w.DecidedPairs < 0 || w.CRDProjects < 0 {
			return Baseline{}, fmt.Errorf("%w: baseline: a withdrawal needs a project, a reason and non-negative counts", ErrInvalid)
		}
	}
	return b, nil
}

// CheckBaseline fails when the decided-pair or covered-project count, or the
// decided pairs of one project, are below the floor minus the counts of the
// named withdrawals (for a project: of its own withdrawal).
func CheckBaseline(b Baseline, decidedPairs, crdProjects int, projectPairs map[string]int) error {
	allowPairs, allowCRD := 0, 0
	own := map[string]int{}
	for _, w := range b.Withdrawals {
		allowPairs += w.DecidedPairs
		allowCRD += w.CRDProjects
		own[w.Project] = w.DecidedPairs
	}
	if decidedPairs < b.DecidedPairs-allowPairs {
		return fmt.Errorf("decided pairs fell to %d, below the committed baseline %d (named withdrawals allow %d); restore the coverage or add a named withdrawal", decidedPairs, b.DecidedPairs, allowPairs)
	}
	if crdProjects < b.CRDProjects-allowCRD {
		return fmt.Errorf("projects with a published CRD rule or attestation fell to %d, below the committed baseline %d (named withdrawals allow %d); restore the coverage or add a named withdrawal", crdProjects, b.CRDProjects, allowCRD)
	}
	for _, p := range baselineKeys(b.ProjectPairs) {
		if projectPairs[p] < b.ProjectPairs[p]-own[p] {
			return fmt.Errorf("%s: decided pairs fell to %d, below the committed baseline %d (its withdrawal allows %d)", p, projectPairs[p], b.ProjectPairs[p], own[p])
		}
	}
	return nil
}

func baselineKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckBaselineMove compares the baseline of a pull request with the one on
// main. A floor may not be lowered, a project floor may not disappear, and a
// withdrawal of main may not grow. The only way to let a number fall is a new
// withdrawal, named with its project and reason, which a reviewer sees in the
// diff. A withdrawal that main has and the pull request drops is folded into
// the floors: the floors must then not be lower, so the allowance is gone.
func CheckBaselineMove(main, pr Baseline) error {
	if pr.DecidedPairs < main.DecidedPairs {
		return fmt.Errorf("decidedPairs floor lowered from %d to %d", main.DecidedPairs, pr.DecidedPairs)
	}
	if pr.CRDProjects < main.CRDProjects {
		return fmt.Errorf("crdPublishedProjects floor lowered from %d to %d", main.CRDProjects, pr.CRDProjects)
	}
	for _, p := range baselineKeys(main.ProjectPairs) {
		if pr.ProjectPairs[p] < main.ProjectPairs[p] {
			return fmt.Errorf("project floor for %s lowered from %d to %d or removed", p, main.ProjectPairs[p], pr.ProjectPairs[p])
		}
	}
	old := map[string]Withdrawal{}
	for _, w := range main.Withdrawals {
		old[w.Project] = w
	}
	for _, w := range pr.Withdrawals {
		if w.DecidedPairs == 0 && w.CRDProjects == 0 {
			return fmt.Errorf("withdrawal for %s drops nothing", w.Project)
		}
		if o, ok := old[w.Project]; ok && (w.DecidedPairs > o.DecidedPairs || w.CRDProjects > o.CRDProjects) {
			return fmt.Errorf("withdrawal for %s grew; add a new named withdrawal instead", w.Project)
		}
	}
	return nil
}
