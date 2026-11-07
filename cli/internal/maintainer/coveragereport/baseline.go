// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// BaselinePath is the repository path of the committed coverage floor.
const BaselinePath = "cli/internal/maintainer/coveragereport/testdata/readme-baseline.json"

// Baseline is the committed floor of the published README numbers: the
// decided-pair count and the covered-project count may not fall below it
// unless a named withdrawal accounts for the drop. The floor is moved only
// by editing this file in the pull request that changes the numbers.
type Baseline struct {
	DecidedPairs int          `json:"decidedPairs"`
	CRDProjects  int          `json:"crdPublishedProjects"`
	Withdrawals  []Withdrawal `json:"withdrawals"`
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
	for _, w := range b.Withdrawals {
		if w.Project == "" || w.Reason == "" || w.DecidedPairs < 0 || w.CRDProjects < 0 {
			return Baseline{}, fmt.Errorf("%w: baseline: a withdrawal needs a project, a reason and non-negative counts", ErrInvalid)
		}
	}
	return b, nil
}

// CheckBaseline fails when the decided-pair or covered-project count is below
// the floor minus the counts of the named withdrawals.
func CheckBaseline(b Baseline, decidedPairs, crdProjects int) error {
	allowPairs, allowCRD := 0, 0
	for _, w := range b.Withdrawals {
		allowPairs += w.DecidedPairs
		allowCRD += w.CRDProjects
	}
	if decidedPairs < b.DecidedPairs-allowPairs {
		return fmt.Errorf("decided pairs fell to %d, below the committed baseline %d (named withdrawals allow %d); restore the coverage or add a named withdrawal", decidedPairs, b.DecidedPairs, allowPairs)
	}
	if crdProjects < b.CRDProjects-allowCRD {
		return fmt.Errorf("projects with a published CRD rule or attestation fell to %d, below the committed baseline %d (named withdrawals allow %d); restore the coverage or add a named withdrawal", crdProjects, b.CRDProjects, allowCRD)
	}
	return nil
}
