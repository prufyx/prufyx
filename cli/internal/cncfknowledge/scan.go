// SPDX-License-Identifier: AGPL-3.0-only

package cncfknowledge

import (
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// Layouts of a CNCF knowledge store, named by their database profile.
const (
	LayoutSingleTarget = "cncf"
	LayoutPerProject   = "cncf-projects"
)

// ScanSelection is the current revision of a verified local CNCF store,
// opened once for a whole scan with the same verification every
// `check ... --knowledge-db` run uses: TUF metadata re-verified at the
// verifier's clock, rollback and clock floors, the selection's trust
// receipt, the layout read from the store, and, for a per-project store,
// every requested project target re-verified against the index.
type ScanSelection struct {
	Layout             string
	TargetPath         string
	Revision           string
	BundleDigest       string
	TrustReceiptDigest string
	Purpose            string
	ImportedVerifiedAt string
	// EvaluatedAt is the verifier's clock, truncated to the second. A scan
	// over this selection is evaluated at this instant and no other.
	EvaluatedAt time.Time
	// Projects are the opened projects in slug order.
	Projects []ScanProject
}

// ScanProject is one opened project. Target is nil for a single-target
// store; in a per-project store its status is "present" or
// "absent_from_index" (no rule can apply then).
type ScanProject struct {
	Project string
	Target  *ProjectTargetBinding
	Bundle  cncfcheck.ExternalBundle
}

// OpenScan opens the current selection of the store at storeRoot for the
// named catalog projects. Any verification failure is returned; there is no
// fallback to the embedded knowledge.
func OpenScan(storeRoot string, projects []string) (ScanSelection, error) {
	if storeRoot == "" || len(projects) == 0 {
		return ScanSelection{}, ErrInvalid
	}
	projects = append([]string(nil), projects...)
	sort.Strings(projects)
	for index := 1; index < len(projects); index++ {
		if projects[index] == projects[index-1] {
			return ScanSelection{}, ErrInvalid
		}
	}
	selected, err := knowledge.OpenSelectedCNCF(knowledge.SelectionRequest{StoreRoot: storeRoot}, projects)
	if err != nil {
		return ScanSelection{}, err
	}
	if !selected.Valid() || selected.Mode() != knowledge.SelectionCurrent {
		return ScanSelection{}, ErrIntegrity
	}
	receipt := selected.TrustReceipt()
	result := ScanSelection{
		Layout: LayoutSingleTarget, TargetPath: receipt.TargetPath, Revision: selected.Revision(),
		BundleDigest: selected.BundleDigest(), TrustReceiptDigest: selected.TrustReceiptDigest(),
		ImportedVerifiedAt: receipt.VerifiedAt, EvaluatedAt: selected.VerifiedAt().UTC().Truncate(time.Second),
	}
	if selected.PerProject() {
		result.Layout = LayoutPerProject
	}
	for _, project := range projects {
		bundle, admission, target, err := selectedBundle(project, selected)
		if err != nil {
			return ScanSelection{}, err
		}
		if !admissionMatchesSelection(admission, selected) || (target == nil) == selected.PerProject() {
			return ScanSelection{}, ErrIntegrity
		}
		result.Purpose = admission.Purpose
		result.Projects = append(result.Projects, ScanProject{Project: project, Target: target, Bundle: bundle})
	}
	return result, nil
}
