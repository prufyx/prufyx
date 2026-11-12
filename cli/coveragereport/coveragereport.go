// Package coveragereport is a stable API for computing coverage pairs from a
// rule pack and a lines file. Every consecutive pair of release lines of a
// project is classified A (attested), B (bounded by a rule), S (spot: only an
// exact-pair rule) or G (gap).
//
// It is a thin wrapper: the types are aliases and Compute delegates to the
// implementation the maintainer command uses, so both always produce the same
// report. The field set follows the underlying types. Report documents use
// the schema SchemaReport; lines files use
// LinesSchema.
package coveragereport

import (
	"time"

	impl "github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// Input is everything a report depends on: the rule pack, the lines file,
// optional additions, the evaluation time and the window.
type Input = impl.Input

// Report is the computed coverage report.
type Report = impl.Report

// Project is one project's row of a report.
type Project = impl.Project

// Pair is one consecutive pair of lines and its status.
type Pair = impl.Pair

// Totals are the report's counts.
type Totals = impl.Totals

// Schema identifiers of the documents.
const (
	SchemaReport = impl.Schema
	LinesSchema  = impl.LinesSchema
)

// Pair statuses.
const (
	StatusA = impl.StatusA
	StatusB = impl.StatusB
	StatusS = impl.StatusS
	StatusG = impl.StatusG
)

// Compute computes the report for the input. Unknown or invalid input is
// rejected with an error.
func Compute(in Input) (Report, error) { return impl.Compute(in) }

// CRDProjectComponents maps every project with a reviewed
// crd.custom_resource_versions target to the component of that target. The
// maintainer command passes it as Input.CRDTargetComponents; without it the
// attestations of a target component are not attributed to their project.
func CRDProjectComponents() map[string]string { return impl.CRDProjectComponents() }

// CRDProjectCount is the number of projects in CRDProjectComponents. The
// maintainer command passes it as Input.CRDVersionProjects.
func CRDProjectCount() int { return impl.CRDProjectCount() }

// DefaultInput returns the Input the maintainer command builds for the ALL
// window: the rule pack, the community pack (nil for none), the lines file and
// the evaluation time, with the window set to ALL, the embedded declared-unknown
// file, and the CRD target fields filled. Callers that want the command's
// numbers should start from it instead of filling Input by hand.
func DefaultInput(pack, communityPack, lines []byte, now time.Time) Input {
	return Input{
		Pack: pack, CommunityPack: communityPack, Lines: lines, Now: now, All: true,
		CRDVersionProjects: CRDProjectCount(), CRDTargetComponents: CRDProjectComponents(),
	}
}
