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

import impl "github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"

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
