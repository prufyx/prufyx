// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// DistributionResultSchema identifies the distribution validation report.
const DistributionResultSchema = "prufyx.io/distribution-validation/v1alpha1"

// DistributionOptions configures distribution validation.
type DistributionOptions struct {
	// Now, when set, also reports every record and statement that is not
	// current at that time (stale, withdrawn, or reviewed after Now).
	Now time.Time
	// Fetch enables the online check every rule source gets: downloading
	// each cited source at its revision and comparing its whole-file sha256
	// and line count. Offline (false) is the default.
	Fetch bool
	// Fetcher is required when Fetch is true.
	Fetcher Fetcher
}

// Distribution finding checks.
const (
	CheckDistributionSchema     = "distribution-schema"
	CheckDistributionNotCurrent = "distribution-not-current"
)

// ValidateDistributions checks a distribution section exactly as the pack
// loader does (distribution.Parse): the closed distribution, family,
// status and control-plane vocabularies, canonical order, the OpenShift
// mapping, and evidence checked with the functions the engine applies to a
// rule's evidence (state, basis, UTC review window of at most 90 days, and
// one to eight sources pinned to a Git commit with whole-file digests).
// With Fetch, every source also gets the online check a rule source gets.
// Finding.EntryIndex is the record's index, then the statement's index
// after the records; Finding.RuleID names the record or statement.
func ValidateDistributions(raw []byte, opts DistributionOptions) (Result, error) {
	result := Result{Schema: DistributionResultSchema}
	section, err := distribution.Parse(raw)
	if err != nil {
		result.Findings = append(result.Findings, Finding{Check: CheckDistributionSchema, Message: err.Error()})
		return result, nil
	}
	if opts.Fetch && opts.Fetcher == nil {
		return Result{}, fmt.Errorf("--fetch requires a Fetcher")
	}
	result.EntryCount = len(section.Records) + len(section.Applicability)
	type item struct {
		name     string
		evidence distribution.Evidence
	}
	items := make([]item, 0, result.EntryCount)
	for _, r := range section.Records {
		items = append(items, item{"distribution " + r.Distribution, r.Evidence})
	}
	for _, a := range section.Applicability {
		items = append(items, item{"applicability " + a.Distribution + " " + a.Family, a.Evidence})
	}
	for i, it := range items {
		if !opts.Now.IsZero() {
			if f := it.evidence.Freshness(opts.Now); f != distribution.FreshnessCurrent {
				result.Findings = append(result.Findings, Finding{EntryIndex: i, RuleID: it.name, Check: CheckDistributionNotCurrent, Message: fmt.Sprintf("%s is %s at %s", it.name, f, opts.Now.UTC().Format(time.RFC3339))})
			}
		}
		if opts.Fetch {
			result.Findings = append(result.Findings, checkOnlineSources(context.Background(), i, it.name, "evidence.sources", it.evidence.Sources, opts.Fetcher)...)
		}
	}
	result.Valid = len(result.Findings) == 0
	return result, nil
}

// ValidatePackDistributions reads a whole pack file and validates its
// distribution section, located the way the pack loader locates it (exact
// top-level member names). A pack without the section has nothing to check
// and is valid.
func ValidatePackDistributions(pack []byte, opts DistributionOptions) (Result, error) {
	section, present, err := lineattest.PackMemberSection(pack, distribution.PackMember)
	if err != nil {
		return Result{}, fmt.Errorf("pack does not decode: %w", err)
	}
	if !present {
		return Result{Schema: DistributionResultSchema, Valid: true}, nil
	}
	return ValidateDistributions(section, opts)
}
