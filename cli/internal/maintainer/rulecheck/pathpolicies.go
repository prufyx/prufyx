// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// PathPolicyResultSchema identifies the path-policy validation report.
const PathPolicyResultSchema = "prufyx.io/path-policy-validation/v1alpha1"

// PathPolicyOptions configures path-policy validation.
type PathPolicyOptions struct {
	// Components are the components a record may name: the subject
	// components of the catalog's projects. Nil means the embedded catalog's
	// (cncfcheck.CatalogSubjectComponents).
	Components []string
	// Now, when set, also reports every record that is not current at that
	// time (stale, withdrawn, or reviewed after Now).
	Now time.Time
}

// Path-policy finding checks.
const (
	CheckPathPolicySchema     = "path-policy-schema"
	CheckPathPolicyComponent  = "path-policy-component"
	CheckPathPolicyNotCurrent = "path-policy-not-current"
)

// ValidatePathPolicies checks a path-policy document exactly as the pack
// loader does. The document must parse strictly (upgradepath.Parse): the
// closed policy vocabulary, one record per component in ascending order,
// and evidence checked with the functions the engine applies to a rule's
// evidence (state, basis, UTC review window of at most 90 days, and one to
// eight pinned sources with immutable URLs and whole-file digests). Every
// record's component must be the subject component of a catalog project.
// Finding.EntryIndex is the record's index.
func ValidatePathPolicies(raw []byte, opts PathPolicyOptions) (Result, error) {
	result := Result{Schema: PathPolicyResultSchema}
	records, err := upgradepath.Parse(raw)
	if err != nil {
		result.Findings = append(result.Findings, Finding{Check: CheckPathPolicySchema, Message: err.Error()})
		return result, nil
	}
	result.EntryCount = len(records)
	components := opts.Components
	if components == nil {
		if components, err = cncfcheck.CatalogSubjectComponents(); err != nil {
			return Result{}, fmt.Errorf("read the catalog: %w", err)
		}
	}
	known := make(map[string]bool, len(components))
	for _, c := range components {
		known[c] = true
	}
	for i, r := range records {
		if !known[r.Component] {
			result.Findings = append(result.Findings, Finding{EntryIndex: i, Check: CheckPathPolicyComponent, Message: fmt.Sprintf("component %s is not the subject component of a catalog project", r.Component)})
		}
		if !opts.Now.IsZero() {
			if f := r.Freshness(opts.Now); f != upgradepath.FreshnessCurrent {
				result.Findings = append(result.Findings, Finding{EntryIndex: i, Check: CheckPathPolicyNotCurrent, Message: fmt.Sprintf("path policy for %s is %s at %s", r.Component, f, opts.Now.UTC().Format(time.RFC3339))})
			}
		}
	}
	result.Valid = len(result.Findings) == 0
	return result, nil
}

// ValidatePackPathPolicies reads a whole pack file and validates its
// pathPolicies section. The section is located the way the pack loader
// locates it (exact top-level member names); a pack without the section has
// nothing to check and is valid.
func ValidatePackPathPolicies(pack []byte, opts PathPolicyOptions) (Result, error) {
	section, present, err := lineattest.PackMemberSection(pack, upgradepath.PackMember)
	if err != nil {
		return Result{}, fmt.Errorf("pack does not decode: %w", err)
	}
	if !present {
		return Result{Schema: PathPolicyResultSchema, Valid: true}, nil
	}
	return ValidatePathPolicies(section, opts)
}
