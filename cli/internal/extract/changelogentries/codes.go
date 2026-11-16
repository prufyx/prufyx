// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import "errors"

// Code is a typed reason a pair is not decided (G). The list is closed.
type Code string

const (
	NoChangelogTarget         Code = "NO_CHANGELOG_TARGET"
	SourceNotPinnedGit        Code = "SOURCE_NOT_PINNED_GIT"
	ShapeNotPerTag            Code = "SHAPE_NOT_PER_TAG"
	PathMissingAtTag          Code = "PATH_MISSING_AT_TAG"
	EntryMissing              Code = "ENTRY_MISSING"
	EntryDuplicate            Code = "ENTRY_DUPLICATE"
	EntryNotFinal             Code = "ENTRY_NOT_FINAL"
	EntryNotAtTag             Code = "ENTRY_NOT_AT_TAG"
	EntryEmpty                Code = "ENTRY_EMPTY"
	EntryRefersElsewhere      Code = "ENTRY_REFERS_ELSEWHERE"
	EntryBoundaryUnproven     Code = "ENTRY_BOUNDARY_UNPROVEN"
	EntryOverBound            Code = "ENTRY_OVER_BOUND"
	EntryParseResidue         Code = "ENTRY_PARSE_RESIDUE"
	EntryAmended              Code = "ENTRY_AMENDED"
	MonorepoEntryAmbiguous    Code = "MONOREPO_ENTRY_AMBIGUOUS"
	TagMoved                  Code = "TAG_MOVED"
	ItemUnresolved            Code = "ITEM_UNRESOLVED"
	ItemRuleShapeUnsupported  Code = "ITEM_RULE_SHAPE_UNSUPPORTED"
	RuleNotLineWide           Code = "RULE_NOT_LINE_WIDE"
	FlagRemovedNotInChangelog Code = "FLAG_REMOVED_NOT_IN_CHANGELOG"
	NotPreviousMinor          Code = "NOT_PREVIOUS_MINOR"
)

// Codes is the closed list of typed reasons, in design order.
func Codes() []Code {
	return []Code{
		NoChangelogTarget, SourceNotPinnedGit, ShapeNotPerTag, PathMissingAtTag,
		EntryMissing, EntryDuplicate, EntryNotFinal, EntryNotAtTag, EntryEmpty,
		EntryRefersElsewhere, EntryBoundaryUnproven, EntryOverBound,
		EntryParseResidue, EntryAmended, MonorepoEntryAmbiguous, TagMoved,
		ItemUnresolved, ItemRuleShapeUnsupported, RuleNotLineWide,
		FlagRemovedNotInChangelog, NotPreviousMinor,
	}
}

// Failure is a typed refusal. Detail is for people; the Code is the contract.
type Failure struct {
	Code   Code
	Detail string
}

func (f *Failure) Error() string {
	if f.Detail == "" {
		return string(f.Code)
	}
	return string(f.Code) + ": " + f.Detail
}

func fail(c Code, detail string) error { return &Failure{Code: c, Detail: detail} }

// CodeOf returns the typed reason of err. ok is false for an error that is
// not a Failure (a read error, for example): such an error is never a G reason
// and never an entry.
func CodeOf(err error) (Code, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f.Code, true
	}
	return "", false
}
