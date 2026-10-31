// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// ExportExternalBundleFromPack and BuildExternalTargetsFromPack are not a
// publication path. They admit a rule pack only by the checks the embedded
// pack passes (catalog, policy, fact registry, review windows); they do not
// apply the knowledge gate, sign anything, or establish that the pack's rules
// were reviewed. Their output is unsigned bytes that every reader re-admits
// after TUF verification. Published knowledge must come only from gated
// sources; a publisher must never feed these an arbitrary pack file. Today
// only tests call them.
//
// ExportExternalBundleFromPack is ExportEmbeddedExternalBundle over a given
// rule pack instead of the embedded one: the pack is first admitted by every
// check the embedded pack passes (against the compiled catalog, policy and
// fact registry), so a renewed or withdrawn rule can be published as a
// single-target envelope without a new binary.
func ExportExternalBundleFromPack(packRaw []byte, revision string) ([]byte, error) {
	if !validExternalRevision(revision) {
		return nil, ErrInvalid
	}
	base, err := admitPack(packRaw)
	if err != nil {
		return nil, err
	}
	if len(base.pack.Distributions) > 0 {
		return nil, errors.Join(ErrIntegrity, ErrDistributionsNotPublishable)
	}
	raw, err := encodeExternalEnvelopeWithRecords(base, revision, "operator_provided", base.pack.Entries, sectionsOf(base.pack))
	if err != nil {
		return nil, err
	}
	if _, err := ParseExternalBundle(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// BuildExternalTargetsFromPack is BuildEmbeddedExternalTargets over a given
// rule pack, admitted as ExportExternalBundleFromPack admits it. Every
// project target gets revision.
func BuildExternalTargetsFromPack(packRaw []byte, revision string) (ExternalTarget, []ExternalTarget, error) {
	if !validExternalRevision(revision) {
		return ExternalTarget{}, nil, ErrInvalid
	}
	base, err := admitPack(packRaw)
	if err != nil {
		return ExternalTarget{}, nil, err
	}
	return buildExternalTargets(base, revision, "operator_provided", func(string, func(string) ([]byte, error)) (string, error) {
		return revision, nil
	})
}

// admitPack admits a complete rule pack against the compiled catalog,
// priority list and fact registry, exactly as the embedded pack is admitted.
func admitPack(packRaw []byte) (bundle, error) {
	landscapeRaw, err := packagedFiles.ReadFile("data/landscape-projects.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	priorityRaw, err := packagedFiles.ReadFile("data/priority-portfolio.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	return assemble(landscapeRaw, priorityRaw, packRaw, compiledDefinitions())
}

// externalEntries is entries without the removal-crossing rules. An external
// pack refuses them (validateExternalPack): the embedded pack alone carries a
// crossing rule, so every derivation of an external bundle from a pack leaves
// it out and keeps the project's target. A pack without one is returned as is.
func externalEntries(entries []Entry) ([]Entry, error) {
	kept := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		crossing, err := constraintengine.AnyCrossingRule([]json.RawMessage{entry.Rule})
		if err != nil {
			return nil, ErrIntegrity
		}
		if !crossing {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(entries) {
		return entries, nil
	}
	return kept, nil
}

// externalPack is pack for an external bundle: without the crossing rules,
// at the schema level the remaining content requires.
func externalPack(pack rulePack) (rulePack, error) {
	entries, err := externalEntries(pack.Entries)
	if err != nil {
		return rulePack{}, err
	}
	if len(entries) == len(pack.Entries) {
		return pack, nil
	}
	pack.Entries = entries
	if pack.Schema, err = requiredPackSchema(pack); err != nil {
		return rulePack{}, ErrIntegrity
	}
	return pack, nil
}

// packWithEmbeddedCrossing is external with the removal-crossing rules that
// the embedded pack holds for project appended. A store target never carries
// such a rule (externalEntries), so a check that evaluated the store alone
// would pass a hop the embedded pack blocks. A store rule that has the id of
// an embedded crossing rule would decide in its place and is refused. The
// result is for selection only; its entries are never encoded or published.
func packWithEmbeddedCrossing(embedded, external rulePack, project string) (rulePack, error) {
	var crossing []Entry
	for _, entry := range embedded.Entries {
		if entry.Project != project {
			continue
		}
		held, err := constraintengine.AnyCrossingRule([]json.RawMessage{entry.Rule})
		if err != nil {
			return rulePack{}, ErrIntegrity
		}
		if held {
			crossing = append(crossing, entry)
		}
	}
	if len(crossing) == 0 {
		return external, nil
	}
	ids := make(map[string]bool, len(crossing))
	for _, entry := range crossing {
		id, err := ruleEntryID(entry)
		if err != nil {
			return rulePack{}, err
		}
		ids[id] = true
	}
	merged := make([]Entry, 0, len(external.Entries)+len(crossing))
	for _, entry := range external.Entries {
		id, err := ruleEntryID(entry)
		if err != nil || ids[id] {
			return rulePack{}, ErrIntegrity
		}
		merged = append(merged, entry)
	}
	external.Entries = append(merged, crossing...)
	return external, nil
}

func ruleEntryID(entry Entry) (string, error) {
	var shape struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(entry.Rule, &shape) != nil || shape.ID == "" {
		return "", ErrIntegrity
	}
	return shape.ID, nil
}
