// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// externalSizeRevision is the longest revision an external target may carry
// in practice; sizing the target with it keeps the reported size an upper
// bound for any real revision.
const externalSizeRevision = "99999999999999999999"

// splitSizeRevision is the longest revision a per-project target or the
// index admits, used to size them as an upper bound.
const splitSizeRevision = "2147483647"

// PackFileReport describes a CNCF rule pack admitted from files rather than
// from the embedded asset.
type PackFileReport struct {
	// Entries is the number of pack entries; MaxEntries the external cap.
	Entries, MaxEntries int
	// TargetBytes is the size of the unsigned external target the pack
	// would be published as; MaxTargetBytes is the cap a client admits.
	TargetBytes, MaxTargetBytes int
	// RegistryFacts is the size of the compiled fact registry the pack is
	// checked against; MaxRegistryFacts is the engine's cap.
	RegistryFacts, MaxRegistryFacts int
	// ProjectTargets are the per-project targets and the index the pack
	// is published as (sized with the longest practical revision); nil
	// with SplitErr set when the pack cannot be split.
	ProjectTargets []ExternalTarget
	SplitErr       error
}

// CheckPackFiles admits a landscape, priority list and rule pack exactly as
// the embedded knowledge is admitted (same registry, policy, landscape and
// engine checks), and reports the pack's published size against the
// external target caps. It never reads the embedded pack.
func CheckPackFiles(landscapeRaw, priorityRaw, packRaw []byte) (PackFileReport, error) {
	b, err := assemble(landscapeRaw, priorityRaw, packRaw, compiledDefinitions())
	if err != nil {
		return PackFileReport{}, err
	}
	capability, err := externalCapabilityDigest(b)
	if err != nil {
		return PackFileReport{}, ErrIntegrity
	}
	pack := b.pack
	pack.Revision = externalSizeRevision
	raw, err := json.Marshal(struct {
		Schema                 string   `json:"schema"`
		Revision               string   `json:"revision"`
		Purpose                string   `json:"purpose"`
		EngineCapabilityDigest string   `json:"engineCapabilityDigest"`
		Pack                   rulePack `json:"pack"`
	}{envelopeSchemaFor(pack), externalSizeRevision, "operator_provided", capability, pack})
	if err != nil {
		return PackFileReport{}, ErrIntegrity
	}
	for _, entry := range b.pack.Entries {
		if len(entry.RequiredFacts) > maxExternalFacts {
			return PackFileReport{}, ErrIntegrity
		}
	}
	index, projects, splitErr := buildExternalTargets(b, splitSizeRevision, "operator_provided", func(string, func(string) ([]byte, error)) (string, error) {
		return splitSizeRevision, nil
	})
	var targets []ExternalTarget
	if splitErr == nil {
		targets = append([]ExternalTarget{index}, projects...)
	}
	return PackFileReport{
		ProjectTargets: targets, SplitErr: splitErr,
		Entries: len(b.pack.Entries), MaxEntries: maxExternalEntries,
		TargetBytes: len(raw), MaxTargetBytes: maxExternalBundleBytes,
		RegistryFacts: len(compiledDefinitions()), MaxRegistryFacts: constraintengine.MaxCompiledRegistryFacts,
	}, nil
}

// BuildAttestationFromFiles returns the corpus attestation for a rule pack
// read from files, computed exactly as BuildAttestation computes it for the
// embedded pack.
func BuildAttestationFromFiles(landscapeRaw, priorityRaw, packRaw []byte) (Attestation, error) {
	b, err := assemble(landscapeRaw, priorityRaw, packRaw, compiledDefinitions())
	if err != nil {
		return Attestation{}, err
	}
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{
		Schema: CorpusAttestationSchema, Attestation: constraintengine.CorpusAttestation,
		Revision: inventory.Revision, PackDigest: inventory.PackDigest, RuleSetDigest: inventory.RuleSetDigest,
		RuleCount: inventory.RuleCount, Components: inventory.Components, Limitations: AttestationLimitations(),
	}, nil
}

// AdmittedPackView decodes a rule pack the way admission decodes it and
// returns what admission reads: every top-level member except entries, and
// every entry, each re-encoded from the decoded value. A reader that
// compares these bytes compares exactly what the engine admits. A pack with
// a repeated or case-variant member anywhere is refused.
func AdmittedPackView(packRaw []byte) (map[string]json.RawMessage, []json.RawMessage, error) {
	// The same exact top-level names and strict check as admission.
	if _, _, err := lineattest.PackSection(packRaw); err != nil {
		return nil, nil, ErrIntegrity
	}
	var pack rulePack
	if strictJSON(packRaw, &pack) != nil {
		return nil, nil, ErrIntegrity
	}
	entries := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			return nil, nil, ErrIntegrity
		}
		entries = append(entries, raw)
	}
	pack.Entries = nil
	members, err := admittedMembers(pack)
	if err != nil {
		return nil, nil, err
	}
	return members, entries, nil
}

// RequiredPackSchema is the lowest pack schema the content of the pack file
// requires: the schema of the highest-level feature it uses, computed by the
// function the parser and validator use to pick the schema a pack must carry
// (requiredPackSchema). A pack that does not decode strictly has none.
func RequiredPackSchema(packRaw []byte) (string, error) {
	if strictjson.Check(packRaw) != nil {
		return "", ErrIntegrity
	}
	var pack rulePack
	if strictJSON(packRaw, &pack) != nil {
		return "", ErrIntegrity
	}
	return requiredPackSchema(pack)
}

// PackSchemaLevel is the level of a pack schema: the schemas ascend with the
// features that introduced them (packFeatureLevels). ok is false for a
// schema this binary does not know.
func PackSchemaLevel(schema string) (int, bool) {
	if schema == packSchema {
		return 0, true
	}
	level := 0
	last := ""
	for _, feature := range packFeatureLevels {
		if feature.schema != last {
			level++
			last = feature.schema
		}
		if feature.schema == schema {
			return level, true
		}
	}
	return 0, false
}

// AdmittedEntry re-encodes one pack entry as admission decodes it.
func AdmittedEntry(raw []byte) (json.RawMessage, error) {
	if strictjson.Check(raw) != nil {
		return nil, ErrIntegrity
	}
	var entry Entry
	if strictJSON(raw, &entry) != nil {
		return nil, ErrIntegrity
	}
	out, err := json.Marshal(entry)
	if err != nil {
		return nil, ErrIntegrity
	}
	return out, nil
}

func admittedMembers(v any) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrIntegrity
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, ErrIntegrity
	}
	delete(members, "entries")
	return members, nil
}
