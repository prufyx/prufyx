// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// externalSizeRevision is the longest revision an external target may carry
// in practice; sizing the target with it keeps the reported size an upper
// bound for any real revision.
const externalSizeRevision = "99999999999999999999"

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
	}{externalBundleSchema, externalSizeRevision, "operator_provided", capability, pack})
	if err != nil {
		return PackFileReport{}, ErrIntegrity
	}
	for _, entry := range b.pack.Entries {
		if len(entry.RequiredFacts) > maxExternalFacts {
			return PackFileReport{}, ErrIntegrity
		}
	}
	return PackFileReport{
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
