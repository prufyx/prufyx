// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// MaxPackBytes is the size cap applied to the community-project rule pack
// file; it matches the cap a client admits for one external knowledge target.
const MaxPackBytes = 1 << 20

// PackFileReport describes a community-project rule pack admitted from files
// rather than from the embedded asset.
type PackFileReport struct {
	Entries                         int
	TargetBytes, MaxTargetBytes     int
	RegistryFacts, MaxRegistryFacts int
}

// CheckPackFiles admits a project registry and rule pack exactly as the
// embedded knowledge is admitted and reports the pack's size and registry
// usage. It never reads the embedded pack.
func CheckPackFiles(registryRaw, packRaw []byte) (PackFileReport, error) {
	b, err := loadRaw(registryRaw, packRaw, definitions())
	if err != nil {
		return PackFileReport{}, err
	}
	return PackFileReport{
		Entries:     len(b.pack.Entries),
		TargetBytes: len(packRaw), MaxTargetBytes: MaxPackBytes,
		RegistryFacts: len(definitions()), MaxRegistryFacts: constraintengine.MaxRegistryFacts,
	}, nil
}

// BuildAttestationFromFiles returns the corpus attestation for a rule pack
// read from files, computed exactly as BuildAttestation computes it for the
// embedded pack.
func BuildAttestationFromFiles(registryRaw, packRaw []byte) (Attestation, error) {
	b, err := loadRaw(registryRaw, packRaw, definitions())
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
