// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
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

// AdmittedPackView decodes a rule pack the way admission decodes it and
// returns what admission reads: every top-level member except entries, and
// every entry, each re-encoded from the decoded value. A pack with a
// repeated or case-variant member anywhere is refused.
func AdmittedPackView(packRaw []byte) (map[string]json.RawMessage, []json.RawMessage, error) {
	if strictjson.Check(packRaw) != nil {
		return nil, nil, ErrIntegrity
	}
	var pack packDocument
	if strict(packRaw, &pack) != nil {
		return nil, nil, ErrIntegrity
	}
	entries := make([]json.RawMessage, 0, len(pack.Entries))
	for _, e := range pack.Entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, nil, ErrIntegrity
		}
		entries = append(entries, raw)
	}
	pack.Entries = nil
	raw, err := json.Marshal(pack)
	if err != nil {
		return nil, nil, ErrIntegrity
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, nil, ErrIntegrity
	}
	delete(members, "entries")
	return members, entries, nil
}

// AdmittedEntry re-encodes one pack entry as admission decodes it.
func AdmittedEntry(raw []byte) (json.RawMessage, error) {
	if strictjson.Check(raw) != nil {
		return nil, ErrIntegrity
	}
	var e entry
	if strict(raw, &e) != nil {
		return nil, ErrIntegrity
	}
	out, err := json.Marshal(e)
	if err != nil {
		return nil, ErrIntegrity
	}
	return out, nil
}
