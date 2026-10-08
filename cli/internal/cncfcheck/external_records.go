// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Records in external targets.
//
// A records envelope (externalBundleSchemaRecords) carries, besides its
// rules, the per-scope records of the rule pack: line attestations
// (lineattest.PackMember), upgrade-path policies (upgradepath.PackMember)
// and served-API lists (servedapis.PackMember). Every record names exactly
// one component, so it belongs to exactly one catalog project: the one whose
// subject component it names. A per-project target carries exactly its
// project's records; the single target carries all of them.
//
// Each section is admitted by the same checks the embedded pack's section
// passes (located by its exact member name, parsed strictly, every
// attestation listing exactly the target's rules of its scope, every
// component a catalog subject, no served list naming a removed API). Any
// failure refuses the whole target. Distribution records are not scoped to
// one project and are refused by every envelope.

// externalRecordMembers are the record sections a records envelope may
// carry, in pack member order.
var externalRecordMembers = []string{lineattest.PackMember, upgradepath.PackMember, servedapis.PackMember}

// knowledgeContentSchema names the document whose digest binds a target's
// rule digest and record digest together.
const knowledgeContentSchema = "prufyx.io/cncf-knowledge-content/v1"

// recordSections are the record sections of one pack, in pack form.
type recordSections struct {
	LineAttestations json.RawMessage `json:"lineAttestations,omitempty"`
	PathPolicies     json.RawMessage `json:"pathPolicies,omitempty"`
	ServedAPIs       json.RawMessage `json:"servedAPIs,omitempty"`
}

func (r recordSections) empty() bool {
	return len(r.LineAttestations) == 0 && len(r.PathPolicies) == 0 && len(r.ServedAPIs) == 0
}

func sectionsOf(pack rulePack) recordSections {
	return recordSections{LineAttestations: pack.LineAttestations, PathPolicies: pack.PathPolicies, ServedAPIs: pack.ServedAPIs}
}

// hasRecordSections reports whether the pack carries any record section an
// external target may carry.
func hasRecordSections(pack rulePack) bool { return !sectionsOf(pack).empty() }

// envelopeSchemaFor is the envelope schema a pack needs: the records schema
// exactly when it carries a record section.
func envelopeSchemaFor(pack rulePack) string {
	if hasRecordSections(pack) {
		return externalBundleSchemaRecords
	}
	return externalBundleSchema
}

// knowledgeContentDigest binds a records target's rule digest and the
// digest of its records (compact JSON of the sections) into the one digest
// its admission, its index entry and a store receipt record.
func knowledgeContentDigest(ruleDigest string, pack rulePack) (string, error) {
	records, err := json.Marshal(sectionsOf(pack))
	if err != nil {
		return "", ErrIntegrity
	}
	return externalDigestJSON(struct {
		Schema       string `json:"schema"`
		RuleDigest   string `json:"ruleDigest"`
		RecordDigest string `json:"recordDigest"`
	}{knowledgeContentSchema, ruleDigest, digest(records)}), nil
}

// admitExternalRecords admits the record sections of a records envelope's
// pack (packRaw are its exact bytes, pack its decoded value) with the
// checks the embedded pack's sections pass.
func admitExternalRecords(base bundle, packRaw json.RawMessage, pack rulePack) error {
	section, present, err := lineattest.PackSection(packRaw)
	if err != nil || present != (len(pack.LineAttestations) > 0) || !bytes.Equal(section, pack.LineAttestations) {
		return ErrIntegrity
	}
	if present {
		if _, err := admitAttestations(section, true, pack.Entries); err != nil {
			return ErrIntegrity
		}
		// Every attestation names a catalog subject component; the family
		// check in lineattest already limits which components it may name.
		subjects := subjectComponents(base.landscape.Projects)
		components, err := sectionComponents(section)
		if err != nil {
			return ErrIntegrity
		}
		for _, component := range components {
			if !subjects[component] {
				return ErrIntegrity
			}
		}
	}
	policySection, hasPolicies, err := lineattest.PackMemberSection(packRaw, upgradepath.PackMember)
	if err != nil || hasPolicies != (len(pack.PathPolicies) > 0) || !bytes.Equal(policySection, pack.PathPolicies) {
		return ErrIntegrity
	}
	if _, err := admitPathPolicies(policySection, hasPolicies, base.landscape.Projects); err != nil {
		return ErrIntegrity
	}
	if _, err := admitServedAPIs(packRaw, pack.ServedAPIs, base.landscape.Projects); err != nil {
		return ErrIntegrity
	}
	return nil
}

// recordOwners maps every catalog subject component to its project. A
// component that is the subject of more than one project maps to "": its
// records have no owner and are refused.
func recordOwners(projects []projectIdentity) map[string]string {
	owners := map[string]string{}
	for _, project := range projects {
		component := subjectComponent(project.Slug, project.RepositoryURL)
		if component == "" {
			continue
		}
		if _, seen := owners[component]; seen {
			owners[component] = ""
			continue
		}
		owners[component] = project.Slug
	}
	return owners
}

// sectionComponents returns the component of every record of a section, in
// order.
func sectionComponents(section json.RawMessage) ([]string, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(section, &items); err != nil {
		return nil, ErrIntegrity
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		var shape struct {
			Component string `json:"component"`
		}
		if err := json.Unmarshal(item, &shape); err != nil || shape.Component == "" {
			return nil, ErrIntegrity
		}
		out = append(out, shape.Component)
	}
	return out, nil
}

// splitSection splits one record section by owning project, keeping the
// records' order. A record whose component has no single owner refuses the
// split.
func splitSection(section json.RawMessage, owners map[string]string) (map[string]json.RawMessage, error) {
	if len(section) == 0 {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(section, &items); err != nil {
		return nil, ErrIntegrity
	}
	components, err := sectionComponents(section)
	if err != nil {
		return nil, err
	}
	byOwner := map[string][]json.RawMessage{}
	for i, item := range items {
		owner := owners[components[i]]
		if owner == "" {
			return nil, ErrIntegrity
		}
		byOwner[owner] = append(byOwner[owner], item)
	}
	out := make(map[string]json.RawMessage, len(byOwner))
	for owner, kept := range byOwner {
		raw, err := json.Marshal(kept)
		if err != nil {
			return nil, ErrIntegrity
		}
		out[owner] = raw
	}
	return out, nil
}

// splitRecords splits the pack's record sections by owning project.
func splitRecords(pack rulePack, projects []projectIdentity) (map[string]recordSections, error) {
	owners := recordOwners(projects)
	attestations, err := splitSection(pack.LineAttestations, owners)
	if err != nil {
		return nil, err
	}
	policies, err := splitSection(pack.PathPolicies, owners)
	if err != nil {
		return nil, err
	}
	served, err := splitSection(pack.ServedAPIs, owners)
	if err != nil {
		return nil, err
	}
	out := map[string]recordSections{}
	for owner, raw := range attestations {
		r := out[owner]
		r.LineAttestations = raw
		out[owner] = r
	}
	for owner, raw := range policies {
		r := out[owner]
		r.PathPolicies = raw
		out[owner] = r
	}
	for owner, raw := range served {
		r := out[owner]
		r.ServedAPIs = raw
		out[owner] = r
	}
	return out, nil
}

// recordsOwnedBy reports whether every record of the pack names project's
// subject component, and no other project's.
func recordsOwnedBy(pack rulePack, project string, projects []projectIdentity) bool {
	owners := recordOwners(projects)
	for _, section := range []json.RawMessage{pack.LineAttestations, pack.PathPolicies, pack.ServedAPIs} {
		if len(section) == 0 {
			continue
		}
		components, err := sectionComponents(section)
		if err != nil {
			return false
		}
		for _, component := range components {
			if owners[component] != project {
				return false
			}
		}
	}
	return true
}
