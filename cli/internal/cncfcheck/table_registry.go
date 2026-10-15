// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// Admission over a reviewed custom-resource table read from a file instead
// of the embedded one. The knowledge gate is built from the base branch, so
// its embedded table is the base's; a change that adds projects to the table
// is admitted by the gate against the table the change proposes, compiled
// with the base's code: the registry is the base's own definitions with the
// custom-resource version sets of the given table in place of the embedded
// table's. Everything else (landscape, policy, identities, rules) is checked
// exactly as CheckPackFiles and BuildAttestationFromFiles check it.

// TableDefinitions returns the fact definitions of the compiled registry
// with the custom-resource version sets of projects in place of those of the
// embedded table.
func TableDefinitions(projects []customresources.Project) []constraintengine.FactDefinition {
	embedded := map[string]bool{}
	for _, d := range customResourceVersionDefinitions() {
		embedded[d.ID] = true
	}
	var out []constraintengine.FactDefinition
	for _, d := range compiledDefinitions() {
		if !embedded[d.ID] {
			out = append(out, d)
		}
	}
	for _, p := range projects {
		out = append(out, constraintengine.FactDefinition{ID: p.FactID(), Component: p.Component, Type: constraintengine.FactSet})
	}
	return out
}

// TableRegistryDigest is the digest of the registry TableDefinitions
// compiles for a table file.
func TableRegistryDigest(tableRaw []byte) (string, error) {
	projects, _, err := customresources.LoadTable(tableRaw)
	if err != nil {
		return "", err
	}
	r, err := constraintengine.NewCompiledRegistry(TableDefinitions(projects))
	if err != nil {
		return "", err
	}
	return r.Digest(), nil
}

// assembleWithTable admits the files against the registry and community
// catalog of a table file.
func assembleWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw []byte) (bundle, int, error) {
	projects, _, err := customresources.LoadTable(tableRaw)
	if err != nil {
		return bundle{}, 0, ErrIntegrity
	}
	definitions := TableDefinitions(projects)
	b, err := assembleWithCommunity(landscapeRaw, priorityRaw, packRaw, definitions, projects)
	return b, len(definitions), err
}

// CheckPackFilesWithTable is CheckPackFiles against the registry and
// community catalog of a table file.
func CheckPackFilesWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw []byte) (PackFileReport, error) {
	b, n, err := assembleWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw)
	if err != nil {
		return PackFileReport{}, err
	}
	return packFileReport(b, n)
}

// BuildAttestationFromFilesWithTable is BuildAttestationFromFiles against
// the registry and community catalog of a table file.
func BuildAttestationFromFilesWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw []byte) (Attestation, error) {
	b, _, err := assembleWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw)
	if err != nil {
		return Attestation{}, err
	}
	return attestationOf(b)
}
