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

// assembleFull admits the files against the registry and community catalog
// given by definitions and tableRaw: a nil tableRaw is the embedded table, a
// nil definitions is this build's compiled registry for that table (the
// compiled registry for the embedded table, TableDefinitions for a table
// file). It returns the bundle and the size of the registry it was admitted
// against.
func assembleFull(landscapeRaw, priorityRaw, packRaw []byte, definitions []constraintengine.FactDefinition, tableRaw []byte) (bundle, int, error) {
	projects := customresources.Projects()
	if tableRaw != nil {
		var err error
		if projects, _, err = customresources.LoadTable(tableRaw); err != nil {
			return bundle{}, 0, ErrIntegrity
		}
	}
	if definitions == nil {
		if tableRaw == nil {
			definitions = compiledDefinitions()
		} else {
			definitions = TableDefinitions(projects)
		}
	}
	b, err := assembleWithCommunity(landscapeRaw, priorityRaw, packRaw, definitions, projects)
	return b, len(definitions), err
}

// CheckPackFilesFull is CheckPackFiles against the registry given by
// definitions and the reviewed custom-resource table tableRaw (see
// assembleFull for the nil defaults). RegistryFacts reports the size of the
// registry the pack was admitted against.
func CheckPackFilesFull(landscapeRaw, priorityRaw, packRaw []byte, definitions []constraintengine.FactDefinition, tableRaw []byte) (PackFileReport, error) {
	b, n, err := assembleFull(landscapeRaw, priorityRaw, packRaw, definitions, tableRaw)
	if err != nil {
		return PackFileReport{}, err
	}
	return packFileReport(b, n)
}

// CheckPackFilesWithTable is CheckPackFiles against the registry and
// community catalog of a table file.
func CheckPackFilesWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw []byte) (PackFileReport, error) {
	if tableRaw == nil {
		return PackFileReport{}, ErrIntegrity
	}
	return CheckPackFilesFull(landscapeRaw, priorityRaw, packRaw, nil, tableRaw)
}

// BuildAttestationFromFilesFull is BuildAttestationFromFiles against the
// registry given by definitions and the table tableRaw (nil defaults as in
// assembleFull).
func BuildAttestationFromFilesFull(landscapeRaw, priorityRaw, packRaw []byte, definitions []constraintengine.FactDefinition, tableRaw []byte) (Attestation, error) {
	b, _, err := assembleFull(landscapeRaw, priorityRaw, packRaw, definitions, tableRaw)
	if err != nil {
		return Attestation{}, err
	}
	return attestationOf(b)
}

// BuildAttestationFromFilesWithTable is BuildAttestationFromFiles against
// the registry and community catalog of a table file.
func BuildAttestationFromFilesWithTable(landscapeRaw, priorityRaw, packRaw, tableRaw []byte) (Attestation, error) {
	if tableRaw == nil {
		return Attestation{}, ErrIntegrity
	}
	return BuildAttestationFromFilesFull(landscapeRaw, priorityRaw, packRaw, nil, tableRaw)
}
