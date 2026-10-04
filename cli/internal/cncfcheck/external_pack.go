// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

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
	raw, err := encodeExternalEnvelope(base, revision, "operator_provided", base.pack.Entries)
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
