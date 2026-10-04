// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"sort"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// NewStoreScanKnowledge builds the scan view of knowledge selected from a
// verified local store. bundles maps every opened project to the external
// envelope admitted for it (the same envelope for every project of a
// single-target store; the project's own target, or an empty envelope for a
// project the index does not list, in a per-project store).
//
// Rules, line reviews and upgrade-path policies come only from those
// envelopes, admitted by the same checks as the embedded pack. The embedded
// pack contributes nothing but the compiled catalog and fact registry that
// every external envelope is admitted against: a project or component that
// was not opened has no rule, no review and no policy.
func NewStoreScanKnowledge(bundles map[string]ExternalBundle) (*ScanKnowledge, error) {
	if len(bundles) == 0 {
		return nil, ErrInvalid
	}
	base, err := load()
	if err != nil {
		return nil, err
	}
	catalog := bundle{landscape: base.landscape, priority: base.priority, registry: base.registry, catalogueDigest: base.catalogueDigest, attestations: lineattest.NewIndex(nil), pathPolicies: upgradepath.NewIndex(nil)}
	k := &ScanKnowledge{b: catalog, rules: map[string][]ScanRule{}, selected: map[string]bundle{}}
	for project, external := range bundles {
		if !external.valid() || !base.hasProject(project) || external.registry.Digest() != base.registry.Digest() {
			return nil, ErrIntegrity
		}
		selected := bundle{landscape: base.landscape, priority: base.priority, pack: external.pack, registry: external.registry, packDigest: external.bundleDigest, catalogueDigest: base.catalogueDigest, external: true}
		if selected.attestations, err = admitAttestations(external.pack.LineAttestations, len(external.pack.LineAttestations) > 0, external.pack.Entries); err != nil {
			return nil, ErrIntegrity
		}
		if selected.pathPolicies, err = admitPathPolicies(external.pack.PathPolicies, len(external.pack.PathPolicies) > 0, base.landscape.Projects); err != nil {
			return nil, ErrIntegrity
		}
		var rules []ScanRule
		for _, entry := range external.pack.Entries {
			if entry.Project != project {
				continue
			}
			rule, err := NewScanRule(entry.Project, entry.Description, entry.Rule)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].Scope.ID < rules[j].Scope.ID })
		k.selected[project] = selected
		k.rules[project] = rules
	}
	return k, nil
}

// bundleFor is the bundle that holds project's rules: the embedded bundle,
// or the bundle opened for project from a store. A project that was not
// opened from a store has none.
func (k *ScanKnowledge) bundleFor(project string) (bundle, bool) {
	if k.selected == nil {
		return k.b, true
	}
	b, ok := k.selected[project]
	return b, ok
}

// bundleForComponent is bundleFor for the project whose subject component
// is component.
func (k *ScanKnowledge) bundleForComponent(component string) (bundle, bool) {
	if k.selected == nil {
		return k.b, true
	}
	for _, project := range k.b.landscape.Projects {
		if subjectComponent(project.Slug, project.RepositoryURL) != component {
			continue
		}
		if b, ok := k.selected[project.Slug]; ok {
			return b, true
		}
	}
	return bundle{}, false
}

// ScanCatalog is the compiled project catalog alone: project names and
// subject components, without any rule, review or policy. A scan checks
// component names against it before it opens a store.
type ScanCatalog struct{ b bundle }

// LoadScanCatalog loads the compiled catalog.
func LoadScanCatalog() (*ScanCatalog, error) {
	base, err := load()
	if err != nil {
		return nil, err
	}
	return &ScanCatalog{b: bundle{landscape: base.landscape}}, nil
}

// Projects lists every catalog project slug in order.
func (c *ScanCatalog) Projects() []string { return catalogProjects(c.b) }

// Component returns the subject component of a catalog project.
func (c *ScanCatalog) Component(slug string) (string, bool) { return catalogComponent(c.b, slug) }
