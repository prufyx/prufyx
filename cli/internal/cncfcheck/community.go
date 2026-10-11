// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"net/url"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// The community catalog.
//
// A community project is a project outside the embedded CNCF landscape
// catalog whose identity is the reviewed upstream record of the
// custom-resource table (customresources.Project.Upstream). The pack can
// carry rules for it (entries whose project is its slug), under the pack
// schema packSchemaCommunity, and the knowledge store can carry a per-project
// target for it under ExternalCommunityTargetPrefix. Nothing else about the
// CNCF pack changes:
//
//   - the landscape stays the only catalog of CNCF projects: a community
//     slug or subject component that is also a landscape one refuses the
//     whole pack, so a community project can never be, or be taken for, a
//     CNCF one;
//   - catalog listings, priority lists, coverage counts and the corpus
//     attestation (the components a scope may be called complete for) stay
//     CNCF only;
//   - a community project is known to a scan only when the knowledge holds
//     data for it (a rule or a record); without data every route answers as
//     it did before the community knowledge step;
//   - line attestations, upgrade-path policies and served-API lists are
//     admitted by the same checks as for a CNCF project, and those checks
//     do not admit a community component yet (lineattest families list no
//     community project, path policies and served-API lists name catalog
//     subjects only): a community project cannot attest until the reviewed
//     path that admits its line reviews exists.
const (
	// ExternalCommunityTargetPrefix is the TUF target path prefix of the
	// per-project targets of community projects.
	ExternalCommunityTargetPrefix = "knowledge/community/projects/"
	// CatalogCommunity is the catalog name a community index entry and a
	// scan inventory entry carry. A CNCF entry carries no catalog field.
	CatalogCommunity = "community"
)

// isCommunitySlug reports whether slug is a community project of the
// reviewed table.
func isCommunitySlug(slug string) bool { return customresources.IsCommunity(slug) }

// communityIdentities derives the catalog identities of the community
// projects of a reviewed table. It refuses a table whose community project
// is also a landscape project (by slug or by subject component), whose
// identity is not a plain GitHub repository, whose component is not the
// one its repository names, or that repeats a slug or a component.
func communityIdentities(projects []customresources.Project, landscape []projectIdentity) (map[string]projectIdentity, error) {
	out := map[string]projectIdentity{}
	subjects := map[string]string{}
	for _, project := range landscape {
		if component := subjectComponent(project.Slug, project.RepositoryURL); component != "" {
			subjects[component] = project.Slug
		}
	}
	taken := map[string]bool{}
	for _, project := range landscape {
		taken[project.Slug] = true
	}
	for _, p := range projects {
		if !p.Community() {
			continue
		}
		parsed, err := url.Parse(p.Upstream.Repository)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !slugPattern.MatchString(p.Slug) || p.Upstream.Name == "" {
			return nil, ErrIntegrity
		}
		component := subjectComponent(p.Slug, p.Upstream.Repository)
		if component == "" || component != p.Component || taken[p.Slug] {
			return nil, ErrIntegrity
		}
		if _, clash := subjects[component]; clash {
			return nil, ErrIntegrity
		}
		taken[p.Slug] = true
		subjects[component] = p.Slug
		// CNCFStage stays empty: nothing here says the project has one.
		out[p.Slug] = projectIdentity{Slug: p.Slug, Name: p.Upstream.Name, RepositoryURL: p.Upstream.Repository}
	}
	return out, nil
}

// isCommunity reports whether slug is a community project of this bundle.
func (b bundle) isCommunity(slug string) bool {
	_, ok := b.community[slug]
	return ok
}

// hasCheckableProject reports whether a check can name slug: a landscape
// project, or a community project the bundle holds data for. A community
// project without data is refused exactly as an unknown project is.
func (b bundle) hasCheckableProject(slug string) bool {
	return b.hasProject(slug) || (b.isCommunity(slug) && b.communityHasData(slug))
}

// hasKnowledgeProject reports whether the pack and the knowledge store can
// hold data for slug: a landscape project or a community project.
func (b bundle) hasKnowledgeProject(slug string) bool {
	return b.hasProject(slug) || b.isCommunity(slug)
}

// catalogOf is the catalog of a knowledge project: "" for a project of the
// CNCF landscape, CatalogCommunity for a community project.
func (b bundle) catalogOf(slug string) string {
	if b.isCommunity(slug) {
		return CatalogCommunity
	}
	return ""
}

// knowledgeProjects lists the landscape projects followed by the community
// projects in slug order: every project that can own an entry or a record.
func (b bundle) knowledgeProjects() []projectIdentity {
	out := append([]projectIdentity(nil), b.landscape.Projects...)
	slugs := make([]string, 0, len(b.community))
	for slug := range b.community {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		out = append(out, b.community[slug])
	}
	return out
}

// communityComponent returns the subject component of a community project.
func (b bundle) communityComponent(slug string) (string, bool) {
	identity, ok := b.community[slug]
	if !ok {
		return "", false
	}
	component := subjectComponent(identity.Slug, identity.RepositoryURL)
	return component, component != ""
}

// communityHasData reports whether the bundle holds knowledge for a
// community project: a rule of its own or a record that names its component.
func (b bundle) communityHasData(slug string) bool {
	component, ok := b.communityComponent(slug)
	if !ok {
		return false
	}
	for _, entry := range b.pack.Entries {
		if entry.Project == slug {
			return true
		}
	}
	for _, section := range []json.RawMessage{b.pack.LineAttestations, b.pack.PathPolicies, b.pack.ServedAPIs} {
		if len(section) == 0 {
			continue
		}
		components, err := sectionComponents(section)
		if err != nil {
			return false
		}
		for _, c := range components {
			if c == component {
				return true
			}
		}
	}
	return false
}

// anyCommunityEntry reports whether a pack holds an entry of a community
// project: the feature of packSchemaCommunity.
func anyCommunityEntry(pack rulePack) bool {
	for _, entry := range pack.Entries {
		if isCommunitySlug(entry.Project) {
			return true
		}
	}
	return false
}

// communityRuleAdmitted holds a community entry to the one shape the
// reviewed derivations produce: a forbid_set_member rule whose only
// condition is the proposed-side custom-resource version set of its own
// project, with no applicability fact, notice, lead, consensus, support
// range or removal crossing. Rules about anything else are refused until a
// reviewed change widens this function, so a community project can never
// carry a rule no route evaluates.
func communityRuleAdmitted(entry Entry, shape ruleShape) bool {
	p, ok := customresources.ProjectFor(entry.Project)
	if !ok || !p.Community() {
		return false
	}
	if shape.Operator != constraintengine.OperatorForbidSetMember || shape.Condition != nil || len(shape.AppliesWhen) != 0 || shape.SetCondition == nil {
		return false
	}
	condition := shape.SetCondition
	if condition.Side != "proposed" || condition.Component != p.Component || condition.FactID != p.FactID() {
		return false
	}
	rules := []json.RawMessage{entry.Rule}
	for _, feature := range []func([]json.RawMessage) (bool, error){constraintengine.AnyNoticeRule, constraintengine.AnyBasisRule, constraintengine.AnySeverityRule, constraintengine.AnyCrossingRule} {
		if present, err := feature(rules); err != nil || present {
			return false
		}
	}
	return true
}

// CommunityProjectHasData reports whether the embedded knowledge holds data
// for a community project (a rule or a record). It is false for a CNCF
// project, for a slug that is not a community project, and for a community
// project without data: every route answers for those as it did before the
// community knowledge step.
func CommunityProjectHasData(slug string) (bool, error) {
	b, err := load()
	if err != nil {
		return false, err
	}
	return b.isCommunity(slug) && b.communityHasData(slug), nil
}

// IsCommunityProject reports whether slug is a community project of the
// reviewed table: a project outside the embedded CNCF landscape catalog.
func IsCommunityProject(slug string) bool { return isCommunitySlug(slug) }

// CommunityLabel is how every user-facing text names the catalog of a
// community project.
const CommunityLabel = customresources.CommunityLabel

// ProjectCatalogLabel is the user-facing catalog label of a knowledge
// project: CommunityLabel for a community project, "" for any other slug
// (a CNCF landscape project carries no label).
func ProjectCatalogLabel(slug string) string {
	if isCommunitySlug(slug) {
		return CommunityLabel
	}
	return ""
}

// communityComponentOf returns the component of a community slug from the
// reviewed table, for callers without a bundle.
func communityComponentOf(slug string) (string, bool) {
	for _, p := range customresources.CommunityProjects() {
		if p.Slug == slug {
			return p.Component, true
		}
	}
	return "", false
}
