// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"sort"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Reasons of the custom-resource version preparation.
const (
	// ReasonCustomResourcesComplete: the set is declared complete.
	ReasonCustomResourcesComplete Reason = "CUSTOM_RESOURCE_VERSIONS_COMPLETE"
	// ReasonCustomResourcesScopeIncomplete: the caller did not declare the
	// manifests to be the complete set that is applied.
	ReasonCustomResourcesScopeIncomplete Reason = "CUSTOM_RESOURCE_MANIFEST_SET_INCOMPLETE"
	// ReasonCustomResourcesUnattributed: an object of a custom-resource
	// group that the reviewed table does not attribute to exactly one
	// project is present, so no project's set is known to be complete.
	ReasonCustomResourcesUnattributed Reason = "CUSTOM_RESOURCE_GROUP_NOT_ATTRIBUTED"
	// ReasonCustomResourcesPaginated: a list in the input is paginated.
	ReasonCustomResourcesPaginated Reason = "CUSTOM_RESOURCE_LIST_PAGINATION_UNRESOLVED"
	// ReasonCustomResourcesMemberInvalid: a project object's
	// group/version/Kind is not a valid set member (too long).
	ReasonCustomResourcesMemberInvalid Reason = "CUSTOM_RESOURCE_VERSION_NOT_REPRESENTABLE"
	// ReasonCustomResourcesTooMany: the project's objects use more
	// group/version/Kind combinations than a set may hold.
	ReasonCustomResourcesTooMany Reason = "CUSTOM_RESOURCE_VERSIONS_SET_TOO_LARGE"
	// ReasonCustomResourcesRendering: a document holds unrendered template
	// syntax or cannot be parsed.
	ReasonCustomResourcesRendering Reason = "CUSTOM_RESOURCE_RENDERING_UNRESOLVED"
	// ReasonCustomResourcesUnresolved: the documents cannot be read as one
	// apply set (an omitted document, an empty input, a document that is
	// not a Kubernetes object).
	ReasonCustomResourcesUnresolved Reason = "CUSTOM_RESOURCE_SHAPE_UNRESOLVED"
)

// CustomResourceScan is the custom-resource version preparation of one
// project over a workspace.
type CustomResourceScan struct {
	Prepared Prepared
	// Fact is the project's custom-resource version set fact.
	Fact string
	// Members maps every declared member to the documents that carry it,
	// in workspace order. Provenance only: it never enters an input.
	Members map[string][]intake.Source
	// Unattributed lists the documents of custom-resource groups the
	// reviewed table does not attribute to exactly one project.
	Unattributed []intake.Source
}

// CustomResourceProjects lists the projects of the reviewed table (CNCF
// catalog and community projects) that have a custom-resource version set,
// in table order.
func CustomResourceProjects() []string {
	var out []string
	for _, p := range customresources.Projects() {
		out = append(out, p.Slug)
	}
	return out
}

// CustomResourceVersionsFact returns the custom-resource version set fact
// of a CNCF catalog project, if it has one. A community project of the
// table has a registered fact too, but no CNCF check route (check cncf,
// scan) reads it: it is not a CNCF catalog project, and no rule or line
// review of it can be published yet.
func CustomResourceVersionsFact(project string) (string, bool) {
	p, ok := customresources.ProjectFor(project)
	if !ok || p.Community() {
		return "", false
	}
	return p.FactID(), true
}

// CommunityCustomResourceProject returns the table entry of a community
// project (outside the CNCF landscape catalog), so that a route can name it
// accurately when it refuses it.
func CommunityCustomResourceProject(project string) (customresources.Project, bool) {
	p, ok := customresources.ProjectFor(project)
	if !ok || !p.Community() {
		return customresources.Project{}, false
	}
	return p, true
}

// PrepareCustomResourceVersions declares, for one project and transition,
// the proposed-side set of group/version/Kind of every object of the
// project's own custom-resource groups in the workspace. The workspace is
// the complete apply set the caller declares (complete) or a part of it.
//
//   - An object is attributed to the project only when the reviewed table
//     lists its API group for that project and no other. Attribution is by
//     group, not kind: an object of another component that shares the group
//     (an Argo Rollout in argoproj.io) joins the owning project's set, which
//     is harmless while rules name only that project's kinds; see the
//     customresources table on shared groups.
//   - The set is declared complete only when complete is declared, no list
//     is paginated, every object of a custom-resource group is attributed to
//     exactly one project and every member is representable. Otherwise the
//     members found are declared with complete=false: a forbidden member
//     still blocks, and nothing passes.
//   - An apply set that cannot be resolved (templates, unparseable or
//     omitted documents, no document) declares only the members of the
//     documents that were read, with complete=false, so a forbidden member
//     still blocks; with no such member the fact is unsupported. An object
//     of a non-List kind with a top-level items array makes the fact
//     unsupported.
func PrepareCustomResourceVersions(workspace intake.Workspace, project, from, to string, complete bool) (CustomResourceScan, error) {
	return prepareCustomResourceVersions(customresources.DefaultIndex(), workspace, project, from, to, complete)
}

// PrepareCustomResourceVersionsBytes is PrepareCustomResourceVersions over
// one caller-supplied file of rendered manifests (YAML or JSON, one or
// more documents, v1 Lists flattened one level).
func PrepareCustomResourceVersionsBytes(raw []byte, project, from, to string, complete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	workspace, err := intake.Decode("input", raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	scan, err := PrepareCustomResourceVersions(workspace, project, from, to, complete)
	if err != nil {
		return Prepared{}, err
	}
	scan.Prepared.SourceDigest = digestBytes(raw)
	return scan.Prepared, nil
}

func prepareCustomResourceVersions(index customresources.Index, workspace intake.Workspace, project, from, to string, complete bool) (CustomResourceScan, error) {
	p, ok := customresources.ProjectFor(project)
	if !ok || !validVersionSyntax(from) || !validVersionSyntax(to) || constraintengine.SameVersion(from, to) {
		return CustomResourceScan{}, ErrInvalid
	}
	scan := CustomResourceScan{Fact: p.FactID(), Members: map[string][]intake.Source{}}
	finish := func(fact inputFact, state State, reason Reason) (CustomResourceScan, error) {
		canonical, err := marshalComponentInput(p.Component, from, to, []inputFact{fact})
		if err != nil {
			return CustomResourceScan{}, ErrInvalid
		}
		scan.Prepared = Prepared{
			CanonicalInputJSON: canonical, SourceDigest: workspace.Digest, InputDigest: digestBytes(canonical), State: state, Reason: reason,
			Omissions: []string{"SELECTED_RENDERED_APPLY_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION", "CUSTOM_RESOURCE_DEFINITIONS_STORED_OBJECTS_CONVERSION_AND_RUNTIME_NOT_EVALUATED"},
		}
		return scan, nil
	}
	unsupported := func(reason Reason) (CustomResourceScan, error) {
		scan.Members = map[string][]intake.Source{}
		return finish(inputFact{ID: p.FactID(), State: "unsupported"}, StateUnknown, reason)
	}
	set := kubernetesApplySetOf(workspace)
	documents := set.documents
	var unresolved Reason
	switch set.reason {
	case "":
	case ReasonKubernetesTemplated:
		unresolved, documents = ReasonCustomResourcesRendering, set.readable
	default:
		unresolved, documents = ReasonCustomResourcesUnresolved, set.readable
	}
	// kubernetesApplySetOf leaves the set unresolved, and the object out of
	// readable, for an object of any kind with a top-level items array.
	invalid := false
	for _, document := range documents {
		api, kind, _ := kubernetesGVK(document.value)
		group := customresources.GroupOf(api)
		if customresources.KubernetesGroup(group) {
			continue
		}
		owner, attribution := index.Owner(group)
		if attribution != customresources.Owned {
			scan.Unattributed = append(scan.Unattributed, document.source)
			continue
		}
		if owner != p.Slug {
			continue
		}
		member := api + "/" + kind
		if !constraintengine.ValidSetMember(member) {
			invalid = true
			continue
		}
		scan.Members[member] = append(scan.Members[member], document.source)
	}
	if len(scan.Members) > constraintengine.MaxSetMembers {
		return unsupported(ReasonCustomResourcesTooMany)
	}
	members := make([]string, 0, len(scan.Members))
	for member := range scan.Members {
		members = append(members, member)
	}
	sort.Strings(members)
	if unresolved != "" {
		if len(members) == 0 {
			scan.Unattributed = nil
			return unsupported(unresolved)
		}
		// Some documents could not be read or placed. The members of the
		// documents that were read form a set that is never complete: a
		// forbidden member present still decides, and nothing is taken as
		// absent.
		return finish(setFact(p.FactID(), members, false), StateUnknown, unresolved)
	}
	reason := ReasonCustomResourcesComplete
	switch {
	case !complete:
		reason = ReasonCustomResourcesScopeIncomplete
	case set.paginated:
		reason = ReasonCustomResourcesPaginated
	case len(scan.Unattributed) > 0:
		reason = ReasonCustomResourcesUnattributed
	case invalid:
		reason = ReasonCustomResourcesMemberInvalid
	}
	return finish(setFact(p.FactID(), members, reason == ReasonCustomResourcesComplete), StatePrepared, reason)
}
