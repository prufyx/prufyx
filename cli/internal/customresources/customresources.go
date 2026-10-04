// SPDX-License-Identifier: AGPL-3.0-only

// Package customresources is the reviewed table of catalog projects whose
// CustomResourceDefinition manifests the crd.version-removal extractor
// reads, and of the API groups those manifests define. It is the one place
// that says which custom-resource group belongs to which project:
//
//   - the fact registry registers one custom-resource version set fact per
//     project of the table, and no other;
//   - the preparation attributes an object to a project only when its API
//     group is listed for exactly that project. A group the table does not
//     list, or lists for more than one project, is never attributed to any
//     project, by suffix, by name or otherwise.
//
// The table holds no versions and no rules: what a release serves is
// derived by the extractor and published only through the knowledge gate.
// A test pins the projects to the extractor's target table.
package customresources

import (
	"regexp"
	"sort"
	"strings"
)

// Group is one API group a project's CustomResourceDefinitions define, and
// the upstream manifest, pinned by full commit, that defines it.
type Group struct {
	Name   string
	Source string
}

// Project is one catalog project of the table.
type Project struct {
	// Slug is the catalog project slug.
	Slug string
	// FactProject is the project part of the fact id
	// component.<FactProject>.custom_resource_versions_set.
	FactProject string
	// Component is the catalog component identity the fact belongs to.
	Component string
	// Groups are the API groups of the project's CustomResourceDefinitions.
	Groups []Group
}

// FactID is the project's custom-resource version set fact.
func (p Project) FactID() string { return FactID(p.FactProject) }

// FactID is the custom-resource version set fact of a fact project.
func FactID(factProject string) string {
	return "component." + factProject + ".custom_resource_versions_set"
}

// table is the reviewed table, ordered by slug. Every source is the
// manifest whose spec.group line names the group, at the commit the
// extractor's paths were checked at.
//
// Shared groups: argoproj.io is defined upstream by Argo CD and by Argo
// Workflows, Rollouts and Events. The catalog project argo-cd is the whole
// Argo project, so the group is listed once, for argo-cd, and objects of the
// other Argo components (a Rollout, a Workflow) join argo-cd's set. That is
// harmless while rules name only Argo CD's own kinds. Listing argoproj.io for
// a second project would make it ambiguous: every argoproj.io object would
// then join no set and keep every set incomplete, so a removed Argo CD
// version would no longer block (a missed blocker, never a false pass).
// Before a second project shares a group, attribution must move to
// (group, kind), with kinds taken from the extractor inventory.
var table = []Project{
	{
		Slug: "argo-cd", FactProject: "argo_cd", Component: "pkg:github/argoproj/argo-cd",
		Groups: []Group{
			{Name: "argoproj.io", Source: "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml"},
		},
	},
	{
		Slug: "istio", FactProject: "istio", Component: "pkg:github/istio/istio",
		Groups: []Group{
			{Name: "extensions.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "networking.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "security.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "telemetry.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
		},
	},
	{
		Slug: "strimzi", FactProject: "strimzi", Component: "pkg:github/strimzi/strimzi-kafka-operator",
		Groups: []Group{
			{Name: "core.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/042-Crd-strimzipodset.yaml"},
			{Name: "kafka.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/040-Crd-kafka.yaml"},
		},
	},
}

// Projects returns a copy of the reviewed table, ordered by slug.
func Projects() []Project { return copyProjects(table) }

// ProjectFor returns the table entry of a catalog slug.
func ProjectFor(slug string) (Project, bool) {
	for _, p := range table {
		if p.Slug == slug {
			return copyProjects([]Project{p})[0], true
		}
	}
	return Project{}, false
}

func copyProjects(in []Project) []Project {
	out := make([]Project, len(in))
	for i, p := range in {
		out[i] = p
		out[i].Groups = append([]Group(nil), p.Groups...)
	}
	return out
}

// KubernetesGroup reports whether an API group is a Kubernetes group: the
// core group (empty), any group without a dot (apps, batch, policy, ...)
// and every group ending in ".k8s.io". Every other group is a custom
// resource group. Scan's served-API check covers exactly the Kubernetes
// groups, so every group is covered by one of the two.
func KubernetesGroup(group string) bool {
	return !strings.Contains(group, ".") || strings.HasSuffix(group, ".k8s.io")
}

// GroupOf returns the API group of an apiVersion ("" for "v1").
func GroupOf(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}

// Attribution says whether a custom resource group belongs to a project.
type Attribution int

const (
	// Unknown: no project of the table lists the group.
	Unknown Attribution = iota
	// Owned: exactly one project lists the group.
	Owned
	// Ambiguous: more than one project lists the group.
	Ambiguous
)

// Index attributes custom resource groups to projects.
type Index struct {
	owners map[string][]string
}

// NewIndex indexes a table. A group listed by two projects is ambiguous,
// never attributed to either.
func NewIndex(projects []Project) Index {
	owners := map[string][]string{}
	for _, p := range projects {
		for _, g := range p.Groups {
			if !containsString(owners[g.Name], p.Slug) {
				owners[g.Name] = append(owners[g.Name], p.Slug)
			}
		}
	}
	for _, slugs := range owners {
		sort.Strings(slugs)
	}
	return Index{owners: owners}
}

// DefaultIndex indexes the reviewed table.
func DefaultIndex() Index { return NewIndex(table) }

// Owner returns the project a group belongs to. Only an exact, listed,
// unambiguous group is Owned; the slug is empty otherwise.
func (x Index) Owner(group string) (string, Attribution) {
	slugs := x.owners[group]
	switch len(slugs) {
	case 0:
		return "", Unknown
	case 1:
		return slugs[0], Owned
	}
	return "", Ambiguous
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

var (
	slugRE        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	factProjectRE = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	groupRE       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	sourceRE      = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/blob/[0-9a-f]{40}/[A-Za-z0-9_./-]+\.ya?ml$`)
)

// Validate checks a table: slugs ascending and unique, well-formed fact
// projects and components, and every group a custom resource group, named
// once per project, with a source pinned by full commit SHA.
func Validate(projects []Project) bool {
	for i, p := range projects {
		if !slugRE.MatchString(p.Slug) || !factProjectRE.MatchString(p.FactProject) || !strings.HasPrefix(p.Component, "pkg:github/") || len(p.Groups) == 0 {
			return false
		}
		if i > 0 && projects[i-1].Slug >= p.Slug {
			return false
		}
		for j, g := range p.Groups {
			if len(g.Name) > 253 || !groupRE.MatchString(g.Name) || KubernetesGroup(g.Name) || !sourceRE.MatchString(g.Source) {
				return false
			}
			if j > 0 && p.Groups[j-1].Name >= g.Name {
				return false
			}
		}
	}
	return true
}
