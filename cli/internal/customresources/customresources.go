// SPDX-License-Identifier: AGPL-3.0-only

// Package customresources is the reviewed table of projects whose
// CustomResourceDefinition manifests the crd.version-removal extractor
// reads, and of the API groups those manifests define. A project is either
// a project of the embedded CNCF landscape catalog or a community project:
// a project outside that catalog, listed here with its reviewed upstream
// provenance (repository and licence) and never described as a CNCF
// project. It is the one place that says which custom-resource group
// belongs to which project:
//
//   - the fact registry registers one custom-resource version set fact per
//     project of the table, and no other;
//   - the preparation attributes an object to a project only when its API
//     group and kind are listed for exactly that project: a group listed
//     without kinds belongs whole to its one project, and a group several
//     projects share is listed with disjoint kinds for each. A group or kind
//     the table does not list, or lists for more than one project, is never
//     attributed to any project, by suffix, by name or otherwise.
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
	// Kinds are the kinds of the group the project owns, sorted and unique.
	// Nil lists the whole group for the project. A group several projects
	// list names kinds in every listing, and the sets are pairwise disjoint.
	Kinds []string `json:",omitempty"`
}

// Catalog names the catalog a project of the table belongs to.
type Catalog string

const (
	// CatalogCNCF: a project of the embedded CNCF landscape catalog,
	// whose identity that catalog carries.
	CatalogCNCF Catalog = "cncf"
	// CatalogCommunity: a project outside the CNCF landscape catalog. Its
	// identity is the reviewed Upstream record of this table, and nothing
	// about it asserts CNCF status. Its version set fact is registered.
	// The pack can carry rules for it (its own pack schema level) and the
	// knowledge store a per-project target for it; a route reads it only
	// once the knowledge holds data for it, and every output labels it with
	// CommunityLabel. It carries no line review: the line-review family
	// admits no community component.
	CatalogCommunity Catalog = "community"
)

// Upstream is the reviewed provenance of a community project: its public
// name, the upstream repository its component names, and the licence of
// that repository, cited from the licence file at a full commit.
type Upstream struct {
	Name          string
	Repository    string
	License       string
	LicenseSource string
}

// Project is one project of the table.
type Project struct {
	// Slug is the catalog project slug: a CNCF landscape catalog slug, or
	// for a community project a slug that is not one.
	Slug string
	// Catalog is the catalog the project belongs to.
	Catalog Catalog
	// Upstream is the provenance of a community project; it is empty for
	// a CNCF catalog project.
	Upstream Upstream
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

// Community reports whether the project is a community project (outside
// the CNCF landscape catalog).
func (p Project) Community() bool { return p.Catalog == CatalogCommunity }

// Label is the user-facing catalog label of the project.
func (p Project) Label() string {
	if p.Community() {
		return CommunityLabel
	}
	return "CNCF catalog"
}

// CommunityLabel is how every user-facing text names a community project's
// catalog: it says what Prufyx knows (the project is not in the CNCF
// landscape catalog Prufyx embeds) and asserts nothing about CNCF status.
// Some community projects are Kubernetes SIG subprojects, so "not a CNCF
// project" would be wrong for them.
const CommunityLabel = "community catalog (not in the embedded CNCF landscape catalog; no CNCF status asserted)"

// FactID is the custom-resource version set fact of a fact project.
func FactID(factProject string) string {
	return "component." + factProject + ".custom_resource_versions_set"
}

// table is the reviewed table, ordered by slug, and reserved the reviewed
// ownership list, ordered by group name; both are read from table.json.
// Every source of the table is the manifest whose spec.group line names the
// group, at the commit the extractor's paths were checked at.
//
// Shared groups: argoproj.io is defined upstream by Argo CD and by Argo
// Workflows, Rollouts and Events. Today the group is listed once, whole, for
// argo-cd, so objects of the other Argo components (a Rollout, a Workflow)
// join argo-cd's set. That is harmless while rules name only Argo CD's own
// kinds. Once the group is listed with kinds per project, an object joins the
// set of the project that lists its kind, and an argoproj.io kind nobody
// lists joins no set and keeps every set incomplete (never a false pass).
// Listing the group whole for a second project is refused by Validate.
//
// wgpolicyk8s.io (Kyverno) and objectbucket.io (Rook) are also installed by
// other software: the Kubernetes Policy WG report group by Trivy operator and
// similar tools, objectbucket.io by lib-bucket-provisioner and NooBaa. They are
// unique within this table, so the objects join the owning project's set; a
// foreign object can only add a member (a PASS may turn into BLOCKED, never the
// reverse). When a rule over these groups is derived, its review must consider
// the other installers.
//
// A group several projects define is listed with kinds in every listing, the
// kind sets disjoint (Validate refuses anything else), and an object is
// attributed by (group, kind) (Index.OwnerOf). A kind no listing names is
// attributed to no project and keeps every set incomplete. A group listed
// without kinds belongs whole to its one project and cannot be shared.
//
// Community projects list only groups they define themselves. The Percona
// Operator for PostgreSQL ships Crunchy Data's postgres-operator.crunchydata.com
// CRDs (it is a fork, up to its 2.x lines): that group belongs to Crunchy
// Data's operator, so it is not listed for Percona, and its objects keep
// every set incomplete. Groups in the namespaces Kubernetes reserves are
// listed only with a reviewed ownership record (reserved).
//
// Reserved groups not listed, so attributed to no project: the provider
// namespaces of Cluster API (addons, bootstrap, controlplane, infrastructure
// and ipam .cluster.x-k8s.io), whose CRDs other providers define too (the Helm
// add-on provider, the RKE2 and Talos bootstrap and control-plane
// providers, cloud providers, IPAM providers); the experimental Gateway API
// group gateway.networking.x-k8s.io (its CRDs lie outside the standard
// channel the extractor reads); the multicluster services API
// multicluster.x-k8s.io (Karmada and Antrea both ship it);
// snapshot.storage.k8s.io and topology.node.k8s.io (shipped by several
// projects, none of which is in the table as its definer). An object of
// such a group keeps every set incomplete, which never passes.
var table, reserved = mustLoadTable(tableJSON)

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

// CommunityProjects returns copies of the community projects of the table
// (outside the CNCF landscape catalog), ordered by slug.
func CommunityProjects() []Project {
	var out []Project
	for _, p := range table {
		if p.Community() {
			out = append(out, p)
		}
	}
	return copyProjects(out)
}

// IsCommunity reports whether a slug is a community project of the table.
func IsCommunity(slug string) bool {
	for _, p := range table {
		if p.Slug == slug {
			return p.Community()
		}
	}
	return false
}

func copyProjects(in []Project) []Project {
	out := make([]Project, len(in))
	for i, p := range in {
		out[i] = p
		out[i].Groups = make([]Group, len(p.Groups))
		for j, g := range p.Groups {
			out[i].Groups[j] = g
			out[i].Groups[j].Kinds = cloneKinds(g.Kinds)
		}
		if p.Groups == nil {
			out[i].Groups = nil
		}
	}
	return out
}

// cloneKinds copies a kinds list and keeps nil (the whole group) apart from
// an empty list.
func cloneKinds(kinds []string) []string {
	if kinds == nil {
		return nil
	}
	out := make([]string, len(kinds))
	copy(out, kinds)
	return out
}

// KubernetesGroup reports whether an API group is a Kubernetes group: the
// core group (empty), any group without a dot (apps, batch, policy, ...)
// and every group ending in ".k8s.io", except a group of the reviewed
// reserved-group ownership list (ReservedGroups): that group is defined by
// CustomResourceDefinitions of one upstream project, kube-apiserver does
// not serve it, and it is a custom resource group. Every other group is a
// custom resource group. Scan's served-API check covers exactly the
// Kubernetes groups, so every group is covered by one of the two.
func KubernetesGroup(group string) bool {
	if !strings.Contains(group, ".") {
		return true
	}
	return strings.HasSuffix(group, ".k8s.io") && !reviewedReserved(reserved, group)
}

// ReservedNamespace reports whether an API group lies in a namespace the
// Kubernetes project reserves for its own APIs and those of its SIG
// subprojects: k8s.io, x-k8s.io and kubernetes.io and their subdomains.
// Such a group may be defined by kube-apiserver, by a SIG subproject's
// CustomResourceDefinitions, or (x-k8s.io) by an API several projects
// implement, so the table lists one only through a reviewed ownership
// record (ReservedGroup) and never by its suffix.
func ReservedNamespace(group string) bool {
	for _, ns := range []string{"k8s.io", "x-k8s.io", "kubernetes.io"} {
		if group == ns || strings.HasSuffix(group, "."+ns) {
			return true
		}
	}
	return false
}

// ReservedGroup is a reviewed ownership record: an API group in a
// Kubernetes-reserved namespace that the CustomResourceDefinitions of one
// upstream repository define, and that kube-apiserver does not serve. The
// owner must list the group in the table, its component must name exactly
// that repository, and no other project may list the group. A group of a
// reserved namespace without a record is never listed (Validate refuses
// it): a .k8s.io group stays a Kubernetes group, and any other reserved
// group, like an API that several projects implement
// (multicluster.x-k8s.io) or a provider namespace
// (infrastructure.cluster.x-k8s.io), belongs to no project.
type ReservedGroup struct {
	Name string
	// Owner is the table slug of the project that defines the group.
	Owner string
	// Repository is the upstream repository whose CustomResourceDefinitions
	// define the group, https://github.com/<owner>/<name>.
	Repository string
	// Reason says why the group belongs to that repository alone.
	Reason string
}

// ReservedGroups returns a copy of the reviewed ownership list.
func ReservedGroups() []ReservedGroup { return append([]ReservedGroup(nil), reserved...) }

func reviewedReserved(records []ReservedGroup, group string) bool {
	for _, r := range records {
		if r.Name == group {
			return true
		}
	}
	return false
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
	owners   map[string][]string
	listings map[string][]listing
}

// listing is one project's listing of a group.
type listing struct {
	slug  string
	kinds []string
}

// NewIndex indexes a table. A group listed by two projects is ambiguous for
// Owner, never attributed to either; OwnerOf tells projects that list
// disjoint kinds of it apart.
func NewIndex(projects []Project) Index {
	owners := map[string][]string{}
	listings := map[string][]listing{}
	for _, p := range projects {
		for _, g := range p.Groups {
			if !containsString(owners[g.Name], p.Slug) {
				owners[g.Name] = append(owners[g.Name], p.Slug)
			}
			listings[g.Name] = append(listings[g.Name], listing{slug: p.Slug, kinds: cloneKinds(g.Kinds)})
		}
	}
	for _, slugs := range owners {
		sort.Strings(slugs)
	}
	return Index{owners: owners, listings: listings}
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

// OwnerOf returns the project an object of a group and kind belongs to. A
// listing without kinds matches every kind of its group; a listing with kinds
// matches exactly those kinds (exact, case-sensitive match, as Kubernetes
// kinds are). Exactly one matching project is Owned, none is Unknown, and
// more than one is Ambiguous (a table that Validate refuses; the index
// fails closed all the same). A listing with an empty non-nil kinds list
// matches nothing. Without kinds anywhere in the table OwnerOf(group, kind)
// equals Owner(group) for every kind.
func (x Index) OwnerOf(group, kind string) (string, Attribution) {
	var matched []string
	for _, l := range x.listings[group] {
		if (l.kinds == nil || containsString(l.kinds, kind)) && !containsString(matched, l.slug) {
			matched = append(matched, l.slug)
		}
	}
	switch len(matched) {
	case 0:
		return "", Unknown
	case 1:
		return matched[0], Owned
	}
	return "", Ambiguous
}

// ListingsSharing returns, in a canonical sorted form, every listing (group,
// project slug and kinds) of every group the project lists itself, the
// project's own listings and those of any project sharing the group. It
// moves exactly when attribution of the project's groups changes, and not on
// edits of other groups. It is empty when the project has no listing.
// A listing without kinds reads "*", one with kinds "[k1,k2]".
func (x Index) ListingsSharing(slug string) []string {
	var out []string
	for group, ls := range x.listings {
		mine := false
		for _, l := range ls {
			mine = mine || l.slug == slug
		}
		if !mine {
			continue
		}
		for _, l := range ls {
			kinds := "*"
			if l.kinds != nil {
				kinds = "[" + strings.Join(l.kinds, ",") + "]"
			}
			out = append(out, group+" "+l.slug+" "+kinds)
		}
	}
	sort.Strings(out)
	return out
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
	// licenseRE is an SPDX licence expression of identifiers joined by OR
	// or AND (LicenseRef-* for a licence SPDX does not list).
	licenseRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}( (OR|AND) [A-Za-z0-9][A-Za-z0-9.+-]{0,63}){0,3}$`)
	licenseFileRE = regexp.MustCompile(`^/blob/[0-9a-f]{40}/(LICENSE|COPYING)([.-][A-Za-z0-9]{1,16})?$`)
	kindRE        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,62}$`)
)

// maxKindsPerGroup bounds the kinds one listing names (the size of a
// version set fact).
const maxKindsPerGroup = 256

// validKinds: nil is the whole group; otherwise a non-empty, sorted,
// unique list of well-formed kinds of bounded size.
func validKinds(kinds []string) bool {
	if kinds == nil {
		return true
	}
	if len(kinds) == 0 || len(kinds) > maxKindsPerGroup {
		return false
	}
	for i, k := range kinds {
		if !kindRE.MatchString(k) || (i > 0 && kinds[i-1] >= k) {
			return false
		}
	}
	return true
}

// Validate checks a table against the reviewed ownership list: slugs
// ascending and unique, well-formed fact projects and components, a known
// catalog, provenance exactly for community projects, and every group a
// custom resource group, named once per project, with a source pinned by
// full commit SHA. A group may name kinds (sorted, unique, well-formed); a
// group listed by more than one project names kinds in every listing and the
// kind sets are pairwise disjoint, so no (group, kind) has two owners. A
// group of a Kubernetes-reserved namespace needs a
// reviewed ownership record naming that project and its repository, and
// every record must be listed by its owner and by no other project, whole
// (a reserved group names no kinds).
func Validate(projects []Project) bool { return validate(projects, reserved) }

func validate(projects []Project, records []ReservedGroup) bool {
	listed := map[string][]string{}
	listedKinds := map[string][][]string{}
	for i, p := range projects {
		if !slugRE.MatchString(p.Slug) || !factProjectRE.MatchString(p.FactProject) || !strings.HasPrefix(p.Component, "pkg:github/") || len(p.Groups) == 0 {
			return false
		}
		if i > 0 && projects[i-1].Slug >= p.Slug {
			return false
		}
		repository := "https://github.com/" + strings.TrimPrefix(p.Component, "pkg:github/")
		switch p.Catalog {
		case CatalogCNCF:
			if p.Upstream != (Upstream{}) {
				return false
			}
		case CatalogCommunity:
			u := p.Upstream
			license, found := strings.CutPrefix(u.LicenseSource, repository)
			if strings.TrimSpace(u.Name) != u.Name || u.Name == "" || len(u.Name) > 64 || u.Repository != repository || !licenseRE.MatchString(u.License) || !found || !licenseFileRE.MatchString(license) {
				return false
			}
		default:
			return false
		}
		for j, g := range p.Groups {
			if len(g.Name) > 253 || !groupRE.MatchString(g.Name) || !sourceRE.MatchString(g.Source) {
				return false
			}
			if j > 0 && p.Groups[j-1].Name >= g.Name {
				return false
			}
			if !validKinds(g.Kinds) {
				return false
			}
			if ReservedNamespace(g.Name) {
				if g.Kinds != nil || !ownsReserved(records, g.Name, p.Slug, repository) {
					return false
				}
			} else if !strings.Contains(g.Name, ".") {
				return false
			}
			listed[g.Name] = append(listed[g.Name], p.Slug)
			listedKinds[g.Name] = append(listedKinds[g.Name], g.Kinds)
		}
	}
	// A group several projects list needs kinds in every listing, and no kind
	// in two listings.
	for _, lists := range listedKinds {
		if len(lists) < 2 {
			continue
		}
		seen := map[string]bool{}
		for _, kinds := range lists {
			if kinds == nil {
				return false
			}
			for _, k := range kinds {
				if seen[k] {
					return false
				}
				seen[k] = true
			}
		}
	}
	for i, r := range records {
		if i > 0 && records[i-1].Name >= r.Name {
			return false
		}
		if !ReservedNamespace(r.Name) || strings.TrimSpace(r.Reason) != r.Reason || len(r.Reason) < 12 || len(r.Reason) > 300 {
			return false
		}
		// Every record is listed by its owner and by no other project: an
		// overlap is refused here, and would make the group ambiguous (never
		// attributed) at run time.
		if len(listed[r.Name]) != 1 || listed[r.Name][0] != r.Owner {
			return false
		}
	}
	return true
}

// ownsReserved reports whether exactly one record names the group, for
// that owner and repository.
func ownsReserved(records []ReservedGroup, group, owner, repository string) bool {
	n := 0
	for _, r := range records {
		if r.Name != group {
			continue
		}
		n++
		if r.Owner != owner || r.Repository != repository {
			return false
		}
	}
	return n == 1
}
