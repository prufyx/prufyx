// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"strings"
	"testing"
)

func TestTableIsValid(t *testing.T) {
	if !Validate(table) {
		t.Fatal("reviewed table does not validate")
	}
	if len(table) == 0 {
		t.Fatal("empty table")
	}
	for _, p := range Projects() {
		if p.FactID() != "component."+p.FactProject+".custom_resource_versions_set" {
			t.Fatalf("%s: fact id %s", p.Slug, p.FactID())
		}
		for _, g := range p.Groups {
			if owner, attribution := DefaultIndex().Owner(g.Name); attribution != Owned || owner != p.Slug {
				t.Fatalf("group %s of %s: owner %q attribution %v", g.Name, p.Slug, owner, attribution)
			}
		}
	}
}

func TestValidateRefusesBadTables(t *testing.T) {
	good := func() []Project {
		return []Project{
			{Slug: "a", Catalog: CatalogCNCF, FactProject: "a", Component: "pkg:github/x/a", Groups: []Group{{Name: "a.example.io", Source: "https://github.com/x/a/blob/0123456789abcdef0123456789abcdef01234567/crds/a.yaml"}}},
			{Slug: "b", Catalog: CatalogCNCF, FactProject: "b", Component: "pkg:github/x/b", Groups: []Group{{Name: "b.example.io", Source: "https://github.com/x/b/blob/0123456789abcdef0123456789abcdef01234567/crds/b.yaml"}}},
		}
	}
	if !validate(good(), nil) {
		t.Fatal("good table refused")
	}
	cases := map[string]func(p []Project){
		"unsorted":                     func(p []Project) { p[0], p[1] = p[1], p[0] },
		"duplicate slug":               func(p []Project) { p[1].Slug = "a" },
		"kubernetes group":             func(p []Project) { p[0].Groups[0].Name = "apps" },
		"k8s.io group":                 func(p []Project) { p[0].Groups[0].Name = "gateway.networking.k8s.io" },
		"no groups":                    func(p []Project) { p[0].Groups = nil },
		"unpinned source":              func(p []Project) { p[0].Groups[0].Source = "https://github.com/x/a/blob/main/crds/a.yaml" },
		"bad group":                    func(p []Project) { p[0].Groups[0].Name = "A.example.io" },
		"bad fact project":             func(p []Project) { p[0].FactProject = "a-b" },
		"group listed twice":           func(p []Project) { p[0].Groups = append(p[0].Groups, p[0].Groups[0]) },
		"other component":              func(p []Project) { p[0].Component = "a" },
		"x-k8s.io group":               func(p []Project) { p[0].Groups[0].Name = "a.x-k8s.io" },
		"kubernetes.io group":          func(p []Project) { p[0].Groups[0].Name = "a.kubernetes.io" },
		"no catalog":                   func(p []Project) { p[0].Catalog = "" },
		"unknown catalog":              func(p []Project) { p[0].Catalog = "landscape" },
		"cncf provenance":              func(p []Project) { p[0].Upstream = Upstream{Name: "A"} },
		"community without provenance": func(p []Project) { p[0].Catalog = CatalogCommunity },
	}
	for name, mutate := range cases {
		p := good()
		mutate(p)
		if validate(p, nil) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestKubernetesGroup(t *testing.T) {
	for group, want := range map[string]bool{
		"":                          true,
		"apps":                      true,
		"batch":                     true,
		"networking.k8s.io":         true,
		"gateway.networking.k8s.io": false, // reviewed: Gateway API CRDs
		"storage.k8s.io":            true,
		"snapshot.storage.k8s.io":   true, // no record: stays a Kubernetes group
		"apiextensions.k8s.io":      true,
		"k8s.io":                    false,
		"cluster.x-k8s.io":          false,
		"kafka.strimzi.io":          false,
		"argoproj.io":               false,
		"k8s.io.example.com":        false,
	} {
		if got := KubernetesGroup(group); got != want {
			t.Errorf("KubernetesGroup(%q) = %v, want %v", group, got, want)
		}
	}
	for api, want := range map[string]string{"v1": "", "apps/v1": "apps", "kafka.strimzi.io/v1beta2": "kafka.strimzi.io"} {
		if got := GroupOf(api); got != want {
			t.Errorf("GroupOf(%q) = %q", api, got)
		}
	}
}

// Only an exact, listed group of exactly one project is attributed: an
// unknown group (even one that shares a suffix with a listed group) and a
// group two projects list are attributed to nobody.
func TestOwnerRefusesUnknownAndAmbiguousGroups(t *testing.T) {
	x := DefaultIndex()
	for _, group := range []string{"access.strimzi.io", "strimzi.io", "kafka.strimzi.io.example.com", "KAFKA.STRIMZI.IO", "istio.io", "install.istio.io", "argoproj.io.", "postgres-operator.crunchydata.com", "infrastructure.cluster.x-k8s.io", ""} {
		if owner, attribution := x.Owner(group); attribution != Unknown || owner != "" {
			t.Errorf("%q attributed to %q (%v)", group, owner, attribution)
		}
	}
	if owner, attribution := x.Owner("kafka.strimzi.io"); attribution != Owned || owner != "strimzi" {
		t.Fatalf("kafka.strimzi.io: %q %v", owner, attribution)
	}
	shared := []Project{
		{Slug: "a", Groups: []Group{{Name: "shared.example.io"}, {Name: "a.example.io"}}},
		{Slug: "b", Groups: []Group{{Name: "shared.example.io"}}},
	}
	y := NewIndex(shared)
	if owner, attribution := y.Owner("shared.example.io"); attribution != Ambiguous || owner != "" {
		t.Fatalf("shared group: %q %v", owner, attribution)
	}
	if owner, attribution := y.Owner("a.example.io"); attribution != Owned || owner != "a" {
		t.Fatalf("own group: %q %v", owner, attribution)
	}
}

func TestProjectsIsACopy(t *testing.T) {
	p := Projects()
	p[0].Groups[0].Name = "changed.example.io"
	p[0].Slug = "changed"
	if table[0].Groups[0].Name == "changed.example.io" || table[0].Slug == "changed" {
		t.Fatal("Projects exposes the table")
	}
	if _, ok := ProjectFor("strimzi"); !ok {
		t.Fatal("strimzi missing")
	}
	if _, ok := ProjectFor("kubernetes"); ok {
		t.Fatal("kubernetes listed")
	}
}

// community returns a valid community project of a synthetic table.
func community(slug, repo string, groups ...string) Project {
	p := Project{Slug: slug, Catalog: CatalogCommunity, FactProject: strings.ReplaceAll(slug, "-", "_"), Component: "pkg:github/" + repo,
		Upstream: Upstream{Name: "Project " + slug, Repository: "https://github.com/" + repo, License: "Apache-2.0", LicenseSource: "https://github.com/" + repo + "/blob/0123456789abcdef0123456789abcdef01234567/LICENSE"}}
	for _, g := range groups {
		p.Groups = append(p.Groups, Group{Name: g, Source: "https://github.com/" + repo + "/blob/0123456789abcdef0123456789abcdef01234567/crds/" + g + ".yaml"})
	}
	return p
}

// A group of a Kubernetes-reserved namespace is listed only through a
// reviewed ownership record that names the listing project and its
// repository, and every record is listed by its owner alone. An overlap
// (two projects, another owner, another repository, a dangling record) is
// refused, never resolved by suffix or order.
func TestValidateReservedGroupOwnership(t *testing.T) {
	records := []ReservedGroup{
		{Name: "gw.networking.k8s.io", Owner: "gw", Repository: "https://github.com/sigs/gw", Reason: "defined by the gw repository's CRDs only"},
		{Name: "q.x-k8s.io", Owner: "q", Repository: "https://github.com/sigs/q", Reason: "defined by the q repository's CRDs only"},
	}
	good := func() []Project {
		return []Project{community("gw", "sigs/gw", "gw.networking.k8s.io"), community("q", "sigs/q", "q.x-k8s.io")}
	}
	if !validate(good(), records) {
		t.Fatal("good table refused")
	}
	if validate(good(), nil) {
		t.Fatal("reserved groups accepted without records")
	}
	cases := map[string]func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup){
		"second project lists the group": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			p[1].Groups = append([]Group{{Name: "gw.networking.k8s.io", Source: p[1].Groups[0].Source}}, p[1].Groups...)
			return p, r
		},
		"record names another owner": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			r[1].Owner = "gw"
			return p, r
		},
		"record names another repository": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			r[0].Repository = "https://github.com/fork/gw"
			return p, r
		},
		"two records for one group": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			return p, append(r, r[1])
		},
		"dangling record": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			return p, append(r, ReservedGroup{Name: "z.x-k8s.io", Owner: "q", Repository: "https://github.com/sigs/q", Reason: "defined by nobody in this table"})
		},
		"record outside the reserved namespaces": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			p[1].Groups[0].Name = "q.example.io"
			r[1].Name = "q.example.io"
			return p, r
		},
		"record without a reason": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			r[0].Reason = ""
			return p, r
		},
		"unsorted records": func(p []Project, r []ReservedGroup) ([]Project, []ReservedGroup) {
			r[0], r[1] = r[1], r[0]
			return p, r
		},
	}
	for name, mutate := range cases {
		r := append([]ReservedGroup(nil), records...)
		p, r := mutate(good(), r)
		if validate(p, r) {
			t.Errorf("%s accepted", name)
		}
	}
}

// A community project carries its own provenance: the repository its
// component names and that repository's licence file at a full commit.
func TestValidateCommunityProvenance(t *testing.T) {
	if !validate([]Project{community("a", "x/a", "a.example.io")}, nil) {
		t.Fatal("good community project refused")
	}
	for name, mutate := range map[string]func(p *Project){
		"no name":             func(p *Project) { p.Upstream.Name = "" },
		"other repository":    func(p *Project) { p.Upstream.Repository = "https://github.com/x/b" },
		"no licence":          func(p *Project) { p.Upstream.License = "" },
		"licence with spaces": func(p *Project) { p.Upstream.License = "Apache 2.0" },
		"licence of another repo": func(p *Project) {
			p.Upstream.LicenseSource = "https://github.com/x/b/blob/0123456789abcdef0123456789abcdef01234567/LICENSE"
		},
		"unpinned licence": func(p *Project) { p.Upstream.LicenseSource = "https://github.com/x/a/blob/main/LICENSE" },
		"licence file not a licence": func(p *Project) {
			p.Upstream.LicenseSource = "https://github.com/x/a/blob/0123456789abcdef0123456789abcdef01234567/README.md"
		},
	} {
		p := community("a", "x/a", "a.example.io")
		mutate(&p)
		if validate([]Project{p}, nil) {
			t.Errorf("%s accepted", name)
		}
	}
}

// Every reviewed ownership record names a project of the table that lists
// the group, that project's repository, and a group kube-apiserver's
// suffix rule would otherwise claim or a reserved SIG namespace.
func TestReservedGroupsAreOwnedByTheirRepository(t *testing.T) {
	records := ReservedGroups()
	if len(records) == 0 {
		t.Fatal("no reviewed reserved group")
	}
	index := DefaultIndex()
	for _, r := range records {
		p, ok := ProjectFor(r.Owner)
		if !ok || r.Repository != "https://github.com/"+strings.TrimPrefix(p.Component, "pkg:github/") {
			t.Fatalf("%s: owner %s / repository %s", r.Name, r.Owner, r.Repository)
		}
		if owner, attribution := index.Owner(r.Name); attribution != Owned || owner != r.Owner {
			t.Fatalf("%s: attributed to %q (%v)", r.Name, owner, attribution)
		}
		if KubernetesGroup(r.Name) || !ReservedNamespace(r.Name) {
			t.Fatalf("%s: Kubernetes group %v, reserved %v", r.Name, KubernetesGroup(r.Name), ReservedNamespace(r.Name))
		}
	}
	// Reserved groups the table must never attribute: an API several
	// projects implement and provider namespaces of Cluster API.
	for _, group := range []string{"multicluster.x-k8s.io", "infrastructure.cluster.x-k8s.io", "bootstrap.cluster.x-k8s.io", "controlplane.cluster.x-k8s.io", "ipam.cluster.x-k8s.io", "addons.cluster.x-k8s.io", "gateway.networking.x-k8s.io", "snapshot.storage.k8s.io", "topology.node.k8s.io", "scheduling.sigs.k8s.io"} {
		if owner, attribution := index.Owner(group); attribution != Unknown {
			t.Errorf("%s attributed to %q (%v)", group, owner, attribution)
		}
	}
}

// Community projects are labelled as such and never as CNCF projects.
func TestCommunityProjectsAreLabelled(t *testing.T) {
	n := 0
	for _, p := range Projects() {
		if !p.Community() {
			if p.Label() != "CNCF catalog" || p.Upstream != (Upstream{}) {
				t.Fatalf("%s: %q %+v", p.Slug, p.Label(), p.Upstream)
			}
			continue
		}
		n++
		if p.Label() != CommunityLabel || strings.Contains(strings.ToLower(p.Upstream.Name), "cncf") {
			t.Fatalf("%s: label %q name %q", p.Slug, p.Label(), p.Upstream.Name)
		}
	}
	if n == 0 {
		t.Fatal("no community project")
	}
	if !strings.Contains(CommunityLabel, "no CNCF status asserted") || strings.Contains(CommunityLabel, "not a CNCF project") {
		t.Fatalf("label %q", CommunityLabel)
	}
}
