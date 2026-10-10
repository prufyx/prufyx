// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import "testing"

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
			{Slug: "a", FactProject: "a", Component: "pkg:github/x/a", Groups: []Group{{Name: "a.example.io", Source: "https://github.com/x/a/blob/0123456789abcdef0123456789abcdef01234567/crds/a.yaml"}}},
			{Slug: "b", FactProject: "b", Component: "pkg:github/x/b", Groups: []Group{{Name: "b.example.io", Source: "https://github.com/x/b/blob/0123456789abcdef0123456789abcdef01234567/crds/b.yaml"}}},
		}
	}
	if !Validate(good()) {
		t.Fatal("good table refused")
	}
	cases := map[string]func(p []Project){
		"unsorted":           func(p []Project) { p[0], p[1] = p[1], p[0] },
		"duplicate slug":     func(p []Project) { p[1].Slug = "a" },
		"kubernetes group":   func(p []Project) { p[0].Groups[0].Name = "apps" },
		"k8s.io group":       func(p []Project) { p[0].Groups[0].Name = "gateway.networking.k8s.io" },
		"no groups":          func(p []Project) { p[0].Groups = nil },
		"unpinned source":    func(p []Project) { p[0].Groups[0].Source = "https://github.com/x/a/blob/main/crds/a.yaml" },
		"bad group":          func(p []Project) { p[0].Groups[0].Name = "A.example.io" },
		"bad fact project":   func(p []Project) { p[0].FactProject = "a-b" },
		"group listed twice": func(p []Project) { p[0].Groups = append(p[0].Groups, p[0].Groups[0]) },
		"other component":    func(p []Project) { p[0].Component = "a" },
	}
	for name, mutate := range cases {
		p := good()
		mutate(p)
		if Validate(p) {
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
		"gateway.networking.k8s.io": true,
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
	for _, group := range []string{"access.strimzi.io", "strimzi.io", "kafka.strimzi.io.example.com", "KAFKA.STRIMZI.IO", "istio.io", "install.istio.io", "argoproj.io.", "monitoring.coreos.com", ""} {
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
