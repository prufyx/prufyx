// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"sort"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/imageidentity"
)

// reviewedRouteComponents binds each catalog member of the image registry to
// the component the catalog's own check routes name for it. The two sides use
// different identities for some projects (a source repository versus an image
// repository), so the pairing is reviewed here, not derived. A typo in a
// registry component, or a catalog route that moves, fails this test.
var reviewedRouteComponents = map[string]struct{ route, registry string }{
	"cloudnativepg":    {"pkg:github/cloudnative-pg/cloudnative-pg", "pkg:oci/cloudnative-pg/cloudnative-pg"},
	"contour":          {"pkg:github/projectcontour/contour", "pkg:oci/projectcontour/contour"},
	"dragonfly":        {"pkg:github/dragonflyoss/dragonfly", "pkg:oci/dragonflyoss/dragonfly"},
	"etcd":             {"pkg:github/etcd-io/etcd", "pkg:oci/etcd-io/etcd"},
	"grafana":          {"pkg:github/grafana/grafana", "pkg:oci/grafana/grafana"},
	"harbor":           {"pkg:github/goharbor/harbor", "pkg:oci/goharbor/harbor"},
	"kubeedge":         {"pkg:github/kubeedge/kubeedge", "pkg:oci/kubeedge/kubeedge"},
	"longhorn":         {"pkg:github/longhorn/longhorn", "pkg:oci/longhornio/longhorn"},
	"mariadb":          {"pkg:github/mariadb/server", "pkg:oci/mariadb/server"},
	"mariadb-operator": {"pkg:github/mariadb-operator/mariadb-operator", "pkg:oci/mariadb-operator/mariadb-operator"},
	"nats":             {"pkg:github/nats-io/nats-server", "pkg:oci/nats-io/nats-server"},
	"opencost":         {"pkg:github/opencost/opencost", "pkg:oci/opencost/opencost"},
	"rook":             {"pkg:github/rook/rook", "pkg:oci/rook/rook"},
	"thanos":           {"pkg:github/thanos-io/thanos", "pkg:oci/thanos-io/thanos"},
	"velero":           {"pkg:github/velero-io/velero", "pkg:oci/velero/velero"},
}

func TestRegistryComponentsMapToCatalogRouteComponents(t *testing.T) {
	catalog, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	routeComponents := map[string]map[string]bool{}
	for _, c := range catalog.Checks {
		if routeComponents[c.Project] == nil {
			routeComponents[c.Project] = map[string]bool{}
		}
		routeComponents[c.Project][c.Component] = true
	}
	members := imageidentity.ObservableComponents(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC))
	var names []string
	for p := range members {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, project := range names {
		reviewed, ok := reviewedRouteComponents[project]
		if !ok {
			t.Errorf("%s: registry member has no reviewed route-component pairing", project)
			continue
		}
		if members[project] != reviewed.registry {
			t.Errorf("%s: registry component %q differs from reviewed %q", project, members[project], reviewed.registry)
		}
		got := routeComponents[project]
		if len(got) == 0 {
			t.Errorf("%s: no catalog route names this project", project)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: several route components %v", project, got)
		}
		for rc := range got {
			if rc != reviewed.route {
				t.Errorf("%s: route component %q differs from reviewed %q", project, rc, reviewed.route)
			}
			t.Logf("%s route=%s registry=%s", project, rc, members[project])
		}
	}
	for project := range reviewedRouteComponents {
		if _, ok := members[project]; !ok {
			t.Errorf("%s: reviewed pairing for a project that is not an observable registry member", project)
		}
	}
}

// Registry-derived rows are attributed only when the bundle records the digest
// of the image table this binary carries.
func TestRegistryRowsNeedTheBundleToNameThisImageTable(t *testing.T) {
	catalog, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var route checkroutemetadata.Check
	for _, c := range nativeRoutes(catalog) {
		if c.Project == "harbor" {
			route = c
			break
		}
	}
	if route.Project == "" {
		t.Fatal("no harbor route")
	}
	bundle := func(adapters ...currentbundle.AdapterBinding) currentbundle.CurrentBundle {
		var b currentbundle.CurrentBundle
		b.Adapters = adapters
		b.Planes.Observed.Components = []currentbundle.CanonicalComponent{{
			ComponentID: "pkg:oci/goharbor/harbor", Version: currentbundle.VersionIdentity{State: "exact", Value: route.From},
		}}
		return b
	}
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for name, b := range map[string]currentbundle.CurrentBundle{
		"missing":   bundle(),
		"different": bundle(currentbundle.AdapterBinding{Name: currentbundle.ImageSourcesDigestAdapter, Version: imageidentity.DigestOf([]byte("other"))}),
	} {
		got := classify(route, b, false, "", now)
		if got.Applicability != IndeterminateNotObservable || got.ObservedVersion != "" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	got := classify(route, bundle(currentbundle.AdapterBinding{Name: currentbundle.ImageSourcesDigestAdapter, Version: imageidentity.Digest()}), false, "", now)
	if got.Applicability == IndeterminateNotObservable || got.ObservedVersion != route.From {
		t.Fatalf("matching digest: %+v", got)
	}
}
