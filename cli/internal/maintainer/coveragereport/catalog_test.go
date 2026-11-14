// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

func catalogRow(slug string, c customresources.Catalog) customresources.Project {
	return customresources.Project{Slug: slug, Catalog: c}
}

// A CatalogSet answers from its own rows. Nil is the embedded table; an empty
// set is a non-nil set of no rows, in which nothing is community.
func TestCatalogSetAnswers(t *testing.T) {
	t.Parallel()
	var embedded *CatalogSet
	if !embedded.Community("gateway-api") || embedded.Community("antrea") || !embedded.Has("antrea") || embedded.Has("no-such-project") {
		t.Fatal("a nil set does not answer from the embedded table")
	}
	empty := NewCatalogSet(nil)
	if empty == nil {
		t.Fatal("an empty set is nil")
	}
	if empty.Community("gateway-api") || empty.Has("gateway-api") || empty.Has("antrea") {
		t.Fatal("an empty set falls back to the embedded table")
	}
	set := NewCatalogSet([]customresources.Project{catalogRow("gateway-api", customresources.CatalogCNCF), catalogRow("antrea", customresources.CatalogCommunity), catalogRow("new-one", customresources.CatalogCommunity)})
	if set.Community("gateway-api") || !set.Community("antrea") || !set.Community("new-one") || !set.Has("gateway-api") || set.Has("strimzi") {
		t.Fatal("a set does not override the embedded table")
	}
}

// Every classification site of a report reads the set it is given, in both
// directions, and the empty set classifies everything as CNCF. Each site has
// its own assertion.
func TestCatalogSetOverridesEmbeddedAtEverySite(t *testing.T) {
	t.Parallel()
	allCNCF := NewCatalogSet(nil)
	strimziCommunity := NewCatalogSet([]customresources.Project{catalogRow("strimzi", customresources.CatalogCommunity)})

	t.Run("project row catalog", func(t *testing.T) {
		t.Parallel()
		if got := rowOf(t, combinedWith(t, nil, gatewayScenario("1.1", "1.2", "1.3")), "gateway-api").Catalog; got != CatalogCommunity {
			t.Fatalf("embedded: %q", got)
		}
		if got := rowOf(t, combinedWith(t, allCNCF, gatewayScenario("1.1", "1.2", "1.3")), "gateway-api").Catalog; got != "" {
			t.Fatalf("empty set: %q, want a CNCF row", got)
		}
		if got := rowOf(t, combinedWith(t, strimziCommunity, strimziScenario("0.49", "0.50", "0.51")), "strimzi").Catalog; got != CatalogCommunity {
			t.Fatalf("set with a community row for a CNCF slug: %q", got)
		}
	})

	t.Run("totals of the two catalogs", func(t *testing.T) {
		t.Parallel()
		embedded := combinedWith(t, nil, gatewayScenario("1.1", "1.2", "1.3"))
		if embedded.CommunityCatalog == nil || embedded.Fleet.Projects != 0 {
			t.Fatalf("embedded: community %+v fleet %+v", embedded.CommunityCatalog, embedded.Fleet)
		}
		flipped := combinedWith(t, allCNCF, gatewayScenario("1.1", "1.2", "1.3"))
		if flipped.CommunityCatalog != nil || flipped.Fleet.Projects != 1 {
			t.Fatalf("empty set: community %+v fleet %+v", flipped.CommunityCatalog, flipped.Fleet)
		}
		moved := combinedWith(t, strimziCommunity, strimziScenario("0.49", "0.50", "0.51"))
		if moved.CommunityCatalog == nil || moved.Fleet.Projects != 0 {
			t.Fatalf("a CNCF slug as community: community %+v fleet %+v", moved.CommunityCatalog, moved.Fleet)
		}
	})

	// A rule without an attestation: a community project does not count as a
	// pack project and is not listed without lines; a CNCF one is, and is.
	t.Run("pack projects and projects without lines", func(t *testing.T) {
		t.Parallel()
		linesBytes, err := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"other": {Lines: []string{"1.0", "1.1"}}}})
		if err != nil {
			t.Fatal(err)
		}
		compute := func(cat *CatalogSet) Report {
			t.Helper()
			r, err := Compute(Input{Pack: []byte(`{"schema":"test","revision":"synthetic","entries":[` + gatewayRule + `]}`), Lines: linesBytes, Now: allNow, All: true, Catalog: cat})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := compute(nil); r.PackProjects != 0 || len(r.WithoutLines) != 0 {
			t.Fatalf("embedded: pack projects %d, without lines %v", r.PackProjects, r.WithoutLines)
		}
		r := compute(allCNCF)
		if r.PackProjects != 1 {
			t.Fatalf("empty set: pack projects %d, want 1", r.PackProjects)
		}
		if !reflect.DeepEqual(r.WithoutLines, []string{"gateway-api"}) {
			t.Fatalf("empty set: without lines %v", r.WithoutLines)
		}
	})

	// The CRD version targets split by catalog.
	t.Run("crd version targets", func(t *testing.T) {
		t.Parallel()
		linesBytes, err := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"other": {Lines: []string{"1.0", "1.1"}}}})
		if err != nil {
			t.Fatal(err)
		}
		compute := func(cat *CatalogSet) Report {
			t.Helper()
			r, err := Compute(Input{Pack: []byte(`{"schema":"test","revision":"synthetic","entries":[]}`), Lines: linesBytes, Now: allNow, All: true,
				CRDVersionProjects: 1, CRDTargetComponents: map[string]string{"gateway-api": "pkg:github/kubernetes-sigs/gateway-api"}, Catalog: cat})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := compute(nil); r.crd.community != 1 || r.crd.cncf != 0 {
			t.Fatalf("embedded: %+v", r.crd)
		}
		if r := compute(allCNCF); r.crd.community != 0 || r.crd.cncf != 1 {
			t.Fatalf("empty set: %+v", r.crd)
		}
	})
}

// The metric v2 producer is looked up in the set: a CNCF row of the set is
// produced by manifests, a community row, a missing row and an empty set are
// not; nil is the embedded table.
func TestProducerForUsesTheCatalogSet(t *testing.T) {
	t.Parallel()
	cncfRow := NewCatalogSet([]customresources.Project{catalogRow("gateway-api", customresources.CatalogCNCF)})
	communityRow := NewCatalogSet([]customresources.Project{catalogRow("antrea", customresources.CatalogCommunity)})
	for _, tc := range []struct {
		name    string
		project string
		cat     *CatalogSet
		want    string
	}{
		{"embedded CNCF row", "antrea", nil, ProducerManifest},
		{"embedded community row", "gateway-api", nil, ProducerNone},
		{"a CNCF row of the set that the embedded table holds as community", "gateway-api", cncfRow, ProducerManifest},
		{"a community row of the set that the embedded table holds as CNCF", "antrea", communityRow, ProducerNone},
		{"no row in the set", "antrea", cncfRow, ProducerNone},
		{"the empty set", "antrea", NewCatalogSet(nil), ProducerNone},
	} {
		if got := producerFor("crd.versions", tc.project, tc.cat); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := producerFor("k8s.api", "kubernetes", NewCatalogSet(nil)); got != ProducerManifest {
		t.Errorf("k8s.api: %q", got)
	}
}
