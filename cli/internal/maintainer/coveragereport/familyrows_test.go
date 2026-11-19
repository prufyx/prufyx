// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"strings"
	"testing"
)

func familyFixture() Report {
	return Report{Projects: []Project{
		{Project: "alpha", Covered: true, Pairs: []Pair{
			{From: "1", To: "2", Status: StatusB, Families: []string{"crd.custom_resource_versions", FamilyChartKubeRange}},
			{From: "2", To: "3", Status: StatusA, Families: []string{"crd.custom_resource_versions"}},
		}},
		{Project: "beta", Pairs: []Pair{{From: "1", To: "2", Status: StatusG}}},
	}}
}

func TestFamilyRowsNeverSummed(t *testing.T) {
	t.Parallel()
	tab, err := FormsOf(familyFixture())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]FamilyRow{}
	for _, f := range tab.Families {
		byKey[f.Family] = f
	}
	if byKey["crd"].Fleet.Pairs != 2 || byKey["chart_declared_kubernetes_range"].Fleet.Pairs != 1 {
		t.Fatalf("rows %+v", tab.Families)
	}
	// The pair in two families is counted once overall.
	if tab.Fleet.AB != 2 || tab.Fleet.Pairs != 3 {
		t.Fatalf("overall %+v", tab.Fleet)
	}
	out := renderFamilyRows(tab.Families)
	if strings.Contains(out, "total") || strings.Contains(out, "3 upgrades in") {
		t.Errorf("a summed row is printed:\n%s", out)
	}
}

func TestZeroFamilyRowSaysNoneYet(t *testing.T) {
	t.Parallel()
	tab, err := FormsOf(familyFixture())
	if err != nil {
		t.Fatal(err)
	}
	out := renderFamilyRows(tab.Families)
	if !strings.Contains(out, "| Chart install API surface | none yet | none yet |") {
		t.Errorf("zero row:\n%s", out)
	}
	if !strings.Contains(out, "| Helm values schema | none yet | none yet |") {
		t.Errorf("zero row:\n%s", out)
	}
}

func TestNoKubernetesSurfaceIsPermanentGap(t *testing.T) {
	t.Parallel()
	r := Report{Projects: []Project{
		{Project: "etcd", KubernetesSurface: KubernetesSurfaceNone, Pairs: []Pair{{From: "1", To: "2", Status: StatusG}, {From: "2", To: "3", Status: StatusG}}},
		{Project: "unknown", Pairs: []Pair{{From: "1", To: "2", Status: StatusG}}},
	}}
	tab, err := FormsOf(r)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Rows[0].GapReason != GapReasonNoSurface || tab.Rows[1].GapReason == GapReasonNoSurface {
		t.Fatalf("reasons %q %q", tab.Rows[0].GapReason, tab.Rows[1].GapReason)
	}
	if tab.Fleet.PermanentGapProjects != 1 || tab.Fleet.PermanentGapPairs != 2 || tab.Fleet.AB != 0 {
		t.Fatalf("fleet %+v", tab.Fleet)
	}
	if !strings.Contains(renderFormsTable(tab), "NO_KUBERNETES_SURFACE (not installed through Kubernetes objects)") {
		t.Error("reason text not shown")
	}
	// Never counted as decided, in any form or family row.
	bad := Report{Projects: []Project{{Project: "x", KubernetesSurface: KubernetesSurfaceNone, Pairs: []Pair{{From: "1", To: "2", Status: StatusA, Families: []string{"crd.custom_resource_versions"}}}}}}
	if _, err := FormsOf(bad); err == nil {
		t.Error("a decided pair of a no-surface project was accepted")
	}
	// Unknown attribute value fails closed.
	if _, err := FormsOf(Report{Projects: []Project{{Project: "x", KubernetesSurface: "maybe"}}}); err == nil {
		t.Error("unknown kubernetesSurface accepted")
	}
}

func TestFormsOfV2HasNoFamilies(t *testing.T) {
	t.Parallel()
	tab, err := FormsOfV2(familyFixture())
	if err != nil || tab.Families != nil {
		t.Fatalf("%v %+v", err, tab.Families)
	}
}
