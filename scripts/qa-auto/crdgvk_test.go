// SPDX-License-Identifier: AGPL-3.0-only

// Run: copy crdgvk.go and this file to cli/cmd/crdgvkqa/ (main.go, main_test.go) and run go test there, as run.sh does for the build.
package main

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func TestRemovalFactMap(t *testing.T) {
	defs := []constraintengine.FactDefinition{
		{ID: "component.kubernetes.in_tree_dockershim_required", Component: kubernetesComponent},
		{ID: "component.kubernetes.unmapped_x_removed_gvk_present", Component: kubernetesComponent},
		{ID: "component.other.some_fact", Component: "pkg:github/o/other"},
	}
	facts := removalFactMap(defs)
	if v, ok := facts["component.kubernetes.in_tree_dockershim_required"]; !ok || v == nil || len(v) != 0 {
		t.Fatalf("fact without removals must be present and empty, got %v present=%v", v, ok)
	}
	for _, absent := range []string{"component.kubernetes.unmapped_x_removed_gvk_present", "component.other.some_fact", "component.kubernetes.not_defined"} {
		if _, ok := facts[absent]; ok {
			t.Fatalf("%s must stay absent", absent)
		}
	}
	members := 0
	for _, v := range facts {
		if len(v) > 0 {
			members++
		}
	}
	if members == 0 {
		t.Fatal("facts with removed GVKs must keep their members")
	}
}

func TestRemovalFactMapRealRegistry(t *testing.T) {
	facts := removalFactMap(cncfcheck.CompiledFactDefinitions())
	if v, ok := facts["component.kubernetes.in_tree_dockershim_required"]; !ok || len(v) != 0 {
		t.Fatalf("dockershim fact must be present with an empty list, got %v present=%v", v, ok)
	}
	if len(facts["component.kubernetes.lease_v1beta1_removed_gvk_present"]) == 0 {
		t.Fatal("lease removal fact must keep its members")
	}
}
