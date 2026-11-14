// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"slices"
	"testing"
)

func TestOperatorLifecycleManagerFixtureExclusions(t *testing.T) {
	var target Target
	for _, candidate := range Targets {
		if candidate.Project == "operator-lifecycle-manager" {
			target = candidate
			break
		}
	}
	if !target.Attest {
		t.Fatal("operator-lifecycle-manager must attest")
	}
	want := []string{
		"pkg/controller/operators/catalog/testdata/",
		"pkg/controller/operators/openshift/testdata/",
		"pkg/controller/operators/testdata/",
		"pkg/package-server/provider/testdata/",
		"test/e2e/data/",
		"test/e2e/testdata/",
		"test/images/busybox-index/",
	}
	got := make([]string, 0, len(target.Exclude))
	for _, exclusion := range target.Exclude {
		if exclusion.Repo != target.Repo || exclusion.Copies || exclusion.PrePatch != "" {
			t.Fatalf("exclusion %#v", exclusion)
		}
		got = append(got, exclusion.Path)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("exclusions %q, want %q", got, want)
	}
}
