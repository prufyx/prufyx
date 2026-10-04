// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The reviewed custom-resource table (which the fact registry and the
// preparation read) names exactly the extractor's targets, with the same
// fact ids and components, in the same order.
func TestTargetsMatchCustomResourceTable(t *testing.T) {
	projects := customresources.Projects()
	if len(projects) != len(Targets) {
		t.Fatalf("%d table projects, %d targets", len(projects), len(Targets))
	}
	for i, tg := range Targets {
		p := projects[i]
		if p.Slug != tg.Project || p.FactProject != tg.FactProject || p.Component != tg.Component || p.FactID() != tg.FactID() {
			t.Fatalf("table %+v differs from target %s/%s/%s", p, tg.Project, tg.FactProject, tg.Component)
		}
		repo := strings.TrimPrefix(tg.Repo, "github.com/")
		for _, g := range p.Groups {
			if !strings.HasPrefix(g.Source, "https://github.com/"+repo+"/blob/") {
				t.Fatalf("%s: group %s cited from another repository: %s", tg.Project, g.Name, g.Source)
			}
			if !targetPathCovers(tg, g.Source) {
				t.Fatalf("%s: group %s cited from a path the extractor does not read: %s", tg.Project, g.Name, g.Source)
			}
		}
	}
}

// targetPathCovers reports whether a cited manifest lies under one of the
// target's listed paths.
func targetPathCovers(tg Target, source string) bool {
	_, rest, ok := strings.Cut(source, "/blob/")
	if !ok || len(rest) < 41 {
		return false
	}
	path := rest[41:]
	for _, spec := range tg.Paths {
		if !spec.Dir && path == spec.Path {
			return true
		}
		if spec.Dir && strings.HasPrefix(path, spec.Path+"/") && !strings.Contains(path[len(spec.Path)+1:], "/") && spec.Match.MatchString(path[len(spec.Path)+1:]) {
			return true
		}
	}
	return false
}

// Every CRD of the frozen Strimzi inventory (both tags) defines a group the
// table lists for Strimzi, and every member the derived rules forbid is in
// such a group: no derived rule can name a group the preparation would not
// attribute to its project.
func TestStrimziGroupsAreInTheTable(t *testing.T) {
	out := mustRun(t, "strimzi", extract.FixtureReader{Root: strimziRoot})
	index := customresources.DefaultIndex()
	seen := 0
	for _, pair := range out.Manifest.Pairs {
		proof := pairProof(t, pair)
		for _, inv := range []*Inventory{proof.From, proof.To} {
			if inv == nil {
				t.Fatal("pair without inventory")
			}
			for _, crd := range inv.CRDs {
				seen++
				if owner, attribution := index.Owner(crd.Group); attribution != customresources.Owned || owner != "strimzi" {
					t.Fatalf("CRD %s group %s: owner %q (%v)", crd.Name, crd.Group, owner, attribution)
				}
			}
		}
	}
	if seen != 20 {
		t.Fatalf("%d CRDs in the inventory", seen)
	}
	members := 0
	for _, entry := range out.Entries {
		for _, fact := range entry.RequiredFacts {
			if fact.ID != target(t, "strimzi").FactID() {
				t.Fatalf("rule reads %s", fact.ID)
			}
		}
		if entry.Rule.SetCondition == nil {
			t.Fatalf("%s has no set condition", entry.Rule.ID)
		}
		for _, member := range entry.Rule.SetCondition.Members {
			members++
			group, _, _ := strings.Cut(member, "/")
			if owner, attribution := index.Owner(group); attribution != customresources.Owned || owner != "strimzi" {
				t.Fatalf("member %s: owner %q (%v)", member, owner, attribution)
			}
		}
	}
	if members != 14 {
		t.Fatalf("%d forbidden members", members)
	}
}
