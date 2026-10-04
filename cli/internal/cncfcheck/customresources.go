// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// customResourceVersionDefinitions registers the custom-resource version
// set of every project of the reviewed custom-resource table, and of no
// other project. Members are group/version/Kind of the objects of the
// project's own API groups in the complete target apply set; a forbid_set_member
// rule over the set blocks on a listed version and passes only on a set
// declared complete.
func customResourceVersionDefinitions() []constraintengine.FactDefinition {
	projects := customresources.Projects()
	out := make([]constraintengine.FactDefinition, 0, len(projects))
	for _, p := range projects {
		out = append(out, constraintengine.FactDefinition{ID: p.FactID(), Component: p.Component, Type: constraintengine.FactSet})
	}
	return out
}

// ReadsCustomResourceVersions reports whether a claim's rule reads a
// custom-resource version set. Passing such a rule only says that no version
// the published rules name is used. No record yet shows, per release pair,
// that the published rules name every version the target release stops
// serving, so no route may turn such a pass into exit 0. Any fact named
// component.<project>.custom_resource_versions_set counts, registered or not.
func ReadsCustomResourceVersions(claim constraintengine.Claim) bool {
	for _, fact := range claim.RequiredFacts {
		if customResourceVersionsFact(fact.FactID) {
			return true
		}
	}
	return false
}

func customResourceVersionsFact(id string) bool {
	project, ok := strings.CutPrefix(id, "component.")
	if !ok {
		return false
	}
	project, ok = strings.CutSuffix(project, ".custom_resource_versions_set")
	return ok && project != ""
}
