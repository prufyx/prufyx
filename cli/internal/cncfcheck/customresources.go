// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
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
