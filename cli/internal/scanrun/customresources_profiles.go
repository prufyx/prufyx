// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// matchesInstallProfile joins complete source evidence to actual imported
// target bytes. A label, a same-serving schema or the union of two profiles
// cannot establish this join. The original apply-set preparation separately
// requires complete consumed-object input.
func matchesInstallProfile(a lineattest.LineAttestation, target, slug string, workspace intake.Workspace, consumed map[string][]intake.Source) bool {
	if a.InstallProfiles == nil || a.Validate() != nil || len(workspace.Omissions) > 0 {
		return false
	}
	p, ok := customresources.ProjectFor(slug)
	if !ok || p.Component != a.Component {
		return false
	}
	groups := map[string]bool{}
	for _, g := range p.Groups {
		groups[g.Name] = true
	}
	observed := map[string]bool{}
	for _, doc := range workspace.Documents {
		if doc.Kind != "CustomResourceDefinition" {
			continue
		}
		spec, _ := doc.Value["spec"].(map[string]any)
		group, _ := spec["group"].(string)
		if group == "" || (doc.APIVersion != "apiextensions.k8s.io/v1" && doc.APIVersion != "apiextensions.k8s.io/v1beta1") {
			return false
		}
		if !groups[group] {
			continue
		}
		if doc.Source.Digest == "" {
			return false
		}
		observed[doc.Source.Digest] = true
	}
	matches := 0
	var selected *lineattest.InstallProfile
	for i := range a.InstallProfiles {
		profile := &a.InstallProfiles[i]
		if profile.Version != target || len(profile.Artifacts) != len(observed) {
			continue
		}
		exact := true
		for _, artifact := range profile.Artifacts {
			if !observed[artifact.Digest] {
				exact = false
			}
		}
		if exact {
			matches++
			selected = profile
		}
	}
	if matches != 1 {
		return false
	}
	served := map[string]bool{}
	for _, member := range selected.Served {
		served[member] = true
	}
	for member := range consumed {
		if !served[member] {
			return false
		}
	}
	return true
}
