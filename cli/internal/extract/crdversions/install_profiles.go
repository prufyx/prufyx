// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// installProfiles preserves each channel's serving relation separately at
// every read release. The source/line/full-tree guards have already passed;
// profiles confer no permission to ignore a conflicting or unread source.
func (x *Extractor) installProfiles(repo extract.RepoRef, from, to *releaseLine, states map[string]*tagState, att *extract.AttestationCandidate) error {
	for _, line := range []*releaseLine{from, to} {
		for i, tag := range line.Tags {
			st := states[tag.Name]
			if st == nil || !st.complete() || !st.scan.Clean() {
				return fmt.Errorf("incomplete release")
			}
			channels := append([]ChannelInventory{{Name: x.target.DeclaredChannel, Files: st.inv.Files, CRDs: st.inv.CRDs}}, st.inv.Channels...)
			sort.Slice(channels, func(i, j int) bool { return channels[i].Name < channels[j].Name })
			for _, ch := range channels {
				profile := lineattest.InstallProfile{Version: line.Versions[i], Commit: tag.Commit, ID: ch.Name, Artifacts: []lineattest.InstallArtifact{}, Served: []string{}}
				ownedPaths, served := map[string]bool{}, map[string]bool{}
				for _, crd := range ch.CRDs {
					owner, attribution := x.index.OwnerOf(crd.Group, crd.Kind)
					if attribution != customresources.Owned || owner != x.target.Project {
						return fmt.Errorf("unowned profile definition")
					}
					ownedPaths[crd.Path] = true
					for _, version := range crd.Versions {
						if version.Served {
							served[member(crd.Group, version.Name, crd.Kind)] = true
						}
					}
				}
				for _, f := range ch.Files {
					if !ownedPaths[f.Path] {
						continue
					}
					id := fmt.Sprintf("profile-%s-%s-%d", slug(profile.Version), ch.Name, len(profile.Artifacts))
					profile.Artifacts = append(profile.Artifacts, lineattest.InstallArtifact{Path: f.Path, Digest: f.SHA256, Source: constraintengine.SourceEvidence{ID: id}})
				}
				for m := range served {
					profile.Served = append(profile.Served, m)
				}
				sort.Strings(profile.Served)
				sort.Slice(profile.Artifacts, func(i, j int) bool { return profile.Artifacts[i].Path < profile.Artifacts[j].Path })
				if len(profile.Artifacts) == 0 || len(profile.Served) == 0 {
					return fmt.Errorf("empty profile")
				}
				att.InstallProfiles = append(att.InstallProfiles, profile)
			}
		}
	}
	return nil
}
