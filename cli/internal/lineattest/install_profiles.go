// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// InstallProfileContract changes whenever the source-profile join semantics
// change. External capabilities bind this parser and runtime requirement.
const InstallProfileContract = "crd-install-profiles-v1:complete-release-profile-census;exact-target-artifact-set;consumed-subset;unknown-on-nonmatch"

const maxInstallProfiles = 8
const maxInstallArtifacts = 64

// InstallProfile describes one complete CRD source artifact set at one exact
// release. It is source evidence, never an observation of a live installation.
type InstallProfile struct {
	Version   string            `json:"version"`
	Commit    string            `json:"commit"`
	ID        string            `json:"id"`
	Artifacts []InstallArtifact `json:"artifacts"`
	Served    []string          `json:"served"`
}

// InstallArtifact names one CRD-bearing file in the component's repository.
// Source binds the file to the same pinned evidence grammar as a rule.
type InstallArtifact struct {
	Path   string                          `json:"path"`
	Digest string                          `json:"digest"`
	Source constraintengine.SourceEvidence `json:"source"`
}

var profileIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var artifactDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (a LineAttestation) validateInstallProfiles() error {
	if a.InstallProfiles == nil {
		return nil
	}
	bad := func() error { return fmt.Errorf("%w: incomplete or invalid installProfiles source census", ErrInvalid) }
	if a.FactFamily != FamilyCustomResourceVersions || a.Releases == nil || len(a.InstallProfiles) == 0 || len(a.InstallProfiles) > 2*MaxReleases*maxInstallProfiles {
		return bad()
	}
	releases := append(append([]Release{}, a.Releases.From...), a.Releases.To...)
	project := ""
	for _, p := range customresources.Projects() {
		if p.Component == a.Component {
			project = p.Slug
		}
	}
	if project == "" {
		return bad()
	}
	index := customresources.DefaultIndex()
	var census []string
	n := 0
	for _, rel := range releases {
		var ids []string
		for n < len(a.InstallProfiles) && a.InstallProfiles[n].Version == rel.Version {
			p := a.InstallProfiles[n]
			n++
			if p.Commit != rel.Commit || !profileIDRE.MatchString(p.ID) || len(ids) >= maxInstallProfiles || (len(ids) > 0 && ids[len(ids)-1] >= p.ID) || len(p.Artifacts) == 0 || len(p.Artifacts) > maxInstallArtifacts || len(p.Served) == 0 || len(p.Served) > constraintengine.MaxSetMembers {
				return bad()
			}
			ids = append(ids, p.ID)
			seenDigests := map[string]bool{}
			for i, f := range p.Artifacts {
				if f.Path == "." || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "../") || path.Clean(f.Path) != f.Path || strings.ContainsAny(f.Path, "\\?#") || !artifactDigestRE.MatchString(f.Digest) || (i > 0 && p.Artifacts[i-1].Path >= f.Path) || seenDigests[f.Digest] {
					return bad()
				}
				seenDigests[f.Digest] = true
				s := f.Source
				u := "https://github.com/" + strings.TrimPrefix(a.Component, "pkg:github/") + "/blob/" + rel.Commit + "/" + f.Path
				if constraintengine.ValidateSources([]constraintengine.SourceEvidence{s}) != nil || s.URL != u || s.Revision != rel.Commit || s.ContentDigest != f.Digest {
					return bad()
				}
			}
			for i, member := range p.Served {
				parts := strings.Split(member, "/")
				if len(parts) != 3 || !constraintengine.ValidSetMember(member) || parts[1] == "" || (i > 0 && p.Served[i-1] >= member) {
					return bad()
				}
				owner, attribution := index.OwnerOf(parts[0], parts[2])
				if attribution != customresources.Owned || owner != project {
					return bad()
				}
			}
		}
		if len(ids) == 0 || (census != nil && !slices.Equal(ids, census)) {
			return bad()
		}
		census = ids
	}
	if n != len(a.InstallProfiles) {
		return bad()
	}
	return nil
}

func installProfilesShape(v any) error {
	list, ok := v.([]any)
	if !ok {
		return ErrInvalid
	}
	for _, item := range list {
		if err := object(item, fields("version", "commit", "id", "artifacts", "served"), func(name string, v any) error {
			if name != "artifacts" {
				return nil
			}
			files, ok := v.([]any)
			if !ok {
				return ErrInvalid
			}
			for _, f := range files {
				if err := object(f, fields("path", "digest", "source"), func(name string, v any) error {
					if name == "source" {
						return object(v, sourceFields, nil)
					}
					return nil
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// CopyInstallProfiles returns an independent copy, preserving nil for legacy
// records so their serialized bytes remain unchanged.
func CopyInstallProfiles(profiles []InstallProfile) []InstallProfile {
	if profiles == nil {
		return nil
	}
	out := append([]InstallProfile{}, profiles...)
	for i := range out {
		out[i].Artifacts = append([]InstallArtifact{}, out[i].Artifacts...)
		out[i].Served = append([]string{}, out[i].Served...)
	}
	return out
}
