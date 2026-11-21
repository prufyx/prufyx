// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"net/url"
	"regexp"
	"strings"
)

// Extra components of a catalog project.
//
// A project owns the component its repositoryURL names (subjectComponent).
// Some CNCF projects ship further upstream components that carry their own
// records (for example a sibling repository in the same organization). The
// reviewed file data/landscape-components.json lists them, one explicit
// purl per entry, so that the records naming such a component have exactly
// one owning project instead of none.
//
// The file is separate from the pinned reduction of the Landscape
// (data/landscape-projects.json), which stays a pure derivation of it. It
// is closed and fails closed: any problem anywhere in it refuses the whole
// load (ErrIntegrity). An entry is owner-approved data (it grants a
// project's published scope and coverage), and the code that reads it
// ships with no entries.
//
// Digest binding: while the file holds no entry the catalogue digest is the
// digest of the pinned Landscape reduction exactly as before. With one or
// more entries it is the digest of the two file digests (see
// catalogueDigestFor), so every digest bound to the catalogue changes
// intentionally and a bundle built without the entries no longer matches.
//
// A listed component only makes records that name it admissible under the
// owner. It is never a rule subject, a scope component of the corpus
// attestation or a coverage row of its own.

const componentsSchema = "prufyx.io/cncf-landscape-components/v1"

var (
	// componentPurlPattern is an exact lowercase GitHub purl: no version,
	// qualifier, subpath, wildcard or organization-only form.
	componentPurlPattern = regexp.MustCompile(`^pkg:github/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/[a-z0-9][a-z0-9._-]*$`)
	// specialSubjectProjects have a subject that is not their repository.
	specialSubjectProjects = map[string]bool{
		"opentelemetry":                   true,
		"buildpacks":                      true,
		"kubeflow":                        true,
		"container-network-interface-cni": true,
	}
)

// componentEntry is one reviewed extra component.
type componentEntry struct {
	Slug string `json:"slug"`
	// Purl is the exact component identity the project additionally owns.
	Purl string `json:"purl"`
	// Source is the reviewed https URL showing that the repository ships
	// under the project. The pinned Landscape reduction carries no list of
	// repositories per project, so every entry needs one.
	Source string `json:"source"`
}

type componentsDocument struct {
	Schema              string           `json:"schema"`
	LandscapeFileDigest string           `json:"landscapeFileDigest"`
	Components          []componentEntry `json:"components"`
}

// attachComponents validates raw (nil means the file is absent: no extras)
// against the landscape and returns the projects with their extra
// components. It does not look at the community table; communityIdentities
// holds the cross-source uniqueness check.
func attachComponents(raw []byte, landscapeDigest string, projects []projectIdentity) ([]projectIdentity, int, error) {
	if raw == nil {
		return projects, 0, nil
	}
	var doc componentsDocument
	if strictJSON(raw, &doc) != nil || doc.Schema != componentsSchema || doc.LandscapeFileDigest != landscapeDigest || doc.Components == nil {
		return nil, 0, ErrIntegrity
	}
	index := make(map[string]int, len(projects))
	for i, project := range projects {
		index[project.Slug] = i
	}
	// claimed maps every component of the catalogue to the claiming slug.
	claimed := map[string]string{}
	for _, project := range projects {
		if component := subjectComponent(project.Slug, project.RepositoryURL); component != "" {
			claimed[component] = project.Slug
		}
	}
	out := append([]projectIdentity(nil), projects...)
	for i, entry := range doc.Components {
		if i > 0 {
			prev := doc.Components[i-1]
			if prev.Slug > entry.Slug || (prev.Slug == entry.Slug && prev.Purl >= entry.Purl) {
				return nil, 0, ErrIntegrity // sorted, so no duplicate either
			}
		}
		at, found := index[entry.Slug]
		if !found || specialSubjectProjects[entry.Slug] {
			return nil, 0, ErrIntegrity
		}
		project := projects[at]
		own := subjectComponent(project.Slug, project.RepositoryURL)
		if own == "" || !componentPurlPattern.MatchString(entry.Purl) || entry.Purl != strings.ToLower(entry.Purl) || entry.Purl == own {
			return nil, 0, ErrIntegrity
		}
		// Same organization is necessary, never sufficient: the entry
		// itself and its source are the grant.
		if strings.Split(strings.TrimPrefix(entry.Purl, "pkg:github/"), "/")[0] != strings.Split(strings.TrimPrefix(own, "pkg:github/"), "/")[0] {
			return nil, 0, ErrIntegrity
		}
		source, err := url.Parse(entry.Source)
		if err != nil || source.Scheme != "https" || source.Host == "" || source.User != nil || source.Fragment != "" || len(entry.Source) > 512 {
			return nil, 0, ErrIntegrity
		}
		if _, clash := claimed[entry.Purl]; clash {
			return nil, 0, ErrIntegrity
		}
		claimed[entry.Purl] = entry.Slug
		out[at].Components = append(append([]string(nil), out[at].Components...), entry.Purl)
	}
	return out, len(doc.Components), nil
}

// catalogueDigestFor is the catalogue digest: the digest of the pinned
// Landscape reduction while no extra component is listed (so every digest
// bound to it is unchanged), else the digest of both file digests.
func catalogueDigestFor(landscapeRaw, componentsRaw []byte, entries int) string {
	if entries == 0 {
		return digest(landscapeRaw)
	}
	return digest([]byte(componentsSchema + "\n" + digest(landscapeRaw) + "\n" + digest(componentsRaw)))
}

// projectComponents lists every component a project owns: its subject
// component, then its reviewed extras.
func projectComponents(project projectIdentity) []string {
	var out []string
	if component := subjectComponent(project.Slug, project.RepositoryURL); component != "" {
		out = append(out, component)
	}
	return append(out, project.Components...)
}

// CatalogExtraComponents maps every reviewed extra component of the
// embedded catalog to its owning project slug. It is empty while the
// reviewed file lists none.
func CatalogExtraComponents() (map[string]string, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, project := range b.landscape.Projects {
		for _, component := range project.Components {
			out[component] = project.Slug
		}
	}
	return out, nil
}
