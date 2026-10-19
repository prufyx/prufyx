// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Check names of the structural check.
const (
	CheckSourceForm    = "source-form"
	CheckSourceRepo    = "source-repository"
	CheckDuplicate     = "duplicate"
	CheckNoTarget      = "project-without-target"
	CheckNoTargetStale = "no-target-entry"
	CheckTargetTable   = "target-table-mismatch"
	CheckPin           = "remote-pin"
)

var (
	// commitRE is a full lowercase commit SHA-1.
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// blobRE is the one accepted shape of a cited source: a github.com blob
	// URL whose ref is a full commit SHA (never a tag or a branch), with a
	// plain repository path. Nothing else (query, fragment, port, escapes).
	blobRE = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/blob/([0-9a-f]{40})/([A-Za-z0-9_./-]+)$`)
)

// Blob is a parsed source URL.
type Blob struct {
	Owner, Repo, Commit, Path string
}

// ParseBlob parses a source URL; it refuses a ref that is not a full commit
// SHA and a path with an empty, "." or ".." segment.
func ParseBlob(u string) (Blob, bool) {
	m := blobRE.FindStringSubmatch(u)
	if m == nil {
		return Blob{}, false
	}
	for _, seg := range append(strings.Split(m[4], "/"), m[1], m[2]) {
		if seg == "" || seg == "." || seg == ".." {
			return Blob{}, false
		}
	}
	return Blob{Owner: m[1], Repo: m[2], Commit: m[3], Path: m[4]}, true
}

// Structure checks one revision offline: every cited source has the pinned
// form and names the project's own repository (or the repository its target
// moves to), no group is claimed twice, every table project has a target or
// a reviewed reason why not, and a target agrees with its table row. The
// loaders have already refused malformed files; this is what only the two
// data sets together can show.
func Structure(in Inputs) []Finding {
	var out []Finding
	add := func(check, subject, format string, args ...any) {
		out = append(out, Finding{check, subject, fmt.Sprintf(format, args...)})
	}
	targets := map[string]crdversions.Target{}
	for _, t := range in.Targets {
		targets[t.Project] = t
	}
	noTarget := map[string]bool{}
	for _, n := range in.Guard.NoTarget {
		noTarget[n.Project] = true
	}
	slugs := map[string]bool{}
	groups := map[string]string{}
	for _, p := range in.Projects {
		if slugs[p.Slug] {
			add(CheckDuplicate, "project "+p.Slug, "listed twice in the table")
		}
		slugs[p.Slug] = true
		own := "github.com/" + strings.TrimPrefix(p.Component, "pkg:github/")
		allowed := []string{own}
		t, hasTarget := targets[p.Slug]
		if hasTarget && t.Remote != nil {
			allowed = append(allowed, t.Remote.Repo)
		}
		switch {
		case !hasTarget && !noTarget[p.Slug]:
			add(CheckNoTarget, "project "+p.Slug, "the table row has no target file and %s lists no reason", GuardPath)
		case hasTarget && noTarget[p.Slug]:
			add(CheckNoTargetStale, "project "+p.Slug, "%s says the project has no target, but %s exists", GuardPath, crdversions.TargetFileName(p.Slug))
		case hasTarget:
			if t.Component != p.Component || t.FactProject != p.FactProject || catalogOf(t) != string(p.Catalog) || t.Repo != own {
				add(CheckTargetTable, "project "+p.Slug, "the target's catalog, repo, component or factProject differs from the table row")
			}
		}
		sources := make([]string, 0, len(p.Groups)+1)
		for _, g := range p.Groups {
			sources = append(sources, g.Source)
			if other, dup := groups[g.Name]; dup {
				add(CheckDuplicate, "group "+g.Name, "claimed by %s and %s", other, p.Slug)
			}
			groups[g.Name] = p.Slug
		}
		if p.Community() {
			sources = append(sources, p.Upstream.LicenseSource)
		}
		for _, s := range sources {
			b, ok := ParseBlob(s)
			if !ok {
				add(CheckSourceForm, "project "+p.Slug, "source %q is not a github.com blob URL pinned by a full commit SHA", s)
				continue
			}
			if !inRepos(allowed, "github.com/"+b.Owner+"/"+b.Repo) {
				add(CheckSourceRepo, "project "+p.Slug, "source %q is not in the project's repository", s)
			}
		}
	}
	for _, n := range in.Guard.NoTarget {
		if !slugs[n.Project] {
			add(CheckNoTargetStale, "project "+n.Project, "listed in noTarget but not in the table")
		}
	}
	for _, t := range in.Targets {
		if !slugs[t.Project] && t.Attest {
			add(CheckTargetTable, "target "+t.Project, "attests but has no table row")
		}
		if r := t.Remote; r != nil {
			seen := map[string]bool{}
			for _, pin := range r.Pins {
				if !commitRE.MatchString(pin.Commit) {
					add(CheckPin, "target "+t.Project, "pin %s: %q is not a full commit SHA", pin.Tag, pin.Commit)
				}
				if seen[pin.Tag] {
					add(CheckDuplicate, "target "+t.Project, "pin %s listed twice", pin.Tag)
				}
				seen[pin.Tag] = true
			}
			if len(r.Pins) == 0 {
				add(CheckPin, "target "+t.Project, "remote source without pins")
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func inRepos(allowed []string, repo string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, repo) {
			return true
		}
	}
	return false
}

func catalogOf(t crdversions.Target) string {
	if t.Catalog == "" {
		return string(customresources.CatalogCNCF)
	}
	return t.Catalog
}
