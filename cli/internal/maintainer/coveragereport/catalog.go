// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import "github.com/prufyx/prufyx/cli/internal/customresources"

// CatalogSet is the catalog split of a custom-resource table: which slugs
// have a row, and which of those are community projects. A report classifies
// a project as community or CNCF only through its CatalogSet.
//
// A nil *CatalogSet means the table embedded in the running program; only the
// maintainer command line, which runs from the tree it is built from, uses
// it. A caller that judges another tree (the merge gate) builds a set from
// that tree's own table and passes it, and an empty set is a valid non-nil
// set in which every project is CNCF and no row exists.
type CatalogSet struct {
	rows      map[string]bool
	community map[string]bool
}

// NewCatalogSet builds the set of a table's projects. The result is never
// nil, also for no projects.
func NewCatalogSet(projects []customresources.Project) *CatalogSet {
	c := &CatalogSet{rows: map[string]bool{}, community: map[string]bool{}}
	for _, p := range projects {
		c.rows[p.Slug] = true
		if p.Community() {
			c.community[p.Slug] = true
		}
	}
	return c
}

// Community reports whether slug is a community project of the set.
func (c *CatalogSet) Community(slug string) bool {
	if c == nil {
		return customresources.IsCommunity(slug)
	}
	return c.community[slug]
}

// Has reports whether slug has a row in the set.
func (c *CatalogSet) Has(slug string) bool {
	if c == nil {
		_, ok := customresources.ProjectFor(slug)
		return ok
	}
	return c.rows[slug]
}
