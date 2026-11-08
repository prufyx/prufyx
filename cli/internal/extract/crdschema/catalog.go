// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// CatalogProjects is the reviewed pilot allow-list of projects whose
// crd.schema-removal extractor the maintainer catalog registers. It is a
// temporary gate until crdversions.Target carries a per-target opt-in field.
// Until then, adding a project means editing this list and moving the code
// digest, so every addition is reviewed. A target the mapper refuses is never
// registered.
var CatalogProjects = []string{"argo-cd"}

// FromCRDVersions returns the catalog extractor of one reviewed crdversions
// target: the mapped target, with the release index reduced to the target's
// exact tag prefixes before any release line is derived, and with the
// target's MinFrom applied to the pairs. A target the mapper refuses is an
// error naming every reason, never a partial extractor.
//
// The extractor is a candidate-and-ledger source only. It attests nothing
// (no crd.schema family is registered) and emits no rule, so what it derives
// feeds no rule and no attestation.
func FromCRDVersions(c crdversions.Target) (*Catalog, error) {
	m, rs := TargetFromCRDVersions(c)
	if len(rs) > 0 {
		parts := make([]string, len(rs))
		for i, r := range rs {
			parts[i] = r.Code + " " + r.Detail
		}
		return nil, fmt.Errorf("crdschema: target %s is not mappable: %s", c.Project, strings.Join(parts, "; "))
	}
	if len(m.TagPrefixes) == 0 {
		return nil, fmt.Errorf("crdschema: target %s has no tag prefix", c.Project)
	}
	x, err := New(c.Project, m.Target, c.Component)
	if err != nil {
		return nil, err
	}
	return &Catalog{Extractor: x, prefixes: m.TagPrefixes, minFrom: c.MinFrom}, nil
}

// Catalog is the extractor as the catalog registers it. Everything but Pairs
// is the embedded Extractor's.
type Catalog struct {
	*Extractor
	prefixes []string
	minFrom  [2]int
}

// Clone returns a fresh extractor of the same target (an extractor holds the
// release lines of its last Pairs call, so each run needs its own). It cannot
// fail: the target was validated when c was built.
func (c *Catalog) Clone() *Catalog {
	x := c.Extractor
	return &Catalog{
		Extractor: &Extractor{slug: x.slug, target: x.target, component: x.component, family: attestedFamily,
			lines: map[string]*releaseLine{}, lineOf: map[string]string{}},
		prefixes: append([]string{}, c.prefixes...),
		minFrom:  c.minFrom,
	}
}

// Pairs implements extract.Extractor. The release index is filtered to the
// target's tag prefixes first (so a sibling spelling or another component's
// tag never becomes a release line), then the pairs whose earlier line is
// before MinFrom are dropped. A pair whose version cannot be read is dropped
// too: nothing outside the target's range is derived.
func (c *Catalog) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	var out []extract.VersionPair
	for _, p := range c.Extractor.Pairs(FilterIndex(index, c.prefixes)) {
		if !atOrAfter(p.From, c.minFrom) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// atOrAfter reports whether the version's major.minor is at or after min.
func atOrAfter(version string, min [2]int) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	maj, e1 := strconv.Atoi(parts[0])
	mnr, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil {
		return false
	}
	return maj > min[0] || (maj == min[0] && mnr >= min[1])
}
