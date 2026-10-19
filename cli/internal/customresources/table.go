// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
)

// TableSchema identifies table.json.
const TableSchema = "prufyx.io/custom-resource-table/v1"

// tableJSON is the reviewed table and the reviewed ownership list. It is
// data, not code, but it is compiled into the binary and reviewed like code:
// it is decoded strictly and must pass Validate, or the program does not
// start.
//
//go:embed table.json
var tableJSON []byte

type tableFile struct {
	Schema   string         `json:"schema"`
	Projects []projectJSON  `json:"projects"`
	Reserved []reservedJSON `json:"reserved"`
}

type projectJSON struct {
	Slug    string `json:"slug"`
	Catalog string `json:"catalog"`
	// Upstream is present exactly for a community project.
	Upstream    *upstreamJSON `json:"upstream,omitempty"`
	FactProject string        `json:"factProject"`
	Component   string        `json:"component"`
	Groups      []groupJSON   `json:"groups"`
}

type upstreamJSON struct {
	Name          string `json:"name"`
	Repository    string `json:"repository"`
	License       string `json:"license"`
	LicenseSource string `json:"licenseSource"`
}

type groupJSON struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Kinds is absent for a whole-group listing. A present empty list is
	// kept non-nil and refused by Validate; null reads as absent, and only
	// the canonical spelling (which drops it) passes the gate.
	Kinds []string `json:"kinds,omitempty"`
}

type reservedJSON struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	Repository string `json:"repository"`
	Reason     string `json:"reason"`
}

func mustLoadTable(raw []byte) ([]Project, []ReservedGroup) {
	projects, records, err := LoadTable(raw)
	if err != nil {
		panic("customresources: table.json: " + err.Error())
	}
	return projects, records
}

// LoadTable decodes and validates a table document: the schema, no unknown
// fields and no trailing data, provenance present exactly for a community
// project, and then everything Validate checks against the document's own
// ownership list.
func LoadTable(raw []byte) ([]Project, []ReservedGroup, error) {
	var doc tableFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("trailing data")
	}
	if doc.Schema != TableSchema {
		return nil, nil, fmt.Errorf("schema %q, want %q", doc.Schema, TableSchema)
	}
	if len(doc.Projects) == 0 {
		return nil, nil, fmt.Errorf("no projects")
	}
	projects := make([]Project, 0, len(doc.Projects))
	for _, pj := range doc.Projects {
		p := Project{Slug: pj.Slug, Catalog: Catalog(pj.Catalog), FactProject: pj.FactProject, Component: pj.Component}
		if (pj.Upstream != nil) != (p.Catalog == CatalogCommunity) {
			return nil, nil, fmt.Errorf("project %s: upstream is required for a community project and refused otherwise", pj.Slug)
		}
		if u := pj.Upstream; u != nil {
			p.Upstream = Upstream{Name: u.Name, Repository: u.Repository, License: u.License, LicenseSource: u.LicenseSource}
		}
		for _, g := range pj.Groups {
			p.Groups = append(p.Groups, Group{Name: g.Name, Source: g.Source, Kinds: cloneKinds(g.Kinds)})
		}
		projects = append(projects, p)
	}
	records := make([]ReservedGroup, 0, len(doc.Reserved))
	for _, r := range doc.Reserved {
		records = append(records, ReservedGroup{Name: r.Name, Owner: r.Owner, Repository: r.Repository, Reason: r.Reason})
	}
	if !validate(projects, records) {
		return nil, nil, fmt.Errorf("the table does not validate")
	}
	return projects, records, nil
}

// encodeTable renders a table in the one spelling table.json has: two-space
// indent, fields in declaration order, no HTML escaping, a final newline.
func encodeTable(projects []Project, records []ReservedGroup) ([]byte, error) {
	doc := tableFile{Schema: TableSchema, Projects: []projectJSON{}, Reserved: []reservedJSON{}}
	for _, p := range projects {
		pj := projectJSON{Slug: p.Slug, Catalog: string(p.Catalog), FactProject: p.FactProject, Component: p.Component, Groups: []groupJSON{}}
		if p.Community() {
			u := p.Upstream
			pj.Upstream = &upstreamJSON{Name: u.Name, Repository: u.Repository, License: u.License, LicenseSource: u.LicenseSource}
		}
		for _, g := range p.Groups {
			pj.Groups = append(pj.Groups, groupJSON{Name: g.Name, Source: g.Source, Kinds: cloneKinds(g.Kinds)})
		}
		doc.Projects = append(doc.Projects, pj)
	}
	for _, r := range records {
		doc.Reserved = append(doc.Reserved, reservedJSON{Name: r.Name, Owner: r.Owner, Repository: r.Repository, Reason: r.Reason})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
