// SPDX-License-Identifier: AGPL-3.0-only

// Package imageidentity is the reviewed registry that ties a container image
// repository to a project and says how its tag becomes a project version.
//
// It only ever answers "this exact image reference is that project at this
// version". Everything else is unknown: an unlisted repository, an expired or
// withdrawn record, a digest-only reference, a tag that does not follow the
// record's declared scheme, an operator image (which never implies the version
// of what it operates), and distribution builds. Nothing here reads a cluster
// and no model is consulted; the table is data reviewed by a person, each
// entry carrying a pinned source citation and a validity window.
package imageidentity

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// ErrInvalid reports a table or record that is not acceptable.
var ErrInvalid = errors.New("image identity: invalid")

const (
	// Schema names the document format.
	Schema = "prufyx.io/image-sources/v1alpha1"
	// State values of a record.
	StateActive    = "active"
	StateWithdrawn = "withdrawn"
	// Roles an image may have. Only these two yield a version, and both
	// yield the version of the record's own component only.
	RoleVersionSource = "version-source"
	RoleOperator      = "operator"
	// CatalogMember means the project slug is a catalog project whose
	// compiled identity must resolve; CatalogNone means it is not (and must
	// not become one without a registry review).
	CatalogMember = "member"
	CatalogNone   = "none"
	// OperandRuleNone is the only operand rule phase 1 knows: an image never
	// implies the version of anything but its own project.
	OperandRuleNone = "none"

	// The closed tag schemes.
	SchemeV       = "v{version}"
	SchemePlain   = "{version}"
	SchemeAlpine  = "{version}-alpine"
	maxRecords    = 512
	maxImages     = 16
	maxDocBytes   = 1 << 20
	timeLayout    = "2006-01-02T15:04:05Z"
	maxImageBytes = 512
)

var (
	slugRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	componentRE = regexp.MustCompile(`^pkg:oci/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	repoRE      = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$`)
	sourceIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	versionRE   = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
)

//go:embed data/image-sources.json
var embedded embed.FS

// Image is one image repository of a project. The repository is canonical:
// an explicit registry host, and "library/" for Docker official images.
type Image struct {
	Repo     string `json:"repo"`
	Role     string `json:"role"`
	SourceID string `json:"sourceId"`
}

// Evidence is the reviewed basis of a record.
type Evidence struct {
	State      string                 `json:"state"`
	ReviewedAt string                 `json:"reviewedAt"`
	ValidUntil string                 `json:"validUntil"`
	Sources    []chartidentity.Source `json:"sources"`
}

// Record maps the images of one project to its component identity.
type Record struct {
	Project       string   `json:"project"`
	Component     string   `json:"component"`
	Catalog       string   `json:"catalog"`
	TagScheme     string   `json:"tagScheme"`
	TagWithDigest bool     `json:"tagWithDigest"`
	OperandRule   string   `json:"operandRule"`
	Images        []Image  `json:"images"`
	Evidence      Evidence `json:"evidence"`
}

// Table is the image-source document.
type Table struct {
	Schema  string   `json:"schema"`
	Records []Record `json:"records"`
}

func decodeStrict(raw []byte, into any) error {
	if len(raw) > maxDocBytes {
		return fmt.Errorf("document too large: %w", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%v: %w", err, ErrInvalid)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data: %w", ErrInvalid)
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q: %w", s, ErrInvalid)
	}
	return t, nil
}

// Parse parses and validates a document.
func Parse(raw []byte) (*Table, error) {
	var t Table
	if err := decodeStrict(raw, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// Marshal returns the canonical bytes of a valid table.
func (t *Table) Marshal() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Validate checks the header, ordering, uniqueness of projects, components and
// repositories, and every record.
func (t *Table) Validate() error {
	if t.Schema != Schema || t.Records == nil || len(t.Records) > maxRecords {
		return fmt.Errorf("image-source table header: %w", ErrInvalid)
	}
	projects, components, repos := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, r := range t.Records {
		if i > 0 && t.Records[i-1].Project >= r.Project {
			return fmt.Errorf("records are unsorted or duplicated at %d: %w", i, ErrInvalid)
		}
		if err := r.validate(); err != nil {
			return fmt.Errorf("record %d (%s): %w", i, r.Project, err)
		}
		if projects[r.Project] || components[r.Component] {
			return fmt.Errorf("duplicate project or component at %d: %w", i, ErrInvalid)
		}
		projects[r.Project], components[r.Component] = true, true
		for _, img := range r.Images {
			if repos[img.Repo] {
				return fmt.Errorf("repository %q appears twice (ambiguous image): %w", img.Repo, ErrInvalid)
			}
			repos[img.Repo] = true
		}
	}
	return nil
}

func (r Record) validate() error {
	if !slugRE.MatchString(r.Project) || !componentRE.MatchString(r.Component) {
		return fmt.Errorf("project or component: %w", ErrInvalid)
	}
	if err := r.validateCatalog(); err != nil {
		return err
	}
	switch r.TagScheme {
	case SchemeV, SchemePlain, SchemeAlpine:
	default:
		return fmt.Errorf("tag scheme %q is not in the closed list: %w", r.TagScheme, ErrInvalid)
	}
	if r.OperandRule != OperandRuleNone {
		return fmt.Errorf("operand rule %q: %w", r.OperandRule, ErrInvalid)
	}
	if len(r.Images) == 0 || len(r.Images) > maxImages {
		return fmt.Errorf("image count: %w", ErrInvalid)
	}
	e := r.Evidence
	if e.State != StateActive && e.State != StateWithdrawn {
		return fmt.Errorf("evidence state: %w", ErrInvalid)
	}
	reviewed, err := parseTime(e.ReviewedAt)
	if err != nil {
		return err
	}
	until, err := parseTime(e.ValidUntil)
	if err != nil || !until.After(reviewed) {
		return fmt.Errorf("validity window: %w", ErrInvalid)
	}
	if err := chartidentity.ValidateSources(e.Sources); err != nil {
		return fmt.Errorf("sources: %v: %w", err, ErrInvalid)
	}
	ids := map[string]bool{}
	for _, s := range e.Sources {
		ids[s.ID] = true
	}
	for i, img := range r.Images {
		if i > 0 && r.Images[i-1].Repo >= img.Repo {
			return fmt.Errorf("images are unsorted or duplicated at %d: %w", i, ErrInvalid)
		}
		if !repoRE.MatchString(img.Repo) || len(img.Repo) > maxImageBytes || !isCanonicalRepo(img.Repo) {
			return fmt.Errorf("image repository %q is not canonical: %w", img.Repo, ErrInvalid)
		}
		if img.Role != RoleVersionSource && img.Role != RoleOperator {
			return fmt.Errorf("image role %q: %w", img.Role, ErrInvalid)
		}
		if !sourceIDRE.MatchString(img.SourceID) || !ids[img.SourceID] {
			return fmt.Errorf("image %q cites no source of this record: %w", img.Repo, ErrInvalid)
		}
	}
	return nil
}

// catalogMemo caches catalog lookups: both catalog packages re-read their
// embedded data on every call.
var catalogMemo sync.Map

func inCatalog(slug string) bool {
	if v, ok := catalogMemo.Load(slug); ok {
		return v.(bool)
	}
	_, errCNCF := cncfcheck.Component(slug)
	_, errProject := projectcheck.Component(slug)
	found := errCNCF == nil || errProject == nil
	catalogMemo.Store(slug, found)
	return found
}

// validateCatalog ties a catalog member to the compiled catalog and keeps a
// non-member from sharing a slug with a catalog project.
func (r Record) validateCatalog() error {
	member := inCatalog(r.Project)
	switch r.Catalog {
	case CatalogMember:
		if !member {
			return fmt.Errorf("project is not a catalog project: %w", ErrInvalid)
		}
	case CatalogNone:
		if member {
			return fmt.Errorf("project is a catalog project but is declared outside it: %w", ErrInvalid)
		}
	default:
		return fmt.Errorf("catalog %q: %w", r.Catalog, ErrInvalid)
	}
	return nil
}

// usable reports whether a record may be consulted at now.
func (r Record) usable(now time.Time) bool {
	until, err := parseTime(r.Evidence.ValidUntil)
	return err == nil && r.Evidence.State == StateActive && now.Before(until)
}

var (
	loadOnce  sync.Once
	embeddedT *Table
	embeddedE error
)

// Load parses the embedded table strictly.
func Load() (*Table, error) {
	loadOnce.Do(func() {
		raw, err := embedded.ReadFile("data/image-sources.json")
		if err != nil {
			embeddedE = err
			return
		}
		embeddedT, embeddedE = Parse(raw)
	})
	return embeddedT, embeddedE
}

// ObservableComponents lists the catalog-member projects with an active,
// unexpired record at now. A project whose record has lapsed is not
// observable, so its checks stay INDETERMINATE rather than reading a missing
// image as an absent component. A broken embedded table observes nothing.
func ObservableComponents(now time.Time) map[string]string {
	out := map[string]string{}
	t, err := Load()
	if err != nil {
		return out
	}
	for _, r := range t.Records {
		if r.Catalog == CatalogMember && r.usable(now) {
			out[r.Project] = r.Component
		}
	}
	return out
}

// Repos returns every repository in the table, sorted (for tests and review).
func (t *Table) Repos() []string {
	var out []string
	for _, r := range t.Records {
		for _, img := range r.Images {
			out = append(out, img.Repo)
		}
	}
	sort.Strings(out)
	return out
}
