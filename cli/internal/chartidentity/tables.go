// SPDX-License-Identifier: AGPL-3.0-only

// Package chartidentity holds the two embedded identity tables that tie a
// Helm chart to what it installs.
//
// The chart-source table is reviewed knowledge: it says which project a
// chart published at a repository URL belongs to. The app-version table is
// derived mechanically from the chart's own Chart.yaml at release tags: it
// says which application version a chart version installs. A chart version
// is not an application version, so without a record the label is shown but
// never used.
package chartidentity

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// ErrInvalid reports a table, record or key that is not acceptable.
var ErrInvalid = errors.New("chart identity: invalid")

const (
	// SourcesSchema and AppVersionsSchema name the two document formats.
	SourcesSchema     = "prufyx.io/chart-sources/v1alpha1"
	AppVersionsSchema = "prufyx.io/chart-app-versions/v1alpha1"
	// BasisMechanical is the only basis an app-version record may carry.
	BasisMechanical = "mechanical"
	// StateActive and StateWithdrawn are the chart-source record states.
	StateActive    = "active"
	StateWithdrawn = "withdrawn"

	maxDocumentBytes = 8 << 20
)

//go:embed data/chart-sources.json data/chart-app-versions.json
var embedded embed.FS

// Component is the identity a chart source resolves to.
type Component struct {
	Component string
	Project   string
}

// SourceEvidence is the reviewed basis of a chart-source record.
type SourceEvidence struct {
	State      string   `json:"state"`
	ReviewedAt string   `json:"reviewedAt"`
	ValidUntil string   `json:"validUntil"`
	Sources    []Source `json:"sources"`
}

// SourceRecord maps one chart (in one repository) to a catalog project.
type SourceRecord struct {
	RepoURL   string         `json:"repoURL"`
	Chart     string         `json:"chart"`
	Component string         `json:"component"`
	Project   string         `json:"project"`
	Evidence  SourceEvidence `json:"evidence"`
}

// SourceTable is the chart-source document.
type SourceTable struct {
	Schema  string         `json:"schema"`
	Records []SourceRecord `json:"records"`
}

// AppVersionEvidence is the mechanical basis of an app-version record.
type AppVersionEvidence struct {
	Basis      string    `json:"basis"`
	Extractor  Extractor `json:"extractor"`
	DerivedAt  string    `json:"derivedAt"`
	ValidUntil string    `json:"validUntil"`
	Sources    []Source  `json:"sources"`
}

// AppVersionRecord maps one chart version to the application version it
// installs.
type AppVersionRecord struct {
	Component    string             `json:"component"`
	Chart        string             `json:"chart"`
	ChartVersion string             `json:"chartVersion"`
	AppVersion   string             `json:"appVersion"`
	Evidence     AppVersionEvidence `json:"evidence"`
}

// AppVersionTable is the app-version document.
type AppVersionTable struct {
	Schema  string             `json:"schema"`
	Records []AppVersionRecord `json:"records"`
}

func decodeStrict(raw []byte, into any) error {
	if len(raw) > maxDocumentBytes {
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

func marshal(v any) ([]byte, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ParseSources parses and validates a chart-source document. Each record's
// project must be a catalog project whose subject component equals the
// record's component.
func ParseSources(raw []byte) (*SourceTable, error) {
	var t SourceTable
	if err := decodeStrict(raw, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// Validate checks the schema, ordering, uniqueness and every record.
func (t *SourceTable) Validate() error {
	if t.Schema != SourcesSchema || t.Records == nil || len(t.Records) > maxRecords {
		return fmt.Errorf("chart-source table header: %w", ErrInvalid)
	}
	for i, r := range t.Records {
		if i > 0 {
			p := t.Records[i-1]
			if p.RepoURL > r.RepoURL || (p.RepoURL == r.RepoURL && p.Chart >= r.Chart) {
				return fmt.Errorf("chart-source records are unsorted or duplicated at %d: %w", i, ErrInvalid)
			}
		}
		if err := r.validate(); err != nil {
			return fmt.Errorf("chart-source record %d: %w", i, err)
		}
	}
	return nil
}

func (r SourceRecord) validate() error {
	norm, err := NormalizeRepoURL(r.RepoURL)
	if err != nil || norm != r.RepoURL {
		return fmt.Errorf("repoURL is not in normal form: %w", ErrInvalid)
	}
	if !chartRE.MatchString(r.Chart) || !componentRE.MatchString(r.Component) {
		return fmt.Errorf("chart or component: %w", ErrInvalid)
	}
	subject, err := cncfcheck.Component(r.Project)
	if err != nil || subject != r.Component {
		return fmt.Errorf("project %q is not a catalog project with subject %q: %w", r.Project, r.Component, ErrInvalid)
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
	return validateSources(e.Sources)
}

// Marshal returns the canonical bytes of a valid table.
func (t *SourceTable) Marshal() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return marshal(t)
}

// ParseAppVersions parses and validates an app-version document.
func ParseAppVersions(raw []byte) (*AppVersionTable, error) {
	var t AppVersionTable
	if err := decodeStrict(raw, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r AppVersionRecord) key() [3]string { return [3]string{r.Component, r.Chart, r.ChartVersion} }

func keyLess(a, b [3]string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// SortAppVersions orders records by component, chart and chart version.
func SortAppVersions(records []AppVersionRecord) {
	sort.Slice(records, func(i, j int) bool { return keyLess(records[i].key(), records[j].key()) })
}

// Validate checks the schema, ordering, uniqueness and every record.
func (t *AppVersionTable) Validate() error {
	if t.Schema != AppVersionsSchema || t.Records == nil || len(t.Records) > maxRecords {
		return fmt.Errorf("app-version table header: %w", ErrInvalid)
	}
	for i, r := range t.Records {
		if i > 0 && !keyLess(t.Records[i-1].key(), r.key()) {
			return fmt.Errorf("app-version records are unsorted or duplicated at %d: %w", i, ErrInvalid)
		}
		if err := r.validate(); err != nil {
			return fmt.Errorf("app-version record %d: %w", i, err)
		}
	}
	return nil
}

func (r AppVersionRecord) validate() error {
	if !componentRE.MatchString(r.Component) || !chartRE.MatchString(r.Chart) {
		return fmt.Errorf("component or chart: %w", ErrInvalid)
	}
	if v, ok := NormalizeVersion(r.ChartVersion); !ok || v != r.ChartVersion {
		return fmt.Errorf("chartVersion: %w", ErrInvalid)
	}
	if v, ok := NormalizeVersion(r.AppVersion); !ok || v != r.AppVersion {
		return fmt.Errorf("appVersion: %w", ErrInvalid)
	}
	e := r.Evidence
	if e.Basis != BasisMechanical {
		return fmt.Errorf("evidence basis: %w", ErrInvalid)
	}
	if !idRE.MatchString(e.Extractor.ID) || !versionRE.MatchString(e.Extractor.Version) || !digestRE.MatchString(e.Extractor.CodeDigest) {
		return fmt.Errorf("extractor identity: %w", ErrInvalid)
	}
	derived, err := parseTime(e.DerivedAt)
	if err != nil {
		return err
	}
	until, err := parseTime(e.ValidUntil)
	if err != nil || !until.After(derived) {
		return fmt.Errorf("validity window: %w", ErrInvalid)
	}
	return validateSources(e.Sources)
}

// Marshal returns the canonical bytes of a valid table.
func (t *AppVersionTable) Marshal() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return marshal(t)
}

// ComponentFor resolves a chart source with this table. A record is usable
// only while it is active and now is before its validUntil; otherwise the
// result is "not found". An unusable repoURL is an error.
func (t *SourceTable) ComponentFor(repoURL, chart string, now time.Time) (Component, bool, error) {
	norm, err := NormalizeRepoURL(repoURL)
	if err != nil {
		return Component{}, false, err
	}
	i := sort.Search(len(t.Records), func(i int) bool {
		r := t.Records[i]
		return r.RepoURL > norm || (r.RepoURL == norm && r.Chart >= chart)
	})
	if i == len(t.Records) || t.Records[i].RepoURL != norm || t.Records[i].Chart != chart {
		return Component{}, false, nil
	}
	r := t.Records[i]
	until, err := parseTime(r.Evidence.ValidUntil)
	if err != nil || r.Evidence.State != StateActive || !now.Before(until) {
		return Component{}, false, nil
	}
	return Component{Component: r.Component, Project: r.Project}, true, nil
}

// AppVersionFor looks up the application version of one chart version. The
// chart version may carry one leading "v"; anything that is not a strict
// X.Y.Z is not found. Expired records are not found.
func (t *AppVersionTable) AppVersionFor(component, chart, chartVersion string, now time.Time) (string, bool, error) {
	v, ok := NormalizeVersion(chartVersion)
	if !ok {
		return "", false, nil
	}
	want := [3]string{component, chart, v}
	i := sort.Search(len(t.Records), func(i int) bool { return !keyLess(t.Records[i].key(), want) })
	if i == len(t.Records) || t.Records[i].key() != want {
		return "", false, nil
	}
	r := t.Records[i]
	until, err := parseTime(r.Evidence.ValidUntil)
	if err != nil || !now.Before(until) {
		return "", false, nil
	}
	return r.AppVersion, true, nil
}

type embeddedTables struct {
	sources     *SourceTable
	appVersions *AppVersionTable
	err         error
}

var (
	loadOnce sync.Once
	loaded   embeddedTables
)

// LoadEmbedded parses both embedded tables strictly.
func LoadEmbedded() (*SourceTable, *AppVersionTable, error) {
	loadOnce.Do(func() {
		raw, err := embedded.ReadFile("data/chart-sources.json")
		if err != nil {
			loaded.err = err
			return
		}
		if loaded.sources, loaded.err = ParseSources(raw); loaded.err != nil {
			return
		}
		raw, err = embedded.ReadFile("data/chart-app-versions.json")
		if err != nil {
			loaded.err = err
			return
		}
		loaded.appVersions, loaded.err = ParseAppVersions(raw)
	})
	return loaded.sources, loaded.appVersions, loaded.err
}

// ComponentFor resolves a chart source with the embedded reviewed table.
func ComponentFor(repoURL, chart string, now time.Time) (Component, bool, error) {
	s, _, err := LoadEmbedded()
	if err != nil {
		return Component{}, false, err
	}
	return s.ComponentFor(repoURL, chart, now)
}

// AppVersionFor looks up an application version in the embedded mechanical
// table.
func AppVersionFor(component, chart, chartVersion string, now time.Time) (string, bool, error) {
	_, a, err := LoadEmbedded()
	if err != nil {
		return "", false, err
	}
	return a.AppVersionFor(component, chart, chartVersion, now)
}
