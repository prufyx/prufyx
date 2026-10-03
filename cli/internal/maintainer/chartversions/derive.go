// SPDX-License-Identifier: AGPL-3.0-only

package chartversions

import (
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	// ExtractorID and ExtractorVersion identify this derivation in records.
	ExtractorID      = "chart.app-version"
	ExtractorVersion = "1.0.0"

	maxChartYAMLBytes = 256 << 10
)

// Reader is what the derivation needs: pinned reads and recorded tags.
type Reader interface {
	extract.PinnedReader
	extract.TagSource
}

// Options carries the fixed inputs of one derivation.
type Options struct {
	DerivedAt  time.Time
	ValidUntil time.Time
	Extractor  chartidentity.Extractor
}

// Withheld is one release tag that produced no record.
type Withheld struct {
	Tag    string `json:"tag"`
	Reason string `json:"reason"`
}

// EntryReport is the outcome for one mapping entry.
type EntryReport struct {
	Component string     `json:"component"`
	Chart     string     `json:"chart"`
	Repo      string     `json:"repo"`
	Matched   int        `json:"matchedTags"`
	Derived   int        `json:"derived"`
	Withheld  []Withheld `json:"withheld"`
}

// Report lists what was derived and what was withheld, and why.
type Report struct {
	Entries []EntryReport `json:"entries"`
}

type chartFields struct {
	name, version, appVersion string
	startLine, endLine        int
}

// parseChartYAML reads the three fields it needs from the top-level mapping
// of Chart.yaml. The returned reason is non-empty when the file cannot be
// established.
func parseChartYAML(data []byte) (chartFields, string) {
	if len(data) > maxChartYAMLBytes {
		return chartFields{}, "Chart.yaml is larger than 256 KiB"
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return chartFields{}, "Chart.yaml is not valid YAML"
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return chartFields{}, "Chart.yaml holds more than one YAML document"
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return chartFields{}, "Chart.yaml is not a mapping"
	}
	top := doc.Content[0]
	seen := map[string]bool{}
	vals := map[string]*yaml.Node{}
	keys := map[string]*yaml.Node{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return chartFields{}, "Chart.yaml has a non-scalar key"
		}
		if seen[k.Value] {
			return chartFields{}, fmt.Sprintf("Chart.yaml repeats the key %q", k.Value)
		}
		seen[k.Value] = true
		vals[k.Value], keys[k.Value] = v, k
	}
	var f chartFields
	for _, name := range []string{"name", "version", "appVersion"} {
		v, ok := vals[name]
		if !ok {
			return chartFields{}, fmt.Sprintf("Chart.yaml has no %s", name)
		}
		if v.Kind != yaml.ScalarNode || strings.ContainsRune(v.Value, '\n') {
			return chartFields{}, fmt.Sprintf("Chart.yaml %s is not a single-line scalar", name)
		}
	}
	f.name, f.version, f.appVersion = vals["name"].Value, vals["version"].Value, vals["appVersion"].Value
	f.startLine = minInt(keys["version"].Line, keys["appVersion"].Line)
	f.endLine = maxInt(vals["version"].Line, vals["appVersion"].Line)
	return f, ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type candidate struct {
	tag    string
	record chartidentity.AppVersionRecord
}

// Derive builds the app-version table for a mapping. Reads go through a
// Recorder over r, so every cited digest is the whole-file sha256 of the
// blob that was read. A tag that cannot be established is withheld; an
// unreadable mirror (missing blob, frozen repository) is an error, never a
// withheld tag.
func Derive(r Reader, m *Mapping, opt Options) (*chartidentity.AppVersionTable, *Report, error) {
	rec := extract.NewRecorder(r)
	table := &chartidentity.AppVersionTable{Schema: chartidentity.AppVersionsSchema, Records: []chartidentity.AppVersionRecord{}}
	report := &Report{Entries: []EntryReport{}}
	for _, e := range m.Entries {
		repo, err := extract.ParseRepo(e.Repo)
		if err != nil {
			return nil, nil, err
		}
		tags, err := r.Tags(repo)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: tags: %w", e.Repo, err)
		}
		er := EntryReport{Component: e.Component, Chart: e.Chart, Repo: e.Repo, Withheld: []Withheld{}}
		var found []candidate
		for _, tag := range tags { // sorted by name
			ver, ok := e.match(tag.Name)
			if !ok {
				continue
			}
			er.Matched++
			rc, why, err := deriveTag(rec, repo, e, tag, ver, opt)
			if err != nil {
				return nil, nil, err
			}
			if why != "" {
				er.Withheld = append(er.Withheld, Withheld{Tag: tag.Name, Reason: why})
				continue
			}
			found = append(found, candidate{tag: tag.Name, record: rc})
		}
		// Two tags naming the same chart version cannot both be right.
		count := map[string]int{}
		for _, c := range found {
			count[c.record.ChartVersion]++
		}
		for _, c := range found {
			if count[c.record.ChartVersion] > 1 {
				er.Withheld = append(er.Withheld, Withheld{Tag: c.tag, Reason: fmt.Sprintf("chart version %s is named by more than one tag", c.record.ChartVersion)})
				continue
			}
			table.Records = append(table.Records, c.record)
			er.Derived++
		}
		sort.Slice(er.Withheld, func(i, j int) bool { return er.Withheld[i].Tag < er.Withheld[j].Tag })
		report.Entries = append(report.Entries, er)
	}
	chartidentity.SortAppVersions(table.Records)
	if err := table.Validate(); err != nil {
		return nil, nil, err
	}
	return table, report, nil
}

func deriveTag(rec *extract.Recorder, repo extract.RepoRef, e Entry, tag extract.Tag, ver string, opt Options) (chartidentity.AppVersionRecord, string, error) {
	var zero chartidentity.AppVersionRecord
	chartVersion, ok := chartidentity.NormalizeVersion(ver)
	if !ok {
		return zero, fmt.Sprintf("tag version %q is not a strict X.Y.Z", ver), nil
	}
	if !extract.IsCommitSHA(tag.Commit) {
		return zero, "tag does not resolve to a commit", nil
	}
	file := path.Join(e.ChartPath, "Chart.yaml")
	data, err := rec.Read(repo, tag.Commit, file)
	if errors.Is(err, extract.ErrNotFound) {
		return zero, "Chart.yaml does not exist at the tag commit", nil
	}
	if err != nil {
		return zero, "", fmt.Errorf("%s@%s:%s: %w", e.Repo, tag.Commit, file, err)
	}
	f, why := parseChartYAML(data)
	if why != "" {
		return zero, why, nil
	}
	if f.name != e.Chart {
		return zero, fmt.Sprintf("Chart.yaml name %q is not the mapped chart %q", f.name, e.Chart), nil
	}
	fileVersion, ok := chartidentity.NormalizeVersion(f.version)
	if !ok {
		return zero, fmt.Sprintf("Chart.yaml version %q is not a strict X.Y.Z", f.version), nil
	}
	if fileVersion != chartVersion {
		return zero, fmt.Sprintf("Chart.yaml version %q differs from the tag version %q", f.version, ver), nil
	}
	appVersion, ok := chartidentity.NormalizeVersion(f.appVersion)
	if !ok {
		return zero, fmt.Sprintf("appVersion %q is not a strict X.Y.Z", f.appVersion), nil
	}
	read, ok := rec.Lookup(repo, tag.Commit, file)
	if !ok {
		return zero, "", fmt.Errorf("internal: read of %s was not recorded", file)
	}
	return chartidentity.AppVersionRecord{
		Component: e.Component, Chart: e.Chart, ChartVersion: chartVersion, AppVersion: appVersion,
		Evidence: chartidentity.AppVersionEvidence{
			Basis: chartidentity.BasisMechanical, Extractor: opt.Extractor,
			DerivedAt: opt.DerivedAt.UTC().Format("2006-01-02T15:04:05Z"), ValidUntil: opt.ValidUntil.UTC().Format("2006-01-02T15:04:05Z"),
			Sources: []chartidentity.Source{{
				ID: "chart-yaml", URL: repo.BlobURL(tag.Commit, file), Revision: tag.Commit,
				ContentDigest: "sha256:" + read.SHA256, StartLine: f.startLine, EndLine: f.endLine,
			}},
		},
	}, "", nil
}
