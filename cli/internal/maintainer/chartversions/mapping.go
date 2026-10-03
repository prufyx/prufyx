// SPDX-License-Identifier: AGPL-3.0-only

// Package chartversions derives the chart-version to application-version
// table from the offline mirror. For every mapped chart it reads Chart.yaml
// at each release tag commit, keeps only releases whose chart version and
// application version are strict X.Y.Z, and records where each value was
// read. It never uses the network and never guesses: a tag it cannot
// establish completely is withheld and reported with its reason.
package chartversions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// MappingSchema names the mapping file format.
const MappingSchema = "prufyx.io/chart-mapping/v1alpha1"

const (
	maxEntries      = 512
	maxMappingBytes = 1 << 20
	versionToken    = "{version}"
)

var (
	componentRE = regexp.MustCompile(`^pkg:[a-z0-9][a-z0-9+._/-]{2,255}$`)
	chartRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	pathPartRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	patternRE   = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
	capturedRE  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]*$`)
)

// Entry maps one chart to the repository that publishes it.
type Entry struct {
	Component string `json:"component"`
	Chart     string `json:"chart"`
	// Repo is the GitHub repository (github.com/owner/name) holding the chart.
	Repo string `json:"repo"`
	// ChartPath is the directory of Chart.yaml inside the repository; empty
	// means the repository root.
	ChartPath string `json:"chartPath"`
	// TagPattern selects release tags: literal text around one "{version}".
	TagPattern string `json:"tagPattern"`
}

// Mapping is the derivation input.
type Mapping struct {
	Schema  string  `json:"schema"`
	Entries []Entry `json:"entries"`
}

// ParseMapping parses a mapping strictly: unknown fields, unsorted or
// duplicate entries and malformed values are rejected.
func ParseMapping(raw []byte) (*Mapping, error) {
	if len(raw) > maxMappingBytes {
		return nil, fmt.Errorf("mapping too large")
	}
	var m Mapping
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("mapping: trailing data")
	}
	if m.Schema != MappingSchema || m.Entries == nil || len(m.Entries) > maxEntries {
		return nil, fmt.Errorf("mapping: bad header")
	}
	for i, e := range m.Entries {
		if i > 0 {
			p := m.Entries[i-1]
			if p.Component > e.Component || (p.Component == e.Component && p.Chart >= e.Chart) {
				return nil, fmt.Errorf("mapping entry %d: entries must be sorted by component, chart and unique", i)
			}
		}
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("mapping entry %d: %w", i, err)
		}
	}
	return &m, nil
}

func (e Entry) validate() error {
	if !componentRE.MatchString(e.Component) || !chartRE.MatchString(e.Chart) {
		return fmt.Errorf("component or chart")
	}
	if _, err := extract.ParseRepo(e.Repo); err != nil || strings.ToLower(e.Repo) != e.Repo {
		return fmt.Errorf("repo must be a lower-case github.com/<owner>/<name>")
	}
	if e.ChartPath != "" {
		for _, seg := range strings.Split(e.ChartPath, "/") {
			if seg == "." || seg == ".." || !pathPartRE.MatchString(seg) {
				return fmt.Errorf("chartPath")
			}
		}
	}
	if strings.Count(e.TagPattern, versionToken) != 1 {
		return fmt.Errorf("tagPattern needs exactly one %s", versionToken)
	}
	pre, post, _ := strings.Cut(e.TagPattern, versionToken)
	if !patternRE.MatchString(pre) || !patternRE.MatchString(post) {
		return fmt.Errorf("tagPattern literal text")
	}
	return nil
}

// LoadMapping reads and parses a mapping file.
func LoadMapping(path string) (*Mapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMappingBytes+1))
	if err != nil {
		return nil, err
	}
	return ParseMapping(raw)
}

// match returns the version text a tag carries under the pattern.
func (e Entry) match(tag string) (string, bool) {
	pre, post, _ := strings.Cut(e.TagPattern, versionToken)
	if !strings.HasPrefix(tag, pre) || !strings.HasSuffix(tag, post) || len(tag) <= len(pre)+len(post) {
		return "", false
	}
	mid := tag[len(pre) : len(tag)-len(post)]
	if !capturedRE.MatchString(mid) {
		return "", false
	}
	return mid, true
}
