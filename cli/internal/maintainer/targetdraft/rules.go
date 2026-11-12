// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// RulesSchema identifies a pinned rules file.
const RulesSchema = "prufyx.io/target-draft-rules/v1"

// Exclusion classes a pinned rule may name.
const (
	// ClassExactFile excludes one file; the file may define only API groups
	// the target does not own.
	ClassExactFile = "exact-file"
	// ClassFixtureDir excludes a directory of test fixtures (path ends in
	// "/"); a fixture may repeat a definition the target already reads but
	// may not carry a different definition of an owned group.
	ClassFixtureDir = "fixture-dir"
)

// Rules are the reviewed, pinned judgments the generator may apply. They are
// input, never derived: an exclusion or an accepted install surface that no
// rule names ends in a typed stop.
type Rules struct {
	Schema string `json:"schema"`
	// Upstream is the provenance of a community-catalog project.
	Upstream *Upstream `json:"upstream,omitempty"`
	// InstallSurface lists files under a documentation or test-like
	// directory that are the accepted install surface of the project.
	InstallSurface []SurfaceRule `json:"installSurface"`
	// Exclusions are the pinned exclusions with their reviewed text.
	Exclusions []ExclusionRule `json:"exclusions"`
}

// Upstream mirrors the provenance block of a community table row.
type Upstream struct {
	Name          string `json:"name"`
	Repository    string `json:"repository"`
	License       string `json:"license"`
	LicenseSource string `json:"licenseSource"`
}

// SurfaceRule accepts one file as install surface.
type SurfaceRule struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ExclusionRule is one pinned exclusion.
type ExclusionRule struct {
	Class    string `json:"class"`
	Path     string `json:"path"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
}

// ParseRules reads a rules document strictly.
func ParseRules(raw []byte) (*Rules, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Rules
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("rules: trailing data")
	}
	if r.Schema != RulesSchema {
		return nil, fmt.Errorf("rules: schema must be %s", RulesSchema)
	}
	seen := map[string]bool{}
	cleanPath := func(p string) error {
		q := strings.TrimSuffix(p, "/")
		if q == "" || strings.HasPrefix(q, "/") || path.Clean(q) != q || q == ".." || strings.HasPrefix(q, "../") || strings.Contains(q, "\\") {
			return fmt.Errorf("rules: path %q is not a clean repository path", p)
		}
		return nil
	}
	for _, s := range r.InstallSurface {
		if err := cleanPath(s.Path); err != nil || strings.HasSuffix(s.Path, "/") || s.Reason == "" {
			return nil, fmt.Errorf("rules: install surface %q needs an exact file path and a reason", s.Path)
		}
		if seen["s:"+s.Path] {
			return nil, fmt.Errorf("rules: duplicate install surface %q", s.Path)
		}
		seen["s:"+s.Path] = true
	}
	for _, e := range r.Exclusions {
		if err := cleanPath(e.Path); err != nil {
			return nil, err
		}
		switch e.Class {
		case ClassExactFile:
			if strings.HasSuffix(e.Path, "/") {
				return nil, fmt.Errorf("rules: %q: an exact-file rule names one file", e.Path)
			}
		case ClassFixtureDir:
			if !strings.HasSuffix(e.Path, "/") {
				return nil, fmt.Errorf("rules: %q: a fixture-dir rule names a directory ending in /", e.Path)
			}
		default:
			return nil, fmt.Errorf("rules: %q: unknown class %q", e.Path, e.Class)
		}
		if e.Reason == "" || e.Evidence == "" {
			return nil, fmt.Errorf("rules: %q needs a reason and pinned evidence", e.Path)
		}
		if seen["e:"+e.Path] {
			return nil, fmt.Errorf("rules: duplicate exclusion %q", e.Path)
		}
		seen["e:"+e.Path] = true
	}
	return &r, nil
}
