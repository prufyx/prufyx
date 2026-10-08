// SPDX-License-Identifier: AGPL-3.0-only

// Package coveragereport measures how much of each project's recent upgrade
// surface the knowledge pack decides. It is reporting only: it reads a rule
// pack and a snapshot of upstream release lines, classifies every pair of
// consecutive lines and never produces, changes or influences a verdict.
package coveragereport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// LinesSchema identifies the lines snapshot file.
const LinesSchema = "prufyx.io/coverage-lines/v1"

// ErrInvalid marks malformed input.
var ErrInvalid = errors.New("invalid coverage report input")

// ProjectLines is one project's known release lines.
type ProjectLines struct {
	// Component is the optional package identity used to match line
	// attestations of a project that has no rule yet.
	Component string `json:"component,omitempty"`
	// Priority marks the project as part of the priority portfolio.
	Priority bool `json:"priority,omitempty"`
	// Lines are the minor release lines that have at least one final
	// release, ascending ("1.28"), without duplicates.
	Lines []string `json:"lines"`
}

// LinesFile is the offline version input: a snapshot of upstream release
// lines per project.
type LinesFile struct {
	Schema string `json:"schema"`
	// CapturedOn is an optional YYYY-MM-DD date of the snapshot.
	CapturedOn string                  `json:"capturedOn,omitempty"`
	Projects   map[string]ProjectLines `json:"projects"`
}

var (
	slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	dateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// ParseLines strictly decodes and validates a lines file.
func ParseLines(raw []byte) (LinesFile, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f LinesFile
	if err := dec.Decode(&f); err != nil {
		return LinesFile{}, fmt.Errorf("%w: lines: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return LinesFile{}, fmt.Errorf("%w: lines: trailing data", ErrInvalid)
	}
	if f.Schema != LinesSchema {
		return LinesFile{}, fmt.Errorf("%w: lines: unknown schema", ErrInvalid)
	}
	if f.CapturedOn != "" && !dateRE.MatchString(f.CapturedOn) {
		return LinesFile{}, fmt.Errorf("%w: lines: capturedOn is not a date", ErrInvalid)
	}
	if len(f.Projects) == 0 {
		return LinesFile{}, fmt.Errorf("%w: lines: no projects", ErrInvalid)
	}
	for slug, p := range f.Projects {
		if !slugRE.MatchString(slug) {
			return LinesFile{}, fmt.Errorf("%w: lines: bad project slug", ErrInvalid)
		}
		for i, line := range p.Lines {
			if !lineattest.ValidLine(line) {
				return LinesFile{}, fmt.Errorf("%w: lines: %s: bad line %q", ErrInvalid, slug, line)
			}
			if i > 0 && !lineattest.LineLess(p.Lines[i-1], line) {
				return LinesFile{}, fmt.Errorf("%w: lines: %s: lines must be strictly ascending", ErrInvalid, slug)
			}
		}
	}
	return f, nil
}

// MarshalLines returns the canonical bytes of a lines file: sorted keys,
// two-space indent, trailing newline.
func MarshalLines(f LinesFile) ([]byte, error) {
	f.Schema = LinesSchema
	for slug, p := range f.Projects {
		if p.Lines == nil {
			p.Lines = []string{}
			f.Projects[slug] = p
		}
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := ParseLines(out); err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// versionTag is a tag spelling a final release version.
var (
	finalTagRE   = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	linkerdTagRE = regexp.MustCompile(`^(?:stable|version)-(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	// cloud-custodian releases are 0.9.N or 0.9.N.M; the line is 9.N.
	custodianTagRE = regexp.MustCompile(`^v?0\.9\.([1-9][0-9]{0,8}|0)(?:\.(?:0|[1-9][0-9]{0,8}))?$`)
)

// LineOfTag maps a tag to the release line of a final release. ok is false
// for a pre-release, a snapshot or any spelling this reviewed table does not
// know: such a tag adds no line (fail closed).
func LineOfTag(project, tag string) (string, bool) {
	tag = strings.TrimSuffix(strings.TrimPrefix(tag, "refs/tags/"), "^{}")
	switch project {
	case "linkerd":
		if m := linkerdTagRE.FindStringSubmatch(tag); m != nil {
			return m[1] + "." + m[2], true
		}
		return "", false
	case "cloud-custodian":
		if m := custodianTagRE.FindStringSubmatch(tag); m != nil {
			return "9." + m[1], true
		}
		return "", false
	}
	if m := finalTagRE.FindStringSubmatch(tag); m != nil {
		return m[1] + "." + m[2], true
	}
	return "", false
}

// LinesFromTags turns per-project tag listings into a lines file. A listing
// is either one tag per line or the output of git ls-remote --tags (the tag
// is the last field). Blank lines and lines starting with # are skipped.
// Priority marks the projects of the priority portfolio.
func LinesFromTags(listings map[string][]byte, priority map[string]bool, capturedOn string) (LinesFile, error) {
	f := LinesFile{Schema: LinesSchema, CapturedOn: capturedOn, Projects: map[string]ProjectLines{}}
	for project, raw := range listings {
		if !slugRE.MatchString(project) {
			return LinesFile{}, fmt.Errorf("%w: bad project slug", ErrInvalid)
		}
		seen := map[string]bool{}
		for _, text := range strings.Split(string(raw), "\n") {
			text = strings.TrimSpace(text)
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			fields := strings.Fields(text)
			if line, ok := LineOfTag(project, fields[len(fields)-1]); ok {
				seen[line] = true
			}
		}
		lines := make([]string, 0, len(seen))
		for line := range seen {
			lines = append(lines, line)
		}
		sort.Slice(lines, func(i, j int) bool { return lineattest.LineLess(lines[i], lines[j]) })
		f.Projects[project] = ProjectLines{Priority: priority[project], Lines: lines}
	}
	if _, err := MarshalLines(f); err != nil {
		return LinesFile{}, err
	}
	return f, nil
}
