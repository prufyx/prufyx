// SPDX-License-Identifier: AGPL-3.0-only

// Package upstream turns committed excerpts of the upstream Kubernetes
// release data (schedule.yaml, eol.yaml, and the stable marker) into minor
// line lifecycle rows of the distribution record shape. It is pure: bytes in,
// rows out, no network, no clock. Any row outside the grammar is a typed
// drift error and no partial output is returned.
package upstream

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/shared"
	"gopkg.in/yaml.v3"
)

var (
	minorRE  = regexp.MustCompile(`^1\.(0|[1-9][0-9]{0,5})$`)
	patchRE  = regexp.MustCompile(`^1\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	stableRE = regexp.MustCompile(`^v(1\.(?:0|[1-9][0-9]{0,5}))\.(0|[1-9][0-9]{0,5})$`)
)

// Minor is one upstream minor line as the release data states it. Dates are
// strings (YYYY-MM-DD); they are never decoded as YAML timestamps or floats.
type Minor struct {
	Line             string
	ReleaseDate      string // empty for an eol.yaml-only line
	MaintenanceStart string // empty for an eol.yaml-only line
	EndOfLife        string
	FinalPatch       string // eol.yaml only
	NextPatch        string // schedule.yaml next.release, when present
}

// Schedule is the parsed schedule.yaml, ascending by line.
type Schedule struct{ Minors []Minor }

// EOL is the parsed eol.yaml, ascending by line.
type EOL struct{ Minors []Minor }

// node helpers: strict mapping walk over yaml.Node.

type mapping struct {
	kv   map[string]*yaml.Node
	path string
}

func asMapping(n *yaml.Node, path string, allowed ...string) (mapping, error) {
	if n.Kind != yaml.MappingNode {
		return mapping{}, shared.Drift(shared.KindFormat, "%s: mapping expected", path)
	}
	if n.Anchor != "" || n.Alias != nil {
		return mapping{}, shared.Drift(shared.KindFormat, "%s: anchors and aliases are not accepted", path)
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	m := mapping{kv: map[string]*yaml.Node{}, path: path}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Anchor != "" {
			return mapping{}, shared.Drift(shared.KindFormat, "%s: non-scalar key", path)
		}
		if !ok[k.Value] {
			return mapping{}, shared.Drift(shared.KindHeader, "%s: unknown key %q", path, k.Value)
		}
		if _, dup := m.kv[k.Value]; dup {
			return mapping{}, shared.Drift(shared.KindFormat, "%s: duplicate key %q", path, k.Value)
		}
		m.kv[k.Value] = v
	}
	return m, nil
}

func (m mapping) req(key string) (*yaml.Node, error) {
	v, ok := m.kv[key]
	if !ok {
		return nil, shared.Drift(shared.KindMissing, "%s: missing %q", m.path, key)
	}
	return v, nil
}

// text returns the scalar text of a string-typed scalar. A scalar YAML would
// type as a number, bool, null or timestamp is refused unless it is quoted:
// an unquoted 1.30 is the float 1.3 and must never become a version.
func (m mapping) text(key string, mustQuote bool) (string, error) {
	v, err := m.req(key)
	if err != nil {
		return "", err
	}
	if v.Kind != yaml.ScalarNode || v.Anchor != "" {
		return "", shared.Drift(shared.KindUnparsable, "%s.%s: scalar expected", m.path, key)
	}
	quoted := v.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
	if v.Tag != "!!str" || (mustQuote && !quoted) {
		return "", shared.Drift(shared.KindUnparsable, "%s.%s: %q is not a string value (quote it)", m.path, key, v.Value)
	}
	return v.Value, nil
}

func (m mapping) date(key string) (string, error) {
	s, err := m.text(key, true)
	if err != nil {
		return "", err
	}
	c, err := shared.ParseCell(s, false)
	if err != nil || c.Precision != distribution.PrecisionDay || c.Value != s {
		return "", shared.Drift(shared.KindUnparsable, "%s.%s: %q is not a YYYY-MM-DD date", m.path, key, s)
	}
	return s, nil
}

func (m mapping) minor(key string) (string, error) {
	s, err := m.text(key, true)
	if err != nil {
		return "", err
	}
	if !minorRE.MatchString(s) {
		return "", shared.Drift(shared.KindUnparsable, "%s.%s: %q is not a 1.N minor", m.path, key, s)
	}
	return s, nil
}

func (m mapping) patch(key, line string) (string, error) {
	s, err := m.text(key, false)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(s, "-+") {
		return "", shared.Drift(shared.KindPrerelease, "%s.%s: %q is a prerelease or build", m.path, key, s)
	}
	if !patchRE.MatchString(s) || !strings.HasPrefix(s, line+".") {
		return "", shared.Drift(shared.KindUnparsable, "%s.%s: %q is not a patch of %s", m.path, key, s, line)
	}
	return s, nil
}

func parseDoc(body string) (mapping, *yaml.Node, error) {
	if err := shared.CheckBody([]byte(body)); err != nil {
		return mapping{}, nil, err
	}
	var docs []*yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(body))
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return mapping{}, nil, shared.Drift(shared.KindFormat, "yaml: %v", err)
		}
		docs = append(docs, &n)
		if len(docs) > 1 {
			return mapping{}, nil, shared.Drift(shared.KindFormat, "more than one yaml document")
		}
	}
	if len(docs) != 1 || docs[0].Kind != yaml.DocumentNode || len(docs[0].Content) != 1 {
		return mapping{}, nil, shared.Drift(shared.KindEmpty, "no yaml document")
	}
	return mapping{}, docs[0].Content[0], nil
}

func seq(n *yaml.Node, path string) ([]*yaml.Node, error) {
	if n.Kind != yaml.SequenceNode || n.Anchor != "" {
		return nil, shared.Drift(shared.KindFormat, "%s: list expected", path)
	}
	if len(n.Content) == 0 || len(n.Content) > 256 {
		return nil, shared.Drift(shared.KindFormat, "%s: 1-256 entries expected", path)
	}
	return n.Content, nil
}

// ParseSchedule parses schedule.yaml (or an excerpt of it holding whole
// entries). Required per entry: release (quoted minor), releaseDate,
// endOfLifeDate, maintenanceModeStartDate. next and previousPatches are
// validated when present. upcoming_releases is validated when present and
// ignored. Duplicate lines, unknown keys and any bad cell reject the file.
func ParseSchedule(body string) (Schedule, error) {
	_, root, err := parseDoc(body)
	if err != nil {
		return Schedule{}, err
	}
	top, err := asMapping(root, "schedule", "schedules", "upcoming_releases")
	if err != nil {
		return Schedule{}, err
	}
	sn, err := top.req("schedules")
	if err != nil {
		return Schedule{}, err
	}
	entries, err := seq(sn, "schedules")
	if err != nil {
		return Schedule{}, err
	}
	var out Schedule
	seen := map[string]bool{}
	for i, en := range entries {
		path := fmt.Sprintf("schedules[%d]", i)
		m, err := asMapping(en, path, "release", "releaseDate", "endOfLifeDate", "maintenanceModeStartDate", "next", "previousPatches")
		if err != nil {
			return Schedule{}, err
		}
		line, err := m.minor("release")
		if err != nil {
			return Schedule{}, err
		}
		if seen[line] {
			return Schedule{}, shared.Drift(shared.KindFormat, "%s: duplicate release %s", path, line)
		}
		seen[line] = true
		mn := Minor{Line: line}
		if mn.ReleaseDate, err = m.date("releaseDate"); err != nil {
			return Schedule{}, err
		}
		if mn.EndOfLife, err = m.date("endOfLifeDate"); err != nil {
			return Schedule{}, err
		}
		if mn.MaintenanceStart, err = m.date("maintenanceModeStartDate"); err != nil {
			return Schedule{}, err
		}
		if !(mn.ReleaseDate <= mn.MaintenanceStart && mn.MaintenanceStart <= mn.EndOfLife) {
			return Schedule{}, shared.Drift(shared.KindUnparsable, "%s: dates out of order (release <= maintenance <= end of life)", path)
		}
		if nx, ok := m.kv["next"]; ok {
			nm, err := asMapping(nx, path+".next", "cherryPickDeadline", "release", "targetDate")
			if err != nil {
				return Schedule{}, err
			}
			if mn.NextPatch, err = nm.patch("release", line); err != nil {
				return Schedule{}, err
			}
			if _, err = nm.date("cherryPickDeadline"); err != nil {
				return Schedule{}, err
			}
			if _, err = nm.date("targetDate"); err != nil {
				return Schedule{}, err
			}
		}
		if pp, ok := m.kv["previousPatches"]; ok {
			items, err := seq(pp, path+".previousPatches")
			if err != nil {
				return Schedule{}, err
			}
			for j, it := range items {
				pm, err := asMapping(it, fmt.Sprintf("%s.previousPatches[%d]", path, j), "cherryPickDeadline", "release", "targetDate")
				if err != nil {
					return Schedule{}, err
				}
				if _, err = pm.patch("release", line); err != nil {
					return Schedule{}, err
				}
				if _, err = pm.date("cherryPickDeadline"); err != nil {
					return Schedule{}, err
				}
				if _, err = pm.date("targetDate"); err != nil {
					return Schedule{}, err
				}
			}
		}
		out.Minors = append(out.Minors, mn)
	}
	if up, ok := top.kv["upcoming_releases"]; ok {
		items, err := seq(up, "upcoming_releases")
		if err != nil {
			return Schedule{}, err
		}
		for j, it := range items {
			um, err := asMapping(it, fmt.Sprintf("upcoming_releases[%d]", j), "cherryPickDeadline", "targetDate")
			if err != nil {
				return Schedule{}, err
			}
			if _, err = um.date("cherryPickDeadline"); err != nil {
				return Schedule{}, err
			}
			if _, err = um.date("targetDate"); err != nil {
				return Schedule{}, err
			}
		}
	}
	sortMinors(out.Minors)
	return out, nil
}

// ParseEOL parses eol.yaml (or an excerpt of it): entries with release
// (quoted minor), endOfLifeDate, finalPatchRelease and an optional free-text
// note, which is validated as a string and not carried.
func ParseEOL(body string) (EOL, error) {
	_, root, err := parseDoc(body)
	if err != nil {
		return EOL{}, err
	}
	top, err := asMapping(root, "eol", "branches")
	if err != nil {
		return EOL{}, err
	}
	bn, err := top.req("branches")
	if err != nil {
		return EOL{}, err
	}
	entries, err := seq(bn, "branches")
	if err != nil {
		return EOL{}, err
	}
	var out EOL
	seen := map[string]bool{}
	for i, en := range entries {
		path := fmt.Sprintf("branches[%d]", i)
		m, err := asMapping(en, path, "release", "endOfLifeDate", "finalPatchRelease", "note")
		if err != nil {
			return EOL{}, err
		}
		line, err := m.minor("release")
		if err != nil {
			return EOL{}, err
		}
		if seen[line] {
			return EOL{}, shared.Drift(shared.KindFormat, "%s: duplicate release %s", path, line)
		}
		seen[line] = true
		mn := Minor{Line: line}
		if mn.EndOfLife, err = m.date("endOfLifeDate"); err != nil {
			return EOL{}, err
		}
		if mn.FinalPatch, err = m.patch("finalPatchRelease", line); err != nil {
			return EOL{}, err
		}
		if _, ok := m.kv["note"]; ok {
			if _, err = m.text("note", false); err != nil {
				return EOL{}, err
			}
		}
		out.Minors = append(out.Minors, mn)
	}
	sortMinors(out.Minors)
	return out, nil
}

// ParseStable parses the stable marker: exactly vMAJOR.MINOR.PATCH, one
// optional trailing LF. A prerelease, a missing patch, markup or anything
// else is rejected. It returns the line and the patch version ("1.37.2").
func ParseStable(body string) (line, patch string, err error) {
	if err := shared.CheckBody([]byte(body)); err != nil {
		return "", "", err
	}
	s := strings.TrimSuffix(body, "\n")
	if strings.ContainsAny(s, "-+") && strings.HasPrefix(s, "v1.") && !strings.ContainsAny(s, "<> \t\n") {
		return "", "", shared.Drift(shared.KindPrerelease, "stable marker %q is a prerelease", s)
	}
	m := stableRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", shared.Drift(shared.KindUnparsable, "stable marker %q", s)
	}
	return m[1], m[1] + "." + m[2], nil
}

func lineNum(l string) int {
	var n int
	fmt.Sscanf(l, "1.%d", &n)
	return n
}

func sortMinors(m []Minor) {
	sort.Slice(m, func(i, j int) bool { return lineNum(m[i].Line) < lineNum(m[j].Line) })
}
