// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// The feature file is the only source of the feature statements in the
// release notes. A statement is either "works" (it names a demo command and
// the evidence behind it) or "not-yet" (it names the one-line reason). The
// file is closed: an unknown field, a missing field or a field that does not
// belong to the state is refused.
const (
	// FeaturesPath is where a tree commits its feature file.
	FeaturesPath = "cli/docs/release-features.json"
	// SmokePath is the list of demo commands CI runs; every "works" demo is on it.
	SmokePath = "cli/docs/release-features-smoke.json"
	// FeaturesSchema is the schema string of the feature file.
	FeaturesSchema = "prufyx.io/release-features/v1"
	// SmokeSchema is the schema string of the smoke list.
	SmokeSchema = "prufyx.io/release-features-smoke/v1"

	StateWorks  = "works"
	StateNotYet = "not-yet"

	maxFeatureFile = 1 << 20
	maxFeatureText = 300
)

// ReservedNotYet are features that may not be "works" until the code that
// ships them has landed; changing this list is a change to the gate code.
var ReservedNotYet = []string{"kind-per-version", "source-citations"}

// Feature is one statement.
type Feature struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	State    string `json:"state"`
	Demo     string `json:"demo"`
	Evidence string `json:"evidence"`
	NotYet   string `json:"notYet"`
}

// Features is the feature file.
type Features struct {
	Schema   string    `json:"schema"`
	Features []Feature `json:"features"`
}

var featureID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// decodeStrict decodes one JSON document into v: no unknown field, no data after it.
func decodeStrict(data []byte, v any) error {
	if len(data) == 0 || len(data) > maxFeatureFile {
		return errors.New("the file is empty or too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON document")
	}
	return nil
}

// plainLine is a single line without markup that could change how the notes
// are read: no backtick, no pipe, no control character, no markup at the start.
func plainLine(s string) bool {
	if s != strings.TrimSpace(s) || len(s) > maxFeatureText {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '`' || r == '|' {
			return false
		}
	}
	return true
}

// LoadFeatures parses and verifies the feature file. Every problem is an error.
func LoadFeatures(data []byte) (*Features, error) {
	var f Features
	if err := decodeStrict(data, &f); err != nil {
		return nil, fmt.Errorf("feature file: %w", err)
	}
	if f.Schema != FeaturesSchema {
		return nil, fmt.Errorf("feature file: schema %q, want %q", f.Schema, FeaturesSchema)
	}
	if len(f.Features) == 0 {
		return nil, errors.New("feature file: no feature")
	}
	seen := map[string]bool{}
	for i, x := range f.Features {
		at := fmt.Sprintf("feature file: entry %d", i+1)
		if !featureID.MatchString(x.ID) {
			return nil, fmt.Errorf("%s: id %q is not a lower-case slug", at, x.ID)
		}
		at = fmt.Sprintf("feature file: %s", x.ID)
		if seen[x.ID] {
			return nil, fmt.Errorf("%s: duplicate id", at)
		}
		seen[x.ID] = true
		for name, v := range map[string]string{"title": x.Title, "demo": x.Demo, "evidence": x.Evidence, "notYet": x.NotYet} {
			if !plainLine(v) {
				return nil, fmt.Errorf("%s: %s is not a plain single line of at most %d characters", at, name, maxFeatureText)
			}
		}
		if x.Title == "" || strings.HasSuffix(x.Title, ".") {
			return nil, fmt.Errorf("%s: title is empty or ends with a period", at)
		}
		switch x.State {
		case StateWorks:
			if x.Demo == "" || x.Evidence == "" {
				return nil, fmt.Errorf("%s: a works feature needs a demo and evidence", at)
			}
			if x.NotYet != "" {
				return nil, fmt.Errorf("%s: a works feature has no notYet reason", at)
			}
			for _, r := range ReservedNotYet {
				if x.ID == r {
					return nil, fmt.Errorf("%s: this feature stays not-yet until the code that ships it has landed", at)
				}
			}
		case StateNotYet:
			if x.NotYet == "" {
				return nil, fmt.Errorf("%s: a not-yet feature needs its reason", at)
			}
			if x.Demo != "" || x.Evidence != "" {
				return nil, fmt.Errorf("%s: a not-yet feature has no demo or evidence", at)
			}
		default:
			return nil, fmt.Errorf("%s: state %q is neither %s nor %s", at, x.State, StateWorks, StateNotYet)
		}
	}
	return &f, nil
}

// WorksLine is the rendered line of a works feature.
func WorksLine(f Feature) string { return fmt.Sprintf("- %s. Run: `%s`", f.Title, f.Demo) }

// NotYetLine is the rendered line of a not-yet feature.
func NotYetLine(f Feature) string { return fmt.Sprintf("- %s: %s", f.Title, f.NotYet) }

// renderFeatures writes the two lists. Every sentence comes from the file.
func renderFeatures(b *strings.Builder, f *Features) {
	var works, not []string
	for _, x := range f.Features {
		if x.State == StateWorks {
			works = append(works, WorksLine(x))
		} else {
			not = append(not, NotYetLine(x))
		}
	}
	b.WriteString("### Works in this release\n\nEach item names the command that shows it; CI runs that command.\n\n")
	if len(works) == 0 {
		b.WriteString("Nothing is listed here.\n\n")
	} else {
		b.WriteString(strings.Join(works, "\n") + "\n\n")
	}
	b.WriteString("### Not yet\n\nThese are not part of this release.\n\n")
	if len(not) == 0 {
		b.WriteString("Nothing is listed here.\n\n")
	} else {
		b.WriteString(strings.Join(not, "\n") + "\n\n")
	}
}

// SmokeEntry is one demo CI runs: the command is run against the built binary
// by a test. A demo that no CI step runs literally cannot be on the list.
type SmokeEntry struct {
	Demo         string   `json:"demo"`
	Kind         string   `json:"kind"`
	Args         []string `json:"args,omitempty"`
	WantExit     *int     `json:"wantExit,omitempty"`
	WantContains string   `json:"wantContains,omitempty"`
}

// SmokeList is the smoke list file.
type SmokeList struct {
	Schema  string       `json:"schema"`
	Entries []SmokeEntry `json:"entries"`
}

// SmokeBinary is the only kind: a command run by the smoke test.
const SmokeBinary = "binary"

// LoadSmoke parses and verifies the smoke list.
func LoadSmoke(data []byte) (*SmokeList, error) {
	var l SmokeList
	if err := decodeStrict(data, &l); err != nil {
		return nil, fmt.Errorf("smoke list: %w", err)
	}
	if l.Schema != SmokeSchema {
		return nil, fmt.Errorf("smoke list: schema %q, want %q", l.Schema, SmokeSchema)
	}
	seen := map[string]bool{}
	for _, e := range l.Entries {
		if !plainLine(e.Demo) || e.Demo == "" {
			return nil, fmt.Errorf("smoke list: a demo is empty or not a plain line")
		}
		if seen[e.Demo] {
			return nil, fmt.Errorf("smoke list: duplicate demo %q", e.Demo)
		}
		seen[e.Demo] = true
		if e.Kind != SmokeBinary {
			return nil, fmt.Errorf("smoke list: %q: kind %q is not %s", e.Demo, e.Kind, SmokeBinary)
		}
		if len(e.Args) == 0 || e.WantExit == nil || e.WantContains == "" {
			return nil, fmt.Errorf("smoke list: %q: an entry needs args, wantExit and wantContains", e.Demo)
		}
		// The command shown is the command run.
		if e.Demo != "prufyx "+strings.Join(e.Args, " ") {
			return nil, fmt.Errorf("smoke list: %q: the demo is not \"prufyx \" plus the args", e.Demo)
		}
	}
	return &l, nil
}

// ReadFeatures reads and verifies the feature file of a tree. A missing file
// is an error that satisfies errors.Is(err, fs.ErrNotExist).
func ReadFeatures(t Tree) (*Features, error) {
	data, err := t.Read(FeaturesPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FeaturesPath, err)
	}
	return LoadFeatures(data)
}
