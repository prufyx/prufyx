// SPDX-License-Identifier: AGPL-3.0-only

// Package targetguard checks the two reviewed data sets that decide whether
// a custom resource version can be attested: the custom-resource table
// (internal/customresources/table.json) and the CRD version targets
// (internal/extract/crdversions/target-*.json).
//
// The offline check validates the structure of both and the way they refer to
// each other, and compares them with the same files at a base revision: a
// removed table row, a removed target or a narrowed target is refused unless
// the reviewed removals list (internal/customresources/guard.json) gains a
// matching entry in the same change. The citations check is the only part
// that uses the network: every pinned source is a commit of its repository
// and the cited path exists at it.
package targetguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Paths of the checked files, relative to the cli module root.
const (
	TablePath = "internal/customresources/table.json"
	GuardPath = "internal/customresources/guard.json"
	TargetDir = "internal/extract/crdversions"
)

// GuardSchema identifies guard.json.
const GuardSchema = "prufyx.io/custom-resource-guard/v1"

// The kinds of a removal entry.
const (
	// KindProject: a project row left the table.
	KindProject = "project"
	// KindGroup: a group left a project that stays in the table.
	KindGroup = "group"
	// KindReserved: a reviewed ownership record left the table.
	KindReserved = "reserved"
	// KindTarget: a target file was deleted.
	KindTarget = "target"
	// KindNarrowed: a target that stays now covers less; Detail says what.
	KindNarrowed = "target-narrowed"
	// KindIdentity: the repository, component, catalog or fact project a
	// project or target stands for changed; Detail says which and to what.
	KindIdentity = "identity"
)

// Guard is guard.json: the reviewed removals and the table projects that
// have no target, each with its reason.
type Guard struct {
	Schema   string     `json:"schema"`
	Removals []Removal  `json:"removals"`
	NoTarget []NoTarget `json:"noTarget"`
}

// Removal is one reviewed removal. Kind, Project and Detail identify what
// was removed (see Diff); Reason is the reviewer's justification.
type Removal struct {
	Kind    string `json:"kind"`
	Project string `json:"project"`
	Detail  string `json:"detail"`
	// Seq numbers the entries of one (kind, project, detail), from 0: a
	// thing removed again after it was restored needs the next number.
	Seq    int    `json:"seq"`
	Reason string `json:"reason"`
}

func (r Removal) id() string  { return r.Kind + "\x00" + r.Project + "\x00" + r.Detail }
func (r Removal) key() string { return fmt.Sprintf("%s\x00%d", r.id(), r.Seq) }

// NoTarget declares that a table project has no target file, and why.
type NoTarget struct {
	Project string `json:"project"`
	Reason  string `json:"reason"`
}

// Inputs is everything the checks read at one revision.
type Inputs struct {
	Projects []customresources.Project
	Reserved []customresources.ReservedGroup
	Targets  []crdversions.Target
	Guard    Guard
	// GuardPresent is false when guard.json does not exist at this revision.
	GuardPresent bool
}

// Load reads the table, the targets and guard.json from fsys, a cli module
// root. Each file is decoded by its own strict loader. A missing guard.json
// is an empty list only when allowMissingGuard is set (the base revision
// of the change that adds the file).
func Load(fsys fs.FS, allowMissingGuard bool) (Inputs, error) {
	var in Inputs
	rawTable, err := fs.ReadFile(fsys, TablePath)
	if err != nil {
		return in, err
	}
	if in.Projects, in.Reserved, err = customresources.LoadTable(rawTable); err != nil {
		return in, fmt.Errorf("%s: %w", TablePath, err)
	}
	sub, err := fs.Sub(fsys, TargetDir)
	if err != nil {
		return in, err
	}
	if in.Targets, err = crdversions.LoadTargets(sub); err != nil {
		return in, err
	}
	rawGuard, err := fs.ReadFile(fsys, GuardPath)
	switch {
	case err == nil:
		if in.Guard, err = DecodeGuard(rawGuard); err != nil {
			return in, fmt.Errorf("%s: %w", GuardPath, err)
		}
		in.GuardPresent = true
	case allowMissingGuard && errors.Is(err, fs.ErrNotExist):
		in.Guard = Guard{Schema: GuardSchema}
	default:
		return in, err
	}
	return in, nil
}

// DecodeGuard decodes guard.json strictly: no unknown fields, no trailing
// data, the schema, and the shape of every entry.
func DecodeGuard(raw []byte) (Guard, error) {
	var g Guard
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return Guard{}, err
	}
	if dec.More() {
		return Guard{}, fmt.Errorf("trailing data")
	}
	if g.Schema != GuardSchema {
		return Guard{}, fmt.Errorf("schema %q, want %q", g.Schema, GuardSchema)
	}
	if g.Removals == nil || g.NoTarget == nil {
		return Guard{}, fmt.Errorf("removals and noTarget must be present (use [])")
	}
	seen := map[string]bool{}
	for _, r := range g.Removals {
		switch r.Kind {
		case KindProject, KindTarget:
			if r.Detail != "" {
				return Guard{}, fmt.Errorf("removal %s %q: detail is empty for this kind", r.Kind, r.Project)
			}
		case KindGroup, KindReserved, KindNarrowed, KindIdentity:
			if r.Detail == "" {
				return Guard{}, fmt.Errorf("removal %s %q: detail is required", r.Kind, r.Project)
			}
		default:
			return Guard{}, fmt.Errorf("removal kind %q is unknown", r.Kind)
		}
		if r.Seq < 0 || r.Project == "" || !reasonOK(r.Reason) {
			return Guard{}, fmt.Errorf("removal %s %q: a project and a reason of 12 to 300 characters are required", r.Kind, r.Project)
		}
		if seen[r.key()] {
			return Guard{}, fmt.Errorf("removal %s %q %q is listed twice", r.Kind, r.Project, r.Detail)
		}
		seen[r.key()] = true
	}
	prev := ""
	for _, n := range g.NoTarget {
		if n.Project == "" || !reasonOK(n.Reason) || n.Project <= prev {
			return Guard{}, fmt.Errorf("noTarget %q: ascending unique projects and a reason of 12 to 300 characters are required", n.Project)
		}
		prev = n.Project
	}
	return g, nil
}

func reasonOK(s string) bool {
	return strings.TrimSpace(s) == s && len(s) >= 12 && len(s) <= 300
}
