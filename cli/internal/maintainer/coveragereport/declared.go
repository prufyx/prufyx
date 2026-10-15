// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// DeclaredSchema identifies the declared-unknown file.
const DeclaredSchema = "prufyx.io/coverage-declared-unknown/v1"

// Reasons a pair may be declared unknown: a closed list.
const (
	ReasonGoDefinedCRDs   = "blocked:go-defined-crds"
	ReasonTemplatedOnly   = "blocked:templated-only"
	ReasonOtherRepository = "blocked:other-repository"
	ReasonTagDeleted      = "frozen:tag-deleted"
	ReasonSharedGroup     = "conflict:shared-group"
	ReasonScanNotClean    = "scan:not-clean"
)

var declaredReasons = map[string]bool{
	ReasonGoDefinedCRDs: true, ReasonTemplatedOnly: true, ReasonOtherRepository: true,
	ReasonTagDeleted: true, ReasonSharedGroup: true, ReasonScanNotClean: true,
}

// MaxDeclarationWindow is the longest validity a declaration may carry.
const MaxDeclarationWindow = 90 * 24 * time.Hour

const maxDeclarations = 4096

//go:embed data/declared-unknown.json
var embeddedDeclared []byte

// EmbeddedDeclared returns the reviewed declared-unknown file shipped with
// the tool.
func EmbeddedDeclared() []byte { return append([]byte(nil), embeddedDeclared...) }

// Declaration states that one pair of consecutive lines of one family is
// unknown for a named reason. It decides nothing: it only tells "reviewed,
// cannot be decided" apart from "nobody looked".
type Declaration struct {
	Project    string `json:"project"`
	Family     string `json:"family"`
	From       string `json:"from"`
	To         string `json:"to"`
	Reason     string `json:"reason"`
	Note       string `json:"note"`
	DeclaredAt string `json:"declaredAt"`
	ValidUntil string `json:"validUntil"`
}

// DeclaredFile is the declared-unknown document.
type DeclaredFile struct {
	Schema       string        `json:"schema"`
	Declarations []Declaration `json:"declarations"`
}

type declKey struct{ project, family, from string }

func (d Declaration) key() declKey { return declKey{d.Project, d.Family, d.From} }

// ParseDeclared strictly decodes and validates a declared-unknown file:
// unknown members are rejected, records are sorted by project, family and
// from line, a record is unique by that key.
func ParseDeclared(raw []byte) (DeclaredFile, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f DeclaredFile
	if err := dec.Decode(&f); err != nil {
		return DeclaredFile{}, fmt.Errorf("%w: declared: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return DeclaredFile{}, fmt.Errorf("%w: declared: trailing data", ErrInvalid)
	}
	if f.Schema != DeclaredSchema {
		return DeclaredFile{}, fmt.Errorf("%w: declared: unknown schema", ErrInvalid)
	}
	if f.Declarations == nil || len(f.Declarations) > maxDeclarations {
		return DeclaredFile{}, fmt.Errorf("%w: declared: declarations must be an array of at most %d records", ErrInvalid, maxDeclarations)
	}
	families := map[string]bool{}
	for _, id := range registeredFamilies() {
		families[id] = true
	}
	for i, d := range f.Declarations {
		bad := func(what string) error {
			return fmt.Errorf("%w: declared: record %d: %s", ErrInvalid, i, what)
		}
		switch {
		case !slugRE.MatchString(d.Project):
			return DeclaredFile{}, bad("bad project slug")
		case !families[d.Family]:
			return DeclaredFile{}, bad("unknown family")
		case !lineattest.ValidLine(d.From) || !lineattest.ValidLine(d.To) || !lineattest.LineLess(d.From, d.To):
			return DeclaredFile{}, bad("from and to must be lines, from before to")
		case !declaredReasons[d.Reason]:
			return DeclaredFile{}, bad("reason is not in the closed list")
		case len(d.Note) > 512:
			return DeclaredFile{}, bad("note is longer than 512 bytes")
		}
		declared, err1 := constraintengine.ParseUTC(d.DeclaredAt)
		until, err2 := constraintengine.ParseUTC(d.ValidUntil)
		if err1 != nil || err2 != nil || !until.After(declared) || until.Sub(declared) > MaxDeclarationWindow {
			return DeclaredFile{}, bad("validUntil must be after declaredAt and at most 90 days later")
		}
		if i > 0 {
			prev := f.Declarations[i-1]
			if prev.key() == d.key() {
				return DeclaredFile{}, bad("duplicate project, family and from")
			}
			if !declLess(prev, d) {
				return DeclaredFile{}, bad("records must be sorted by project, family and from")
			}
		}
	}
	return f, nil
}

func declLess(a, b Declaration) bool {
	if a.Project != b.Project {
		return a.Project < b.Project
	}
	if a.Family != b.Family {
		return a.Family < b.Family
	}
	return lineattest.LineLess(a.From, b.From)
}

// currentAt reports whether the declaration may be relied on at now: inside
// its window and not within the expiry horizon.
func (d Declaration) currentAt(now time.Time) bool {
	declared, err1 := constraintengine.ParseUTC(d.DeclaredAt)
	until, err2 := constraintengine.ParseUTC(d.ValidUntil)
	if err1 != nil || err2 != nil {
		return false
	}
	return !now.Before(declared) && until.Sub(now) > ExpiryHorizon
}
