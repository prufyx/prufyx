// SPDX-License-Identifier: AGPL-3.0-only

// Package hopstop is the hop-stop record: the signed outcome of one hop (a
// pair of consecutive release lines) that the pipeline derived without an
// attestation. It carries a code from a CLOSED set and nothing else a person
// could have typed: no free text, no URL. An unknown code, a code outside the
// set, a transient code or any field out of its shape refuses the record.
//
// release-pending and derive-failed are states of a run, never outcomes of a
// hop: a record that carries one is refused, so a hop cannot stay unresolved
// for ever behind a stale transient record and a derivable rule cannot be
// hidden behind it.
//
// The record is public, additive and carries no project knowledge of its own:
// the project is a slug, the family one of the lineattest families.
package hopstop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Schema is the schema version of a hop-stop record. A record of another
// schema is refused.
const Schema = "prufyx.io/hop-stop/v1"

// PackMember is the name of the pack section that will carry the records.
// The section is not yet one of lineattest.PackMembers: adding it changes
// the pack schema level and is a separate, reviewed step.
const PackMember = "hopStops"

// MaxReasons bounds Record.Reasons.
const MaxReasons = 8

const familyStopPrefix = "family-stop:"

var finalCodes = []string{
	"hop-not-previous-minor",
	"declared-incomplete",
	"scan-unclean",
	"rules-not-line-wide",
	"definition-removed",
	"tags-missing",
	"window-shortened",
}

// FamilyStopSuffixes is the closed set of router stop names a hop may end in
// as "family-stop:<name>". Extending it is a code change.
var FamilyStopSuffixes = []string{"frozen", "narrowed", "parked", "unsupported"}

var transientCodes = []string{"release-pending", "derive-failed"}

// Final reports whether code is a final stop code: one of the closed list, or
// "family-stop:" followed by a member of FamilyStopSuffixes.
func Final(code string) bool {
	if slices.Contains(finalCodes, code) {
		return true
	}
	if rest, ok := strings.CutPrefix(code, familyStopPrefix); ok {
		return slices.Contains(FamilyStopSuffixes, rest)
	}
	return false
}

// Transient reports whether code is a transient code (never persisted).
func Transient(code string) bool { return slices.Contains(transientCodes, code) }

// Record is one hop-stop.
type Record struct {
	Schema      string   `json:"schema"`
	Project     string   `json:"project"`
	Family      string   `json:"family"`
	FromLine    string   `json:"fromLine"`
	ToLine      string   `json:"toLine"`
	Code        string   `json:"code"`
	Reasons     []string `json:"reasons"`
	ToolCommit  string   `json:"toolCommit"`
	FactsDigest string   `json:"factsDigest"`
}

// ErrInvalid marks a refused record or section.
var ErrInvalid = errors.New("hop-stop refused")

var (
	slugRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Validate checks one record. It never repairs.
func (r Record) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	switch {
	case r.Schema != Schema:
		return bad("schema is not %s", Schema)
	case !slugRE.MatchString(r.Project):
		return bad("project is not a slug")
	}
	if _, ok := lineattest.LookupFamily(r.Family); !ok {
		return bad("family is not a known family")
	}
	switch {
	case !lineattest.ValidLine(r.FromLine) || !lineattest.ValidLine(r.ToLine):
		return bad("a line is not major.minor")
	case !lineattest.LineLess(r.FromLine, r.ToLine):
		return bad("fromLine is not before toLine")
	case Transient(r.Code):
		return bad("code %s is transient and is never a final outcome", r.Code)
	case !Final(r.Code):
		return bad("code is not in the closed set")
	case !commitRE.MatchString(r.ToolCommit):
		return bad("toolCommit is not a full commit id")
	case !digestRE.MatchString(r.FactsDigest):
		return bad("factsDigest is not sha256:<hex>")
	case len(r.Reasons) > MaxReasons:
		return bad("more than %d reasons", MaxReasons)
	}
	for i, reason := range r.Reasons {
		if !Final(reason) {
			return bad("reason %d is not a code of the closed set", i)
		}
		if i > 0 && r.Reasons[i-1] >= reason {
			return bad("reasons are not sorted and unique")
		}
	}
	return nil
}

func (r Record) key() string {
	return r.Project + "\x00" + r.Family + "\x00" + r.FromLine + "\x00" + r.ToLine
}

// Admit checks a whole section: every record valid, one record per
// (project, family, from, to), sorted by that key. Anything else is refused.
func Admit(records []Record) error {
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if i > 0 && records[i-1].key() >= r.key() {
			return fmt.Errorf("%w: records are not sorted by hop or repeat a hop (record %d)", ErrInvalid, i)
		}
	}
	return nil
}

// Parse reads a section strictly: one JSON array, no unknown member, no
// repeated or case-variant member, then Admit.
func Parse(raw []byte) ([]Record, error) {
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []Record
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if out == nil {
		out = []Record{}
	}
	if err := Admit(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Marshal returns the canonical bytes of an admitted section: sorted,
// indented, newline-ended.
func Marshal(records []Record) ([]byte, error) {
	cp := slices.Clone(records)
	sort.Slice(cp, func(i, j int) bool { return cp[i].key() < cp[j].key() })
	if err := Admit(cp); err != nil {
		return nil, err
	}
	if cp == nil {
		cp = []Record{}
	}
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
