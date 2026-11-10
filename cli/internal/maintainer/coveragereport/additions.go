// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

// AdditionsSchema identifies the append-only additions file: release lines of
// projects that are not in the pinned snapshot, each with its own capture date.
const AdditionsSchema = "prufyx.io/coverage-lines-additions/v1"

// PinnedTagsDir is the repository directory of the tag files an addition is
// derived from (<project>.tags, one tag per line or git ls-remote output).
const PinnedTagsDir = "cli/internal/maintainer/coveragereport/testdata/tags"

var sha256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// AdditionEntry is one added project: the per-project fields of the lines
// snapshot plus its own capture date and the digests that bind it to its tag
// file.
type AdditionEntry struct {
	// CapturedOn is the YYYY-MM-DD date of the tag listing the entry is
	// derived from. Required.
	CapturedOn string `json:"capturedOn"`
	// TagFileSha256 is the digest ("sha256:<hex>") of the committed tag file
	// the entry is derived from.
	TagFileSha256 string `json:"tagFileSha256"`
	// EntryDigest is the digest of the canonical entry without this member.
	EntryDigest string `json:"entryDigest"`
	ProjectLines
}

// AdditionsFile is the additions file.
type AdditionsFile struct {
	Schema    string                   `json:"schema"`
	Additions map[string]AdditionEntry `json:"additions"`
}

// EntryDigestOf is the digest of the canonical entry: its JSON with the
// entryDigest member empty (and so omitted).
func EntryDigestOf(e AdditionEntry) string {
	e.EntryDigest = ""
	raw, err := json.Marshal(entryForDigest(e))
	if err != nil {
		return ""
	}
	return digestOf(raw)
}

// entryForDigest is AdditionEntry without the digest member, so the digest
// does not depend on the omission rules of the entry type.
func entryForDigest(e AdditionEntry) any {
	return struct {
		CapturedOn    string `json:"capturedOn"`
		TagFileSha256 string `json:"tagFileSha256"`
		ProjectLines
	}{e.CapturedOn, e.TagFileSha256, e.ProjectLines}
}

// TagFileDigest is the digest a tag file is bound by.
func TagFileDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDate(s string) bool {
	if !dateRE.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// ParseAdditions strictly decodes and validates an additions file. An absent
// or empty file (no bytes, or only white space) is the valid empty set. A
// present file must hold the schema; an empty "additions" object is valid.
// Every entry is validated like a snapshot entry, needs a real capturedOn, a
// tag file digest and an entry digest that equals the recomputed one.
func ParseAdditions(raw []byte) (AdditionsFile, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return AdditionsFile{Schema: AdditionsSchema, Additions: map[string]AdditionEntry{}}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f AdditionsFile
	if err := dec.Decode(&f); err != nil {
		return AdditionsFile{}, fmt.Errorf("%w: additions: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return AdditionsFile{}, fmt.Errorf("%w: additions: trailing data", ErrInvalid)
	}
	if f.Schema != AdditionsSchema {
		return AdditionsFile{}, fmt.Errorf("%w: additions: unknown schema", ErrInvalid)
	}
	if f.Additions == nil {
		return AdditionsFile{}, fmt.Errorf("%w: additions: the additions member is missing", ErrInvalid)
	}
	for slug, e := range f.Additions {
		if err := validateAddition(slug, e); err != nil {
			return AdditionsFile{}, err
		}
	}
	return f, nil
}

func validateAddition(slug string, e AdditionEntry) error {
	if err := validateProject(slug, e.ProjectLines); err != nil {
		return err
	}
	if len(e.Lines) == 0 {
		return fmt.Errorf("%w: additions: %s: no lines", ErrInvalid, slug)
	}
	if !validDate(e.CapturedOn) {
		return fmt.Errorf("%w: additions: %s: capturedOn is missing or not a date", ErrInvalid, slug)
	}
	if !sha256RE.MatchString(e.TagFileSha256) {
		return fmt.Errorf("%w: additions: %s: tagFileSha256 is missing or malformed", ErrInvalid, slug)
	}
	if !sha256RE.MatchString(e.EntryDigest) || e.EntryDigest != EntryDigestOf(e) {
		return fmt.Errorf("%w: additions: %s: entryDigest does not match the entry", ErrInvalid, slug)
	}
	return nil
}

// MarshalAdditions returns the canonical bytes of an additions file: sorted
// keys, two-space indent, trailing newline. It fills no digest; seal entries
// with SealAddition.
func MarshalAdditions(f AdditionsFile) ([]byte, error) {
	f.Schema = AdditionsSchema
	if f.Additions == nil {
		f.Additions = map[string]AdditionEntry{}
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := ParseAdditions(out); err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// SealAddition derives the entry of one project from its tag file with the
// repository's own tag reader and fills both digests. priority and component
// are not derivable from tags; they are taken as given and covered by the
// entry digest.
func SealAddition(project string, tags []byte, capturedOn string, priority bool, component string) (AdditionEntry, error) {
	if !validDate(capturedOn) {
		return AdditionEntry{}, fmt.Errorf("%w: additions: %s: capturedOn is not a date", ErrInvalid, project)
	}
	f, err := LinesFromTags(map[string][]byte{project: tags}, map[string]bool{project: priority}, capturedOn)
	if err != nil {
		return AdditionEntry{}, err
	}
	pl := f.Projects[project]
	pl.Component = component
	e := AdditionEntry{CapturedOn: capturedOn, TagFileSha256: TagFileDigest(tags), ProjectLines: pl}
	e.EntryDigest = EntryDigestOf(e)
	if err := validateAddition(project, e); err != nil {
		return AdditionEntry{}, err
	}
	return e, nil
}

// VerifyAdditionFromTags regenerates the entry from its tag file and requires
// equality with the entry as committed. It proves the entry is the offline
// reading of that tag file; it does not prove the tag file is the upstream
// tag set (see cli/docs/coverage-report.md).
func VerifyAdditionFromTags(project string, e AdditionEntry, tags []byte) error {
	if err := validateAddition(project, e); err != nil {
		return err
	}
	if TagFileDigest(tags) != e.TagFileSha256 {
		return fmt.Errorf("%w: additions: %s: the tag file does not match tagFileSha256", ErrInvalid, project)
	}
	want, err := SealAddition(project, tags, e.CapturedOn, e.Priority, e.Component)
	if err != nil {
		return err
	}
	if want.EntryDigest != e.EntryDigest {
		return fmt.Errorf("%w: additions: %s: the entry is not the reading of its tag file", ErrInvalid, project)
	}
	return nil
}

// CheckDisjoint refuses an addition whose key is also a pinned project, and an
// addition whose non-empty component is owned by a pinned entry or by another
// addition. Attestations are attributed by component, so an owner must be
// unique: the attribution never depends on map order over the union.
func CheckDisjoint(pinned LinesFile, add AdditionsFile) error {
	var dup []string
	owner := map[string]string{}
	for slug, p := range pinned.Projects {
		if p.Component != "" {
			owner[p.Component] = slug
		}
	}
	slugs := make([]string, 0, len(add.Additions))
	for slug := range add.Additions {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		if _, ok := pinned.Projects[slug]; ok {
			dup = append(dup, slug)
		}
	}
	if len(dup) > 0 {
		return fmt.Errorf("%w: additions: %v is already in the pinned snapshot; an addition never overrides a pinned entry", ErrInvalid, dup)
	}
	for _, slug := range slugs {
		c := add.Additions[slug].Component
		if c == "" {
			continue
		}
		if o, ok := owner[c]; ok {
			return fmt.Errorf("%w: additions: %s: component %s is already owned by %s", ErrInvalid, slug, c, o)
		}
		owner[c] = slug
	}
	return nil
}

// EvaluationClockDate is the date the README block is evaluated on:
// the later of the pinned snapshot's evaluation date (pinnedOn, else
// capturedOn) and the capture date of every addition. The block's clock is
// noon UTC of that date. With no additions it is the pinned date exactly.
func EvaluationClockDate(pinned LinesFile, add AdditionsFile) (string, error) {
	date := pinned.CapturedOn
	if pinned.PinnedOn != "" {
		date = pinned.PinnedOn
	}
	if !validDate(date) {
		return "", fmt.Errorf("%w: the pinned lines snapshot has no captured date", ErrInvalid)
	}
	for _, e := range add.Additions {
		if e.CapturedOn > date {
			date = e.CapturedOn
		}
	}
	return date, nil
}

// EvaluationClock is noon UTC of EvaluationClockDate.
func EvaluationClock(pinned LinesFile, add AdditionsFile) (time.Time, error) {
	date, err := EvaluationClockDate(pinned, add)
	if err != nil {
		return time.Time{}, err
	}
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: clock date: %v", ErrInvalid, err)
	}
	return d.Add(12 * time.Hour).UTC(), nil
}

// ValidSlug reports whether s is a project slug the lines files accept.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// TagFileName is the file name of a project's tag file inside PinnedTagsDir.
func TagFileName(project string) string { return project + ".tags" }
