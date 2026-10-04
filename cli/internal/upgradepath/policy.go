// SPDX-License-Identifier: AGPL-3.0-only

package upgradepath

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// A path-policy record is reviewed knowledge: one component's policy with a
// cited source and a validity window, in exactly the evidence form a rule
// uses. A rule pack carries the records in its PackMember section.

// PackMember is the rule pack member that holds the path-policy section.
const PackMember = "pathPolicies"

// Limits.
const (
	// MaxRecords bounds one path-policy document.
	MaxRecords = 256
	// MaxWindow is the longest validity window a record may carry, the same
	// as a rule's in a CNCF pack.
	MaxWindow = 90 * 24 * time.Hour
)

// Evidence states, as a rule's.
const (
	StateActive    = "active"
	StateWithdrawn = "withdrawn"
)

// Freshness values, the same tokens a rule claim reports.
const (
	FreshnessCurrent           = "current"
	FreshnessStale             = "stale"
	FreshnessWithdrawn         = "withdrawn"
	FreshnessClockBeforeReview = "clock_before_review"
)

// ErrInvalid marks a malformed path-policy document.
var ErrInvalid = errors.New("invalid upgrade path policy")

// Evidence is a record's provenance and validity window, with the members
// and meaning of a rule's evidence: an absent basis means a maintainer
// reviewed it; a mechanical record names its extractor and derivation time.
type Evidence struct {
	State      string                            `json:"state"`
	Basis      string                            `json:"basis,omitempty"`
	Extractor  *constraintengine.Extractor       `json:"extractor,omitempty"`
	DerivedAt  string                            `json:"derivedAt,omitempty"`
	ReviewedAt string                            `json:"reviewedAt"`
	ValidUntil string                            `json:"validUntil"`
	Sources    []constraintengine.SourceEvidence `json:"sources"`
}

// Record is one path-policy record, in exactly its pack form.
type Record struct {
	Component string   `json:"component"`
	Policy    string   `json:"policy"`
	Evidence  Evidence `json:"evidence"`
}

// PathPolicy is the in-memory policy the record states.
func (r Record) PathPolicy() PathPolicy { return PathPolicy{Component: r.Component, Policy: r.Policy} }

// Parse decodes and validates a path-policy document: a non-empty JSON array
// of records in strictly ascending component order. Decoding is exact:
// member names match case-sensitively, every member is required unless
// documented optional, no member repeats, no value is null and nothing
// trails the array.
func Parse(raw []byte) ([]Record, error) {
	if err := checkShape(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var records []Record
	if err := dec.Decode(&records); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := Validate(records); err != nil {
		return nil, err
	}
	return records, nil
}

// Validate checks every record and the document: 1 to MaxRecords records,
// at most one per component, in strictly ascending component order.
func Validate(records []Record) error {
	if len(records) == 0 || len(records) > MaxRecords {
		return fmt.Errorf("%w: a document holds 1-%d records, got %d", ErrInvalid, MaxRecords, len(records))
	}
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("record %d (%s): %w", i, r.Component, err)
		}
		if i > 0 {
			prev := records[i-1].Component
			if prev == r.Component {
				return fmt.Errorf("%w: two records for %s", ErrInvalid, r.Component)
			}
			if prev > r.Component {
				return fmt.Errorf("%w: records are not in ascending component order: %s follows %s", ErrInvalid, r.Component, prev)
			}
		}
	}
	return nil
}

// Validate checks one record on its own, with the checks a rule's evidence
// gets from the engine plus the CNCF review window.
func (r Record) Validate() error {
	if !constraintengine.ValidComponent(r.Component) {
		return fmt.Errorf("%w: component %q is not a package URL", ErrInvalid, r.Component)
	}
	if !ValidPolicy(r.Policy) {
		return fmt.Errorf("%w: policy %q is not one of %s, %s, %s", ErrInvalid, r.Policy, PolicySequentialMinor, PolicyDirect, PolicySequentialMajor)
	}
	return r.Evidence.validate()
}

func (e Evidence) validate() error {
	if e.State != StateActive && e.State != StateWithdrawn {
		return fmt.Errorf("%w: evidence.state must be %q or %q", ErrInvalid, StateActive, StateWithdrawn)
	}
	if err := constraintengine.ValidateReviewedOrMechanicalBasis(e.Basis, e.Extractor, e.DerivedAt); err != nil {
		return fmt.Errorf("%w: evidence.basis: %v", ErrInvalid, err)
	}
	reviewed, err := constraintengine.ParseUTC(e.ReviewedAt)
	if err != nil {
		return fmt.Errorf("%w: evidence.reviewedAt must be a UTC RFC 3339 time", ErrInvalid)
	}
	until, err := constraintengine.ParseUTC(e.ValidUntil)
	if err != nil || !until.After(reviewed) || until.Sub(reviewed) > MaxWindow {
		return fmt.Errorf("%w: evidence.validUntil must be a UTC RFC 3339 time after reviewedAt and at most %s later", ErrInvalid, MaxWindow)
	}
	if e.DerivedAt != "" {
		if derived, err := constraintengine.ParseUTC(e.DerivedAt); err != nil || !derived.Before(until) {
			return fmt.Errorf("%w: evidence.derivedAt must be before validUntil", ErrInvalid)
		}
	}
	if err := constraintengine.ValidateSources(e.Sources); err != nil {
		return fmt.Errorf("%w: evidence.sources: %v", ErrInvalid, err)
	}
	return nil
}

// Freshness evaluates the record at now exactly as the engine evaluates a
// rule's evidence: withdrawn first, then before reviewedAt
// (clock_before_review), then at or after validUntil (stale). Only a current
// record may be used to plan; any other state is treated as no policy.
func (r Record) Freshness(now time.Time) string {
	if r.Evidence.State != StateActive {
		return FreshnessWithdrawn
	}
	reviewed, err1 := constraintengine.ParseUTC(r.Evidence.ReviewedAt)
	until, err2 := constraintengine.ParseUTC(r.Evidence.ValidUntil)
	if err1 != nil || err2 != nil {
		return FreshnessStale
	}
	if now.Before(reviewed) {
		return FreshnessClockBeforeReview
	}
	if !now.Before(until) {
		return FreshnessStale
	}
	return FreshnessCurrent
}

// Status is the result of looking a component's policy up at a time.
type Status struct {
	// Found is false when no record names the component.
	Found     bool   `json:"found"`
	Record    Record `json:"record"`
	Freshness string `json:"freshness,omitempty"`
}

// Policy returns the policy to plan with, or nil when there is no record or
// the record is not current. A nil policy is never a licence to skip lines.
// The two nil cases differ: with no record (Found false) PlanPath plans one
// direct hop that the caller must still decide; a record that exists but is
// not current (RecordNotCurrent) is a gap of its own, and the caller must not
// fall back to a direct hop, because the knowledge said how to upgrade and
// only its review lapsed.
func (s Status) Policy() *PathPolicy {
	if !s.Found || s.Freshness != FreshnessCurrent {
		return nil
	}
	p := s.Record.PathPolicy()
	return &p
}

// RecordNotCurrent reports a record that exists but may not be used: stale,
// withdrawn or reviewed after the lookup time. The caller reports the path
// as a gap; it never plans the upgrade as if the component had no record.
func (s Status) RecordNotCurrent() bool { return s.Found && s.Freshness != FreshnessCurrent }

// Index looks records up by component. Build it only from a validated
// document (Parse or Validate).
type Index struct {
	byComponent map[string]Record
}

// NewIndex indexes records.
func NewIndex(records []Record) Index {
	ix := Index{byComponent: make(map[string]Record, len(records))}
	for _, r := range records {
		ix.byComponent[r.Component] = copyOf(r)
	}
	return ix
}

// Lookup returns the component's record, if any, with its freshness at now.
func (ix Index) Lookup(component string, now time.Time) Status {
	r, ok := ix.byComponent[component]
	if !ok {
		return Status{}
	}
	return Status{Found: true, Record: copyOf(r), Freshness: r.Freshness(now)}
}

// Len is the number of indexed records.
func (ix Index) Len() int { return len(ix.byComponent) }

func copyOf(r Record) Record {
	r.Evidence.Sources = append([]constraintengine.SourceEvidence(nil), r.Evidence.Sources...)
	if r.Evidence.Extractor != nil {
		x := *r.Evidence.Extractor
		r.Evidence.Extractor = &x
	}
	return r
}

// Marshal renders a document in canonical order after validating it.
func Marshal(records []Record) ([]byte, error) {
	sorted := append([]Record(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Component < sorted[j].Component })
	if err := Validate(sorted); err != nil {
		return nil, err
	}
	return json.Marshal(sorted)
}

// Exact shape. Each object level names its members; a trailing "?" marks an
// optional one.
var (
	recordFields    = fieldSet("component", "policy", "evidence")
	evidenceFields  = fieldSet("state", "basis?", "extractor?", "derivedAt?", "reviewedAt", "validUntil", "sources")
	extractorFields = fieldSet("id", "version", "codeDigest")
	sourceFields    = fieldSet("id", "url", "revision", "contentDigest", "startLine", "endLine")
)

func fieldSet(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		if len(n) > 0 && n[len(n)-1] == '?' {
			out[n[:len(n)-1]] = false
		} else {
			out[n] = true
		}
	}
	return out
}

// checkShape reads the document token by token, rejecting repeated members
// (which encoding/json would resolve to the last value), and then checks
// every object against its exact member names (encoding/json would match
// names case-insensitively), required members and nulls.
func checkShape(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	doc, err := readValue(dec, 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	list, ok := doc.([]any)
	if !ok {
		return fmt.Errorf("%w: the document must be a JSON array", ErrInvalid)
	}
	for i, item := range list {
		err := object(item, recordFields, func(name string, v any) error {
			if name != "evidence" {
				return nil
			}
			return object(v, evidenceFields, func(name string, v any) error {
				switch name {
				case "extractor":
					return object(v, extractorFields, nil)
				case "sources":
					sources, ok := v.([]any)
					if !ok {
						return fmt.Errorf("sources must be an array")
					}
					for _, s := range sources {
						if err := object(s, sourceFields, nil); err != nil {
							return err
						}
					}
				}
				return nil
			})
		})
		if err != nil {
			return fmt.Errorf("%w: record %d: %v", ErrInvalid, i, err)
		}
	}
	return nil
}

const maxDepth = 16

// readValue decodes one JSON value from the token stream, rejecting a member
// name that repeats within one object.
func readValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("nesting deeper than %d", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		out := map[string]any{}
		for dec.More() {
			nameTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, ok := nameTok.(string)
			if !ok {
				return nil, fmt.Errorf("member name expected")
			}
			if _, seen := out[name]; seen {
				return nil, fmt.Errorf("member %q repeats", name)
			}
			value, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return out, nil
	case json.Delim('['):
		out := []any{}
		for dec.More() {
			value, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return out, nil
	}
	return tok, nil
}

func object(v any, want map[string]bool, inner func(string, any) error) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("expected an object")
	}
	for name, required := range want {
		if _, ok := m[name]; required && !ok {
			return fmt.Errorf("member %q is required", name)
		}
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := want[name]; !ok {
			return fmt.Errorf("unknown member %q", name)
		}
		if m[name] == nil {
			return fmt.Errorf("member %q is null", name)
		}
		if inner != nil {
			if err := inner(name, m[name]); err != nil {
				return err
			}
		}
	}
	return nil
}
