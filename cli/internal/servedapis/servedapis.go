// SPDX-License-Identifier: AGPL-3.0-only

// Package servedapis defines the served-API list: a record that, for one
// component and one minor release line, names every "apiVersion kind" pair
// the line serves. Scan uses it to tell a manifest object the target line
// still serves from one nobody reviewed.
//
// A list is a statement about the knowledge corpus, never a compatibility
// claim. Records are parsed strictly, indexed for lookup and carry the same
// provenance and validity window as a line attestation (lineattest.Evidence);
// only a current record whose basis the trust policy admits may be relied on.
package servedapis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// PackMember is the rule pack member that holds the served-list section.
const PackMember = "servedAPIs"

// Completeness is the only completeness statement a record makes.
const Completeness = "COMPLETE_SERVED_API_LIST_FOR_LINE"

// KubernetesComponent is the only component a served list may name.
const KubernetesComponent = "pkg:github/kubernetes/kubernetes"

// Limits.
const (
	MaxRecords = 1024
	MaxAPIs    = 4096
)

// ErrInvalid marks a malformed served-list document.
var ErrInvalid = errors.New("invalid served-API list")

// Record is one served list, in exactly its pack form. APIs holds
// "apiVersion kind" pairs ("apps/v1 Deployment", "v1 ConfigMap"), strictly
// ascending.
type Record struct {
	Component    string              `json:"component"`
	Line         string              `json:"line"`
	Completeness string              `json:"completeness"`
	APIs         []string            `json:"apis"`
	Evidence     lineattest.Evidence `json:"evidence"`
}

var pairRE = regexp.MustCompile(`^(?:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?v[0-9]{1,4}(?:(?:alpha|beta)[0-9]{1,4})? [A-Z][A-Za-z0-9]{0,62}$`)

func less(a, b Record) bool {
	if a.Component != b.Component {
		return a.Component < b.Component
	}
	return lineattest.LineLess(a.Line, b.Line)
}

// Sort puts records in canonical order: component, then line numerically.
func Sort(records []Record) {
	sort.SliceStable(records, func(i, j int) bool { return less(records[i], records[j]) })
}

// Parse decodes and validates a served-list document: a non-empty JSON array
// of records. Decoding is exact: no repeated or case-folded member, no
// unknown member, every member present, no null and nothing trailing.
func Parse(raw []byte) ([]Record, error) {
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var shape []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for i, item := range shape {
		for _, name := range []string{"component", "line", "completeness", "apis", "evidence"} {
			if v, ok := item[name]; !ok || string(bytes.TrimSpace(v)) == "null" {
				return nil, fmt.Errorf("%w: record %d: member %q is required", ErrInvalid, i, name)
			}
		}
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

// Validate checks every record and the document as a whole: canonical order
// and one record per scope.
func Validate(records []Record) error {
	if len(records) == 0 || len(records) > MaxRecords {
		return fmt.Errorf("%w: a document holds 1-%d records, got %d", ErrInvalid, MaxRecords, len(records))
	}
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("served list %d (%s %s): %w", i, r.Component, r.Line, err)
		}
		if i > 0 && !less(records[i-1], r) {
			return fmt.Errorf("%w: served lists are not unique and in canonical order (component, line): %s %s follows %s %s", ErrInvalid, r.Component, r.Line, records[i-1].Component, records[i-1].Line)
		}
	}
	return nil
}

// Validate checks one record on its own.
func (r Record) Validate() error {
	if r.Component != KubernetesComponent || !constraintengine.ValidComponent(r.Component) {
		return fmt.Errorf("%w: component %q has no served-list family", ErrInvalid, r.Component)
	}
	if !lineattest.ValidLine(r.Line) {
		return fmt.Errorf("%w: line %q is not major.minor", ErrInvalid, r.Line)
	}
	if r.Completeness != Completeness {
		return fmt.Errorf("%w: completeness must be %s", ErrInvalid, Completeness)
	}
	if len(r.APIs) == 0 || len(r.APIs) > MaxAPIs {
		return fmt.Errorf("%w: apis must hold 1-%d pairs", ErrInvalid, MaxAPIs)
	}
	for i, pair := range r.APIs {
		if !pairRE.MatchString(pair) {
			return fmt.Errorf("%w: %q is not an \"apiVersion kind\" pair", ErrInvalid, pair)
		}
		if i > 0 && r.APIs[i-1] >= pair {
			return fmt.Errorf("%w: apis must be strictly ascending; %q follows %q", ErrInvalid, pair, r.APIs[i-1])
		}
	}
	if err := r.Evidence.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// Marshal renders a document in canonical order.
func Marshal(records []Record) ([]byte, error) {
	sorted := append([]Record(nil), records...)
	Sort(sorted)
	if err := Validate(sorted); err != nil {
		return nil, err
	}
	return json.Marshal(sorted)
}

// Status is a record together with its freshness at the lookup time.
type Status struct {
	Record    Record
	Freshness string
}

// Current reports whether the record may be relied on.
func (s Status) Current() bool { return s.Freshness == lineattest.FreshnessCurrent }

// Index looks records up by scope. Build it only from a validated document.
type Index struct {
	byKey map[[2]string]Record
}

// NewIndex indexes records.
func NewIndex(records []Record) Index {
	ix := Index{byKey: make(map[[2]string]Record, len(records))}
	for _, r := range records {
		r.APIs = append([]string(nil), r.APIs...)
		ix.byKey[[2]string{r.Component, r.Line}] = r
	}
	return ix
}

// For returns the record for one component and line with its freshness at
// now; ok is false when there is none. Only a current record may be relied
// on; any other freshness is treated as no record.
func (ix Index) For(component, line string, now time.Time) (Status, bool) {
	r, ok := ix.byKey[[2]string{component, line}]
	if !ok {
		return Status{}, false
	}
	r.APIs = append([]string(nil), r.APIs...)
	return Status{Record: r, Freshness: r.Evidence.Freshness(now)}, true
}

// Len is the number of indexed records.
func (ix Index) Len() int { return len(ix.byKey) }
