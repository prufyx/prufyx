// SPDX-License-Identifier: AGPL-3.0-only

// Package bundlechart is the bundle field "chart identity": the chart name and
// chart version of a chart-installed component, with the object the identity
// was read from, so the user can see why Prufyx believes it.
//
// The only sources are the user's own declaration and the standard chart label
// on workloads the collector already reads. Release records, Secrets,
// ConfigMaps, values, rendered manifests and every other label or annotation
// are never sources; nothing in this package reads from a cluster. The kept
// fields are fixed by Entry and nothing else is ever retained. Conflicting
// evidence is never resolved: it is marked ambiguous and the answer is UNKNOWN.
package bundlechart

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	// Schema is the apiVersion of the persisted chart identity set.
	Schema = "prufyx.io/chart-identity/v1alpha1"
	// Kind is the kind of the persisted chart identity set.
	Kind = "ChartIdentitySet"
	// FileName is the per-context collector output file.
	FileName = "chart-identity.json"
	// DeclarationSchema and DeclarationKind identify the user's declaration file.
	DeclarationSchema = "prufyx.io/chart-declaration/v1alpha1"
	DeclarationKind   = "ChartDeclaration"
	// ChartLabel is the only label the label path reads.
	ChartLabel = "helm.sh/chart"

	SourceDeclared = "declared"
	SourceLabel    = "label"

	StateResolved  = "resolved"
	StateAmbiguous = "ambiguous"

	// StatusIdentified: at least one identity and none ambiguous.
	StatusIdentified = "identified"
	// StatusNotDeclared: no identity was declared or read. UNKNOWN.
	StatusNotDeclared = "not_declared"
	// StatusAmbiguous: conflicting or incomplete evidence. UNKNOWN.
	StatusAmbiguous = "ambiguous"

	// NextActionDeclare is the fixed next action when no identity is known.
	NextActionDeclare = "declare the chart name and version"
	// NextActionDisambiguate is the fixed next action for conflicting evidence.
	NextActionDisambiguate = "declare the one chart name and version that is installed"

	OmissionLabelMalformed = "CHART_LABEL_MALFORMED"
	OmissionTruncated      = "CHART_IDENTITY_TRUNCATED"
	OmissionSourceUnread   = "CHART_LABEL_SOURCE_UNREAD"

	MaxNameBytes    = 253
	MaxVersionBytes = 128
	MaxEntries      = 256
	// MaxDeclarationBytes bounds the declaration file.
	MaxDeclarationBytes = 64 << 10
)

var (
	// ErrInvalid marks malformed input; callers fail closed.
	ErrInvalid = errors.New("invalid chart identity")

	nameRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
	versionRE  = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
	k8sNameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	kindRE     = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	omissionRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
)

// Entry is one chart identity. These are all the kept fields.
type Entry struct {
	ChartName       string `json:"chartName"`
	ChartVersion    string `json:"chartVersion"`
	Source          string `json:"source"`
	SourceKind      string `json:"sourceKind,omitempty"`
	SourceNamespace string `json:"sourceNamespace,omitempty"`
	SourceName      string `json:"sourceName,omitempty"`
	State           string `json:"state"`
}

// Omission counts dropped candidates; it never carries their content.
type Omission struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// Set is the persisted bundle field.
type Set struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	NextAction string     `json:"nextAction,omitempty"`
	Entries    []Entry    `json:"entries"`
	Omissions  []Omission `json:"omissions"`
}

// Declared is one chart the user declared.
type Declared struct{ Name, Version string }

// LabelObservation is the chart label of one already-read workload object.
type LabelObservation struct {
	Kind, Namespace, Name string
	Label                 string
}

// ValidName reports whether s is an acceptable chart name.
func ValidName(s string) bool { return len(s) <= MaxNameBytes && nameRE.MatchString(s) }

// ValidVersion reports whether s is an acceptable chart version.
func ValidVersion(s string) bool { return len(s) <= MaxVersionBytes && versionRE.MatchString(s) }

// SplitLabel splits a chart label "<name>-<version>". The split must be
// unique: every position that yields a valid name and a valid version is a
// candidate and more than one candidate means the label is ambiguous.
func SplitLabel(label string) (name, version string, ok bool) {
	if len(label) > MaxNameBytes+1+MaxVersionBytes {
		return "", "", false
	}
	found := 0
	for i := 1; i < len(label)-1; i++ {
		if label[i] != '-' {
			continue
		}
		n, v := label[:i], label[i+1:]
		if ValidName(n) && ValidVersion(v) {
			name, version = n, v
			found++
		}
	}
	return name, version, found == 1
}

// ParseDeclaration reads the user's declaration file. Anything unexpected is
// an error: a declaration is never partly accepted.
func ParseDeclaration(data []byte) ([]Declared, error) {
	if len(data) > MaxDeclarationBytes {
		return nil, fmt.Errorf("declaration too large: %w", ErrInvalid)
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Charts     []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"charts"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("declaration is not the expected document: %w", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing declaration data: %w", ErrInvalid)
	}
	if doc.APIVersion != DeclarationSchema || doc.Kind != DeclarationKind || len(doc.Charts) == 0 || len(doc.Charts) > MaxEntries {
		return nil, fmt.Errorf("declaration header or size: %w", ErrInvalid)
	}
	out := make([]Declared, 0, len(doc.Charts))
	for _, c := range doc.Charts {
		if !ValidName(c.Name) || !ValidVersion(c.Version) {
			return nil, fmt.Errorf("declared chart name or version: %w", ErrInvalid)
		}
		out = append(out, Declared{Name: c.Name, Version: c.Version})
	}
	return out, nil
}

// Build merges the declaration and the label observations into a Set.
//
// Rules: a declared chart is one entry (source "declared"). A label that does
// not parse uniquely is dropped and counted. Two different versions for one
// chart name in one namespace, two different declared versions, or a declared
// version that differs from a label version of the same chart make every
// involved entry ambiguous; nothing is picked. A workload read that failed
// (unreadSources) makes the whole set ambiguous: unread labels could conflict. Entries that agree are all kept
// and shown. Identical (chart, version, namespace) labels keep one source
// object, the first in kind/name order.
func Build(declared []Declared, labels []LabelObservation, unreadSources int) Set {
	set := Set{APIVersion: Schema, Kind: Kind, Entries: []Entry{}, Omissions: []Omission{}}
	malformed, truncated := 0, 0
	var entries []Entry
	for _, d := range declared {
		if !ValidName(d.Name) || !ValidVersion(d.Version) {
			malformed++
			continue
		}
		entries = append(entries, Entry{ChartName: d.Name, ChartVersion: d.Version, Source: SourceDeclared})
	}
	sorted := append([]LabelObservation(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	seen := map[[3]string]bool{}
	for _, l := range sorted {
		name, version, ok := SplitLabel(l.Label)
		if !ok || !kindRE.MatchString(l.Kind) || !validObjectName(l.Name) || (l.Namespace != "" && !validObjectName(l.Namespace)) {
			malformed++
			continue
		}
		key := [3]string{name + "\x00" + version, l.Namespace, ""}
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, Entry{ChartName: name, ChartVersion: version, Source: SourceLabel,
			SourceKind: l.Kind, SourceNamespace: l.Namespace, SourceName: l.Name})
	}
	if len(entries) > MaxEntries {
		truncated = len(entries) - MaxEntries
		entries = entries[:MaxEntries]
	}
	if entries == nil {
		entries = []Entry{}
	}
	set.Entries = entries
	markStates(set.Entries)
	if malformed > 0 {
		set.Omissions = append(set.Omissions, Omission{Code: OmissionLabelMalformed, Count: malformed})
	}
	if truncated > 0 {
		set.Omissions = append(set.Omissions, Omission{Code: OmissionTruncated, Count: truncated})
	}
	if unreadSources > 0 {
		set.Omissions = append(set.Omissions, Omission{Code: OmissionSourceUnread, Count: unreadSources})
	}
	sortEntries(set.Entries)
	set.Status, set.NextAction = status(set)
	return set
}

func status(set Set) (string, string) {
	for _, o := range set.Omissions {
		if o.Code == OmissionTruncated || o.Code == OmissionSourceUnread {
			return StatusAmbiguous, NextActionDisambiguate
		}
	}
	if len(set.Entries) == 0 {
		return StatusNotDeclared, NextActionDeclare
	}
	for _, e := range set.Entries {
		if e.State == StateAmbiguous {
			return StatusAmbiguous, NextActionDisambiguate
		}
	}
	return StatusIdentified, ""
}

// markStates sets every entry's State from the evidence alone.
func markStates(entries []Entry) {
	declared := map[string]map[string]bool{} // chart -> versions
	labelNS := map[[2]string]map[string]bool{}
	labelAny := map[string]map[string]bool{}
	for _, e := range entries {
		if e.Source == SourceDeclared {
			add(declared, e.ChartName, e.ChartVersion)
		} else {
			k := [2]string{e.ChartName, e.SourceNamespace}
			if labelNS[k] == nil {
				labelNS[k] = map[string]bool{}
			}
			labelNS[k][e.ChartVersion] = true
			add(labelAny, e.ChartName, e.ChartVersion)
		}
	}
	for i := range entries {
		e := &entries[i]
		e.State = StateResolved
		if len(declared[e.ChartName]) > 1 {
			e.State = StateAmbiguous
		}
		if e.Source == SourceLabel && len(labelNS[[2]string{e.ChartName, e.SourceNamespace}]) > 1 {
			e.State = StateAmbiguous
		}
		// A declaration and a label that disagree: both are shown, neither wins.
		if d := declared[e.ChartName]; len(d) > 0 && len(labelAny[e.ChartName]) > 0 {
			for v := range labelAny[e.ChartName] {
				if !d[v] {
					e.State = StateAmbiguous
				}
			}
		}
	}
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		for _, p := range [][2]string{{a.ChartName, b.ChartName}, {a.ChartVersion, b.ChartVersion}, {a.Source, b.Source}, {a.SourceKind, b.SourceKind}, {a.SourceNamespace, b.SourceNamespace}, {a.SourceName, b.SourceName}} {
			if p[0] != p[1] {
				return p[0] < p[1]
			}
		}
		return false
	})
}

func validObjectName(s string) bool { return len(s) <= MaxNameBytes && k8sNameRE.MatchString(s) }

// Decode strictly reads a persisted Set and proves it is exactly what Build
// would have produced from its own entries: states, status and next action are
// recomputed and any difference is an error.
func Decode(data []byte) (Set, error) {
	var set Set
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return Set{}, fmt.Errorf("chart identity document: %w", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Set{}, fmt.Errorf("trailing chart identity data: %w", ErrInvalid)
	}
	if err := Validate(set); err != nil {
		return Set{}, err
	}
	return set, nil
}

// Validate checks a Set against every bound and recomputes its derived fields.
func Validate(set Set) error {
	if set.APIVersion != Schema || set.Kind != Kind || set.Entries == nil || set.Omissions == nil || len(set.Entries) > MaxEntries || len(set.Omissions) > 3 {
		return fmt.Errorf("chart identity header or size: %w", ErrInvalid)
	}
	for _, e := range set.Entries {
		if !ValidName(e.ChartName) || !ValidVersion(e.ChartVersion) {
			return fmt.Errorf("chart identity name or version: %w", ErrInvalid)
		}
		switch e.Source {
		case SourceDeclared:
			if e.SourceKind != "" || e.SourceNamespace != "" || e.SourceName != "" {
				return fmt.Errorf("declared identity carries an object reference: %w", ErrInvalid)
			}
		case SourceLabel:
			if !kindRE.MatchString(e.SourceKind) || !validObjectName(e.SourceName) || (e.SourceNamespace != "" && !validObjectName(e.SourceNamespace)) {
				return fmt.Errorf("label identity object reference: %w", ErrInvalid)
			}
		default:
			return fmt.Errorf("chart identity source: %w", ErrInvalid)
		}
	}
	for _, o := range set.Omissions {
		if !omissionRE.MatchString(o.Code) || o.Count < 1 || (o.Code != OmissionLabelMalformed && o.Code != OmissionTruncated && o.Code != OmissionSourceUnread) {
			return fmt.Errorf("chart identity omission: %w", ErrInvalid)
		}
	}
	states := append([]Entry(nil), set.Entries...)
	markStates(states)
	for i := range states {
		if states[i].State != set.Entries[i].State {
			return fmt.Errorf("chart identity state is not derivable from its evidence: %w", ErrInvalid)
		}
	}
	status, next := status(set)
	if set.Status != status || set.NextAction != next {
		return fmt.Errorf("chart identity status is not derivable from its evidence: %w", ErrInvalid)
	}
	if !sort.SliceIsSorted(set.Entries, func(i, j int) bool { return less(set.Entries[i], set.Entries[j]) }) {
		return fmt.Errorf("chart identity entries are not canonical: %w", ErrInvalid)
	}
	return nil
}

func less(a, b Entry) bool {
	x := []Entry{a, b}
	sortEntries(x)
	return x[0] == a && a != b
}

// Summary is the one status line shown to the user. It names no chart and no
// object, only the count and the next action.
func Summary(set Set) string {
	if set.NextAction == "" {
		return fmt.Sprintf("Chart identity: %s (%d)", set.Status, len(set.Entries))
	}
	return fmt.Sprintf("Chart identity: %s (%d); next: %s", set.Status, len(set.Entries), strings.TrimSpace(set.NextAction))
}
