// SPDX-License-Identifier: AGPL-3.0-only

// Package lineattest defines the line attestation: a statement that, for one
// component, one minor release line and one fact family, the rules it lists
// are every rule the knowledge pack holds; an empty list means there are
// none. It tells "nothing in scope changes on this line" apart from "nobody
// looked at this line".
//
// An attestation is a statement about the knowledge corpus, never a
// compatibility claim. It does not take part in any rule verdict. This
// package parses attestations strictly, checks that each one lists exactly
// the pack's rules for its line and family, reports freshness, indexes them
// for lookup and classifies changes between two attestation sets.
package lineattest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Completeness is the only completeness statement an attestation makes.
const Completeness = "COMPLETE_REVIEWED_RULES_FOR_LINE"

// FamilyKubernetesRemovedServedGVK covers the Kubernetes rules that block an
// upgrade because the target minor line stops serving an API group version
// of a kind (beta and stable versions served by default).
const FamilyKubernetesRemovedServedGVK = "kubernetes.removed_served_gvk"

// Limits.
const (
	// MaxWindow is the longest validity window an attestation may carry,
	// the same as a rule's.
	MaxWindow = 90 * 24 * time.Hour
	// MaxRuleIDs bounds the rules one attestation may list.
	MaxRuleIDs = 256
	// MaxAttestations bounds one attestation document.
	MaxAttestations = 1024
)

// ErrInvalid marks a malformed attestation document.
var ErrInvalid = errors.New("invalid line attestation")

// Family is one fact family: the component it belongs to and the facts whose
// rules it covers.
type Family struct {
	ID        string
	Component string
	facts     *regexp.Regexp
	// fromPreviousLine states the family's hop shape: every transition into
	// line M.m starts on line M.(m-1). It is the only hop shape defined; a
	// family without it has no line-wide rules and cannot be attested.
	fromPreviousLine bool
}

// Covers reports whether a rule condition on (component, factID) belongs to
// the family.
func (f Family) Covers(component, factID string) bool {
	return component == f.Component && f.facts.MatchString(factID)
}

// LineTransitions returns the transitions into line that the family's hops
// take, as the engine's half-open version bounds: from any release of the
// previous minor line, [M.(m-1).0, M.m.0), to any release of the line,
// [M.m.0, M.(m+1).0). ok is false when the line has no previous minor line
// in the same major (m = 0) or the family defines no hop shape.
func (f Family) LineTransitions(line string) (from, to constraintengine.VersionBound, ok bool) {
	if !f.fromPreviousLine || !ValidLine(line) {
		return from, to, false
	}
	major, minor := lineNumbers(line)
	if minor == 0 || minor >= 1<<32-1 || major >= 1<<32 {
		return from, to, false
	}
	at := func(m uint64) string { return fmt.Sprintf("%d.%d.0", major, m) }
	return constraintengine.VersionBound{Gte: at(minor - 1), Lt: at(minor)}, constraintengine.VersionBound{Gte: at(minor), Lt: at(minor + 1)}, true
}

// CoversLine reports whether a rule subject matches every transition into
// line, using the engine's own matcher semantics (constraintengine.Match):
// an anchor pair matches one transition only, and a range matches a
// transition when from and to each lie inside its half-open bounds. So the
// rule must carry a range whose from bound contains the whole previous minor
// line and whose to bound contains the whole target line:
//
//	range.from.gte <= M.(m-1).0  and  M.m.0 <= range.from.lt
//	range.to.gte   <= M.m.0      and  M.(m+1).0 <= range.to.lt
//
// Every release version of the previous line lies in [M.(m-1).0, M.m.0) and
// every release version of the line in [M.m.0, M.(m+1).0), so these bounds
// are necessary and sufficient. The engine caps each side of a range at one
// minor line, so in practice they hold with equality. A version the engine
// cannot parse makes the comparison fail, and the rule is not line-wide.
func (f Family) CoversLine(t constraintengine.RuleTransition, line string) bool {
	from, to, ok := f.LineTransitions(line)
	if !ok || t.Range == nil {
		return false
	}
	return contains(t.Range.From, from) && contains(t.Range.To, to)
}

// contains reports outer.gte <= inner.gte and inner.lt <= outer.lt.
func contains(outer, inner constraintengine.VersionBound) bool {
	le := func(a, b string) bool {
		return constraintengine.VersionLess(a, b) || constraintengine.SameVersion(a, b)
	}
	return le(outer.Gte, inner.Gte) && le(inner.Lt, outer.Lt)
}

// families is the closed, compiled family vocabulary. Adding a family is a
// code change, reviewed once; an attestation naming any other family is
// rejected.
var families = map[string]Family{
	FamilyKubernetesRemovedServedGVK: {
		ID:        FamilyKubernetesRemovedServedGVK,
		Component: "pkg:github/kubernetes/kubernetes",
		facts:     regexp.MustCompile(`^component\.kubernetes\.[a-z0-9_]+_removed_gvk_present$`),
		// Kubernetes upgrades a control plane one minor line at a time.
		fromPreviousLine: true,
	},
}

// LookupFamily returns a family by id.
func LookupFamily(id string) (Family, bool) {
	f, ok := families[id]
	return f, ok
}

// FamilyIDs lists the known families in order.
func FamilyIDs() []string {
	out := make([]string, 0, len(families))
	for id := range families {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// LineAttestation is one attestation record, in exactly its pack form.
type LineAttestation struct {
	Component    string   `json:"component"`
	Line         string   `json:"line"`
	FactFamily   string   `json:"factFamily"`
	Completeness string   `json:"completeness"`
	RuleIDs      []string `json:"ruleIds"`
	Evidence     Evidence `json:"evidence"`
}

// Evidence is an attestation's provenance and validity window. Basis is
// required: "reviewed" (a maintainer read the cited sources) or "mechanical"
// (a versioned extractor derived it from pinned bytes, in which case
// extractor and derivedAt are required and reviewedAt equals derivedAt).
type Evidence struct {
	Basis      string                            `json:"basis"`
	Extractor  *constraintengine.Extractor       `json:"extractor,omitempty"`
	DerivedAt  string                            `json:"derivedAt,omitempty"`
	ReviewedAt string                            `json:"reviewedAt"`
	ValidUntil string                            `json:"validUntil"`
	Sources    []constraintengine.SourceEvidence `json:"sources"`
}

// Key identifies the scope of one attestation.
type Key struct {
	Component string
	Line      string
	Family    string
}

func (k Key) String() string { return k.Component + " " + k.Line + " " + k.Family }

// Key returns the attestation's scope.
func (a LineAttestation) Key() Key {
	return Key{Component: a.Component, Line: a.Line, Family: a.FactFamily}
}

var lineRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// ValidLine reports whether line is a minor release line such as "1.28".
func ValidLine(line string) bool { return lineRE.MatchString(line) }

// LineOf returns the minor line of a release version: "1.28.3" -> "1.28".
func LineOf(version string) (string, bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", false
	}
	line := parts[0] + "." + parts[1]
	if !ValidLine(line) {
		return "", false
	}
	if _, err := strconv.ParseUint(parts[2], 10, 32); err != nil || (len(parts[2]) > 1 && parts[2][0] == '0') {
		return "", false
	}
	return line, true
}

func lineNumbers(line string) (uint64, uint64) {
	major, minor, _ := strings.Cut(line, ".")
	a, _ := strconv.ParseUint(major, 10, 64)
	b, _ := strconv.ParseUint(minor, 10, 64)
	return a, b
}

// LineLess orders two valid lines numerically.
func LineLess(a, b string) bool {
	am, an := lineNumbers(a)
	bm, bn := lineNumbers(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

func keyLess(a, b Key) bool {
	if a.Component != b.Component {
		return a.Component < b.Component
	}
	if a.Family != b.Family {
		return a.Family < b.Family
	}
	return LineLess(a.Line, b.Line)
}

// Sort puts attestations in their canonical order: component, fact family,
// then line, numerically.
func Sort(atts []LineAttestation) {
	sort.SliceStable(atts, func(i, j int) bool { return keyLess(atts[i].Key(), atts[j].Key()) })
}

// Parse decodes and validates an attestation document: a non-empty JSON
// array of records. Decoding is exact: every member is required unless
// documented optional, member names match case-sensitively, no member
// repeats, no value is null and nothing trails the array.
func Parse(raw []byte) ([]LineAttestation, error) {
	if err := checkShape(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var atts []LineAttestation
	if err := dec.Decode(&atts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := Validate(atts); err != nil {
		return nil, err
	}
	return atts, nil
}

// Validate checks every record and the document as a whole: canonical order
// and one attestation per scope.
func Validate(atts []LineAttestation) error {
	if len(atts) == 0 || len(atts) > MaxAttestations {
		return fmt.Errorf("%w: a document holds 1-%d attestations, got %d", ErrInvalid, MaxAttestations, len(atts))
	}
	for i, a := range atts {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("attestation %d (%s): %w", i, a.Key(), err)
		}
		if i > 0 {
			prev := atts[i-1].Key()
			if prev == a.Key() {
				return fmt.Errorf("%w: two attestations for %s", ErrInvalid, a.Key())
			}
			if !keyLess(prev, a.Key()) {
				return fmt.Errorf("%w: attestations are not in canonical order (component, factFamily, line): %s follows %s", ErrInvalid, a.Key(), prev)
			}
		}
	}
	return nil
}

// Validate checks one record on its own.
func (a LineAttestation) Validate() error {
	family, ok := families[a.FactFamily]
	if !ok {
		return fmt.Errorf("%w: unknown factFamily %q", ErrInvalid, a.FactFamily)
	}
	if !constraintengine.ValidComponent(a.Component) || a.Component != family.Component {
		return fmt.Errorf("%w: component %q is not the component of family %s", ErrInvalid, a.Component, family.ID)
	}
	if !ValidLine(a.Line) {
		return fmt.Errorf("%w: line %q is not major.minor", ErrInvalid, a.Line)
	}
	if a.Completeness != Completeness {
		return fmt.Errorf("%w: completeness must be %s", ErrInvalid, Completeness)
	}
	if a.RuleIDs == nil || len(a.RuleIDs) > MaxRuleIDs {
		return fmt.Errorf("%w: ruleIds must be an array of at most %d ids", ErrInvalid, MaxRuleIDs)
	}
	for i, id := range a.RuleIDs {
		if !constraintengine.ValidID(id) {
			return fmt.Errorf("%w: rule id %q", ErrInvalid, id)
		}
		if i > 0 && a.RuleIDs[i-1] >= id {
			return fmt.Errorf("%w: ruleIds must be strictly ascending; %q follows %q", ErrInvalid, id, a.RuleIDs[i-1])
		}
	}
	return a.Evidence.Validate()
}

// Validate checks the evidence on its own: basis, extractor and derivation,
// the validity window and the cited sources. Records of other kinds that
// carry the same provenance (served lists) use it.
func (e Evidence) Validate() error {
	if e.Basis != constraintengine.BasisReviewed && e.Basis != constraintengine.BasisMechanical {
		return fmt.Errorf("%w: evidence.basis must be %q or %q", ErrInvalid, constraintengine.BasisReviewed, constraintengine.BasisMechanical)
	}
	if err := constraintengine.ValidateBasis(e.Basis, e.Extractor, e.DerivedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	reviewed, err := constraintengine.ParseUTC(e.ReviewedAt)
	if err != nil {
		return fmt.Errorf("%w: evidence.reviewedAt", ErrInvalid)
	}
	until, err := constraintengine.ParseUTC(e.ValidUntil)
	if err != nil || !until.After(reviewed) || until.Sub(reviewed) > MaxWindow {
		return fmt.Errorf("%w: evidence.validUntil must be after reviewedAt and at most %s later", ErrInvalid, MaxWindow)
	}
	if e.Basis == constraintengine.BasisMechanical && e.DerivedAt != e.ReviewedAt {
		return fmt.Errorf("%w: a mechanical attestation's reviewedAt is its derivedAt", ErrInvalid)
	}
	if err := constraintengine.ValidateSources(e.Sources); err != nil {
		return fmt.Errorf("%w: evidence.sources: %v", ErrInvalid, err)
	}
	return nil
}

// Field sets of each object level, for the exact shape check.
var (
	recordFields    = fields("component", "line", "factFamily", "completeness", "ruleIds", "evidence")
	evidenceFields  = fields("basis", "extractor?", "derivedAt?", "reviewedAt", "validUntil", "sources")
	extractorFields = fields("id", "version", "codeDigest")
	sourceFields    = fields("id", "url", "revision", "contentDigest", "startLine", "endLine")
)

type fieldSet map[string]bool // name -> required

func fields(names ...string) fieldSet {
	out := fieldSet{}
	for _, n := range names {
		name, optional := strings.CutSuffix(n, "?")
		out[name] = !optional
	}
	return out
}

// checkShape walks the document's tokens and rejects nulls, repeated or
// unexpected members (compared case-sensitively, unlike encoding/json) and
// missing required members.
func checkShape(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := noDuplicateMembers(raw); err != nil {
		return err
	}
	list, ok := doc.([]any)
	if !ok {
		return fmt.Errorf("%w: the document must be a JSON array", ErrInvalid)
	}
	for i, item := range list {
		if err := object(item, recordFields, func(name string, v any) error {
			switch name {
			case "ruleIds":
				ids, ok := v.([]any)
				if !ok {
					return fmt.Errorf("ruleIds must be an array")
				}
				for _, id := range ids {
					if _, ok := id.(string); !ok {
						return fmt.Errorf("ruleIds must hold strings")
					}
				}
			case "evidence":
				return object(v, evidenceFields, func(name string, v any) error {
					switch name {
					case "extractor":
						return object(v, extractorFields, nil)
					case "sources":
						srcs, ok := v.([]any)
						if !ok {
							return fmt.Errorf("sources must be an array")
						}
						for _, s := range srcs {
							if err := object(s, sourceFields, nil); err != nil {
								return err
							}
						}
					}
					return nil
				})
			}
			return nil
		}); err != nil {
			return fmt.Errorf("%w: attestation %d: %v", ErrInvalid, i, err)
		}
	}
	return nil
}

func object(v any, want fieldSet, inner func(string, any) error) error {
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
		value := m[name]
		if _, ok := want[name]; !ok {
			return fmt.Errorf("unknown member %q", name)
		}
		if value == nil {
			return fmt.Errorf("member %q is null", name)
		}
		if inner != nil {
			if err := inner(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// noDuplicateMembers rejects an object that names a member twice, which
// encoding/json would silently resolve to the last value.
func noDuplicateMembers(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		object bool
		seen   map[string]bool
		key    bool // the next token in this object is a member name
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.key {
			if name, ok := tok.(string); ok {
				if top.seen[name] {
					return fmt.Errorf("%w: member %q repeats", ErrInvalid, name)
				}
				top.seen[name] = true
				top.key = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, seen: map[string]bool{}, key: true})
			continue
		case json.Delim('['):
			stack = append(stack, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].key = true
		}
	}
}

// Marshal renders a document in canonical order.
func Marshal(atts []LineAttestation) ([]byte, error) {
	sorted := append([]LineAttestation(nil), atts...)
	Sort(sorted)
	if err := Validate(sorted); err != nil {
		return nil, err
	}
	return json.Marshal(sorted)
}
