// SPDX-License-Identifier: AGPL-3.0-only

// Package ledger lists, for the pairs of one helm.values run, everything the
// extractor refused to classify and why. It only reads the extractor's
// proofs; it derives nothing and changes no rule. Its output is
// deterministic: the same proofs give the same bytes.
package ledger

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
)

// Scope says what a refusal is about.
type Scope string

// Scopes.
const (
	// ScopePair: the whole pair was withheld; Key is empty.
	ScopePair Scope = "pair"
	// ScopeRemoved: a key of the earlier chart the later schema might refuse.
	ScopeRemoved Scope = "removed"
	// ScopeRequired: a key the later schema requires.
	ScopeRequired Scope = "required"
	// ScopeTemplates: a template entry that was not scanned.
	ScopeTemplates Scope = "templates"
	// ScopeUnread: a key the "no longer read" notice considered.
	ScopeUnread Scope = "notice-unread"
	// ScopeChanged: a key the "default changed" notice considered.
	ScopeChanged Scope = "notice-changed"
)

// Reason is the typed cause of a refusal.
type Reason string

// Pair-level reasons: a release did not read completely.
const (
	ChartDirMissing      Reason = "chart-dir-missing"
	ChartYAMLNotFile     Reason = "chart-yaml-not-a-file"
	ChartYAMLInvalid     Reason = "chart-yaml-invalid"
	ChartNameMismatch    Reason = "chart-name-mismatch"
	ChartVersionMismatch Reason = "chart-version-mismatch"
	ValuesNotFile        Reason = "values-not-a-file"
	ValuesOutsideSubset  Reason = "values-outside-strict-subset"
	ValuesNotMapping     Reason = "values-not-a-mapping"
	SchemaNotFile        Reason = "schema-not-a-file"
	SchemaInvalid        Reason = "schema-invalid"
	RequirementsInvalid  Reason = "requirements-invalid"
	RequirementsNotFile  Reason = "requirements-not-a-file"
	TemplatesOverBound   Reason = "templates-over-bound"
	// UnclassifiedProblem is a read problem this package has no name for;
	// it is listed rather than dropped.
	UnclassifiedProblem Reason = "unclassified-problem"
)

// Key-level reasons.
const (
	SchemaOpaque        Reason = "schema-opaque"
	SubchartKey         Reason = "subchart-key"
	PackagedSubchart    Reason = "packaged-subchart"
	MemberUnexpressible Reason = "member-unexpressible"
	MemberOverBound     Reason = "member-over-bound"
	TemplateNotScanned  Reason = "template-not-scanned"
	// NoticeUnproven: the later chart cannot prove the key is unread.
	NoticeUnproven Reason = "notice-unproven"
	// NoticeAmbiguousScalar: a scalar default whose YAML reading is not unique.
	NoticeAmbiguousScalar Reason = "notice-ambiguous-scalar"
	// NoticeSchemaNamed: the later schema names, requires or refuses the key.
	NoticeSchemaNamed Reason = "notice-schema"
	// UnclassifiedKey is a key class this package has no name for; it is
	// listed rather than dropped.
	UnclassifiedKey Reason = "unclassified-key"
)

// Entry is one refusal.
type Entry struct {
	Pair   string `json:"pair"`
	Scope  Scope  `json:"scope"`
	Key    string `json:"key,omitempty"`
	Reason Reason `json:"reason"`
	// Detail is bounded (96 runes) extractor wording for people. It may
	// name a schema keyword or a key path; it never carries a read error
	// (those can quote file content) or a default value.
	Detail string `json:"detail,omitempty"`
}

// Ledger is a sorted list of refusals.
type Ledger struct {
	Entries []Entry `json:"entries"`
}

// Collect lists the refusals in one pair's proof. pair names the pair
// ("from->to"). A nil proof gives none.
//
// Decisions are not refusals: a rejected key, a key still defaulted, a key
// the earlier schema already refused, a notice key, a key still read and a
// scalar whose reading is the same are all classified, one way or the
// other. Only what the extractor declined to classify is listed.
func Collect(pair string, p *helmvalues.PairProof) []Entry {
	if p == nil {
		return nil
	}
	var out []Entry
	add := func(scope Scope, key string, class, detail string) {
		if r, refusal := classReason(scope, class); refusal {
			out = append(out, Entry{Pair: pair, Scope: scope, Key: key, Reason: r, Detail: bound(detail)})
		}
	}
	for _, side := range []*helmvalues.SideRecord{p.From, p.To} {
		if side == nil {
			continue
		}
		if side.Problem != "" {
			// Only the tag is kept: a read error can quote file content.
			out = append(out, Entry{Pair: pair, Scope: ScopePair, Reason: pairReason(side.Problem), Detail: bound(side.Tag)})
			continue
		}
		for _, name := range side.Templates.Refused {
			out = append(out, Entry{Pair: pair, Scope: ScopeTemplates, Key: name, Reason: TemplateNotScanned, Detail: bound(side.Tag)})
		}
	}
	if p.Required != nil {
		for _, n := range p.Required.Opaque {
			out = append(out, Entry{Pair: pair, Scope: ScopeRequired, Key: n.Path, Reason: SchemaOpaque, Detail: bound(n.Reason)})
		}
		for _, k := range p.Required.Keys {
			add(ScopeRequired, k.Path, k.Class, k.Detail)
		}
	}
	if p.Removed != nil {
		overBound := overBoundRE.MatchString(p.Removed.Outcome)
		for _, k := range p.Removed.Keys {
			if k.Class == helmvalues.ClassRejected && overBound {
				// Every rejected key is held back when the rule would name
				// more members than a rule may hold.
				out = append(out, Entry{Pair: pair, Scope: ScopeRemoved, Key: k.Path, Reason: MemberOverBound, Detail: bound(k.Detail)})
				continue
			}
			add(ScopeRemoved, k.Path, k.Class, k.Detail)
		}
	}
	if p.Soft != nil {
		for _, n := range []struct {
			scope  Scope
			record *helmvalues.NoticeRecord
		}{{ScopeUnread, p.Soft.Unread}, {ScopeChanged, p.Soft.Changed}} {
			if n.record == nil {
				continue
			}
			for _, k := range n.record.Keys {
				detail := k.Detail
				if k.Class == helmvalues.ClassUnproven {
					detail = n.record.Outcome
				}
				add(n.scope, k.Path, k.Class, detail)
			}
		}
	}
	return out
}

// FromAny is Collect for a proof that was stored as JSON.
func FromAny(pair string, proof any) ([]Entry, error) {
	if proof == nil {
		return nil, nil
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("ledger: proof of %s: %w", pair, err)
	}
	var p helmvalues.PairProof
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("ledger: proof of %s: %w", pair, err)
	}
	return Collect(pair, &p), nil
}

// New returns the ledger of the given entries, sorted and without
// duplicates.
func New(entries ...[]Entry) *Ledger {
	var all []Entry
	for _, e := range entries {
		all = append(all, e...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Pair != b.Pair {
			return a.Pair < b.Pair
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Detail < b.Detail
	})
	out := all[:0]
	for i, e := range all {
		if i > 0 && e == all[i-1] {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	return &Ledger{Entries: out}
}

// Counts is the number of refusals per scope and reason, as "scope/reason".
func (l *Ledger) Counts() map[string]int {
	m := map[string]int{}
	for _, e := range l.Entries {
		m[string(e.Scope)+"/"+string(e.Reason)]++
	}
	return m
}

// JSON is the ledger as indented JSON ending in a newline.
func (l *Ledger) JSON() ([]byte, error) {
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

var overBoundRE = regexp.MustCompile(`^no rule: [0-9]+ keys, over the bound of [0-9]+ members per rule$`)

// decisionClasses are the key classes that are a decision, not a refusal.
var decisionClasses = map[string]bool{
	helmvalues.ClassRule: true, helmvalues.ClassDefault: true, helmvalues.ClassNullDefault: true,
	helmvalues.ClassAlready: true, helmvalues.ClassInactive: true, helmvalues.ClassEmptyAncestor: true,
	helmvalues.ClassRejected: true, helmvalues.ClassStillDefaulted: true, helmvalues.ClassWasRejected: true,
	helmvalues.ClassNotice: true, helmvalues.ClassStillRead: true, helmvalues.ClassSameValue: true,
}

// refusalClasses are the key classes that are a refusal to classify.
var refusalClasses = map[string]Reason{
	helmvalues.ClassOpaque:          SchemaOpaque,
	helmvalues.ClassSubchart:        SubchartKey,
	helmvalues.ClassOpaqueSubcharts: PackagedSubchart,
	helmvalues.ClassUnexpressible:   MemberUnexpressible,
	helmvalues.ClassOverBound:       MemberOverBound,
	helmvalues.ClassUnproven:        NoticeUnproven,
	helmvalues.ClassAmbiguous:       NoticeAmbiguousScalar,
	helmvalues.ClassSchema:          NoticeSchemaNamed,
}

// KnownClass reports whether the ledger has placed a key class as a
// decision or a refusal. A test walks every Class constant of the
// extractor against it, so a new class cannot be dropped silently.
func KnownClass(class string) bool {
	_, refusal := refusalClasses[class]
	return refusal || decisionClasses[class]
}

// classReason maps a key class to its refusal reason; a decision gives
// false, and a class nobody has placed is listed as UnclassifiedKey.
func classReason(_ Scope, class string) (Reason, bool) {
	if r, ok := refusalClasses[class]; ok {
		return r, true
	}
	if decisionClasses[class] {
		return "", false
	}
	return UnclassifiedKey, true
}

// maxDetail bounds Detail, in runes.
const maxDetail = 96

func bound(s string) string {
	r := []rune(s)
	if len(r) > maxDetail {
		return string(r[:maxDetail])
	}
	return s
}

// The extractor's read-problem wordings, anchored: an optional chart
// directory prefix (no space or colon), then the exact text. The tests pin
// each against a real run and refuse look-alikes.
const dir = `(?:[^ :]+/)*`

var pairReasons = []struct {
	re     *regexp.Regexp
	reason Reason
}{
	{regexp.MustCompile(`^the chart directory [^ ]+ does not exist$`), ChartDirMissing},
	{regexp.MustCompile(`^` + dir + `Chart\.yaml is not a file$`), ChartYAMLNotFile},
	{regexp.MustCompile(`^` + dir + `values\.yaml is not a file$`), ValuesNotFile},
	{regexp.MustCompile(`^` + dir + `values\.schema\.json is not a file$`), SchemaNotFile},
	{regexp.MustCompile(`^requirements\.yaml is not a file$`), RequirementsNotFile},
	{regexp.MustCompile(`^` + dir + `values\.yaml is not a mapping$`), ValuesNotMapping},
	{regexp.MustCompile(`^` + dir + `Chart\.yaml names chart ".*", not ".*"$`), ChartNameMismatch},
	{regexp.MustCompile(`^` + dir + `Chart\.yaml declares version [^ ]+, the tag names [^ ]+$`), ChartVersionMismatch},
	{regexp.MustCompile(`^` + dir + `Chart\.yaml: `), ChartYAMLInvalid},
	{regexp.MustCompile(`^` + dir + `values\.yaml: `), ValuesOutsideSubset},
	{regexp.MustCompile(`^` + dir + `values\.schema\.json: `), SchemaInvalid},
	{regexp.MustCompile(`^requirements\.yaml: `), RequirementsInvalid},
	{regexp.MustCompile(`^templates: `), TemplatesOverBound},
}

// pairReason names a release's read problem from the extractor's wording;
// a wording it does not know is UnclassifiedProblem.
func pairReason(problem string) Reason {
	for _, p := range pairReasons {
		if p.re.MatchString(problem) {
			return p.reason
		}
	}
	return UnclassifiedProblem
}

// All lists every reason this package can give, in a fixed order.
func All() []Reason {
	return []Reason{
		ChartDirMissing, ChartYAMLNotFile, ChartYAMLInvalid, ChartNameMismatch, ChartVersionMismatch,
		ValuesNotFile, ValuesOutsideSubset, ValuesNotMapping, SchemaNotFile, SchemaInvalid,
		RequirementsInvalid, RequirementsNotFile, TemplatesOverBound, UnclassifiedProblem,
		SchemaOpaque, SubchartKey, PackagedSubchart, MemberUnexpressible, MemberOverBound, TemplateNotScanned,
		NoticeUnproven, NoticeAmbiguousScalar, NoticeSchemaNamed, UnclassifiedKey,
	}
}
