// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// Notices are soft facts proven at both anchors from files read
// completely. Each becomes one verdict-neutral set notice per pair: it
// never passes, blocks or makes a scope incomplete, and a soft fact that is
// not proven is recorded in the proof and never becomes a notice.
const (
	// ReasonUnread is the reason of the "no longer read" notice
	// (notice_set_member_present).
	ReasonUnread = "HELM_VALUES_KEY_NOT_REFERENCED"
	// ReasonDefaultChanged is the reason of the "default changed" notice
	// (notice_set_member_absent).
	ReasonDefaultChanged = "HELM_VALUES_DEFAULT_CHANGED"
)

// Notice key classes.
const (
	ClassNotice    = "notice"
	ClassUnproven  = "unproven"
	ClassStillRead = "still-read"
	ClassSchema    = "schema"
	ClassSameValue = "same-value"
	ClassAmbiguous = "ambiguous-scalar"
)

// maxNoticeSources bounds the sources of a notice (the engine admits 8).
const maxNoticeSources = 8

// maxShownScalar bounds a default shown in a notice's text.
const maxShownScalar = 48

// NoticeRecord classifies every key a notice considered.
type NoticeRecord struct {
	Keys    []KeyClass `json:"keys"`
	Outcome string     `json:"outcome"`
}

// unreadProblem is why the later anchor cannot prove that a key its
// templates do not name is not read, "" when it can: every template file
// parsed, no index, tpl, whole-values or other unresolved access, a
// templates directory, and no dependency or vendored subchart (a
// dependency's templates, a library chart's among them, render with values
// this scan does not read).
func unreadProblem(s *side) string {
	t := s.templates
	switch {
	case !s.templatesDir:
		return "the later chart has no templates directory"
	case len(t.Refused) > 0:
		return "a later template file was not parsed"
	case t.Dynamic > 0:
		return "the later templates use index"
	case t.Tpl > 0:
		return "the later templates use tpl"
	case t.WholeValues > 0:
		return "the later templates use the whole values"
	case t.Indirect > 0:
		return "the later templates reach values in a way the scan does not resolve"
	case len(s.subcharts) > 0 || s.opaqueSubcharts || s.chartsDir:
		return "the later chart has dependencies or a charts directory"
	}
	return ""
}

// related reports whether a is b, a key above it or a key below it.
func related(a, b []string) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// schemaNames reports whether a values schema may name path: a required
// key that is path, a key above it or a key below it; path declared under
// properties, or a key above it declared with a schema that is not an
// object; or a schema object on the way that the walk does not read. A key the later schema names is still part of the
// chart's interface, so it is never claimed unread.
func schemaNames(root schemaNode, path []string) bool {
	if root == nil {
		return false
	}
	for _, q := range walkSchema(root).Required {
		if related(path, q) {
			return true
		}
	}
	n := root
	for i, k := range path {
		if n.opaqueReason(i == 0) != "" {
			return true
		}
		child, named, _ := n.property(k)
		if !named {
			return false
		}
		if child == nil {
			return true
		}
		n = child
	}
	return true
}

// unread derives the notice_set_member_present notice: values keys the
// earlier anchor's templates name literally that the later anchor's
// templates provably do not read. A key is a member only when the later
// anchor passes unreadProblem, no later template names the key, a key above
// it or a key below it, the later values schema does not name it (see
// schemaNames), and the key is not under subchart or global values.
func (x *Extractor) unread(pair extract.VersionPair, from, to *side) (*NoticeRecord, *chartrun.Candidate) {
	rec := &NoticeRecord{Keys: []KeyClass{}}
	removed := softFacts(from, to).ReferencesRemoved
	if len(removed) == 0 {
		rec.Outcome = "no notice: every key the earlier templates name is still named"
		return rec, nil
	}
	problem := unreadProblem(to)
	later := make([][]string, 0, len(to.templates.Paths))
	for _, q := range to.templates.Paths {
		later = append(later, strings.Split(q, "."))
	}
	var members []string
	files := map[string]bool{}
	for _, display := range removed {
		p := strings.Split(display, ".")
		class := ClassNotice
		m, expressible := helmvaluespath.Member(p)
		switch {
		case problem != "":
			class = ClassUnproven
		case from.subchartKey(p) || to.subchartKey(p):
			class = ClassSubchart
		case schemaNames(to.schema, p):
			class = ClassSchema
		default:
			for _, q := range later {
				if related(p, q) {
					class = ClassStillRead
					break
				}
			}
		}
		if class == ClassNotice && !expressible {
			class = ClassUnexpressible
		}
		rec.Keys = append(rec.Keys, KeyClass{Path: display, Class: class})
		if class == ClassNotice {
			members = append(members, m)
			for _, f := range from.templates.files[display] {
				files[f] = true
			}
		}
	}
	if problem != "" {
		rec.Outcome = "no notice: " + problem
		return rec, nil
	}
	if len(members) == 0 {
		rec.Outcome = "no notice: every key no longer named is still read or not expressible"
		return rec, nil
	}
	members = sortedUnique(members)
	if len(members) > maxRuleMembers {
		markOverBound(rec)
		rec.Outcome = fmt.Sprintf("no notice: %d keys, over the bound of %d members per rule", len(members), maxRuleMembers)
		return rec, nil
	}
	id, err := x.ruleID(pair, "unread-values")
	if err != nil {
		rec.Outcome = "no notice: " + err.Error()
		return rec, nil
	}
	t := x.target
	next := fmt.Sprintf("the %s chart %s templates no longer read the listed values keys; a value you set there does not change what that chart version renders (template scan of the chart's own templates at both release tags)", t.Chart.Name, pair.To)
	if len(next) > maxNext || !constraintengine.ValidNoticeText(id, next) {
		rec.Outcome = "no notice: the notice text does not meet the notice text rule"
		return rec, nil
	}
	rec.Outcome = "notice"
	sources := []extract.SourceRef{{ID: "chart-yaml-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.chartYAML}}
	for _, f := range sortedUnique(keys(files)) {
		if len(sources) == maxNoticeSources {
			break
		}
		sources = append(sources, extract.SourceRef{ID: fmt.Sprintf("template-%s-%d", slug(pair.From), len(sources)), Repo: pair.Repo, Commit: pair.FromCommit, Path: t.ChartPath + "/" + f})
	}
	return rec, &chartrun.Candidate{
		Project: t.Project,
		Description: fmt.Sprintf("Notice, never a verdict: the templates of the %s chart %s (%s) no longer read %d values key(s) that chart %s's templates name. No template of %s names the key, a key above it or a key below it, every template parses, none uses index, tpl, the whole values or another route the scan does not resolve, and the chart has no dependencies or charts directory, so a value set for such a key does not change what the chart renders. Derived from a syntactic scan of the chart's own templates at both release tags; keys under subchart or global values are not considered.",
			t.Chart.Name, pair.To, t.Name, len(members), pair.From, pair.To),
		RequiredFacts: []extract.Fact{x.valuesFact()},
		Rule: chartrun.Rule{
			ID: id, Operator: constraintengine.OperatorNoticeSetMemberPresent, Subject: x.subject(pair),
			SetCondition: &extract.SetCondition{Side: "proposed", Component: t.Component, FactID: t.FactID(), Members: members},
			ReasonCode:   ReasonUnread,
			NextAction:   next,
		},
		Sources: sources,
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func markOverBound(rec *NoticeRecord) {
	for i := range rec.Keys {
		if rec.Keys[i].Class == ClassNotice {
			rec.Keys[i].Class = ClassOverBound
		}
	}
}

// decimalRE is the number spelling both YAML 1.1 (Helm's reader) and the
// strict decoder read as the same number.
var decimalRE = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$`)

// yaml11AmbiguousRE matches a string a YAML 1.1 reader may read as
// something else when it is written unquoted (a boolean, a null, a number,
// a sexagesimal or a timestamp). The strict decoder keeps no quoting, so
// such a string is never compared.
var yaml11AmbiguousRE = regexp.MustCompile(`^(?i:y|n|yes|no|on|off|true|false|null|~)$|^[-+.0-9]`)

// helmScalar is a scalar as Helm reads it: its kind and canonical text. ok
// is false for anything whose reading may differ between YAML readers.
func helmScalar(v any) (kind, text string, ok bool) {
	switch x := v.(type) {
	case bool:
		return "bool", strconv.FormatBool(x), true
	case json.Number:
		if !decimalRE.MatchString(string(x)) {
			return "", "", false
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return "", "", false
		}
		return "number", strconv.FormatFloat(f, 'g', -1, 64), true
	case string:
		if yaml11AmbiguousRE.MatchString(x) {
			return "", "", false
		}
		return "string", x, true
	}
	return "", "", false
}

// admitted reports whether a schema leaves path as it is: no schema, or
// the path declared or under an open object, never refused and never under
// a keyword the walk does not read.
func admitted(s schemaNode, path []string) bool {
	if s == nil {
		return true
	}
	_, refused, reason := rejection(s, path)
	return !refused && (reason == "every key is declared" || strings.HasPrefix(reason, "open"))
}

// changedDefaults derives the notice_set_member_absent notice: values keys
// whose scalar default differs between the anchors as Helm reads it, under
// no subchart or global key, that both schemas leave as they are. The
// notice holds only over a complete values set: a key the user does not set
// takes the chart's default.
func (x *Extractor) changedDefaults(pair extract.VersionPair, from, to *side) (*NoticeRecord, *chartrun.Candidate) {
	rec := &NoticeRecord{Keys: []KeyClass{}}
	type change struct{ old, new string }
	var members []string
	shown := map[string]change{}
	for _, p := range helmvaluespath.ValuePaths(from.values) {
		old, _ := helmvaluespath.ValueAt(from.values, p)
		v, ok := helmvaluespath.ValueAt(to.values, p)
		if !ok || !scalar(old) || !scalar(v) {
			continue
		}
		k1, t1, ok1 := helmScalar(old)
		k2, t2, ok2 := helmScalar(v)
		display := helmvaluespath.DisplayPath(p)
		class, detail := ClassNotice, ""
		switch {
		case !ok1 || !ok2:
			if fmt.Sprint(old) == fmt.Sprint(v) {
				continue
			}
			class = ClassAmbiguous
		case k1 == k2 && t1 == t2:
			if fmt.Sprint(old) == fmt.Sprint(v) {
				continue
			}
			class = ClassSameValue
		case from.subchartKey(p) || to.subchartKey(p):
			class = ClassSubchart
		case from.opaqueSubcharts || to.opaqueSubcharts:
			class = ClassOpaqueSubcharts
		case !admitted(from.schema, p) || !admitted(to.schema, p):
			class = ClassSchema
		}
		m, expressible := helmvaluespath.Member(p)
		if class == ClassNotice && !expressible {
			class = ClassUnexpressible
		}
		if class == ClassNotice {
			detail = shownScalar(k1, t1) + " -> " + shownScalar(k2, t2)
			members = append(members, m)
			shown[m] = change{shownScalar(k1, t1), shownScalar(k2, t2)}
		}
		rec.Keys = append(rec.Keys, KeyClass{Path: display, Class: class, Detail: detail})
	}
	if len(members) == 0 {
		rec.Outcome = "no notice: no scalar default changed as Helm reads it"
		return rec, nil
	}
	members = sortedUnique(members)
	if len(members) > maxRuleMembers {
		markOverBound(rec)
		rec.Outcome = fmt.Sprintf("no notice: %d keys, over the bound of %d members per rule", len(members), maxRuleMembers)
		return rec, nil
	}
	id, err := x.ruleID(pair, "changed-defaults")
	if err != nil {
		rec.Outcome = "no notice: " + err.Error()
		return rec, nil
	}
	t := x.target
	valid := func(s string) bool { return len(s) <= maxNext && constraintengine.ValidNoticeText(id, s) }
	next := fmt.Sprintf("the %s chart %s changes the default of the listed values keys (values.yaml at %s and %s); where you do not set a key, the chart default is used: check that each new default suits your release", t.Chart.Name, pair.To, pair.From, pair.To)
	if len(members) == 1 {
		c := shown[members[0]]
		one := fmt.Sprintf("the %s chart %s changes the default of values key %s from %s to %s; where you do not set the key, the chart default is used: check that the new default suits your release", t.Chart.Name, pair.To, members[0], c.old, c.new)
		if len(c.old) <= maxShownScalar && len(c.new) <= maxShownScalar && valid(one) {
			next = one
		}
	}
	if !valid(next) {
		rec.Outcome = "no notice: the notice text does not meet the notice text rule"
		return rec, nil
	}
	rec.Outcome = "notice"
	return rec, &chartrun.Candidate{
		Project: t.Project,
		Description: fmt.Sprintf("Notice, never a verdict: the %s chart %s (%s) changes the default of %d values key(s) from chart %s. Each default is a scalar written so that every YAML reader reads it the same way, differs between the two release tags as Helm reads it, lies under no subchart or global key, and neither values schema closes the key off or leaves it unread. The notice applies only over a complete values set: a key the supplied values do not set takes the new default. Derived from values.yaml and values.schema.json at both release tags.",
			t.Chart.Name, pair.To, t.Name, len(members), pair.From),
		RequiredFacts: []extract.Fact{x.valuesFact()},
		Rule: chartrun.Rule{
			ID: id, Operator: constraintengine.OperatorNoticeSetMemberAbsent, Subject: x.subject(pair),
			SetCondition: &extract.SetCondition{Side: "proposed", Component: t.Component, FactID: t.FactID(), Members: members},
			ReasonCode:   ReasonDefaultChanged,
			NextAction:   next,
		},
		Sources: []extract.SourceRef{
			{ID: "values-yaml-" + slug(pair.From), Repo: pair.Repo, Commit: pair.FromCommit, Path: from.valuesYAML},
			{ID: "values-yaml-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.valuesYAML},
		},
	}
}

// shownScalar renders a scalar for a notice: a string quoted, any other
// kind as read.
func shownScalar(kind, text string) string {
	if kind == "string" {
		return strconv.Quote(text)
	}
	return text
}
