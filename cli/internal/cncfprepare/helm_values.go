// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// Reasons of the Helm values preparation.
const (
	// ReasonHelmValuesComplete: the values-path set is declared complete.
	ReasonHelmValuesComplete Reason = "HELM_VALUES_COMPLETE"
	// ReasonHelmValuesNotDeclaredComplete: the caller did not declare the
	// supplied files and assignments to be every values source of the
	// release.
	ReasonHelmValuesNotDeclaredComplete Reason = "HELM_VALUES_NOT_DECLARED_COMPLETE"
	// ReasonHelmValuesNullOverride: the merged values hold a null. Helm
	// keeps a null through the merge of the supplied values and then
	// removes the key, with any chart default under it, from the release
	// values. The rules assume the chart's default mappings are kept, so the
	// set is never complete.
	ReasonHelmValuesNullOverride Reason = "HELM_VALUES_NULL_OVERRIDE"
	// ReasonHelmValuesUniverseTooLarge: the rules that read the set name
	// more members than a set may hold, so the set is not supported.
	ReasonHelmValuesUniverseTooLarge Reason = "HELM_VALUES_UNIVERSE_TOO_LARGE"
	// ReasonHelmValuesUniverseUnresolved: a rule reads the set other than
	// through a set condition, so the members the rules name are not known
	// and the set is not supported.
	ReasonHelmValuesUniverseUnresolved Reason = "HELM_VALUES_UNIVERSE_UNRESOLVED"
	// ReasonHelmValuesNoFact: no rule of the chart reads a values-path set
	// fact, so none is declared; the values are read but not used.
	ReasonHelmValuesNoFact Reason = "HELM_VALUES_NO_FACT"
)

// Errors of the Helm values readers. Each is a refusal of the caller's
// input, never a partial result.
var (
	// ErrHelmValuesFile: a values file is outside the strict YAML subset or
	// its root is not a mapping.
	ErrHelmValuesFile = errors.New("values file is outside the strict YAML subset, or its root is not a mapping")
	// ErrHelmSet: an assignment is outside the accepted --helm-set grammar.
	ErrHelmSet = errors.New("assignment is outside the accepted KEY=VALUE grammar")
	// ErrHelmSetPath: an assignment's key passes through a value that is
	// not a mapping, which Helm refuses.
	ErrHelmSetPath = errors.New("assignment's key passes through a value that is not a mapping")
)

// maxHelmSetBytes bounds one assignment.
const maxHelmSetBytes = 4096

// HelmSet is one accepted KEY=VALUE assignment: the key path it sets and
// whether its value is null (which removes the path, as Helm does).
type HelmSet struct {
	Path []string
	Null bool
}

// ParseHelmSet reads one assignment in the subset of Helm's --set grammar
// that can be read exactly:
//
//   - KEY is a dotted key path. Within a key, "\." "\=" "\," and "\\" stand
//     for ".", "=", "," and "\". Every key is non-empty. List syntax ("[")
//     and any other escape are refused.
//   - VALUE is everything after the first unescaped "=". An unescaped ","
//     (Helm reads several assignments) and a leading "{" (Helm reads a
//     list) are refused. A value that is "null" in any letter case, after
//     escapes are removed, removes the path; any other value sets it (its
//     type does not matter to the set of key paths).
func ParseHelmSet(text string) (HelmSet, error) {
	if text == "" || len(text) > maxHelmSetBytes || !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return HelmSet{}, ErrHelmSet
	}
	var path []string
	var key []rune
	runes := []rune(text)
	index := 0
	assigned := false
	for index < len(runes) && !assigned {
		r := runes[index]
		index++
		switch r {
		case '\\':
			if index >= len(runes) {
				return HelmSet{}, ErrHelmSet
			}
			next := runes[index]
			index++
			if next != '.' && next != '=' && next != ',' && next != '\\' {
				return HelmSet{}, ErrHelmSet
			}
			key = append(key, next)
		case '.', '=':
			if len(key) == 0 {
				return HelmSet{}, ErrHelmSet
			}
			path = append(path, string(key))
			key = nil
			assigned = r == '='
		case '[', ']', ',':
			return HelmSet{}, ErrHelmSet
		default:
			key = append(key, r)
		}
	}
	if !assigned || len(path) == 0 {
		return HelmSet{}, ErrHelmSet
	}
	var value []rune
	for i := index; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\\':
			if i+1 >= len(runes) {
				return HelmSet{}, ErrHelmSet
			}
			i++
			value = append(value, runes[i])
		case r == ',':
			return HelmSet{}, ErrHelmSet
		case r == '{' && i == index:
			return HelmSet{}, ErrHelmSet
		default:
			value = append(value, r)
		}
	}
	return HelmSet{Path: path, Null: strings.EqualFold(string(value), "null")}, nil
}

// DecodeHelmValues reads one values file in the strict YAML subset (JSON is
// part of it). An empty file, or one holding only null, is an empty mapping;
// any other root must be a mapping.
func DecodeHelmValues(raw []byte) (map[string]any, error) {
	_, value, err := helmvaluespath.DecodeYAML(raw)
	if err != nil {
		return nil, ErrHelmValuesFile
	}
	if value == nil {
		return map[string]any{}, nil
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, ErrHelmValuesFile
	}
	return root, nil
}

// MergeHelmValues merges the supplied values the way Helm merges a
// release's own values before it applies the chart's defaults: the files in
// order, a later one winning (two mappings merge key by key; any other
// value, null included, replaces), then the assignments in order (each sets
// its path, creating a missing mapping on the way; a null value sets null).
// An assignment whose key passes through a value that is present and not a
// mapping (null included) is refused, as Helm refuses it: the error is a
// HelmSetPathError naming the assignment. A null is kept: Helm removes it
// only when it applies the chart's defaults. The inputs are not changed.
func MergeHelmValues(files []map[string]any, sets []HelmSet) (map[string]any, error) {
	out := map[string]any{}
	for _, file := range files {
		out = mergeHelmMaps(out, file)
	}
	for index, set := range sets {
		var value any = "set"
		if set.Null {
			value = nil
		}
		cur := out
		for i, k := range set.Path {
			if i == len(set.Path)-1 {
				cur[k] = value
				break
			}
			existing, present := cur[k]
			var next map[string]any
			switch m, ok := existing.(map[string]any); {
			case !present:
				next = map[string]any{}
			case ok:
				next = copyHelmMap(m)
			default:
				return nil, HelmSetPathError{Index: index}
			}
			cur[k] = next
			cur = next
		}
	}
	return out, nil
}

// HelmSetPathError is the refusal of the assignment at Index (in the order
// given) whose key passes through a value that is not a mapping.
type HelmSetPathError struct{ Index int }

func (e HelmSetPathError) Error() string { return ErrHelmSetPath.Error() }

// Unwrap makes the error match ErrHelmSetPath.
func (e HelmSetPathError) Unwrap() error { return ErrHelmSetPath }

func mergeHelmMaps(a, b map[string]any) map[string]any {
	out := copyHelmMap(a)
	for k, v := range b {
		if bm, ok := v.(map[string]any); ok {
			if am, ok := out[k].(map[string]any); ok {
				out[k] = mergeHelmMaps(am, bm)
				continue
			}
			out[k] = copyHelmMap(bm)
			continue
		}
		out[k] = v
	}
	return out
}

func copyHelmMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if inner, ok := v.(map[string]any); ok {
			v = copyHelmMap(inner)
		}
		out[k] = v
	}
	return out
}

// HelmNullPaths lists the key paths of merged values whose value is null,
// in path order; nothing under a null is visited.
func HelmNullPaths(values map[string]any) [][]string {
	var out [][]string
	var visit func(m map[string]any, path []string)
	visit = func(m map[string]any, path []string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := helmvaluespath.AppendPath(path, k)
			switch v := m[k].(type) {
			case nil:
				out = append(out, p)
			case map[string]any:
				visit(v, p)
			}
		}
	}
	visit(values, nil)
	return out
}

// HelmChartHop is one declared chart hop: the component, its chart, the
// chart versions on both sides, and the Kubernetes versions the caller
// declared (empty when not declared).
type HelmChartHop struct {
	Component      string
	Chart          constraintengine.ChartRef
	From, To       string
	Kubernetes     string
	KubernetesFrom string
	KubernetesTo   string
}

// HelmValuesScan is the values-path preparation of one chart hop.
type HelmValuesScan struct {
	Prepared Prepared
	// Fact is the values-path set fact.
	Fact string
	// PathsRead counts every key path of the merged values whose value is
	// not null.
	PathsRead int
	// Unnamed counts the paths whose member would exceed the member bound;
	// no rule can name one, so none is a member.
	Unnamed int
	// UniverseSize is the number of distinct members the rules that read
	// the fact name.
	UniverseSize int
	// Members are the declared members: the merged values' paths that the
	// rules name. Nil when the set is not supported.
	Members []string
	// NullPaths are the key paths whose merged value is null.
	NullPaths [][]string
}

// HelmUniverse is the set of members the rules that read a values-path set
// fact name. Resolved is false when some rule reads the fact other than
// through a set condition, so the members it depends on are not known.
type HelmUniverse struct {
	Members  []string
	Resolved bool
}

// PrepareHelmValues declares, for one chart hop, the proposed-side
// values-path set fact of the chart: the key paths of the merged values
// (through mappings only, null values left out), each written with
// helmvaluespath.Member, restricted to the members the universe names.
//
// Every rule that reads the fact lists only members of the universe, so a
// rule decides the same over the restricted set as over every path: a
// required member is present in one exactly when it is present in the
// other, and so is a refused member. The set is declared complete only when
// all of these hold: the caller declared the values complete, the merged
// values hold no null, and the universe is resolved and within the set
// bound. A universe that is not resolved or too large makes the fact
// unsupported. The current side carries no fact. The chart identity is
// declared on both sides; a Kubernetes version is declared on a side only
// when the caller gave it. An empty fact declares no fact at all: no rule
// of the chart reads one, and an invented id would only be refused.
func PrepareHelmValues(hop HelmChartHop, fact string, values map[string]any, universe HelmUniverse, declaredComplete bool) (HelmValuesScan, error) {
	if hop.Component == "" || !constraintengine.ValidChartRef(hop.Chart) || !validVersionSyntax(hop.From) || !validVersionSyntax(hop.To) || constraintengine.SameVersion(hop.From, hop.To) {
		return HelmValuesScan{}, ErrInvalid
	}
	for _, v := range []string{hop.KubernetesFrom, hop.KubernetesTo} {
		if v != "" && (hop.Kubernetes == "" || hop.Kubernetes == hop.Component || !validKubernetesVersion(v)) {
			return HelmValuesScan{}, ErrInvalid
		}
	}
	scan := HelmValuesScan{Fact: fact, NullPaths: HelmNullPaths(values)}
	allowed := map[string]bool{}
	for _, member := range universe.Members {
		allowed[member] = true
	}
	scan.UniverseSize = len(allowed)
	members := map[string]bool{}
	for _, path := range helmvaluespath.ValuePaths(values) {
		scan.PathsRead++
		member, ok := helmvaluespath.Member(path)
		if !ok {
			scan.Unnamed++
			continue
		}
		if allowed[member] {
			members[member] = true
		}
	}
	finish := func(f *inputFact, state State, reason Reason) (HelmValuesScan, error) {
		canonical, err := marshalHelmChartInput(hop, f)
		if err != nil {
			return HelmValuesScan{}, ErrInvalid
		}
		scan.Prepared = Prepared{
			CanonicalInputJSON: canonical, InputDigest: digestBytes(canonical), State: state, Reason: reason,
			Omissions: []string{"HELM_VALUES_ARE_CALLER_SUPPLIED_NOT_THE_DEPLOYED_RELEASE", "CHART_TEMPLATES_DEFAULTS_AND_APPLICATION_UPGRADE_NOT_EVALUATED"},
		}
		return scan, nil
	}
	switch {
	case fact == "":
		if len(allowed) > 0 || !universe.Resolved {
			return HelmValuesScan{}, ErrInvalid
		}
		return finish(nil, StatePrepared, ReasonHelmValuesNoFact)
	case !universe.Resolved:
		return finish(&inputFact{ID: fact, State: "unsupported"}, StateUnknown, ReasonHelmValuesUniverseUnresolved)
	case scan.UniverseSize > constraintengine.MaxSetMembers:
		return finish(&inputFact{ID: fact, State: "unsupported"}, StateUnknown, ReasonHelmValuesUniverseTooLarge)
	}
	scan.Members = make([]string, 0, len(members))
	for member := range members {
		scan.Members = append(scan.Members, member)
	}
	sort.Strings(scan.Members)
	reason := ReasonHelmValuesComplete
	switch {
	case !declaredComplete:
		reason = ReasonHelmValuesNotDeclaredComplete
	case len(scan.NullPaths) > 0:
		reason = ReasonHelmValuesNullOverride
	}
	declared := setFact(fact, scan.Members, reason == ReasonHelmValuesComplete)
	return finish(&declared, StatePrepared, reason)
}

type helmInputComponent struct {
	Component string                     `json:"component"`
	Version   string                     `json:"version"`
	Facts     []inputFact                `json:"facts"`
	Chart     *constraintengine.ChartRef `json:"chart,omitempty"`
}

type helmInputSide struct {
	Components []helmInputComponent `json:"components"`
}

type helmInputEnvelope struct {
	Schema    string        `json:"schema"`
	Authority string        `json:"authority"`
	Current   helmInputSide `json:"current"`
	Proposed  helmInputSide `json:"proposed"`
}

func marshalHelmChartInput(hop HelmChartHop, fact *inputFact) ([]byte, error) {
	chart := hop.Chart
	proposed := []inputFact{}
	if fact != nil {
		proposed = append(proposed, *fact)
	}
	input := helmInputEnvelope{
		Schema: InputSchema, Authority: InputAuthority,
		Current:  helmInputSide{Components: []helmInputComponent{{Component: hop.Component, Version: hop.From, Facts: []inputFact{}, Chart: &chart}}},
		Proposed: helmInputSide{Components: []helmInputComponent{{Component: hop.Component, Version: hop.To, Facts: proposed, Chart: &chart}}},
	}
	if hop.KubernetesFrom != "" {
		input.Current.Components = append(input.Current.Components, helmInputComponent{Component: hop.Kubernetes, Version: hop.KubernetesFrom, Facts: []inputFact{}})
	}
	if hop.KubernetesTo != "" {
		input.Proposed.Components = append(input.Proposed.Components, helmInputComponent{Component: hop.Kubernetes, Version: hop.KubernetesTo, Facts: []inputFact{}})
	}
	compact, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return append(compact, '\n'), nil
}
