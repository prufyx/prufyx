// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// declaredCharts reads the chart identity each input component declares,
// by component. The engine already admitted the input, so a component that
// declares a chart declares the same one on both sides. It is empty for an
// input of application versions only.
func declaredCharts(raw []byte) (map[string]constraintengine.ChartRef, error) {
	type chartComponent struct {
		Component string                     `json:"component"`
		Chart     *constraintengine.ChartRef `json:"chart"`
	}
	type chartSide struct {
		Components []chartComponent `json:"components"`
	}
	var input struct {
		Current  chartSide `json:"current"`
		Proposed chartSide `json:"proposed"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return nil, ErrIntegrity
	}
	charts := map[string]constraintengine.ChartRef{}
	for _, side := range []chartSide{input.Current, input.Proposed} {
		for _, component := range side.Components {
			if component.Chart == nil {
				continue
			}
			if seen, found := charts[component.Component]; found && seen != *component.Chart {
				return nil, ErrIntegrity
			}
			charts[component.Component] = *component.Chart
		}
	}
	return charts, nil
}

// selectChartFamily is the selection of a fact-family check whose input
// declares a chart hop. It is kept apart from selectFamily, which serves
// application hops and never selects a chart rule.
//
// For a component the input declares as a chart hop, it selects:
//
//   - the chart rules about exactly that chart whose facts all belong to
//     facts (a chart rule that reads no fact, such as a Kubernetes minimum,
//     belongs to every family of its chart), narrowed to those whose anchor
//     matches the declared chart versions when a verdict rule does;
//   - the application rules about that component whose facts all belong to
//     facts (at least one), so the engine reports each as undetermined
//     (RULE_APP_VERSION_NOT_DECLARED): a chart version never decides an
//     application rule.
//
// A chart rule about another chart, and every rule about a component the
// input does not declare as a chart hop, is never selected.
func (b bundle) selectChartFamily(project string, facts []string, raw []byte, charts map[string]constraintengine.ChartRef) (selection, error) {
	if len(deferredOf(b.pack, project)) > 0 {
		// A rule of the project is not evaluable by this build: no other
		// rule may give a claim (a pass) for a hop the missing rule may block.
		return b.admit(nil, nil)
	}
	allowed := map[string]bool{}
	for _, fact := range facts {
		allowed[fact] = true
	}
	var input struct {
		Current  sideShape `json:"current"`
		Proposed sideShape `json:"proposed"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return selection{}, ErrIntegrity
	}
	versions := func(side sideShape) map[string]string {
		values := map[string]string{}
		for _, identity := range side.Components {
			values[identity.Component] = identity.Version
		}
		return values
	}
	current, proposed := versions(input.Current), versions(input.Proposed)
	family := make([]json.RawMessage, 0)
	matched := make([]json.RawMessage, 0)
	verdicts := 0
	for _, entry := range b.pack.Entries {
		if entry.Project != project || entry.deferred != nil {
			continue
		}
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return selection{}, ErrIntegrity
		}
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			return selection{}, ErrIntegrity
		}
		declared, chartHop := charts[subject.Component]
		if !chartHop {
			continue
		}
		conditions := shape.conditions()
		inFamily := true
		for _, condition := range conditions {
			inFamily = inFamily && allowed[condition.FactID]
		}
		if !inFamily {
			continue
		}
		if subject.Chart == nil {
			// An application rule of the family: selected so that it is
			// reported undetermined, never counted as a matching verdict.
			if len(conditions) == 0 {
				continue
			}
			family = append(family, entry.Rule)
			matched = append(matched, entry.Rule)
			continue
		}
		if !subject.AdmitsChart(&declared) {
			continue
		}
		family = append(family, entry.Rule)
		from, to := current[subject.Component], proposed[subject.Component]
		if subject.Match(from, to) == constraintengine.MatchNone {
			continue
		}
		matched = append(matched, entry.Rule)
		notice, err := isVerdictNeutralRule(entry.Rule)
		if err != nil {
			return selection{}, ErrIntegrity
		}
		if !notice {
			verdicts++
		}
	}
	if verdicts == 0 {
		return b.admit(b.chartFallbackRules(family, matched), nil)
	}
	return b.admit(matched, nil)
}

// chartFallbackRules is the fallback of a chart selection: every family rule
// except a lead for another transition that the trust policy leaves out
// anyway, as in fallbackRules.
func (b bundle) chartFallbackRules(candidates, matched []json.RawMessage) []json.RawMessage {
	matching := make(map[string]bool, len(matched))
	for _, rule := range matched {
		matching[string(rule)] = true
	}
	kept := make([]json.RawMessage, 0, len(candidates))
	for _, rule := range candidates {
		if !matching[string(rule)] && !b.policy.Admits(constraintengine.BasisLead) {
			if basis, err := constraintengine.RawRuleBasis(rule); err == nil && basis == constraintengine.BasisLead {
				continue
			}
		}
		kept = append(kept, rule)
	}
	return kept
}
