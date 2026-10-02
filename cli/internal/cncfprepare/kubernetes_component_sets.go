// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Set-valued facts of the component-configuration adapter. For each
// control-plane and node component the adapter can declare two sets:
//
//   - the feature gates the component sets at all, through --feature-gates or
//     a configuration document's featureGates map. A gate set to false is
//     still set: a component rejects an unrecognised gate at startup
//     whatever value it is given;
//   - the long command-line options the component is given.
//
// A set is declared complete only when the caller declared the component's
// scope complete and every source in it was resolved (the same rule the bool
// predicates use for absence). The sets over-approximate: every token that
// spells a long option counts, even one another option might consume as its
// value, so a removed spelling is never missed. A name the engine cannot
// represent as a set member is dropped and the set is marked incomplete; a
// set larger than the engine bound is declared unsupported.
//
// Like the bool predicates, a set fact is emitted only when the active
// knowledge declares it, and a published forbid_set_member rule decides it.

const (
	k8sSetKindFeatureGates = "feature_gates"
	k8sSetKindFlags        = "flags"

	// ReasonKubernetesComponentSettingSetsComplete reports a preparation
	// that declared only setting sets, every one of them complete. Which
	// members a rule forbids is decided by the rule, not by preparation.
	ReasonKubernetesComponentSettingSetsComplete Reason = "KUBERNETES_COMPONENT_SETTING_SETS_COMPLETE"
)

type k8sSetFact struct {
	Fact  string
	Scope string
	Kind  string
}

// k8sComponentSetFacts is the adapter's set-fact table, one fact per
// component and kind. Fact identifiers are stable public names.
var k8sComponentSetFacts = func() []k8sSetFact {
	scopes := []struct{ scope, slug string }{
		{K8sScopeAPIServer, "kube_apiserver"},
		{K8sScopeControllerManager, "kube_controller_manager"},
		{K8sScopeScheduler, "kube_scheduler"},
		{K8sScopeKubelet, "kubelet"},
		{K8sScopeKubeProxy, "kube_proxy"},
	}
	facts := make([]k8sSetFact, 0, 2*len(scopes))
	for _, scope := range scopes {
		for _, kind := range []string{k8sSetKindFeatureGates, k8sSetKindFlags} {
			facts = append(facts, k8sSetFact{Fact: "component.kubernetes." + scope.slug + "_" + kind + "_set", Scope: scope.scope, Kind: kind})
		}
	}
	return facts
}()

// KubernetesComponentConfigSetFacts returns every set fact the adapter
// defines, in table order.
func KubernetesComponentConfigSetFacts() []string {
	facts := make([]string, 0, len(k8sComponentSetFacts))
	for _, set := range k8sComponentSetFacts {
		facts = append(facts, set.Fact)
	}
	return facts
}

// members returns the sorted member names of one set and whether the set is
// complete, or ok=false when it exceeds the engine bound.
func (m *k8sComponentModel) members(set k8sSetFact) (members []string, complete, ok bool) {
	names := map[string]bool{}
	resolved := false
	switch set.Kind {
	case k8sSetKindFeatureGates:
		var gates map[string][]k8sGateValue
		gates, resolved = m.gates(set.Scope)
		for name, occurrences := range gates {
			if len(occurrences) > 0 {
				names[name] = true
			}
		}
	case k8sSetKindFlags:
		var flags []k8sFlag
		flags, resolved = m.flags(set.Scope)
		for _, flag := range flags {
			names[flag.name] = true
		}
	}
	complete = resolved && m.allComplete([]string{set.Scope})
	members = make([]string, 0, len(names))
	for name := range names {
		if !constraintengine.ValidSetMember(name) {
			complete = false
			continue
		}
		members = append(members, name)
	}
	if len(members) > constraintengine.MaxSetMembers {
		return nil, false, false
	}
	sort.Strings(members)
	return members, complete, true
}

func setFact(id string, members []string, complete bool) inputFact {
	return inputFact{ID: id, State: "declared", SetValue: &inputSetValue{Members: members, Complete: complete}}
}
