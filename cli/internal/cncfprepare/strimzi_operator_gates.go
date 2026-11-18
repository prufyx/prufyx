// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Strimzi Cluster Operator feature gates. One caller-supplied rendered
// Cluster Operator Deployment is read for exactly one thing: the literal value
// of the STRIMZI_FEATURE_GATES environment variable of the container named
// strimzi-cluster-operator. Only the gate names parsed from that value are
// kept. No other environment entry, envFrom source, argument, container,
// Secret, ConfigMap or object content is read into the output, and no raw
// value or token is ever echoed in a reason, an omission or an error.
const (
	StrimziOperatorGatesFact = "component.strimzi.cluster_operator_feature_gates_set"

	StrimziOperatorGatesFrom   = "0.41.0"
	StrimziOperatorGatesTo     = "0.44.0"
	StrimziOperatorGatesRuleID = "strimzi.feature-gate-usekraft-removed.0-44"

	strimziOperatorContainer = "strimzi-cluster-operator"
	strimziFeatureGatesEnv   = "STRIMZI_FEATURE_GATES"
	strimziGatesMaxValue     = 4096
)

const (
	ReasonStrimziOperatorGatesDeclared Reason = "STRIMZI_OPERATOR_FEATURE_GATES_DECLARED"
	ReasonStrimziOperatorGatesAbsent   Reason = "STRIMZI_OPERATOR_FEATURE_GATES_ABSENT_UNDECLARED"
	ReasonStrimziOperatorEnvFrom       Reason = "STRIMZI_OPERATOR_ENV_MAY_COME_FROM_ENVFROM"
	ReasonStrimziOperatorUnresolved    Reason = "STRIMZI_OPERATOR_DEPLOYMENT_SHAPE_UNRESOLVED"
	ReasonStrimziOperatorTemplated     Reason = "STRIMZI_OPERATOR_DEPLOYMENT_RENDERING_UNRESOLVED"
)

// StrimziKnownGates041 and StrimziKnownGates044 are the feature gate names
// the Cluster Operator accepts, from the FeatureGates source at the pinned
// releases (case exact; any other name makes the operator refuse to start).
//
//	0.41.0 = 12cff8da6eb52031120ae78911ee968bd116c8ef,
//	  cluster-operator/src/main/java/io/strimzi/operator/cluster/FeatureGates.java
//	  L19-20 (names), L36 (accepted syntax), L46-55 (switch; default throws).
//	0.44.0 = 7e49e5fb5c01cb001476b82710dcb954c038fc08,
//	  operator-common/src/main/java/io/strimzi/operator/common/featuregates/FeatureGates.java
//	  L21 (name), L36 (accepted syntax), L46-52 (switch; default throws).
//	  The value defaults to "" when the variable is absent:
//	  cluster-operator/src/main/java/io/strimzi/operator/cluster/ClusterOperatorConfig.java L191.
var (
	StrimziKnownGates041 = []string{"ContinueReconciliationOnManualRollingUpdateFailure", "UseKRaft"}
	StrimziKnownGates044 = []string{"ContinueReconciliationOnManualRollingUpdateFailure"}
)

// strimziOperatorPair is the one reviewed transition; the match goes through
// the engine's own transition matcher.
var strimziOperatorPair = constraintengine.RuleTransition{Component: StrimziComponent, From: StrimziOperatorGatesFrom, To: StrimziOperatorGatesTo}

// strimziGatesSyntax is the Java regular expression the operator applies to
// the whole value (String.matches), at 0.41.0 and 0.44.0 alike:
//
//	(\s*[+-][a-zA-Z0-9]+\s*,)*\s*[+-][a-zA-Z0-9]+\s*
//
// Java's \s is [ \t\n\x0B\f\r]. The prefix is mandatory: a bare name does
// not match, so it is never read as a gate.
const javaSpace = `[ \t\n\x0B\f\r]`

var (
	strimziGatesSyntax = regexp.MustCompile(`^(?:` + javaSpace + `*[+-][a-zA-Z0-9]+` + javaSpace + `*,)*` + javaSpace + `*[+-][a-zA-Z0-9]+` + javaSpace + `*$`)
	strimziGatesBlank  = regexp.MustCompile(`^` + javaSpace + `*$`)
)

// PrepareStrimziOperatorDeployment declares the feature-gate set of one
// caller-supplied rendered Cluster Operator Deployment for the reviewed
// 0.41.0 -> 0.44.0 hop. The Deployment is assumed to be the proposed
// operator; its image is not checked. envComplete is the caller's
// declaration that, when the variable is absent, no other mechanism
// supplies it; it never overrides a non-empty envFrom.
func PrepareStrimziOperatorDeployment(raw []byte, from, to, distribution string, envComplete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) {
		return Prepared{}, ErrInvalid
	}
	// Facts are in ascending id order, as the engine requires.
	facts := []inputFact{
		{ID: StrimziOperatorGatesFact, State: "missing"},
		{ID: StrimziDistributionFact, State: "missing"},
	}
	if distribution == StrimziDistributionOfficial || distribution == StrimziDistributionCustom {
		facts[1] = inputFact{ID: StrimziDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonStrimziGuardUnresolved
	switch {
	case !strimziOperatorPair.IsAnchor(from, to):
		reason = ReasonStrimziPairUnsupported
	case facts[1].State != "declared":
		reason = ReasonStrimziGuardUnresolved
	default:
		inspected := inspectStrimziOperatorDeployment(raw, envComplete)
		reason = inspected.Reason
		if inspected.Set != nil {
			facts[0] = inputFact{ID: StrimziOperatorGatesFact, State: "declared", SetValue: inspected.Set}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(StrimziComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"OPERATOR_DEPLOYMENT_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"ONLY_STRIMZI_FEATURE_GATES_ENV_LITERAL_READ_NO_OTHER_ENV_ENVFROM_ARGS_SECRET_OR_CONFIGMAP",
			"OPERATOR_IMAGE_AND_VERSION_NOT_CHECKED_DEPLOYMENT_ASSUMED_TO_BE_THE_PROPOSED_OPERATOR",
			"OTHER_FEATURE_GATES_AND_OPERATOR_CONFIGURATION_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

type strimziOperatorInspection struct {
	Set    *inputSetValue
	Reason Reason
}

func inspectStrimziOperatorDeployment(raw []byte, envComplete bool) strimziOperatorInspection {
	unresolved := strimziOperatorInspection{Reason: ReasonStrimziOperatorUnresolved}
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return strimziOperatorInspection{Reason: ReasonStrimziOperatorTemplated}
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return unresolved
	}
	root, ok := value.(map[string]any)
	if !ok {
		return unresolved
	}
	if api, kind, ok := kubernetesGVK(root); !ok || api != "apps/v1" || kind != "Deployment" {
		return unresolved
	}
	spec, _ := root["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	containers, ok := podSpec["containers"].([]any)
	if !ok {
		return unresolved
	}
	var operator map[string]any
	for _, entry := range containers {
		container, ok := entry.(map[string]any)
		if !ok {
			return unresolved
		}
		name, ok := container["name"].(string)
		if !ok {
			return unresolved
		}
		if name != strimziOperatorContainer {
			continue
		}
		if operator != nil {
			return unresolved
		}
		operator = container
	}
	if operator == nil {
		return unresolved
	}
	// Only the name of each env entry is looked at; its value is read for the
	// one reviewed variable and for nothing else.
	var gates map[string]any
	if rawEnv, present := operator["env"]; present {
		env, ok := rawEnv.([]any)
		if !ok {
			return unresolved
		}
		for _, entry := range env {
			item, ok := entry.(map[string]any)
			if !ok {
				return unresolved
			}
			name, ok := item["name"].(string)
			if !ok {
				return unresolved
			}
			if name != strimziFeatureGatesEnv {
				continue
			}
			if gates != nil {
				return unresolved
			}
			gates = item
		}
	}
	if gates == nil {
		// Absent variable: the operator reads "" (no gates) only when nothing
		// else can supply it. envFrom can, and its content is never read.
		if rawFrom, present := operator["envFrom"]; present {
			from, ok := rawFrom.([]any)
			if !ok {
				return unresolved
			}
			if len(from) != 0 {
				return strimziOperatorInspection{Reason: ReasonStrimziOperatorEnvFrom}
			}
		}
		if !envComplete {
			return strimziOperatorInspection{Reason: ReasonStrimziOperatorGatesAbsent}
		}
		return strimziOperatorInspection{Set: &inputSetValue{Members: []string{}, Complete: true}, Reason: ReasonStrimziOperatorGatesDeclared}
	}
	if _, indirect := gates["valueFrom"]; indirect {
		return unresolved
	}
	literal, ok := gates["value"].(string)
	if !ok || len(literal) > strimziGatesMaxValue {
		return unresolved
	}
	set := parseStrimziFeatureGates(literal)
	if set == nil {
		return unresolved
	}
	return strimziOperatorInspection{Set: set, Reason: ReasonStrimziOperatorGatesDeclared}
}

// parseStrimziFeatureGates applies the operator's own syntax to the whole
// value. A blank value is the empty complete set. A value that does not match
// is not a configuration the operator accepts: it yields an incomplete empty
// set and no member, so a bare or malformed name can never block. A matching
// value yields its names, complete only when every name is one the operator
// knows at 0.41.0 or 0.44.0 (any other name is an unreviewed sibling). A
// name that is not a valid set member or a set beyond the engine bound
// returns nil (unsupported).
func parseStrimziFeatureGates(value string) *inputSetValue {
	if strimziGatesBlank.MatchString(value) {
		return &inputSetValue{Members: []string{}, Complete: true}
	}
	if !strimziGatesSyntax.MatchString(value) {
		return &inputSetValue{Members: []string{}, Complete: false}
	}
	seen := map[string]bool{}
	complete := true
	for _, token := range strings.Split(value, ",") {
		name := strings.Trim(token, " \t\n\x0B\f\r")[1:]
		if !constraintengine.ValidSetMember(name) {
			return nil
		}
		if !slices.Contains(StrimziKnownGates041, name) && !slices.Contains(StrimziKnownGates044, name) {
			complete = false
		}
		seen[name] = true
	}
	if len(seen) > constraintengine.MaxSetMembers {
		return nil
	}
	members := make([]string, 0, len(seen))
	for name := range seen {
		members = append(members, name)
	}
	sort.Strings(members)
	return &inputSetValue{Members: members, Complete: complete}
}
