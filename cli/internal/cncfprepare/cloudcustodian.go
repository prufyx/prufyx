// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Cloud Custodian 0.9.51 removes the json-diff filter from the IAM access-key
// resource. The adapter accepts one complete, caller-selected JSON policy and
// projects only whether that one policy directly contains the reviewed filter.
// It does not load YAML, resolve variables/includes, contact AWS, or retain
// policy names, resource names, filter values, or other private content.
const (
	CloudCustodianComponent = "pkg:github/cloud-custodian/cloud-custodian"
	CloudCustodianFact      = "component.cloud_custodian.iam_access_key_json_diff_present"
	CloudCustodianFrom      = "0.9.50"
	CloudCustodianTo        = "0.9.51"
	CloudCustodianLatestTo  = "0.9.52"
)

var cloudCustodianLatestOrigins = [...]string{"0.9.51", "0.9.50", "0.9.49", "0.9.48", "0.9.47"}

const (
	ReasonCloudCustodianJsonDiffPresent Reason = "CLOUD_CUSTODIAN_JSON_DIFF_PRESENT"
	ReasonCloudCustodianJsonDiffAbsent  Reason = "CLOUD_CUSTODIAN_JSON_DIFF_ABSENT"
	ReasonCloudCustodianUnsupported     Reason = "CLOUD_CUSTODIAN_POLICY_INPUT_UNSUPPORTED"
	ReasonCloudCustodianUnsupportedPair Reason = "CLOUD_CUSTODIAN_UNSUPPORTED_VERSION_PAIR"
)

// PrepareCloudCustodian derives the one boolean consumed by the bounded
// Cloud Custodian rule. A PREPARED false value means only that the selected
// complete policy has an empty filter list; it is not an absence assertion for
// other policies, variables, includes, or resource selection paths.
func PrepareCloudCustodian(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if to == CloudCustodianLatestTo && sourceContractDigest(cloudCustodianLatestSourceContract) != CloudCustodianLatestSourceContractDigest {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	state, reason := StateUnknown, ReasonCloudCustodianUnsupported
	var present bool
	if !cloudCustodianPairSupported(from, to) {
		reason = ReasonCloudCustodianUnsupportedPair
	} else if policy, ok := cloudCustodianPolicy(value); ok {
		if filters, ok := policy["filters"].([]any); ok {
			switch {
			case len(filters) == 0:
				state, present, reason = StatePrepared, false, ReasonCloudCustodianJsonDiffAbsent
			case len(filters) == 1 && cloudCustodianJsonDiff(filters[0]):
				state, present, reason = StatePrepared, true, ReasonCloudCustodianJsonDiffPresent
			}
		}
	}
	fact := inputFact{ID: CloudCustodianFact, State: "unsupported"}
	if state == StatePrepared {
		fact.State = "declared"
		fact.BoolValue = &present
	}
	canonical, err := marshalComponentInput(CloudCustodianComponent, from, to, []inputFact{fact})
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
			"ONE_CALLER_SELECTED_JSON_POLICY_ONLY",
			"VARIABLES_INCLUDES_AND_DYNAMIC_RESOURCE_SELECTION_NOT_RESOLVED",
			"AWS_API_POLICY_EXECUTION_AND_RUNTIME_NOT_PERFORMED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func cloudCustodianPairSupported(from, to string) bool {
	if from == CloudCustodianFrom && to == CloudCustodianTo {
		return true
	}
	if to != CloudCustodianLatestTo {
		return false
	}
	for _, origin := range cloudCustodianLatestOrigins {
		if from == origin {
			return true
		}
	}
	return false
}

func cloudCustodianPolicy(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	// Cloud Custodian's policy document has a deliberately narrow root here.
	// In particular, root-level vars/includes can change the selected policy
	// before evaluation and must not be silently ignored.
	for key := range root {
		if key != "policies" {
			return nil, false
		}
	}
	policies, ok := root["policies"].([]any)
	if !ok || len(policies) != 1 {
		return nil, false
	}
	policy, ok := policies[0].(map[string]any)
	if !ok {
		return nil, false
	}
	name, nameOK := policy["name"].(string)
	resource, resourceOK := policy["resource"].(string)
	if !nameOK || !validCloudCustodianLiteralName(name) || hasUnresolvedCloudCustodianValue(name) || !resourceOK || (resource != "iam-access-key" && resource != "aws.iam-access-key") {
		return nil, false
	}
	// Variables can replace the selected resource or filter values at runtime;
	// a policy containing them is outside this caller-selected static subset.
	if _, hasVariables := policy["vars"]; hasVariables {
		return nil, false
	}
	if _, ok := policy["filters"]; !ok {
		return nil, false
	}
	return policy, true
}

func validCloudCustodianLiteralName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name || strings.TrimSpace(name) == "" {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func cloudCustodianJsonDiff(value any) bool {
	filter, ok := value.(map[string]any)
	if !ok {
		return false
	}
	typeValue, typeOK := filter["type"].(string)
	selector, selectorOK := filter["selector"].(string)
	if !typeOK || typeValue != "json-diff" || !selectorOK || (selector != "previous" && selector != "date" && selector != "locked") {
		return false
	}
	if selectorValue, present := filter["selector_value"]; present {
		if selector != "date" {
			return false
		}
		value, ok := selectorValue.(string)
		if !ok || hasUnresolvedCloudCustodianValue(value) {
			return false
		}
	}
	for key := range filter {
		if key != "type" && key != "selector" && key != "selector_value" {
			return false
		}
	}
	return true
}

// Cloud Custodian resolves several substitution forms before policy
// execution. Braces are rejected in this static subset, covering ${...},
// {{...}}, and single-brace .format-style values without retaining them.
func hasUnresolvedCloudCustodianValue(value string) bool {
	return strings.ContainsAny(value, "{}")
}
