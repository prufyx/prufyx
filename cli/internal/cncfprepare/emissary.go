// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strconv"
	"unicode/utf8"
)

// Emissary 4.0.1 removes diagd's extra metrics endpoint option. This adapter
// accepts only a caller-declared direct diagd argv and never executes it or
// inspects a wrapper, environment, Helm values, or runtime.
const (
	EmissaryComponent = "pkg:github/emissary-ingress/emissary"
	EmissaryFact      = "component.emissary.removed_metrics_endpoint_present"
	EmissaryFrom      = "3.10.0"
	EmissaryTo        = "4.0.1"
)

const (
	ReasonEmissaryMetricsPresent   Reason = "EMISSARY_REMOVED_METRICS_ENDPOINT_PRESENT"
	ReasonEmissaryMetricsAbsent    Reason = "EMISSARY_REMOVED_METRICS_ENDPOINT_ABSENT"
	ReasonEmissaryArgumentsUnknown Reason = "EMISSARY_ARGUMENTS_UNRESOLVED"
	ReasonEmissaryUnsupportedPair  Reason = "EMISSARY_UNSUPPORTED_VERSION_PAIR"
)

func PrepareEmissary(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) ||
		!validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	argv, argvOK := emissaryStringArray(value)
	state, reason := StateUnknown, ReasonEmissaryArgumentsUnknown
	factState := "missing"
	var factValue *bool
	if from != EmissaryFrom || to != EmissaryTo {
		reason = ReasonEmissaryUnsupportedPair
	} else if argvOK {
		present, recognized := inspectEmissaryArgv(argv)
		if recognized {
			factState = "declared"
			factValue = &present
			state = StatePrepared
			if present {
				reason = ReasonEmissaryMetricsPresent
			} else {
				reason = ReasonEmissaryMetricsAbsent
			}
		}
	}
	canonical, err := marshalComponentInput(EmissaryComponent, from, to, []inputFact{{ID: EmissaryFact, State: factState, BoolValue: factValue}})
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
			"DIRECT_ARGV_IS_CALLER_DECLARED_NOT_EXECUTED",
			"WRAPPERS_ENVIRONMENT_HELM_VALUES_AND_RUNTIME_NOT_EVALUATED",
			"BANNER_ENDPOINT_DEFAULT_CHANGE_NOT_CHECKED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func emissaryStringArray(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 256 {
		return nil, false
	}
	argv := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, false
		}
		argv[i] = text
	}
	return argv, true
}

// inspectEmissaryArgv recognizes a deliberately small direct-argv surface.
// Unknown option-looking tokens remain unresolved so an omitted flag cannot be
// mistaken for a complete effective invocation. Everything after -- is opaque.
func inspectEmissaryArgv(argv []string) (present, recognized bool) {
	if len(argv) == 0 || argv[0] != "diagd" {
		return false, false
	}
	positionals := 0
	for i := 1; i < len(argv); i++ {
		token := argv[i]
		if token == "--" {
			return present, true
		}
		if token == "--metrics-endpoint" {
			if i+1 >= len(argv) || argv[i+1] == "" || argv[i+1][0] == '-' {
				return false, false
			}
			return true, true
		}
		if token != "" && token[0] == '-' {
			name, value, hasValue := splitEmissaryOption(token)
			if name == "--metrics-endpoint" {
				if !hasValue {
					return false, false
				}
				return true, true
			}
			if emissaryStringValueOptions[name] {
				if hasValue {
					if value == "" {
						return false, false
					}
					continue
				}
				if i+1 >= len(argv) || argv[i+1] == "" {
					return false, false
				}
				i++
				continue
			}
			if emissaryIntValueOptions[name] {
				if hasValue {
					if _, err := strconv.Atoi(value); value == "" || err != nil {
						return false, false
					}
					continue
				}
				if i+1 >= len(argv) || argv[i+1] == "" {
					return false, false
				}
				if _, err := strconv.Atoi(argv[i+1]); err != nil {
					return false, false
				}
				i++
				continue
			}
			if emissaryBoolOptions[name] && !hasValue {
				continue
			}
			return false, false
		}
		positionals++
		if positionals > 3 {
			return false, false
		}
	}
	return present, true
}

var emissaryStringValueOptions = map[string]bool{
	"--config-path": true, "--kick": true, "--banner-endpoint": true,
	"--host": true, "--notices": true,
}

var emissaryIntValueOptions = map[string]bool{
	"--ambex-pid": true, "--workers": true, "--port": true,
	"--validation-retries": true,
}

var emissaryBoolOptions = map[string]bool{
	"--k8s": true, "--no-checks": true, "--no-envoy": true, "--reload": true,
	"--debug": true, "--dev-magic": true, "--verbose": true,
	"--allow-fs-commands": true, "--report-action-keys": true, "--help": true,
}

func splitEmissaryOption(token string) (name, value string, hasValue bool) {
	for i := 0; i < len(token); i++ {
		if token[i] == '=' {
			return token[:i], token[i+1:], true
		}
	}
	return token, "", false
}
