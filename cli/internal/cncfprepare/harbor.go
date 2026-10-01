// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	HarborComponent = "pkg:github/goharbor/harbor"
	HarborFact      = "component.harbor.installer_with_chartmuseum_present"
	HarborFrom      = "2.7.0"
	HarborTo        = "2.8.0"
	HarborAPI       = "prufyx.io/harbor-installer-argv/v1alpha1"
	HarborKind      = "HarborInstallerArguments"
)

var harborChartMuseumPairs = map[string]string{
	HarborFrom: "2.8.0",
	"2.10.3":   "2.15.2",
	"2.11.2":   "2.15.2",
	"2.12.4":   "2.15.2",
	"2.13.5":   "2.15.2",
	"2.14.4":   "2.15.2",
}

const (
	ReasonHarborArgvWitness      Reason = "HARBOR_INSTALLER_CHARTMUSEUM_FLAG_PRESENT"
	ReasonHarborArgvNoWitness    Reason = "HARBOR_INSTALLER_CHARTMUSEUM_FLAG_ABSENT"
	ReasonHarborAuthorityMissing Reason = "EFFECTIVE_ARGV_DECLARATION_MISSING"
	ReasonHarborUnsupportedPair  Reason = "UNSUPPORTED_VERSION_PAIR"
	ReasonHarborArgvUnsupported  Reason = "EFFECTIVE_ARGV_UNSUPPORTED"
)

// PrepareHarbor derives one bounded fact from a caller-selected, complete
// Harbor make/install.sh argv declaration. It does not execute the installer,
// resolve wrappers or environment/configuration, or inspect chart/database
// state. A false fact is emitted only for a fully modeled literal vector.
func PrepareHarbor(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "effectiveArgvDeclared": true, "argv": true}) != nil {
		return Prepared{}, ErrInvalid
	}
	if api, ok := root["apiVersion"].(string); !ok || api != HarborAPI {
		return Prepared{}, ErrInvalid
	}
	if kind, ok := root["kind"].(string); !ok || kind != HarborKind {
		return Prepared{}, ErrInvalid
	}
	declared := false
	if rawDeclared, exists := root["effectiveArgvDeclared"]; exists {
		var ok bool
		declared, ok = rawDeclared.(bool)
		if !ok {
			return Prepared{}, ErrInvalid
		}
	}
	items, ok := root["argv"].([]any)
	if !ok || len(items) > 256 {
		return Prepared{}, ErrInvalid
	}
	argv := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || len(text) > 4096 {
			return Prepared{}, ErrInvalid
		}
		argv[i] = text
	}

	fact := inputFact{ID: HarborFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonHarborAuthorityMissing
	if declared {
		reason = ReasonHarborArgvUnsupported
		if harborChartMuseumPairs[from] != to {
			reason = ReasonHarborUnsupportedPair
		} else if valid, present := inspectHarborArgv(argv, to); valid {
			value := present
			fact = inputFact{ID: HarborFact, State: "declared", BoolValue: &value}
			state = StatePrepared
			if present {
				reason = ReasonHarborArgvWitness
			} else {
				reason = ReasonHarborArgvNoWitness
			}
		}
	}
	canonical, err := marshalComponentInput(HarborComponent, from, to, []inputFact{fact})
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
			"EFFECTIVE_ARGV_OPERATOR_DECLARED_NOT_LIVE_OBSERVATION",
			"INSTALLER_WRAPPER_ENV_CONFIG_AND_RESPONSE_FILE_RESOLUTION_NOT_PERFORMED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectHarborArgv accepts only the literal, no-value options registered by
// the reviewed installer. --help is deliberately unsupported because the
// target exits before normal option processing; it cannot prove absence.
func inspectHarborArgv(argv []string, target string) (valid, present bool) {
	seen := map[string]bool{}
	for _, token := range argv {
		if token == "" || hasExpansion(token) || strings.IndexFunc(token, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return false, false
		}
		if token == "--help" || !strings.HasPrefix(token, "--") || strings.Contains(token, "=") {
			return false, false
		}
		name := strings.TrimPrefix(token, "--")
		if name == "" || seen[name] {
			return false, false
		}
		switch name {
		case "with-trivy":
		case "with-notary", "with-clair":
			if target != HarborTo {
				return false, false
			}
		case "with-chartmuseum":
			present = true
		default:
			return false, false
		}
		seen[name] = true
	}
	return true, present
}
