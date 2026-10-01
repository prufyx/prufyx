// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const (
	OpenFGAComponent = "pkg:github/openfga/openfga"
	OpenFGAFact      = "component.openfga.oidc_required_fields_missing"
	OpenFGAFrom      = "1.17.1"
	OpenFGATo        = "1.18.0"
)

const (
	ReasonOpenFGAMissing     Reason = "OPENFGA_OIDC_REQUIRED_FIELDS_MISSING"
	ReasonOpenFAPresent      Reason = "OPENFGA_OIDC_REQUIRED_FIELDS_PRESENT"
	ReasonOpenFGAIncomplete  Reason = "OPENFGA_EFFECTIVE_CONFIG_INCOMPLETE"
	ReasonOpenFGAUnsupported Reason = "OPENFGA_EFFECTIVE_CONFIG_UNSUPPORTED"
	ReasonOpenFGAPair        Reason = "OPENFGA_UNSUPPORTED_VERSION_PAIR"
)

// PrepareOpenFGAOIDC reads a native-shaped JSON projection of OpenFGA's
// effective configuration. The caller must explicitly attest that file,
// environment, and flag precedence was resolved before this function is
// called; this preparer never reads those other sources.
func PrepareOpenFGAOIDC(raw []byte, from, to string, effectiveComplete *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	caseAmbiguous, err := openFGARelevantCaseAmbiguity(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	var value any
	if !caseAmbiguous {
		value, err = decodeStrictAllowNull(raw)
		if err != nil {
			return Prepared{}, ErrInvalid
		}
	}
	missing := true
	state, reason := StateUnknown, ReasonOpenFGAUnsupported
	pairSupported := from == OpenFGAFrom && to == OpenFGATo
	if effectiveComplete == nil || !*effectiveComplete {
		reason = ReasonOpenFGAIncomplete
	} else if caseAmbiguous {
		reason = ReasonOpenFGAUnsupported
	} else if method, issuer, audience, ok := openFGAFields(value); ok && method == "oidc" {
		missing = issuer == "" || audience == ""
		state = StatePrepared
		if !pairSupported {
			reason = ReasonOpenFGAPair
		} else if missing {
			reason = ReasonOpenFGAMissing
		} else {
			reason = ReasonOpenFAPresent
		}
	} else if !pairSupported {
		reason = ReasonOpenFGAPair
	}
	fact := inputFact{ID: OpenFGAFact, State: "unsupported"}
	if state == StatePrepared {
		fact.State = "declared"
		fact.BoolValue = &missing
	}
	canonical, err := marshalComponentInput(OpenFGAComponent, from, to, []inputFact{fact})
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
			"EFFECTIVE_CONFIG_COMPLETENESS_IS_CALLER_DECLARED",
			"FILE_ENVIRONMENT_AND_FLAG_PRECEDENCE_NOT_RESOLVED_HERE",
			"ISSUER_AND_AUDIENCE_VALUES_NOT_RETAINED",
			"NO_SERVER_STARTUP_TOKEN_OR_RUNTIME_VALIDATION",
		},
	}, nil
}

func openFGAFields(value any) (method, issuer, audience string, ok bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return "", "", "", false
	}
	authnValue, present := root["authn"]
	if !present {
		return "", "", "", false
	}
	authn, ok := authnValue.(map[string]any)
	if !ok {
		return "", "", "", false
	}
	method, ok = authn["method"].(string)
	if !ok {
		return "", "", "", false
	}
	if method != "oidc" {
		return method, "", "", true
	}
	oidcValue, present := authn["oidc"]
	if !present {
		return method, "", "", true
	}
	oidc, ok := oidcValue.(map[string]any)
	if !ok {
		return "", "", "", false
	}
	issuerValue, issuerPresent := oidc["issuer"]
	audienceValue, audiencePresent := oidc["audience"]
	if issuerPresent {
		issuer, ok = issuerValue.(string)
		if !ok {
			return "", "", "", false
		}
	}
	if audiencePresent {
		audience, ok = audienceValue.(string)
		if !ok {
			return "", "", "", false
		}
	}
	return method, issuer, audience, true
}

// decodeStrict rejects case-insensitive duplicate keys globally. Before that
// strict parse, this scanner distinguishes a selected OpenFGA key ambiguity
// so it can remain an unresolved fact rather than an accidental assertion.
func openFGARelevantCaseAmbiguity(raw []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	ambiguous := false
	var walk func([]string) error
	walk = func(path []string) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch delimiter := token.(type) {
		case json.Delim:
			switch delimiter {
			case '{':
				seen := map[string]string{}
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return err
					}
					key, ok := keyToken.(string)
					if !ok || key == "" {
						return ErrInvalid
					}
					folded := strings.ToLower(key)
					if openFGARelevantKey(path, key) && !openFGACanonicalKey(path, key) {
						ambiguous = true
					}
					if prior, exists := seen[folded]; exists {
						if prior == key {
							return ErrInvalid
						}
						if openFGARelevantPath(path, folded) {
							ambiguous = true
						}
					}
					seen[folded] = key
					if err := walk(append(path, key)); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			case '[':
				for decoder.More() {
					if err := walk(path); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			default:
				return ErrInvalid
			}
		default:
			return nil
		}
	}
	if err := walk(nil); err != nil {
		return false, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return false, ErrInvalid
	}
	return ambiguous, nil
}

func openFGARelevantPath(path []string, folded string) bool {
	if len(path) == 0 {
		return folded == "authn"
	}
	if len(path) == 1 && strings.EqualFold(path[0], "authn") {
		return folded == "method" || folded == "oidc"
	}
	return len(path) == 2 && strings.EqualFold(path[0], "authn") && strings.EqualFold(path[1], "oidc") && (folded == "issuer" || folded == "audience")
}

func openFGARelevantKey(path []string, key string) bool {
	if strings.Contains(key, ".") {
		folded := strings.ToLower(key)
		switch len(path) {
		case 0:
			return folded == "authn.method" || folded == "authn.oidc" || folded == "authn.oidc.issuer" || folded == "authn.oidc.audience"
		case 1:
			return strings.EqualFold(path[0], "authn") && (folded == "oidc.issuer" || folded == "oidc.audience")
		case 2:
			return strings.EqualFold(path[0], "authn") && strings.EqualFold(path[1], "oidc") && (folded == "issuer" || folded == "audience")
		}
	}
	return (len(path) == 0 && strings.EqualFold(key, "authn")) ||
		(len(path) == 1 && strings.EqualFold(path[0], "authn") && (strings.EqualFold(key, "method") || strings.EqualFold(key, "oidc"))) ||
		(len(path) == 2 && strings.EqualFold(path[0], "authn") && strings.EqualFold(path[1], "oidc") && (strings.EqualFold(key, "issuer") || strings.EqualFold(key, "audience")))
}

func openFGACanonicalKey(path []string, key string) bool {
	if len(path) == 0 {
		return key == "authn"
	}
	if len(path) == 1 && path[0] == "authn" {
		return key == "method" || key == "oidc"
	}
	return len(path) == 2 && path[0] == "authn" && path[1] == "oidc" && (key == "issuer" || key == "audience")
}
