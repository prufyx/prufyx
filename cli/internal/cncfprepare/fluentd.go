// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	FluentDComponent    = "pkg:github/fluent/fluentd"
	FluentDFrom         = "1.17.1"
	FluentDTo           = "1.18.0"
	FluentDRiskFact     = "component.fluentd.literal_treatment_change_risk"
	FluentDCompleteFact = "component.fluentd.selected_value_complete"
	FluentDDefaultFact  = "component.fluentd.current_default_used"
	FluentDPreserveFact = "component.fluentd.preserve_literal_treatment"

	FluentDRubyComponent        = "pkg:generic/ruby"
	FluentDDistributionFact     = "component.fluentd.distribution"
	FluentDDistributionOfficial = "official_upstream"
	FluentDDistributionCustom   = "custom_build"
)

const (
	ReasonFluentDBlocked     Reason = "FLUENTD_LITERAL_TREATMENT_MAY_CHANGE"
	ReasonFluentDPass        Reason = "FLUENTD_LITERAL_TREATMENT_PRESERVED"
	ReasonFluentDIncomplete  Reason = "FLUENTD_LITERAL_DECLARATION_INCOMPLETE"
	ReasonFluentDUnsupported Reason = "FLUENTD_LITERAL_DECLARATION_UNSUPPORTED"
	ReasonFluentDPair        Reason = "FLUENTD_UNSUPPORTED_VERSION_PAIR"

	ReasonFluentDRubyTargetDeclared    Reason = "FLUENTD_RUBY_TARGET_DECLARED"
	ReasonFluentDRubyTargetUnsupported Reason = "FLUENTD_RUBY_TARGET_UNSUPPORTED"
)

// PrepareFluentD dispatches a raw caller declaration to the matching Fluentd
// adapter by input shape. The literal-treatment declaration always carries
// "current"/"proposed" keys; the Ruby-minimum-target declaration only ever
// carries "distribution" and/or "rubyVersion".
func PrepareFluentD(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalid
	}
	_, hasCurrent := object["current"]
	_, hasProposed := object["proposed"]
	_, hasDistribution := object["distribution"]
	_, hasRubyVersion := object["rubyVersion"]
	if !hasCurrent && !hasProposed && (hasDistribution || hasRubyVersion) {
		return PrepareFluentDRubyTarget(raw, from, to)
	}
	return PrepareFluentDLiteral(raw, from, to)
}

// PrepareFluentDRubyTarget accepts a caller declaration of the proposed
// Fluentd distribution and the operator's own proposed Ruby version target.
// It does not observe an installed Ruby interpreter, package, or plugin; the
// Ruby version is an operator declaration for the already-reviewed minimum
// Ruby requirement rules, never inferred from any environment or runtime.
func PrepareFluentDRubyTarget(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok || allowFields(object, map[string]bool{"distribution": true, "rubyVersion": true}) != nil {
		return Prepared{}, ErrInvalid
	}
	distribution, distributionPresent := "", false
	if v, exists := object["distribution"]; exists {
		text, ok := v.(string)
		if !ok {
			return Prepared{}, ErrInvalid
		}
		distribution, distributionPresent = text, true
	}
	rubyVersion, rubyPresent := "", false
	if v, exists := object["rubyVersion"]; exists {
		text, ok := v.(string)
		if !ok {
			return Prepared{}, ErrInvalid
		}
		rubyVersion, rubyPresent = text, true
	}
	validDistribution := distributionPresent && (distribution == FluentDDistributionOfficial || distribution == FluentDDistributionCustom)
	validRuby := rubyPresent && validVersionSyntax(rubyVersion)
	fact := inputFact{ID: FluentDDistributionFact, State: "unsupported"}
	if validDistribution {
		fact = inputFact{ID: FluentDDistributionFact, State: "declared", EnumValue: distribution}
	}
	proposed := make([]inputComponent, 0, 2)
	if validRuby {
		proposed = append(proposed, inputComponent{Component: FluentDRubyComponent, Version: rubyVersion, Facts: []inputFact{}})
	}
	proposed = append(proposed, inputComponent{Component: FluentDComponent, Version: to, Facts: []inputFact{fact}})
	state, reason := StateUnknown, ReasonFluentDRubyTargetUnsupported
	if validDistribution && validRuby {
		state, reason = StatePrepared, ReasonFluentDRubyTargetDeclared
	}
	canonical, err := marshalFluentDRubyTarget(from, proposed)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"RUBY_VERSION_IS_CALLER_DECLARED_NOT_OBSERVED",
		"CUSTOM_PACKAGING_PLUGINS_AND_RUNTIME_BEHAVIOR_NOT_VERIFIED",
	}}, nil
}

func marshalFluentDRubyTarget(from string, proposed []inputComponent) ([]byte, error) {
	input := inputEnvelope{
		Schema:    InputSchema,
		Authority: InputAuthority,
		Current:   inputSide{Components: []inputComponent{{Component: FluentDComponent, Version: from, Facts: []inputFact{}}}},
		Proposed:  inputSide{Components: proposed},
	}
	compact, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return append(compact, '\n'), nil
}

// PrepareFluentDLiteral accepts a deliberately small declaration around two
// selected classic-config literal values. It does not parse a Fluentd file or
// Ruby and retains only the marker-presence fact.
func PrepareFluentDLiteral(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 5 {
		return Prepared{}, ErrInvalid
	}
	for key := range object {
		if key != "current" && key != "proposed" && key != "selectedValueComplete" && key != "currentDefaultUsed" && key != "preserveLiteralTreatment" {
			return Prepared{}, ErrInvalid
		}
	}
	current, ok1 := object["current"].(string)
	proposed, ok2 := object["proposed"].(string)
	complete, ok3 := object["selectedValueComplete"].(bool)
	defaultUsed, ok4 := object["currentDefaultUsed"].(bool)
	preserve, ok5 := object["preserveLiteralTreatment"].(bool)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return Prepared{}, ErrInvalid
	}
	canonicalFacts := []inputFact{
		{ID: FluentDDefaultFact, State: "unsupported"},
		{ID: FluentDRiskFact, State: "unsupported"},
		{ID: FluentDPreserveFact, State: "unsupported"},
		{ID: FluentDCompleteFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonFluentDUnsupported
	if !complete || !defaultUsed || !preserve {
		reason = ReasonFluentDIncomplete
	} else {
		currentMarker, currentOK := fluentDLiteralMarker(current)
		_, proposedOK := fluentDLiteralMarker(strings.Trim(proposed, "'"))
		wrapper := len(proposed) == len(current)+2 && strings.HasPrefix(proposed, "'") && strings.HasSuffix(proposed, "'") && proposed[1:len(proposed)-1] == current
		if !currentOK || (!proposedOK && !wrapper) || (proposedOK && !wrapper && proposed != current) {
			reason = ReasonFluentDUnsupported
		} else if from != FluentDFrom || to != FluentDTo {
			reason = ReasonFluentDPair
		} else {
			state = StatePrepared
			for _, i := range []int{0, 2, 3} {
				canonicalFacts[i].State = "declared"
				v := true
				canonicalFacts[i].BoolValue = &v
			}
			risk := currentMarker > 0 && !wrapper
			canonicalFacts[1] = inputFact{ID: FluentDRiskFact, State: "declared", BoolValue: &risk}
			if risk {
				reason = ReasonFluentDBlocked
			} else {
				reason = ReasonFluentDPass
			}
		}
	}
	canonical, err := marshalComponentInput(FluentDComponent, from, to, canonicalFacts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"SELECTED_CLASSIC_CONFIG_LITERAL_VALUES_NOT_RETAINED",
		"ONLY_ONE_SELECTED_LITERAL_DECLARATION_IS_SUPPORTED",
		"RUBY_INTERPOLATION_IS_NOT_PARSED_OR_EXECUTED",
		"INCLUDES_ENVIRONMENT_VARIABLES_AND_RUNTIME_BEHAVIOR_REMAIN_UNRESOLVED",
	}}, nil
}

// fluentDLiteralMarker validates the complete selected JSON literal and
// returns the number of simple interpolation markers found (0 or 1).
func fluentDLiteralMarker(raw string) (int, bool) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\\'$\uFFFD") || !utf8.ValidString(raw) || !json.Valid([]byte(raw)) {
		return 0, false
	}
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return 0, false
	}
	if _, ok := strictLiteralJSON([]byte(raw)); !ok {
		return 0, false
	}
	markers := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for i < len(raw) && raw[i] != '"' {
			if raw[i] == '#' && i+1 < len(raw) && raw[i+1] == '{' {
				end := strings.IndexByte(raw[i+2:], '}')
				if end < 1 {
					return 0, false
				}
				body := raw[i+2 : i+2+end]
				for _, c := range body {
					if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_ +*/().-", c)) {
						return 0, false
					}
				}
				markers++
				if markers > 1 {
					return 0, false
				}
				i += 2 + end
			}
			i++
		}
		if i >= len(raw) {
			return 0, false
		}
	}
	return markers, true
}

func strictLiteralJSON(raw []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() (any, bool)
	walk = func() (any, bool) {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		switch d := token.(type) {
		case json.Delim:
			if d == '{' {
				obj := map[string]any{}
				seen := map[string]bool{}
				for decoder.More() {
					kt, e := decoder.Token()
					if e != nil {
						return nil, false
					}
					key, ok := kt.(string)
					if !ok || seen[key] {
						return nil, false
					}
					seen[key] = true
					v, ok := walk()
					if !ok {
						return nil, false
					}
					obj[key] = v
				}
				if _, err := decoder.Token(); err != nil {
					return nil, false
				}
				return obj, true
			}
			if d == '[' {
				var arr []any
				for decoder.More() {
					v, ok := walk()
					if !ok {
						return nil, false
					}
					arr = append(arr, v)
				}
				if _, err := decoder.Token(); err != nil {
					return nil, false
				}
				return arr, true
			}
			return nil, false
		default:
			return token, true
		}
	}
	v, ok := walk()
	if !ok {
		return nil, false
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, false
	}
	return v, true
}
