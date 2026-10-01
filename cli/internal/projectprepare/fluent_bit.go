// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bufio"
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	FluentBitProject    = "fluent-bit"
	FluentBitComponent  = "pkg:github/fluent/fluent-bit"
	FluentBitFrom       = "3.2.0"
	FluentBitTo         = "4.0.0"
	FluentBitFact       = "component.fluent_bit.proposed_http2_enabled"
	FluentBitTargetFact = "component.fluent_bit.target_required_http2_enabled"
)

var fluentBitHTTP2TargetPairs = map[string]bool{
	"3.2.10\x005.1.2": true,
	"4.0.14\x005.1.2": true,
	"4.1.2\x005.1.2":  true,
	"4.2.8\x005.1.2":  true,
	"5.0.10\x005.1.2": true,
}

const (
	fluentBitPreparedReason    = "FLUENT_BIT_HTTP2_SETTING_INSPECTED"
	fluentBitIncompleteReason  = "FLUENT_BIT_HTTP2_DECLARATIONS_INCOMPLETE"
	fluentBitUnsupportedReason = "FLUENT_BIT_CLASSIC_CONFIG_UNSUPPORTED"
)

// PrepareFluentBit accepts a caller-selected, effective classic configuration
// snippet. The parser intentionally supports one [OUTPUT] Name opentelemetry
// section only. It does not read includes or environment variables and drops
// every value except the reviewed http2/grpc settings.
func PrepareFluentBit(raw []byte, from, to string, complete, currentDefaultWasUsed, preserveHTTP2Enabled bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	enabled, supported, err := parseFluentBitConfig(raw)
	if err != nil {
		return Prepared{}, err
	}
	fact := inputFact{ID: FluentBitFact, State: "unsupported"}
	state, reason := "UNKNOWN", fluentBitIncompleteReason
	if from != FluentBitFrom || to != FluentBitTo {
		reason = "UNSUPPORTED_VERSION_PAIR"
	} else if !supported {
		reason = fluentBitUnsupportedReason
	} else if complete && currentDefaultWasUsed && preserveHTTP2Enabled {
		fact.State = "declared"
		fact.BoolValue = &enabled
		state, reason = "PREPARED", fluentBitPreparedReason
	}
	canonical, err := marshalInput(FluentBitComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_EFFECTIVE_CLASSIC_CONFIG_NOT_LIVE_OBSERVATION",
			"CURRENT_DEFAULT_AND_PRESERVATION_INTENT_ARE_OPERATOR_DECLARATIONS",
			"ONLY_HTTP2_ENABLED_SETTING_IS_EVALUATED;_PROTOCOL_NEGOTIATION_TLS_CONNECTIVITY_AND_RUNTIME_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// PrepareFluentBitHTTP2Target derives the same bounded output fact for five
// reviewed routes to Fluent Bit 5.1.2. It is a target-only requirement: the
// caller declares that its selected output needs HTTP/2. It does not infer an
// origin default or preservation intent.
func PrepareFluentBitHTTP2Target(raw []byte, from, to string, complete, requireHTTP2 bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	enabled, supported, err := parseFluentBitConfig(raw)
	if err != nil {
		return Prepared{}, err
	}
	fact := inputFact{ID: FluentBitTargetFact, State: "unsupported"}
	state, reason := "UNKNOWN", fluentBitIncompleteReason
	if !fluentBitHTTP2TargetPairs[from+"\x00"+to] {
		reason = "UNSUPPORTED_VERSION_PAIR"
	} else if !supported {
		reason = fluentBitUnsupportedReason
	} else if complete && requireHTTP2 {
		fact.State = "declared"
		fact.BoolValue = &enabled
		state, reason = "PREPARED", fluentBitPreparedReason
	}
	canonical, err := marshalInput(FluentBitComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_EFFECTIVE_CLASSIC_CONFIG_NOT_LIVE_OBSERVATION",
			"HTTP2_REQUIREMENT_IS_OPERATOR_DECLARED_TARGET_INTENT",
			"ONLY_HTTP2_ENABLED_SETTING_IS_EVALUATED;_PROTOCOL_NEGOTIATION_TLS_CONNECTIVITY_AND_RUNTIME_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// parseFluentBitConfig returns supported=false for syntax outside the bounded
// surface. Duplicate keys are ambiguous effective configuration and therefore
// remain unsupported/UNKNOWN without retaining or exposing their values.
func parseFluentBitConfig(raw []byte) (enabled, supported bool, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxInputBytes)
	sectionSeen, nameSeen := false, false
	seen := map[string]bool{}
	var http2, grpc string
	indent := -1
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if !utf8.ValidString(line) || hasFluentBitControlOrUnicodeSpace(line) {
			return false, false, nil
		}
		if line == "" || line[0] == '#' {
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		// The native classic parser recognizes a group from its leading '[';
		// do not treat an indented group or a group with trailing text as an
		// unrelated OUTPUT property and then attribute later http2 settings to
		// the preceding selected section.
		if strings.HasPrefix(trimmed, "[") {
			if line != trimmed || line != "[OUTPUT]" || sectionSeen {
				return false, false, nil
			}
			sectionSeen = true
			continue
		}
		if !sectionSeen || strings.HasPrefix(trimmed, "@") || strings.Contains(line, "${") || strings.Contains(line, "{{") {
			return false, false, nil
		}
		indentLen := 0
		for indentLen < len(line) && line[indentLen] == ' ' {
			indentLen++
		}
		if indentLen == 0 || (indentLen < len(line) && line[indentLen] == '\t') {
			return false, false, nil
		}
		if indent == -1 {
			indent = indentLen
		} else if indent != indentLen {
			return false, false, nil
		}
		property := line[indentLen:]
		if property == "" || property[0] == '#' {
			continue
		}
		separator := strings.IndexByte(property, ' ')
		if separator <= 0 || separator == len(property)-1 {
			return false, false, nil
		}
		key := property[:separator]
		value := strings.Trim(property[separator+1:], " ")
		if value == "" {
			return false, false, nil
		}
		if seen[key] {
			return false, false, nil
		}
		seen[key] = true
		if strings.EqualFold(key, "name") && key != "Name" || strings.EqualFold(key, "http2") && key != "http2" || strings.EqualFold(key, "grpc") && key != "grpc" {
			return false, false, nil
		}
		switch key {
		case "Name":
			if value != "opentelemetry" || nameSeen {
				return false, false, nil
			}
			nameSeen = true
		case "http2":
			if value != "on" && value != "off" && value != "force" {
				return false, false, nil
			}
			http2 = value
		case "grpc":
			if value != "on" && value != "off" && value != "auto" {
				return false, false, nil
			}
			grpc = value
		}
	}
	if scanner.Err() != nil || !sectionSeen || !nameSeen {
		return false, false, nil
	}
	if grpc == "on" || grpc == "auto" || (http2 != "" && http2 != "on" && http2 != "off" && http2 != "force") {
		return false, false, nil
	}
	return http2 == "on" || http2 == "force", true, nil
}

func hasFluentBitControlOrUnicodeSpace(s string) bool {
	for _, r := range s {
		if r == '\t' || unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') {
			return true
		}
	}
	return false
}
