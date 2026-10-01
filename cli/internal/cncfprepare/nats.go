// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "strings"

// NATS 2.11 rejects literal ASCII spaces in the directly declared server,
// cluster, and gateway names that 2.10 accepted. This adapter accepts only a
// standalone JSON object; it never resolves includes, variables, defaults, or
// another configuration file.
const (
	NATSComponent = "pkg:github/nats-io/nats-server"
	NATSFact      = "component.nats.selected_name_has_ascii_space"
	NATSFrom      = "2.10.0"
	NATSTo        = "2.11.0"
)

const (
	ReasonNATSNameSpacePresent  Reason = "NATS_SELECTED_NAME_ASCII_SPACE_PRESENT"
	ReasonNATSNameSpaceAbsent   Reason = "NATS_SELECTED_NAME_ASCII_SPACE_ABSENT"
	ReasonNATSConfigUnsupported Reason = "NATS_CONFIG_INPUT_UNSUPPORTED"
)

// PrepareNATS derives one fact from directly declared literal server_name,
// cluster.name, and gateway.name values. The upstream parser applies
// strings.ToLower to these keys, so a case-colliding selected key is ambiguous.
// JSON-like NATS configuration is the deliberately small admitted form; classic
// blocks, includes, environment references, dotted descendant paths, duplicates, and
// unsupported parent shapes remain UNKNOWN.
func PrepareNATS(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	space, ok := false, false
	if natsJSONEscapesSupported(raw) {
		value, err := decodeStrict(raw)
		if err != nil {
			return Prepared{}, ErrInvalid
		}
		space, ok = natsSelectedNameSpace(value)
	}
	fact := inputFact{ID: NATSFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonNATSConfigUnsupported
	if ok {
		fact = inputFact{ID: NATSFact, State: "declared", BoolValue: &space}
		state = StatePrepared
		if space {
			reason = ReasonNATSNameSpacePresent
		} else {
			reason = ReasonNATSNameSpaceAbsent
		}
	}
	canonical, err := marshalComponentInput(NATSComponent, from, to, []inputFact{fact})
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
			"NATS_CONFIG_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"INCLUDES_VARIABLES_DEFAULTS_AND_RUNTIME_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func natsSelectedNameSpace(value any) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok || hasNATSKey(root, "include") || hasNATSDottedSelectedKey(root, false) {
		return false, false
	}
	selected := 0
	space := false
	if value, found, unique := natsKey(root, "server_name"); found {
		if !unique {
			return false, false
		}
		name, ok := value.(string)
		if !ok || natsDynamicString(name) {
			return false, false
		}
		selected++
		space = space || strings.Contains(name, " ")
	}
	for _, parent := range []string{"cluster", "gateway"} {
		parentValue, found, unique := natsKey(root, parent)
		if !found {
			continue
		}
		if !unique {
			return false, false
		}
		object, ok := parentValue.(map[string]any)
		if !ok || hasNATSKey(object, "include") || hasNATSDottedSelectedKey(object, true) {
			return false, false
		}
		if value, found, unique := natsKey(object, "name"); found {
			if !unique {
				return false, false
			}
			name, ok := value.(string)
			if !ok || natsDynamicString(name) {
				return false, false
			}
			selected++
			space = space || strings.Contains(name, " ")
		}
	}
	return space, selected > 0
}

func natsKey(object map[string]any, target string) (any, bool, bool) {
	var value any
	count := 0
	for key, candidate := range object {
		if strings.ToLower(key) == target {
			count++
			value = candidate
		}
	}
	return value, count > 0, count == 1
}

func hasNATSKey(object map[string]any, target string) bool {
	_, found, _ := natsKey(object, target)
	return found
}

func hasNATSDottedSelectedKey(object map[string]any, nested bool) bool {
	for key := range object {
		lower := strings.ToLower(key)
		if nested && strings.HasPrefix(lower, "name.") {
			return true
		}
		if !nested && (lower == "cluster.name" || lower == "gateway.name" || strings.HasPrefix(lower, "server_name.") || strings.HasPrefix(lower, "cluster.name.") || strings.HasPrefix(lower, "gateway.name.")) {
			return true
		}
	}
	return false
}

func natsDynamicString(value string) bool { return strings.Contains(value, "$") }

// natsJSONEscapesSupported retains only the escape forms admitted by the
// reviewed NATS lexer within this JSON-only subset. encoding/json would decode
// additional JSON escapes (for example \\u and \\/), which could make an
// unsupported NATS configuration appear as a literal selected name.
func natsJSONEscapesSupported(raw []byte) bool {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			switch raw[index] {
			case '"', '\\', 't', 'n', 'r':
			default:
				return false
			}
		}
	}
	return true
}
