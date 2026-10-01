// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	CoreDNSComponent        = "pkg:github/coredns/coredns"
	CoreDNSDistributionFact = "component.coredns.distribution"
	CoreDNSFact             = "component.coredns.federation_directive_present"
	CoreDNSFrom             = "1.6.9"
	CoreDNSTo               = "1.7.0"
	CoreDNSLatestTo         = "1.14.7"
	coreDNSMaxNesting       = 32
)

const (
	ReasonCoreDNSDirectivePresent = Reason("COREDNS_DIRECT_FEDERATION_DIRECTIVE_PRESENT")
	ReasonCoreDNSDirectiveAbsent  = Reason("COREDNS_DIRECT_FEDERATION_DIRECTIVE_ABSENT")
	ReasonCoreDNSInputUnsupported = Reason("COREDNS_COREFILE_SELECTED_SYNTAX_UNSUPPORTED")
	ReasonCoreDNSIncomplete       = Reason("COREDNS_COREFILE_COMPLETENESS_OR_DISTRIBUTION_UNDECLARED")
	ReasonCoreDNSPairUnsupported  = Reason("COREDNS_TRANSITION_NOT_REVIEWED")
)

// PrepareCoreDNSCorefile minimizes only whether a literal federation directive
// occurs directly in a local Corefile server block. It is intentionally not a
// Corefile validator or resolver: imports, snippets, substitutions, quoted or
// escaped syntax remain UNKNOWN. It admits only balanced brace-delimited
// bodies and ignores their opaque property tokens.
func PrepareCoreDNSCorefile(raw []byte, from, to, distribution string, complete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{{ID: CoreDNSDistributionFact, State: "missing"}, {ID: CoreDNSFact, State: "unsupported"}}
	state, reason := StateUnknown, ReasonCoreDNSPairUnsupported
	if distribution == "official" || distribution == "custom" {
		facts[0] = inputFact{ID: CoreDNSDistributionFact, State: "declared", EnumValue: distribution}
	}
	if !coreDNSReviewedPair(from, to) {
		reason = ReasonCoreDNSPairUnsupported
	} else if !complete || distribution != "official" {
		reason = ReasonCoreDNSIncomplete
	} else if present, ok := coreDNSDirectFederation(raw); ok {
		facts[1] = inputFact{ID: CoreDNSFact, State: "declared", BoolValue: &present}
		state = StatePrepared
		if present {
			reason = ReasonCoreDNSDirectivePresent
		} else {
			reason = ReasonCoreDNSDirectiveAbsent
		}
	} else {
		reason = ReasonCoreDNSInputUnsupported
	}
	canonical, err := marshalComponentInput(CoreDNSComponent, from, to, facts)
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
			"COREFILE_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"IMPORTS_SNIPPETS_SUBSTITUTIONS_PLUGIN_VALIDATION_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func coreDNSReviewedPair(from, to string) bool {
	if from == CoreDNSFrom && to == CoreDNSTo {
		return true
	}
	if to != CoreDNSLatestTo {
		return false
	}
	switch from {
	case "1.9.4", "1.10.1", "1.11.4", "1.12.4", "1.13.2":
		return true
	default:
		return false
	}
}

func coreDNSDirectFederation(raw []byte) (bool, bool) {
	depth, blocks := 0, 0
	directFederation := false
	for _, line := range strings.Split(string(raw), "\n") {
		body, safe := coreDNSCodeLine(line)
		if !safe || body == "" {
			if !safe {
				return false, false
			}
			continue
		}
		tokens := coreDNSTokens(body)
		if len(tokens) == 0 {
			return false, false
		}
		if depth == 0 {
			if len(tokens) < 2 || tokens[len(tokens)-1] != "{" || containsCoreDNSBrace(tokens[:len(tokens)-1]) || strings.HasPrefix(tokens[0], "(") || tokens[0] == "import" {
				return false, false
			}
			depth, blocks = 1, blocks+1
			continue
		}
		if strings.HasPrefix(tokens[0], "(") || tokens[0] == "import" {
			return false, false
		}
		if len(tokens) == 1 && tokens[0] == "}" {
			depth--
			if depth < 0 {
				return false, false
			}
			continue
		}
		openBraces := coreDNSTokenCount(tokens, "{")
		if containsCoreDNSToken(tokens, "}") || openBraces > 1 || (openBraces == 1 && (len(tokens) == 1 || tokens[len(tokens)-1] != "{")) {
			return false, false
		}
		// A first token at server-block depth is a direct plugin position. The
		// remaining tokens and balanced nested bodies are opaque to this narrow
		// adapter, which does not validate plugin-specific grammar.
		if depth == 1 && tokens[0] == "federation" {
			directFederation = true
		}
		if openBraces == 1 {
			if depth >= coreDNSMaxNesting {
				return false, false
			}
			depth++
		}
	}
	return directFederation, depth == 0 && blocks > 0
}

func coreDNSCodeLine(line string) (string, bool) {
	if comment := strings.IndexByte(line, '#'); comment >= 0 {
		line = line[:comment]
	}
	if strings.ContainsAny(line, "\\\"'") || strings.Contains(line, "{$") || strings.Contains(line, "{%") {
		return "", false
	}
	return strings.TrimSpace(line), true
}

func coreDNSTokens(line string) []string {
	line = strings.NewReplacer("{", " { ", "}", " } ").Replace(line)
	return strings.Fields(line)
}

func containsCoreDNSBrace(tokens []string) bool {
	for _, token := range tokens {
		if token == "{" || token == "}" {
			return true
		}
	}
	return false
}

func containsCoreDNSToken(tokens []string, wanted string) bool {
	return coreDNSTokenCount(tokens, wanted) != 0
}

func coreDNSTokenCount(tokens []string, wanted string) int {
	count := 0
	for _, token := range tokens {
		if token == wanted {
			count++
		}
	}
	return count
}
