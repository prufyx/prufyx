// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "strings"

// This file holds the argv scanning that the Falco and Kuma native routes share
// verbatim. Both reviewed rules define their predicate as literal containment of
// a bounded set of removed option spellings in one caller-declared effective
// argv, so both need exactly the same conservative token scan. Neither adapter
// models a project option table: an option table that guessed an arity wrongly
// could skip a removed spelling as if it were another option's value, which is
// precisely the negative-presence PASS that must never be emitted.

const maxDeclaredArgvTokens = 256

// declaredArgvTokens accepts only a flat JSON array of non-empty strings. Any
// other shape stays unresolved; it is never coerced into an argv.
func declaredArgvTokens(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > maxDeclaredArgvTokens {
		return nil, false
	}
	argv := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, false
		}
		argv[index] = text
	}
	return argv, true
}

// scanRemovedArgvSpellings decides whether a bounded set of removed option
// spellings is literally present in the supplied tokens.
//
// Every token is examined, including tokens that another option might consume as
// its value, so no removed spelling can be skipped. present is therefore safe in
// the only direction that matters: absence is reported only when no token in the
// whole slice can be one of the removed spellings.
//
// resolved is false whenever a token could hide a removed spelling from a
// literal comparison:
//   - a clustered or value-attached short token such as -Ab or -S100, where a
//     removed short spelling may be an inner character;
//   - a bare - or --, after which the reviewed parsers' treatment of the
//     remaining tokens is not established by the pinned evidence.
//
// Long options in --name=value form are compared on the name half as well, so
// --snaplen=100 is recognized as the --snaplen spelling.
func scanRemovedArgvSpellings(tokens []string, removed map[string]bool) (present, resolved bool) {
	for _, token := range tokens {
		if removed[token] {
			present = true
			continue
		}
		if !strings.HasPrefix(token, "-") {
			// A positional or an option value. It cannot be an option spelling.
			continue
		}
		if token == "-" || token == "--" {
			return false, false
		}
		if strings.HasPrefix(token, "--") {
			if name, _, found := strings.Cut(token, "="); found {
				if removed[name] {
					present = true
				}
			}
			continue
		}
		if len(token) > 2 {
			// -Ab or -S100: a removed short spelling may be an inner character,
			// and the reviewed evidence does not establish this parser's
			// clustering or attached-value behavior.
			return false, false
		}
	}
	return present, true
}

// argvExecutableMatches reports whether one literal argv[0] spelling names the
// given upstream executable. Only a bare name or a plain path whose final
// segment is that name is accepted; a wrapper, an interpreter, a shell string,
// or any spelling carrying whitespace is another command surface, which the
// callers then declare so the rule's own applicability guard keeps the claim
// UNKNOWN. This proves nothing about binary, image, or runtime identity.
func argvExecutableMatches(token, name string) bool {
	if token == "" || strings.ContainsAny(token, " \t\n\r\v\f") {
		return false
	}
	if token == name {
		return true
	}
	if !strings.HasPrefix(token, "/") && !strings.HasPrefix(token, "./") && !strings.HasPrefix(token, "../") {
		return false
	}
	index := strings.LastIndexByte(token, '/')
	return token[index+1:] == name
}

// argvRenderingUnresolved reports a templating or shell-substitution marker
// anywhere in the supplied bytes. A marker means the effective argv is not yet
// decided, so no presence predicate may be derived from it.
func argvRenderingUnresolved(raw []byte) bool {
	text := string(raw)
	return strings.Contains(text, "{{") || strings.Contains(text, "${")
}
