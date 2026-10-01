// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	SpireComponent            = "pkg:github/spiffe/spire"
	SpireDistributionFact     = "component.spire.distribution"
	SpireExecutionSurfaceFact = "component.spire.execution_surface"
	SpireRemovedTTLFact       = "component.spire.removed_entry_ttl_flag_present"

	SpireDistributionOfficial = "official_upstream"
	SpireDistributionCustom   = "custom_build"
	SpireSurfaceEntryCreate   = "spire_server_entry_create"
	SpireSurfaceOther         = "other"

	SpireFrom = "1.10.4"
	SpireTo   = "1.11.0"

	spireExecutable = "spire-server"
)

const (
	ReasonSpireRemovedTTLPresent Reason = "SPIRE_REMOVED_ENTRY_TTL_OPTION_PRESENT"
	ReasonSpireRemovedTTLAbsent  Reason = "SPIRE_REMOVED_ENTRY_TTL_OPTION_ABSENT"
	ReasonSpireSurfaceOther      Reason = "SPIRE_SELECTED_SURFACE_NOT_SPIRE_SERVER_ENTRY_CREATE"
	ReasonSpireGuardUnresolved   Reason = "SPIRE_DISTRIBUTION_DECLARATION_MISSING"
	ReasonSpirePairUnsupported   Reason = "SPIRE_TRANSITION_NOT_REVIEWED"
	ReasonSpireArgvUnresolved    Reason = "SPIRE_ARGUMENTS_UNRESOLVED"
	ReasonSpireInputUnsupported  Reason = "SPIRE_ARGV_SHAPE_UNRESOLVED"
	ReasonSpireTemplated         Reason = "SPIRE_ARGV_RENDERING_UNRESOLVED"
)

// spireRemovedTTLSpellings is the exact bounded set the reviewed
// spire.removed-entry-ttl.1-11 rule already names in its own fact description.
// It is copied from that description and is never extended here.
var spireRemovedTTLSpellings = map[string]bool{"-ttl": true, "--ttl": true}

// spireEntryCreateSubcommand is the exact literal command path the reviewed
// rule scopes itself to. Only this direct spelling is resolved.
var spireEntryCreateSubcommand = []string{"entry", "create"}

// PrepareSpireEntryCreateArgv derives the three facts the reviewed SPIRE
// 1.10.4 -> 1.11.0 rule already requires from one caller-declared explicit
// effective spire-server entry create argv, instead of making an operator
// hand-author the canonical declaration.
//
// It authors no new compatibility claim: it decides only whether the supplied
// argv literally contains -ttl or --ttl on the reviewed command surface, and
// binds that to the rule's existing pinned source spans. The argv is
// caller-declared data; it is never executed, and no wrapper, entrypoint,
// image, environment, Helm value, default, registration entry, replacement TTL
// value, or runtime behavior is inferred. An unreviewed pair, a missing
// distribution declaration, another command surface, unresolved rendering, an
// option delimiter, and an unparseable shape all stay UNKNOWN rather than
// becoming a negative-presence PASS.
func PrepareSpireEntryCreateArgv(raw []byte, from, to, distribution string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: SpireDistributionFact, State: "missing"},
		{ID: SpireExecutionSurfaceFact, State: "unsupported"},
		{ID: SpireRemovedTTLFact, State: "unsupported"},
	}
	if distribution == SpireDistributionOfficial || distribution == SpireDistributionCustom {
		facts[0] = inputFact{ID: SpireDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonSpireGuardUnresolved
	switch {
	case !spireReviewedPair(from, to):
		reason = ReasonSpirePairUnsupported
	case facts[0].State != "declared":
		reason = ReasonSpireGuardUnresolved
	default:
		surface, present, inspectReason := inspectSpireEntryCreateArgv(raw)
		reason = inspectReason
		if surface != "" {
			facts[1] = inputFact{ID: SpireExecutionSurfaceFact, State: "declared", EnumValue: surface}
		}
		if surface == SpireSurfaceEntryCreate && present != nil {
			facts[2] = inputFact{ID: SpireRemovedTTLFact, State: "declared", BoolValue: present}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(SpireComponent, from, to, facts)
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
			"DECLARED_ARGV_IS_CALLER_SUPPLIED_NOT_EXECUTED",
			"WRAPPERS_ENTRYPOINTS_IMAGES_ENVIRONMENT_DEFAULTS_REPLACEMENT_TTL_VALUES_AND_REGISTRATION_ENTRIES_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectSpireEntryCreateArgv returns the resolved command surface and, when
// that surface is the reviewed spire-server entry create command, whether a
// removed spelling is literally present. present stays nil whenever the argv
// cannot be resolved against the bounded reviewed set.
func inspectSpireEntryCreateArgv(raw []byte) (surface string, present *bool, reason Reason) {
	if argvRenderingUnresolved(raw) {
		return "", nil, ReasonSpireTemplated
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return "", nil, ReasonSpireInputUnsupported
	}
	argv, ok := declaredArgvTokens(value)
	if !ok {
		return "", nil, ReasonSpireInputUnsupported
	}
	if !spireEntryCreateSurface(argv) {
		// A wrapper, another spire-server subcommand, spire-agent, or a
		// spelling that interleaves other words before the subcommand. The
		// reviewed evidence scopes this rule to the direct command path only,
		// so the rule's own applicability guard, not this adapter, keeps the
		// claim UNKNOWN rather than silently ignoring the supplied argv.
		return SpireSurfaceOther, nil, ReasonSpireSurfaceOther
	}
	found, resolved := scanSpireRemovedTTLSpellings(argv[1+len(spireEntryCreateSubcommand):])
	if !resolved {
		return SpireSurfaceEntryCreate, nil, ReasonSpireArgvUnresolved
	}
	if found {
		return SpireSurfaceEntryCreate, &found, ReasonSpireRemovedTTLPresent
	}
	return SpireSurfaceEntryCreate, &found, ReasonSpireRemovedTTLAbsent
}

// spireEntryCreateSurface accepts only the direct literal command path
// spire-server entry create. Any other arrangement, including a word placed
// between the executable and the subcommand, is another command surface.
func spireEntryCreateSurface(argv []string) bool {
	if len(argv) < 1+len(spireEntryCreateSubcommand) {
		return false
	}
	if !argvExecutableMatches(argv[0], spireExecutable) {
		return false
	}
	for index, word := range spireEntryCreateSubcommand {
		if argv[1+index] != word {
			return false
		}
	}
	return true
}

// scanSpireRemovedTTLSpellings decides whether the reviewed removed option
// spellings -ttl and --ttl are literally present in the supplied tokens.
//
// Every token is examined, including tokens that another option might consume
// as its value, so no removed spelling can be skipped. present is therefore
// safe in the only direction that matters: absence is reported only when no
// token in the whole slice can be one of the two removed spellings.
//
// Unlike the shared bounded-set scan, this one does not have to give up on a
// single-dash token longer than two characters. Both removed spellings are
// multi-character option names, so neither can be an inner character of a
// clustered short token: under a single-character clustering convention -ttl
// would be three separate single-character options, and the removed option
// would still have to appear as its own token to be used at all. That matters
// here because spire-server's own option names are themselves single-dash
// multi-character spellings such as -spiffeID or -selector, and refusing every
// one of them would leave no resolvable invocation.
//
// A token in name=value form is compared on its name half for both the -name=
// and --name= spellings, so -ttl=1h and --ttl=1h are recognized.
//
// resolved is false for a bare - or --, after which the reviewed parser
// evidence does not establish the treatment of the remaining tokens; the rule's
// own fact description names delimiter-terminated invocations as outside that
// evidence.
func scanSpireRemovedTTLSpellings(tokens []string) (present, resolved bool) {
	for _, token := range tokens {
		if spireRemovedTTLSpellings[token] {
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
		if name, _, found := strings.Cut(token, "="); found && spireRemovedTTLSpellings[name] {
			present = true
		}
	}
	return present, true
}

// spireReviewedPair covers exactly the one packaged SPIRE transition; no other
// origin or target is admitted.
func spireReviewedPair(from, to string) bool {
	return from == SpireFrom && to == SpireTo
}
