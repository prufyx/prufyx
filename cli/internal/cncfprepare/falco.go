// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "unicode/utf8"

const (
	FalcoComponent            = "pkg:github/falcosecurity/falco"
	FalcoDistributionFact     = "component.falco.distribution"
	FalcoExecutionSurfaceFact = "component.falco.execution_surface"
	FalcoRemovedFlagsFact     = "component.falco.removed_040_cli_flags_present"

	FalcoDistributionOfficial = "official_upstream"
	FalcoDistributionCustom   = "custom_build"
	FalcoSurfaceFalco         = "falco"
	FalcoSurfaceOther         = "other"

	FalcoFrom       = "0.40.0"
	FalcoTo041      = "0.41.0"
	FalcoTo042      = "0.42.0"
	falcoExecutable = "falco"
)

const (
	ReasonFalcoRemovedFlagsPresent Reason = "FALCO_REMOVED_040_CLI_FLAGS_PRESENT"
	ReasonFalcoRemovedFlagsAbsent  Reason = "FALCO_REMOVED_040_CLI_FLAGS_ABSENT"
	ReasonFalcoSurfaceOther        Reason = "FALCO_SELECTED_SURFACE_NOT_FALCO_EXECUTABLE"
	ReasonFalcoGuardUnresolved     Reason = "FALCO_DISTRIBUTION_DECLARATION_MISSING"
	ReasonFalcoPairUnsupported     Reason = "FALCO_TRANSITION_NOT_REVIEWED"
	ReasonFalcoArgvUnresolved      Reason = "FALCO_ARGUMENTS_UNRESOLVED"
	ReasonFalcoInputUnsupported    Reason = "FALCO_ARGV_SHAPE_UNRESOLVED"
	ReasonFalcoTemplated           Reason = "FALCO_ARGV_RENDERING_UNRESOLVED"
)

// falcoRemovedSpellings is the exact bounded set the reviewed
// falco.deprecated-cli-flags-removed rules already name. It is copied from the
// rule's own fact description and is never extended here.
var falcoRemovedSpellings = map[string]bool{
	"-A": true, "-b": true, "--print-base64": true, "-S": true, "--snaplen": true,
}

// PrepareFalcoArgv derives the three facts the reviewed Falco 0.40.0 -> 0.41.0
// and 0.40.0 -> 0.42.0 rules already require from one caller-declared explicit
// effective Falco argv, instead of making an operator hand-author the canonical
// declaration.
//
// It authors no new compatibility claim: it decides only whether the supplied
// argv literally contains one of the five removed 0.40 spellings, and binds that
// to the rules' existing pinned source spans. The argv is caller-declared data;
// it is never executed, and no wrapper, entrypoint, image, environment, Helm
// value, default, or runtime behavior is inferred. An unreviewed pair, a missing
// distribution declaration, another command surface, unresolved rendering, a
// clustered or attached short token, an option delimiter, and an unparseable
// shape all stay UNKNOWN rather than becoming a negative-presence PASS.
func PrepareFalcoArgv(raw []byte, from, to, distribution string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: FalcoDistributionFact, State: "missing"},
		{ID: FalcoExecutionSurfaceFact, State: "unsupported"},
		{ID: FalcoRemovedFlagsFact, State: "unsupported"},
	}
	if distribution == FalcoDistributionOfficial || distribution == FalcoDistributionCustom {
		facts[0] = inputFact{ID: FalcoDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonFalcoGuardUnresolved
	switch {
	case !falcoReviewedPair(from, to):
		reason = ReasonFalcoPairUnsupported
	case facts[0].State != "declared":
		reason = ReasonFalcoGuardUnresolved
	default:
		surface, present, inspectReason := inspectFalcoArgv(raw)
		reason = inspectReason
		if surface != "" {
			facts[1] = inputFact{ID: FalcoExecutionSurfaceFact, State: "declared", EnumValue: surface}
		}
		if surface == FalcoSurfaceFalco && present != nil {
			facts[2] = inputFact{ID: FalcoRemovedFlagsFact, State: "declared", BoolValue: present}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(FalcoComponent, from, to, facts)
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
			"WRAPPERS_ENTRYPOINTS_IMAGES_ENVIRONMENT_DEFAULTS_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectFalcoArgv returns the resolved command surface and, when that surface
// is the reviewed Falco executable, whether a removed spelling is literally
// present. present stays nil whenever the argv cannot be resolved against the
// bounded reviewed set.
func inspectFalcoArgv(raw []byte) (surface string, present *bool, reason Reason) {
	if argvRenderingUnresolved(raw) {
		return "", nil, ReasonFalcoTemplated
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return "", nil, ReasonFalcoInputUnsupported
	}
	argv, ok := declaredArgvTokens(value)
	if !ok {
		return "", nil, ReasonFalcoInputUnsupported
	}
	if !argvExecutableMatches(argv[0], falcoExecutable) {
		// A wrapper, an interpreter, or another Falco-project command. The
		// rule's applicability guard, not this adapter, then keeps the claim
		// UNKNOWN rather than silently ignoring the supplied argv.
		return FalcoSurfaceOther, nil, ReasonFalcoSurfaceOther
	}
	found, resolved := scanRemovedArgvSpellings(argv[1:], falcoRemovedSpellings)
	if !resolved {
		return FalcoSurfaceFalco, nil, ReasonFalcoArgvUnresolved
	}
	if found {
		return FalcoSurfaceFalco, &found, ReasonFalcoRemovedFlagsPresent
	}
	return FalcoSurfaceFalco, &found, ReasonFalcoRemovedFlagsAbsent
}

// falcoReviewedPair covers exactly the two packaged Falco transitions; no other
// origin or target is admitted.
func falcoReviewedPair(from, to string) bool {
	return from == FalcoFrom && (to == FalcoTo041 || to == FalcoTo042)
}
