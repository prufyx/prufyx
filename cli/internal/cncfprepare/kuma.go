// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "unicode/utf8"

const (
	KumaComponent            = "pkg:github/kumahq/kuma"
	KumaDistributionFact     = "component.kuma.distribution"
	KumaExecutionSurfaceFact = "component.kuma.execution_surface"
	KumaRemovedFlagsFact     = "component.kuma.removed_exclude_uid_flags_present"

	KumaDistributionOfficial           = "official_upstream"
	KumaDistributionCustom             = "custom_build"
	KumaSurfaceInstallTransparentProxy = "kumactl_install_transparent_proxy"
	KumaSurfaceOther                   = "other"

	KumaFrom = "2.8.0"
	KumaTo   = "2.9.0"

	kumaExecutable = "kumactl"
)

const (
	ReasonKumaRemovedFlagsPresent Reason = "KUMA_REMOVED_EXCLUDE_UID_FLAGS_PRESENT"
	ReasonKumaRemovedFlagsAbsent  Reason = "KUMA_REMOVED_EXCLUDE_UID_FLAGS_ABSENT"
	ReasonKumaSurfaceOther        Reason = "KUMA_SELECTED_SURFACE_NOT_INSTALL_TRANSPARENT_PROXY"
	ReasonKumaGuardUnresolved     Reason = "KUMA_DISTRIBUTION_DECLARATION_MISSING"
	ReasonKumaPairUnsupported     Reason = "KUMA_TRANSITION_NOT_REVIEWED"
	ReasonKumaArgvUnresolved      Reason = "KUMA_ARGUMENTS_UNRESOLVED"
	ReasonKumaInputUnsupported    Reason = "KUMA_ARGV_SHAPE_UNRESOLVED"
	ReasonKumaTemplated           Reason = "KUMA_ARGV_RENDERING_UNRESOLVED"
)

// kumaRemovedSpellings is the exact bounded set the reviewed
// kuma.deprecated-exclude-uid-flags-removed rule already names. It is copied
// from the rule's own fact description and is never extended here.
var kumaRemovedSpellings = map[string]bool{
	"--exclude-outbound-tcp-ports-for-uids": true,
	"--exclude-outbound-udp-ports-for-uids": true,
}

// kumaInstallTransparentProxySubcommand is the exact literal command path the
// reviewed rule scopes itself to. Only this direct spelling is resolved.
var kumaInstallTransparentProxySubcommand = []string{"install", "transparent-proxy"}

// PrepareKumaInstallTransparentProxyArgv derives the three facts the reviewed
// Kuma 2.8.0 -> 2.9.0 rule already requires from one caller-declared explicit
// effective kumactl install transparent-proxy argv, instead of making an
// operator hand-author the canonical declaration.
//
// It authors no new compatibility claim: it decides only whether the supplied
// argv literally contains one of the two removed UID exclusion spellings, and
// binds that to the rule's existing pinned source spans. The argv is
// caller-declared data; it is never executed, and no wrapper, image, default,
// consolidated-flag equivalence, Dataplane migration, or runtime behavior is
// inferred. An unreviewed pair, a missing distribution declaration, another
// command surface, unresolved rendering, an ambiguous short token, and an
// unparseable shape all stay UNKNOWN rather than becoming a negative-presence
// PASS.
func PrepareKumaInstallTransparentProxyArgv(raw []byte, from, to, distribution string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: KumaDistributionFact, State: "missing"},
		{ID: KumaExecutionSurfaceFact, State: "unsupported"},
		{ID: KumaRemovedFlagsFact, State: "unsupported"},
	}
	if distribution == KumaDistributionOfficial || distribution == KumaDistributionCustom {
		facts[0] = inputFact{ID: KumaDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonKumaGuardUnresolved
	switch {
	case !kumaReviewedPair(from, to):
		reason = ReasonKumaPairUnsupported
	case facts[0].State != "declared":
		reason = ReasonKumaGuardUnresolved
	default:
		surface, present, inspectReason := inspectKumaInstallTransparentProxyArgv(raw)
		reason = inspectReason
		if surface != "" {
			facts[1] = inputFact{ID: KumaExecutionSurfaceFact, State: "declared", EnumValue: surface}
		}
		if surface == KumaSurfaceInstallTransparentProxy && present != nil {
			facts[2] = inputFact{ID: KumaRemovedFlagsFact, State: "declared", BoolValue: present}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(KumaComponent, from, to, facts)
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
			"WRAPPERS_IMAGES_DEFAULTS_CONSOLIDATED_FLAG_AND_DATAPLANE_MIGRATION_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectKumaInstallTransparentProxyArgv returns the resolved command surface
// and, when that surface is the reviewed kumactl install transparent-proxy
// command, whether a removed spelling is literally present. present stays nil
// whenever the argv cannot be resolved against the bounded reviewed set.
func inspectKumaInstallTransparentProxyArgv(raw []byte) (surface string, present *bool, reason Reason) {
	if argvRenderingUnresolved(raw) {
		return "", nil, ReasonKumaTemplated
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return "", nil, ReasonKumaInputUnsupported
	}
	argv, ok := declaredArgvTokens(value)
	if !ok {
		return "", nil, ReasonKumaInputUnsupported
	}
	if !kumaInstallTransparentProxySurface(argv) {
		// A wrapper, another kumactl subcommand, or a spelling that interleaves
		// global options before the subcommand. The reviewed evidence scopes
		// this rule to the direct command path only, so the rule's own
		// applicability guard, not this adapter, keeps the claim UNKNOWN.
		return KumaSurfaceOther, nil, ReasonKumaSurfaceOther
	}
	found, resolved := scanRemovedArgvSpellings(argv[1+len(kumaInstallTransparentProxySubcommand):], kumaRemovedSpellings)
	if !resolved {
		return KumaSurfaceInstallTransparentProxy, nil, ReasonKumaArgvUnresolved
	}
	if found {
		return KumaSurfaceInstallTransparentProxy, &found, ReasonKumaRemovedFlagsPresent
	}
	return KumaSurfaceInstallTransparentProxy, &found, ReasonKumaRemovedFlagsAbsent
}

// kumaInstallTransparentProxySurface accepts only the direct literal command
// path kumactl install transparent-proxy. Any other arrangement, including
// global options placed before the subcommand, is another command surface.
func kumaInstallTransparentProxySurface(argv []string) bool {
	if len(argv) < 1+len(kumaInstallTransparentProxySubcommand) {
		return false
	}
	if !argvExecutableMatches(argv[0], kumaExecutable) {
		return false
	}
	for index, word := range kumaInstallTransparentProxySubcommand {
		if argv[1+index] != word {
			return false
		}
	}
	return true
}

// kumaReviewedPair covers exactly the one packaged Kuma transition.
func kumaReviewedPair(from, to string) bool {
	return from == KumaFrom && to == KumaTo
}
