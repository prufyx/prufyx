// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	KubeEdgeComponent        = "pkg:github/kubeedge/kubeedge"
	KubeEdgeDistributionFact = "component.kubeedge.distribution"
	KubeEdgeArgvCompleteFact = "component.kubeedge.effective_argv_complete"
	KubeEdgeSurfaceFact      = "component.kubeedge.execution_surface"
	KubeEdgeSelectorFact     = "component.kubeedge.init_version_selection_form"

	KubeEdgeDistributionOfficial = "official_upstream"
	KubeEdgeDistributionCustom   = "custom_build"
	KubeEdgeSurfaceInit          = "keadm_init"
	KubeEdgeSurfaceOther         = "other"

	KubeEdgeSelectorLegacyProfile = "legacy_profile_version"
	KubeEdgeSelectorVersionFlag   = "kubeedge_version_flag_only"

	KubeEdgeFrom = "1.18.0"
	KubeEdgeTo   = "1.19.0"

	keadmExecutable = "keadm"
)

// keadmInitSubcommand is the exact literal command path the reviewed rule
// scopes itself to. Only this direct spelling is resolved.
var keadmInitSubcommand = []string{"init"}

const (
	// keadmProfileOption and keadmKubeEdgeVersionOption are the exact two option
	// spellings the reviewed rule's own fact description names. They are copied
	// from that description and from the pinned v1.18 and v1.19 keadm flag
	// registrations; no other spelling is admitted.
	keadmProfileOption           = "--profile"
	keadmKubeEdgeVersionOption   = "--kubeedge-version"
	keadmProfileVersionKeyPrefix = "version="
)

const (
	ReasonKubeEdgeLegacyProfileVersion Reason = "KUBEEDGE_LEGACY_PROFILE_VERSION_SELECTOR_PRESENT"
	ReasonKubeEdgeVersionFlagOnly      Reason = "KUBEEDGE_TARGET_VERSION_FLAG_ONLY_SELECTOR_PRESENT"
	ReasonKubeEdgeSelectorMissing      Reason = "KUBEEDGE_INIT_VERSION_SELECTOR_MISSING"
	ReasonKubeEdgeSelectorUnsupported  Reason = "KUBEEDGE_INIT_VERSION_SELECTOR_UNSUPPORTED"
	ReasonKubeEdgeSelectorConflict     Reason = "KUBEEDGE_INIT_VERSION_SELECTORS_CONFLICT"
	ReasonKubeEdgeSurfaceOther         Reason = "KUBEEDGE_SELECTED_SURFACE_NOT_KEADM_INIT"
	ReasonKubeEdgeGuardMissing         Reason = "KUBEEDGE_GUARD_DECLARATION_MISSING"
	ReasonKubeEdgePairUnsupported      Reason = "KUBEEDGE_TRANSITION_NOT_REVIEWED"
	ReasonKubeEdgeArgvUnresolved       Reason = "KUBEEDGE_ARGUMENTS_UNRESOLVED"
	ReasonKubeEdgeInputUnsupported     Reason = "KUBEEDGE_ARGV_SHAPE_UNRESOLVED"
	ReasonKubeEdgeTemplated            Reason = "KUBEEDGE_ARGV_RENDERING_UNRESOLVED"
)

// PrepareKubeEdgeInitArgv derives the four facts the reviewed KubeEdge
// 1.18.0 -> 1.19.0 rule already requires from one caller-declared explicit
// effective keadm init argv, instead of making an operator hand-author the
// canonical declaration.
//
// It authors no new compatibility claim. The reviewed evidence already states
// the whole grammar this adapter decides:
//
//   - the pinned v1.18 keadm flag registration documents --profile as
//     "/path/version.yaml or version=v<version>", and the pinned v1.18 install
//     path splits that value on "=" and treats only the literal key "version"
//     as a version selector;
//   - the pinned v1.19 install path passes --profile straight to external
//     values-file reading with no version parsing at all;
//   - the pinned v1.19 release note states that --kubeedge-version selects the
//     version and "--profile version is no longer supported";
//   - the pinned v1.19 flag registration carries --kubeedge-version.
//
// So the adapter decides only which of the two reviewed selector forms the
// supplied argv literally uses. Every shape the fact description places outside
// that grammar -- an external values file, both selectors together, neither
// selector, an option delimiter, or an unparseable document -- stays missing,
// unsupported, or conflicting rather than becoming a result.
//
// The argv is caller-declared data. It is never executed, no --profile values
// file is opened, and no wrapper, entrypoint, image, environment, Helm value,
// chart, default, or runtime behavior is inferred. Argv completeness,
// distribution, and the command surface remain the caller's own declarations.
func PrepareKubeEdgeInitArgv(raw []byte, from, to, distribution string, argvComplete *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if distribution != "" && distribution != KubeEdgeDistributionOfficial && distribution != KubeEdgeDistributionCustom {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: KubeEdgeDistributionFact, State: "missing"},
		{ID: KubeEdgeArgvCompleteFact, State: "missing"},
		{ID: KubeEdgeSurfaceFact, State: "unsupported"},
		{ID: KubeEdgeSelectorFact, State: "unsupported"},
	}
	if distribution != "" {
		facts[0] = inputFact{ID: KubeEdgeDistributionFact, State: "declared", EnumValue: distribution}
	}
	if argvComplete != nil {
		facts[1] = inputFact{ID: KubeEdgeArgvCompleteFact, State: "declared", BoolValue: argvComplete}
	}
	state, reason := StateUnknown, ReasonKubeEdgeGuardMissing
	switch {
	case !kubeEdgeReviewedPair(from, to):
		reason = ReasonKubeEdgePairUnsupported
	case facts[0].State != "declared" || facts[1].State != "declared":
		reason = ReasonKubeEdgeGuardMissing
	default:
		surface, selector, inspectReason := inspectKeadmInitArgv(raw, to)
		reason = inspectReason
		if surface != "" {
			facts[2] = inputFact{ID: KubeEdgeSurfaceFact, State: "declared", EnumValue: surface}
		}
		if surface == KubeEdgeSurfaceInit && selector != "" {
			facts[3] = inputFact{ID: KubeEdgeSelectorFact, State: "declared", EnumValue: selector}
			state = StatePrepared
		}
		if surface == KubeEdgeSurfaceInit && selector == "" && inspectReason == ReasonKubeEdgeSelectorConflict {
			facts[3] = inputFact{ID: KubeEdgeSelectorFact, State: "conflict"}
		}
		if surface == KubeEdgeSurfaceInit && selector == "" && inspectReason == ReasonKubeEdgeSelectorMissing {
			facts[3] = inputFact{ID: KubeEdgeSelectorFact, State: "missing"}
		}
	}
	canonical, err := marshalComponentInput(KubeEdgeComponent, from, to, facts)
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
			"EXTERNAL_PROFILE_VALUES_FILES_NOT_OPENED_OR_INTERPRETED",
			"WRAPPERS_ENTRYPOINTS_IMAGES_ENVIRONMENT_HELM_VALUES_AND_CHART_DEFAULTS_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectKeadmInitArgv returns the resolved command surface and, when that
// surface is the reviewed keadm init command, which of the two reviewed
// selector forms the argv literally uses. The selector stays empty whenever the
// argv cannot be resolved against that bounded grammar.
func inspectKeadmInitArgv(raw []byte, target string) (surface, selector string, reason Reason) {
	if argvRenderingUnresolved(raw) {
		return "", "", ReasonKubeEdgeTemplated
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return "", "", ReasonKubeEdgeInputUnsupported
	}
	argv, ok := declaredArgvTokens(value)
	if !ok {
		return "", "", ReasonKubeEdgeInputUnsupported
	}
	if !keadmInitSurface(argv) {
		// A wrapper, another keadm subcommand such as join or upgrade, or a
		// spelling that interleaves other words before the subcommand. The
		// reviewed evidence scopes this rule to the direct keadm init command
		// only, so the rule's own applicability guard, not this adapter, keeps
		// the claim UNKNOWN rather than silently ignoring the supplied argv.
		return KubeEdgeSurfaceOther, "", ReasonKubeEdgeSurfaceOther
	}
	form, resolved := scanKeadmInitVersionSelectors(argv[1+len(keadmInitSubcommand):], target)
	if !resolved {
		return KubeEdgeSurfaceInit, "", ReasonKubeEdgeArgvUnresolved
	}
	switch form {
	case keadmSelectorLegacy:
		return KubeEdgeSurfaceInit, KubeEdgeSelectorLegacyProfile, ReasonKubeEdgeLegacyProfileVersion
	case keadmSelectorVersionFlag:
		return KubeEdgeSurfaceInit, KubeEdgeSelectorVersionFlag, ReasonKubeEdgeVersionFlagOnly
	case keadmSelectorBoth:
		return KubeEdgeSurfaceInit, "", ReasonKubeEdgeSelectorConflict
	case keadmSelectorNeither:
		return KubeEdgeSurfaceInit, "", ReasonKubeEdgeSelectorMissing
	default:
		return KubeEdgeSurfaceInit, "", ReasonKubeEdgeSelectorUnsupported
	}
}

// keadmInitSurface accepts only the direct literal command path keadm init.
// Any other arrangement, including a word placed between the executable and the
// subcommand, is another command surface.
func keadmInitSurface(argv []string) bool {
	if len(argv) < 1+len(keadmInitSubcommand) {
		return false
	}
	if !argvExecutableMatches(argv[0], keadmExecutable) {
		return false
	}
	for index, word := range keadmInitSubcommand {
		if argv[1+index] != word {
			return false
		}
	}
	return true
}

type keadmSelectorForm int

const (
	keadmSelectorUnsupported keadmSelectorForm = iota
	keadmSelectorNeither
	keadmSelectorLegacy
	keadmSelectorVersionFlag
	keadmSelectorBoth
)

// scanKeadmInitVersionSelectors decides which reviewed version-selector form
// the supplied tokens use.
//
// Every token is examined, including tokens that another option might consume
// as its value, so no selector spelling can be skipped. There is deliberately
// no option table: an option table that guessed an arity wrongly could step
// over --profile or --kubeedge-version as if it were another option's value,
// which would silently downgrade a conflict or a legacy witness into a clean
// version-flag-only result.
//
// Both the separated form (--profile version=v1.19.0) and the attached form
// (--profile=version=v1.19.0) are recognized, because the pinned v1.18 install
// path splits the whole option value on "=" and compares only its first
// segment with the literal key "version".
//
// A --profile value that is not in version= form is the external values-file
// spelling that the pinned v1.18 flag help documents as "/path/version.yaml".
// The reviewed fact description states that "a version-like filename does not
// prove legacy intent", so such an argv is reported unsupported and never
// becomes either selector form.
//
// A --kubeedge-version value other than the reviewed target is unsupported:
// the reviewed kubeedge_version_flag_only form is defined as selecting that
// exact target, and no other tag is covered.
//
// resolved is false whenever a token could hide or displace a selector
// spelling:
//   - a bare - or --, after which the reviewed evidence does not establish the
//     treatment of the remaining tokens;
//   - any single-dash token, because the pinned v1.18 and v1.19 keadm flag
//     registrations declare only long-form options and so establish nothing
//     about shorthand spellings, clustering, or attached short values;
//   - a --profile or --kubeedge-version option whose value token is missing
//     entirely.
func scanKeadmInitVersionSelectors(tokens []string, target string) (form keadmSelectorForm, resolved bool) {
	legacyProfile, externalProfile, versionFlag, unsupportedVersionFlag := false, false, false, false
	for index := 0; index < len(tokens); index++ {
		token := tokens[index]
		if !strings.HasPrefix(token, "-") {
			// A positional or an option value. It cannot be a selector spelling.
			continue
		}
		if token == "-" || token == "--" || !strings.HasPrefix(token, "--") {
			return keadmSelectorUnsupported, false
		}
		optionName, optionValue, attached := strings.Cut(token, "=")
		switch optionName {
		case keadmProfileOption:
			if !attached {
				index++
				if index >= len(tokens) {
					return keadmSelectorUnsupported, false
				}
				optionValue = tokens[index]
			}
			if strings.HasPrefix(optionValue, keadmProfileVersionKeyPrefix) {
				legacyProfile = true
				continue
			}
			// An external values file, an empty value, or any other spelling.
			externalProfile = true
		case keadmKubeEdgeVersionOption:
			if !attached {
				index++
				if index >= len(tokens) {
					return keadmSelectorUnsupported, false
				}
				optionValue = tokens[index]
			}
			if optionValue == "v"+target || optionValue == target {
				versionFlag = true
				continue
			}
			unsupportedVersionFlag = true
		}
	}
	switch {
	case legacyProfile && (versionFlag || unsupportedVersionFlag):
		// The pinned v1.18 install path only consults --profile version= when
		// --kubeedge-version is empty, so an argv carrying both selectors does
		// not have one reviewed meaning.
		return keadmSelectorBoth, true
	case legacyProfile && externalProfile:
		// Repeated --profile options with different meanings.
		return keadmSelectorUnsupported, true
	case legacyProfile:
		return keadmSelectorLegacy, true
	case externalProfile || unsupportedVersionFlag:
		return keadmSelectorUnsupported, true
	case versionFlag:
		return keadmSelectorVersionFlag, true
	default:
		return keadmSelectorNeither, true
	}
}

// kubeEdgeReviewedPair covers exactly the one packaged KubeEdge transition; no
// other origin or target is admitted.
func kubeEdgeReviewedPair(from, to string) bool {
	return from == KubeEdgeFrom && to == KubeEdgeTo
}
