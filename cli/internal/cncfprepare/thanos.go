// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "strings"

// Thanos 0.42 removes one literal flag from each of its Receive and Store
// subcommands. This adapter reads one caller-supplied Kubernetes workload JSON
// object. It neither contacts Kubernetes nor infers generated arguments,
// image provenance, Query compatibility, compaction, storage, or runtime
// behavior.
const (
	ThanosComponent = "pkg:github/thanos-io/thanos"
	ThanosFact      = "component.thanos.removed_subcommand_flags_present"
	ThanosFrom      = "0.41.0"
	ThanosTo        = "0.42.0"
	ThanosLatestTo  = "0.42.4"
)

const (
	ReasonThanosRemovedFlagPresent    Reason = "THANOS_REMOVED_RECEIVE_OR_STORE_FLAG_PRESENT"
	ReasonThanosRemovedFlagAbsent     Reason = "THANOS_REMOVED_RECEIVE_OR_STORE_FLAG_ABSENT"
	ReasonThanosWorkloadUnsupported   Reason = "THANOS_WORKLOAD_INPUT_UNSUPPORTED"
	ReasonThanosTransitionUnsupported Reason = "THANOS_TRANSITION_NOT_REVIEWED"
)

// PrepareThanos accepts only apps/v1 Deployment, StatefulSet, or DaemonSet
// objects with one explicitly named "thanos" container. The retained
// 0.41.0 -> 0.42.0 route requires command:["thanos"]. The exact 0.42.4
// routes require command:["/bin/thanos"] or an omitted command bound to the
// captured target Dockerfile ENTRYPOINT. All routes require an admitted
// upstream image tagged for the target endpoint. Args begin with the literal
// Receive or Store subcommand and have no argument delimiter or Kingpin @file
// expansion: opaque expanded arguments are never used to conclude that an
// option is absent. Sidecars are allowed when their names make Thanos
// selection unambiguous.
func PrepareThanos(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	present, ok, sourceDerivedEntrypoint := false, false, false
	fact := inputFact{ID: ThanosFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonThanosTransitionUnsupported
	if grammar, reviewed := thanosReviewedTransition(from, to); reviewed {
		present, ok, sourceDerivedEntrypoint = thanosRemovedFlagFact(value, to, grammar)
		reason = ReasonThanosWorkloadUnsupported
	}
	if ok {
		fact.State = "declared"
		fact.BoolValue = &present
		state = StatePrepared
		if present {
			reason = ReasonThanosRemovedFlagPresent
		} else {
			reason = ReasonThanosRemovedFlagAbsent
		}
	}
	canonical, err := marshalComponentInput(ThanosComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	omissions := []string{
		"NATIVE_WORKLOAD_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
		"GENERATED_ARGUMENT_SOURCES_IMAGE_PROVENANCE_AND_RUNTIME_NOT_EVALUATED",
		"QUERY_STORAGE_COMPACTION_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
	}
	if sourceDerivedEntrypoint {
		omissions = append(omissions, "DEFAULT_ENTRYPOINT_SOURCE_DERIVED_FOR_EXACT_ADMITTED_IMAGE_NOT_RUNTIME_OBSERVATION")
	} else {
		omissions = append(omissions, "DEFAULT_ENTRYPOINT_NOT_INFERRED")
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          omissions,
	}, nil
}

type thanosCommandGrammar uint8

const (
	thanosLegacyExplicitCommand thanosCommandGrammar = iota + 1
	thanosTargetEntrypointCommand
)

// thanosReviewedTransition preserves the historical 0.41.0 -> 0.42.0
// grammar exactly. The latest-target pairs accept only the source-qualified
// /bin/thanos command or its Dockerfile-derived omission. The exact origins
// make this a target argv constraint, not a claim about every hop's behavior.
func thanosReviewedTransition(from, to string) (thanosCommandGrammar, bool) {
	if from == ThanosFrom && to == ThanosTo {
		return thanosLegacyExplicitCommand, true
	}
	if to != ThanosLatestTo {
		return 0, false
	}
	switch from {
	case "0.37.2", "0.38.0", "0.39.2", "0.40.1", "0.41.0":
		return thanosTargetEntrypointCommand, true
	default:
		return 0, false
	}
}

func thanosRemovedFlagFact(value any, to string, grammar thanosCommandGrammar) (bool, bool, bool) {
	root, ok := value.(map[string]any)
	if !ok || root["apiVersion"] != "apps/v1" || !oneOfString(root["kind"], "Deployment", "StatefulSet", "DaemonSet") {
		return false, false, false
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok || !nonemptyString(metadata["name"]) || !nonemptyString(metadata["namespace"]) {
		return false, false, false
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return false, false, false
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return false, false, false
	}
	templateSpec, ok := template["spec"].(map[string]any)
	if !ok {
		return false, false, false
	}
	containers, ok := templateSpec["containers"].([]any)
	if !ok || len(containers) == 0 {
		return false, false, false
	}
	var args []any
	sourceDerivedEntrypoint := false
	found := 0
	names := make(map[string]struct{}, len(containers))
	for _, item := range containers {
		container, ok := item.(map[string]any)
		name, named := container["name"].(string)
		if !ok || !named || name == "" {
			return false, false, false
		}
		if _, duplicate := names[name]; duplicate {
			return false, false, false
		}
		names[name] = struct{}{}
		if name != "thanos" {
			continue
		}
		found++
		var argsOK, commandOK bool
		args, argsOK = container["args"].([]any)
		if !argsOK || len(args) == 0 || !targetImage(container["image"], to) {
			return false, false, false
		}
		command, exists := container["command"]
		if grammar == thanosTargetEntrypointCommand && !exists {
			// The captured v0.42.4 Dockerfile binds an omitted command to
			// /bin/thanos for the exact admitted image; it is not runtime proof.
			commandOK = true
			sourceDerivedEntrypoint = true
		} else {
			words, wordsOK := command.([]any)
			commandOK = wordsOK && len(words) == 1 && thanosCommand(words[0], grammar)
		}
		if !commandOK {
			return false, false, false
		}
	}
	if found != 1 {
		return false, false, false
	}
	words := make([]string, len(args))
	for i, item := range args {
		word, ok := item.(string)
		if !ok || word == "" || strings.ContainsRune(word, '\x00') || strings.Contains(word, "$") || strings.HasPrefix(word, "@") {
			return false, false, false
		}
		words[i] = word
	}
	if words[0] != "receive" && words[0] != "store" {
		return false, false, false
	}
	for _, word := range words[1:] {
		if word == "--" {
			return false, false, false
		}
	}
	if grammar == thanosTargetEntrypointCommand {
		if words[0] == "receive" {
			present, admitted := thanosLatestLiteralFlagFact(words[1:], "--shipper.ignore-unequal-block-size")
			return present, admitted, sourceDerivedEntrypoint
		}
		present, admitted := thanosLatestLiteralFlagFact(words[1:], "--debug.advertise-compatibility-label")
		return present, admitted, sourceDerivedEntrypoint
	}
	if words[0] == "receive" {
		return literalFlagPresent(words[1:], "--shipper.ignore-unequal-block-size"), true, sourceDerivedEntrypoint
	}
	return literalFlagPresent(words[1:], "--debug.advertise-compatibility-label"), true, sourceDerivedEntrypoint
}

func oneOfString(value any, choices ...string) bool {
	text, ok := value.(string)
	return ok && oneOf(text, choices...)
}

func literalFlagPresent(words []string, flag string) bool {
	for _, word := range words {
		// This rule covers removal of the option itself, not an inferred
		// historical Boolean value. Empty, false, negative-alias, and duplicate
		// appearances still retain the removed spelling in the supplied argv.
		if literalFlagWord(word, flag) {
			return true
		}
	}
	return false
}

// thanosLatestLiteralFlagFact admits only self-contained target argv atoms.
// A bare unrelated option may consume the following token, so it cannot prove
// whether a removed-looking word is an option or that option's value.
func thanosLatestLiteralFlagFact(words []string, flag string) (present bool, admitted bool) {
	for _, word := range words {
		if literalFlagWord(word, flag) {
			present = true
			continue
		}
		if !strings.HasPrefix(word, "-") || !strings.Contains(word, "=") {
			return false, false
		}
	}
	return present, true
}

func literalFlagWord(word, flag string) bool {
	negative := "--no-" + strings.TrimPrefix(flag, "--")
	return word == flag || strings.HasPrefix(word, flag+"=") || word == negative || strings.HasPrefix(word, negative+"=")
}

// targetImage recognizes the two image locations documented in the retained
// Thanos changelog source (quay.io/thanos/thanos and the thanosio/thanos
// Docker Hub mirror). It binds a supplied target manifest to an upstream image
// identity and target tag without claiming that it was pulled or deployed.
func targetImage(value any, to string) bool {
	image, ok := value.(string)
	if !ok || strings.Contains(image, "@") {
		return false
	}
	for _, repository := range []string{"quay.io/thanos/thanos", "thanosio/thanos", "docker.io/thanosio/thanos"} {
		if image == repository+":v"+to {
			return true
		}
	}
	return false
}

func thanosCommand(value any, grammar thanosCommandGrammar) bool {
	command, ok := value.(string)
	if !ok {
		return false
	}
	if grammar == thanosLegacyExplicitCommand {
		return command == "thanos"
	}
	return command == "/bin/thanos"
}
