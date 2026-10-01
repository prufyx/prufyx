// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	InTotoComponent       = "pkg:github/in-toto/in-toto"
	InTotoRunKeyFact      = "component.in_toto.in_toto_run_key_argument"
	InTotoRunKeyLegacy    = "legacy_key"
	InTotoRunKeySigning   = "signing_key"
	InTotoFrom            = "2.2.0"
	InTotoTo              = "3.0.0"
	maxInTotoArgvItems    = 256
	maxInTotoArgumentSize = 4096
)

const (
	ReasonInTotoRunArgumentObserved     Reason = "IN_TOTO_RUN_KEY_ARGUMENT_OBSERVED"
	ReasonInTotoRunArgumentsUnsupported Reason = "IN_TOTO_RUN_ARGUMENT_SHAPE_UNSUPPORTED"
)

// PrepareInTotoRun derives only the pre-boundary signing option family from a
// supplied planned argv array. It does not authenticate a running process,
// read a key, split shell text, or inspect the opaque wrapped command.
func PrepareInTotoRun(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	argv, ok := inTotoStringArray(value)
	fact := inputFact{ID: InTotoRunKeyFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonInTotoRunArgumentsUnsupported
	if ok {
		if family, supported := inspectInTotoRunArgv(argv); supported {
			fact = inputFact{ID: InTotoRunKeyFact, State: "declared", EnumValue: family}
			state, reason = StatePrepared, ReasonInTotoRunArgumentObserved
		}
	}
	canonical, err := marshalComponentInput(InTotoComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"PROCESS_AND_VERSION_PROVENANCE_NOT_ESTABLISHED",
		"KEY_FORMAT_LOAD_PASSWORD_AND_SIGNING_NOT_EVALUATED",
		"WRAPPED_COMMAND_NOT_EVALUATED",
		OmissionNoWholeUpgrade,
	}}, nil
}

func inTotoStringArray(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > maxInTotoArgvItems {
		return nil, false
	}
	argv := make([]string, len(items))
	for i, item := range items {
		arg, ok := item.(string)
		if !ok || len(arg) > maxInTotoArgumentSize || !utf8.ValidString(arg) || strings.IndexFunc(arg, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, false
		}
		argv[i] = arg
	}
	return argv, true
}

func inspectInTotoRunArgv(argv []string) (string, bool) {
	if len(argv) < 7 || argv[0] != "in-toto-run" || (argv[1] != "-n" && argv[1] != "--step-name") || !inTotoOptionValue(argv[2]) {
		return "", false
	}
	family := ""
	switch argv[3] {
	case "-k", "--key":
		family = InTotoRunKeyLegacy
	case "--signing-key":
		family = InTotoRunKeySigning
	default:
		return "", false
	}
	if !inTotoOptionValue(argv[4]) || argv[5] != "--" || len(argv[6:]) == 0 || argv[6] == "" {
		return "", false
	}
	// Every token after this first valid boundary belongs to the wrapped
	// command. Key-looking tokens and later delimiters are deliberately opaque.
	return family, true
}

func inTotoOptionValue(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-")
}
