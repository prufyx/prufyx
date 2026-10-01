// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	JaegerComponent                 = "pkg:github/jaegertracing/jaeger"
	JaegerExplicitConfigFact        = "component.jaeger.explicit_config_provided"
	JaegerNonMemoryStorageFact      = "component.jaeger.non_memory_storage_required"
	JaegerOfficialDistributionFact  = "component.jaeger.official_jaeger_distribution"
	JaegerFrom                      = "1.76.0"
	JaegerTo                        = "2.20.0"
	jaegerDirectInvocationAuthority = "OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY"
)

var jaegerExplicitConfigPairs = map[string]bool{
	"1.76.0\x002.20.0": true,
	"2.15.1\x002.20.0": true,
	"2.16.0\x002.20.0": true,
	"2.17.0\x002.20.0": true,
	"2.18.0\x002.20.0": true,
	"2.19.0\x002.20.0": true,
}

var ErrInvalidJaeger = ErrInvalid

const (
	ReasonJaegerConfigWitness    Reason = "JAEGER_SINGLETON_CONFIG_LITERAL_WITNESS"
	ReasonJaegerArgumentsUnknown Reason = "JAEGER_ARGUMENTS_UNRESOLVED"
	ReasonJaegerUnsupportedPair  Reason = "UNSUPPORTED_VERSION_PAIR"
)

// PrepareJaeger derives only the existing explicit-config fact from one private,
// operator-declared direct Jaeger v2 argv document. The first slice recognizes
// exactly one literal local --config=<value> atom. It neither reads that location
// nor infers its content, storage backend, credentials, distribution, or runtime.
func PrepareJaeger(raw []byte, from, to string, nonMemoryStorage, officialDistribution *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidJaeger
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalidJaeger
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"authority": true, "argv": true}) != nil {
		return Prepared{}, ErrInvalidJaeger
	}

	factState, factValue, reason, state := "missing", (*bool)(nil), ReasonJaegerArgumentsUnknown, StateUnknown
	if !jaegerExplicitConfigPairs[from+"\x00"+to] {
		reason = ReasonJaegerUnsupportedPair
	} else if jaegerSingletonLiteral(root) {
		present := true
		factState, factValue, reason, state = "declared", &present, ReasonJaegerConfigWitness, StatePrepared
	}
	canonical, err := marshalComponentInput(JaegerComponent, from, to, []inputFact{
		{ID: JaegerExplicitConfigFact, State: factState, BoolValue: factValue},
		jaegerManualFact(JaegerNonMemoryStorageFact, nonMemoryStorage),
		jaegerManualFact(JaegerOfficialDistributionFact, officialDistribution),
	})
	if err != nil {
		return Prepared{}, ErrInvalidJaeger
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CONFIG_LOCATION_EXISTENCE_AND_READABILITY_NOT_VERIFIED",
			"CONFIG_CONTENT_AND_STORAGE_BACKEND_NOT_EVALUATED",
			"CREDENTIALS_AND_STARTUP_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func jaegerManualFact(id string, value *bool) inputFact {
	if value == nil {
		return inputFact{ID: id, State: "missing"}
	}
	return inputFact{ID: id, State: "declared", BoolValue: value}
}

func jaegerSingletonLiteral(root map[string]any) bool {
	authority, authorityOK := root["authority"].(string)
	argv, argvOK := root["argv"].([]any)
	if !authorityOK || authority != jaegerDirectInvocationAuthority || !argvOK || len(argv) != 1 {
		return false
	}
	argument, argumentOK := argv[0].(string)
	if !argumentOK || !strings.HasPrefix(argument, "--config=") {
		return false
	}
	return jaegerLocalConfigLiteral(strings.TrimPrefix(argument, "--config="))
}

// jaegerLocalConfigLiteral intentionally accepts a small filesystem-like ASCII
// subset only. URI providers, expansion syntax, whitespace, quoting, and shell
// escapes are outside this direct-arguments-only contract and stay UNKNOWN.
func jaegerLocalConfigLiteral(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._/+-", character)) {
			return false
		}
	}
	return true
}
