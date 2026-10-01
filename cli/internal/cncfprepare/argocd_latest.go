// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ArgoCDLatestTo               = "3.5.2"
	ArgoCDLatestDistributionFact = "component.argo_cd.latest_distribution"
	ArgoCDLatestSurfaceFact      = "component.argo_cd.latest_execution_surface"
	ArgoCDLatestRepositoryFact   = "component.argo_cd.plain_http_oci_repository_unusable"
	ArgoCDLatestResolvedFact     = "component.argo_cd.repository_settings_complete_and_precedence_resolved"
	ArgoCDLatestPlainHTTPFact    = "component.argo_cd.selected_repository_uses_plain_http"

	ArgoCDLatestDistributionOfficial = "official_upstream"
	ArgoCDLatestDistributionCustom   = "custom_build"
	ArgoCDLatestRepositorySurface    = "repository_secret"
)

var argoCDLatestOrigins = [...]string{"3.4.8", "3.3.14", "3.2.12", "3.1.16", "3.0.23"}

const (
	ReasonArgoCDLatestBlocked         Reason = "ARGO_CD_PLAIN_HTTP_OCI_REPOSITORY_UNUSABLE"
	ReasonArgoCDLatestClear           Reason = "ARGO_CD_SELECTED_OCI_REPOSITORY_CLEAR"
	ReasonArgoCDLatestUnsupported     Reason = "ARGO_CD_REPOSITORY_SECRET_UNSUPPORTED"
	ReasonArgoCDLatestUnsupportedPair Reason = "ARGO_CD_UNSUPPORTED_VERSION_PAIR"
	ReasonArgoCDLatestGuardMissing    Reason = "ARGO_CD_DISTRIBUTION_GUARD_MISSING"
)

// PrepareArgoCDLatestRepository examines one caller-selected, pre-apply v1
// repository Secret using stringData. It projects only whether a selected OCI
// repository is unusable under the reviewed Helm 4 plain-HTTP boundary. Secret
// values, names, URLs, credentials, and unrelated fields are discarded.
func PrepareArgoCDLatestRepository(raw []byte, from, to, distribution string, settingsResolved, usesPlainHTTP *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) ||
		!validVersionSyntax(from) || !validVersionSyntax(to) || from == to ||
		(distribution != "" && distribution != ArgoCDLatestDistributionOfficial && distribution != ArgoCDLatestDistributionCustom) {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}

	surfaceState, conditionState := "unsupported", "unsupported"
	var condition *bool
	state, reason := StateUnknown, ReasonArgoCDLatestUnsupported
	if !argoCDLatestPairSupported(from, to) {
		reason = ReasonArgoCDLatestUnsupportedPair
	} else if blocked, ok := inspectArgoCDLatestRepository(value); ok {
		surfaceState, conditionState = "declared", "declared"
		condition = &blocked
		state = StatePrepared
		if blocked {
			reason = ReasonArgoCDLatestBlocked
		} else {
			reason = ReasonArgoCDLatestClear
		}
	}
	if distribution != ArgoCDLatestDistributionOfficial || settingsResolved == nil || !*settingsResolved {
		state, reason = StateUnknown, ReasonArgoCDLatestGuardMissing
	}

	facts := []inputFact{
		{ID: ArgoCDLatestDistributionFact, State: "missing"},
		{ID: ArgoCDLatestSurfaceFact, State: surfaceState},
		{ID: ArgoCDLatestRepositoryFact, State: conditionState, BoolValue: condition},
		{ID: ArgoCDLatestResolvedFact, State: "missing"},
		{ID: ArgoCDLatestPlainHTTPFact, State: "missing"},
	}
	if distribution != "" {
		facts[0].State, facts[0].EnumValue = "declared", distribution
	}
	if surfaceState == "declared" {
		facts[1].EnumValue = ArgoCDLatestRepositorySurface
	}
	if settingsResolved != nil {
		facts[3].State, facts[3].BoolValue = "declared", settingsResolved
	}
	if usesPlainHTTP != nil {
		facts[4].State, facts[4].BoolValue = "declared", usesPlainHTTP
	}
	if usesPlainHTTP == nil || !*usesPlainHTTP {
		state, reason = StateUnknown, ReasonArgoCDLatestGuardMissing
	}
	canonical, err := marshalComponentInput(ArgoCDComponent, from, to, facts)
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
			"ONE_CALLER_SELECTED_PRE_APPLY_REPOSITORY_SECRET_ONLY",
			"SECRET_VALUES_NAMES_URLS_AND_CREDENTIALS_DISCARDED",
			"REPOSITORY_CONNECTIVITY_HELM_EXECUTION_AND_RUNTIME_NOT_PERFORMED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func argoCDLatestPairSupported(from, to string) bool {
	if to != ArgoCDLatestTo {
		return false
	}
	for _, origin := range argoCDLatestOrigins {
		if from == origin {
			return true
		}
	}
	return false
}

func inspectArgoCDLatestRepository(value any) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "type": true, "stringData": true}) != nil {
		return false, false
	}
	api, err := requiredString(root, "apiVersion")
	if err != nil || api != "v1" {
		return false, false
	}
	kind, err := requiredString(root, "kind")
	if err != nil || kind != "Secret" {
		return false, false
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok || allowFields(metadata, map[string]bool{"name": true, "namespace": true, "labels": true}) != nil {
		return false, false
	}
	name, err := requiredString(metadata, "name")
	if err != nil || !safeArgoIdentity(name) {
		return false, false
	}
	labels, ok := metadata["labels"].(map[string]any)
	if !ok {
		return false, false
	}
	secretKind, err := requiredString(labels, "argocd.argoproj.io/secret-type")
	if err != nil || secretKind != "repository" {
		return false, false
	}
	if secretType, exists := root["type"]; exists {
		text, ok := secretType.(string)
		if !ok || text != "Opaque" {
			return false, false
		}
	}
	data, ok := root["stringData"].(map[string]any)
	if !ok {
		return false, false
	}
	repositoryType, ok := argoCDSecretString(data, "type")
	if !ok {
		return false, false
	}
	enableOCI, ok := argoCDSecretBool(data, "enableOCI")
	// The reviewed conflicting-flags claim is specific to a type=helm
	// repository with OCI enabled. Native type=oci and dependency-chain cases
	// need additional context and remain UNKNOWN.
	if !ok || repositoryType != "helm" || !enableOCI {
		return false, false
	}
	repositoryURL, ok := argoCDSecretString(data, "url")
	if !ok || !safeArgoOCIRepository(repositoryURL) {
		return false, false
	}
	forceHTTP, ok := argoCDSecretBool(data, "insecureOCIForceHttp")
	if !ok {
		return false, false
	}
	insecure, ok := argoCDSecretBool(data, "insecure")
	if !ok {
		return false, false
	}
	return !forceHTTP || insecure, true
}

func argoCDSecretString(data map[string]any, key string) (string, bool) {
	value, exists := data[key]
	if !exists {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func argoCDSecretBool(data map[string]any, key string) (bool, bool) {
	value, exists := data[key]
	if !exists {
		return false, true
	}
	text, ok := value.(string)
	if !ok || (text != "true" && text != "false") {
		return false, false
	}
	return text == "true", true
}

func safeArgoIdentity(value string) bool {
	return value != "" && len(value) <= 253 && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func safeArgoOCIRepository(value string) bool {
	if value == "" || len(value) > 2048 || strings.Contains(value, "://") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return false
	}
	parsed, err := url.Parse("//" + value)
	return err == nil && parsed.Scheme == "" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && parsed.RawQuery == "" && parsed.Opaque == ""
}
