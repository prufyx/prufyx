// SPDX-License-Identifier: AGPL-3.0-only

package certmanagervalues

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ExternalBundleSchema           = "prufyx.io/community-knowledge-bundle/v1"
	ExternalEngineCapabilityID     = "cert-manager.removed-monitor-values/v1"
	ExternalEngineCapabilityDigest = "sha256:3ef06fa67fcd51ca9bf2a6d6e8dd0ba8d68ce6bf3e58c8931e66844317c49e32"
	externalComponent              = "pkg:helm/quay.io/jetstack/charts/cert-manager"
	maxExternalBundleBytes         = 256 << 10
	maxExternalSources             = 8
	maxExternalSpans               = 16
	maxExternalIDBytes             = 128
	maxExternalURLBytes            = 2048
	maxRevisionOrdinal             = 1<<31 - 1
)

const externalEngineCapabilityContract = `{"schema":"prufyx.io/cert-manager-removed-monitor-values-engine/v1","operator":"presence","allowedPaths":["prometheus.servicemonitor.path","prometheus.servicemonitor.targetPort","prometheus.podmonitor.path"],"reportSchema":"prufyx.io/cert-manager-removed-monitor-values-assessment/v1alpha1"}`

var (
	externalRevisionRE   = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
	externalIDRE         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$`)
	externalReasonRE     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,95}$`)
	externalGitRevRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	externalSpanRE       = regexp.MustCompile(`^([1-9][0-9]{0,6})(?:-([1-9][0-9]{0,6}))?$`)
	externalMetricPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,127}$`)
	externalPortNameRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$`)
)

// ExternalBundle is a strictly parsed declarative target. It does not establish
// publisher identity or update trust. Only the separately reviewed store and
// verifier may attach those properties to an issued report.
type ExternalBundle struct {
	document     externalBundleDocument
	bundleDigest string
	ruleDigest   string
	reviewedAt   time.Time
	validUntil   time.Time
	seal         *externalBundleSeal
}

type externalBundleSeal struct{}

// ExternalAdmission is the bounded semantic identity returned to the store's
// import callback. It contains no claim of signature or origin verification.
type ExternalAdmission struct {
	Schema                 string
	Revision               string
	Purpose                string
	EngineCapabilityDigest string
	HasRule                bool
	EvidenceExpiresAt      string
	RuleDigest             string
	RuleID                 string
}

type externalBundleDocument struct {
	Schema               string                       `json:"schema"`
	Revision             string                       `json:"revision"`
	Purpose              string                       `json:"purpose"`
	RequiredCapabilities []externalCapabilityDocument `json:"requiredCapabilities"`
	Rules                []externalRuleDocument       `json:"rules"`
}

type externalCapabilityDocument struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type externalRuleDocument struct {
	ID               string                           `json:"id"`
	Operator         string                           `json:"operator"`
	Component        string                           `json:"component"`
	Current          externalChartDocument            `json:"current"`
	Target           externalChartDocument            `json:"target"`
	RemovedPaths     []string                         `json:"removedPaths"`
	ReplacementFacts externalReplacementFactsDocument `json:"replacementFacts"`
	Sources          []externalSourceDocument         `json:"sources"`
	Evidence         externalEvidenceDocument         `json:"evidence"`
}

type externalReplacementFactsDocument struct {
	MetricsPath     string `json:"metricsPath"`
	MetricsPortName string `json:"metricsPortName"`
}

type externalChartDocument struct {
	Version             string `json:"version"`
	ChartManifestDigest string `json:"chartManifestDigest"`
}

type externalSourceDocument struct {
	ID                   string   `json:"id"`
	URL                  string   `json:"url"`
	Revision             string   `json:"revision"`
	ContentDigest        string   `json:"contentDigest"`
	Spans                []string `json:"spans,omitempty"`
	LicensingDisposition string   `json:"licensingDisposition"`
}

type externalEvidenceDocument struct {
	State            string                      `json:"state"`
	ReviewedAt       string                      `json:"reviewedAt"`
	ValidUntil       string                      `json:"validUntil"`
	TestVectorDigest string                      `json:"testVectorDigest"`
	Withdrawal       *externalWithdrawalDocument `json:"withdrawal,omitempty"`
}

type externalWithdrawalDocument struct {
	ReasonCode string `json:"reasonCode"`
	SourceID   string `json:"sourceID"`
}

// ExternalArtifact contains only the private input digest and the selected
// rule's public path-presence projection. It is bound to the exact bundle and
// rule used for projection and retains no raw values.
type ExternalArtifact struct {
	digest        string
	matches       []string
	shapeResolved bool
	bundleDigest  string
	ruleDigest    string
	seal          *externalArtifactSeal
}

type externalArtifactSeal struct{}

type ExternalRequest struct {
	Values             ExternalArtifact
	From               string
	To                 string
	CurrentChartDigest string
	TargetChartDigest  string
	SchemaValidation   string
}

// ExternalProjection is an unsealed predicate result. It deliberately carries
// no origin-verification claim and cannot be passed to MarshalReport. The
// verifier-backed orchestration layer must bind its trust receipt before issuing
// any externally verified report.
type ExternalProjection struct {
	Schema                     string     `json:"schema"`
	Revision                   string     `json:"revision"`
	Purpose                    string     `json:"purpose"`
	BundleDigest               string     `json:"bundleDigest"`
	RuleID                     string     `json:"ruleID,omitempty"`
	RuleDigest                 string     `json:"ruleDigest,omitempty"`
	EngineCapabilityID         string     `json:"engineCapabilityID"`
	EngineCapabilityDigest     string     `json:"engineCapabilityDigest"`
	EvaluatedAt                string     `json:"evaluatedAt"`
	EvidenceReviewedAt         string     `json:"evidenceReviewedAt,omitempty"`
	EvidenceValidUntil         string     `json:"evidenceValidUntil,omitempty"`
	EvidenceState              string     `json:"evidenceState,omitempty"`
	EvidenceFreshness          string     `json:"evidenceFreshness"`
	Question                   string     `json:"question"`
	Scope                      string     `json:"scope"`
	Transition                 Transition `json:"transition"`
	Inputs                     Inputs     `json:"inputs"`
	Policy                     Policy     `json:"policy"`
	Claim                      Claim      `json:"claim"`
	MatchedPaths               []string   `json:"matchedPaths"`
	ReplacementMetricsPath     string     `json:"replacementMetricsPath,omitempty"`
	ReplacementMetricsPortName string     `json:"replacementMetricsPortName,omitempty"`
	Sources                    []Source   `json:"sources"`
	Omissions                  []string   `json:"omissions"`
	Truth                      Truth      `json:"truth"`
}

// ParseExternalBundle strictly admits a complete compatible declarative target.
// A compatible target may contain zero cert-manager rules; that is valid missing
// coverage and evaluates to UNKNOWN. A present partial rule is rejected.
func ParseExternalBundle(raw []byte) (ExternalBundle, error) {
	if len(raw) == 0 || len(raw) > maxExternalBundleBytes || !utf8.Valid(raw) {
		return ExternalBundle{}, externalIntegrity("bundle bytes")
	}
	if digestBytes([]byte(externalEngineCapabilityContract)) != ExternalEngineCapabilityDigest {
		return ExternalBundle{}, externalIntegrity("compiled capability identity")
	}
	if err := validateJSON(raw); err != nil {
		return ExternalBundle{}, externalIntegrity("bundle JSON")
	}
	if err := validateExternalShape(raw); err != nil {
		return ExternalBundle{}, err
	}
	var document externalBundleDocument
	if err := decodeClosed(raw, &document); err != nil {
		return ExternalBundle{}, externalIntegrity("bundle fields")
	}
	if err := validateExternalHeader(document); err != nil {
		return ExternalBundle{}, err
	}
	bundle := ExternalBundle{document: document, bundleDigest: digestBytes(raw), seal: &externalBundleSeal{}}
	if len(document.Rules) == 0 {
		return bundle, nil
	}
	rule := document.Rules[0]
	reviewedAt, validUntil, err := validateExternalRule(rule)
	if err != nil {
		return ExternalBundle{}, err
	}
	canonicalRule, err := json.Marshal(rule)
	if err != nil {
		return ExternalBundle{}, externalIntegrity("canonical rule")
	}
	bundle.ruleDigest = digestBytes(canonicalRule)
	bundle.reviewedAt = reviewedAt
	bundle.validUntil = validUntil
	return bundle, nil
}

func validateExternalShape(raw []byte) error {
	root, err := exactObject(raw,
		[]string{"schema", "revision", "purpose", "requiredCapabilities", "rules"}, nil)
	if err != nil {
		return err
	}
	capabilities, err := exactArray(root["requiredCapabilities"])
	if err != nil {
		return err
	}
	for _, capability := range capabilities {
		if _, err := exactObject(capability, []string{"id", "digest"}, nil); err != nil {
			return err
		}
	}
	rules, err := exactArray(root["rules"])
	if err != nil {
		return err
	}
	for _, ruleRaw := range rules {
		rule, err := exactObject(ruleRaw,
			[]string{"id", "operator", "component", "current", "target", "removedPaths", "replacementFacts", "sources", "evidence"}, nil)
		if err != nil {
			return err
		}
		for _, chartField := range []string{"current", "target"} {
			if _, err := exactObject(rule[chartField], []string{"version", "chartManifestDigest"}, nil); err != nil {
				return err
			}
		}
		if _, err := exactArray(rule["removedPaths"]); err != nil {
			return err
		}
		if _, err := exactObject(rule["replacementFacts"], []string{"metricsPath", "metricsPortName"}, nil); err != nil {
			return err
		}
		sources, err := exactArray(rule["sources"])
		if err != nil {
			return err
		}
		for _, sourceRaw := range sources {
			source, err := exactObject(sourceRaw,
				[]string{"id", "url", "revision", "contentDigest", "licensingDisposition"}, []string{"spans"})
			if err != nil {
				return err
			}
			if spans, present := source["spans"]; present {
				if _, err := exactArray(spans); err != nil {
					return err
				}
			}
		}
		evidence, err := exactObject(rule["evidence"],
			[]string{"state", "reviewedAt", "validUntil", "testVectorDigest"}, []string{"withdrawal"})
		if err != nil {
			return err
		}
		if withdrawal, present := evidence["withdrawal"]; present {
			if _, err := exactObject(withdrawal, []string{"reasonCode", "sourceID"}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func exactObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, externalIntegrity("object shape")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil || fields == nil {
		return nil, externalIntegrity("object shape")
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, present := fields[name]; !present {
			return nil, externalIntegrity("required field")
		}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	for name := range fields {
		if _, present := allowed[name]; !present {
			return nil, externalIntegrity("unknown or case-aliased field")
		}
	}
	return fields, nil
}

func exactArray(raw []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
		return nil, externalIntegrity("array shape")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil || items == nil {
		return nil, externalIntegrity("array shape")
	}
	return items, nil
}

func (bundle ExternalBundle) Admission() (ExternalAdmission, error) {
	if !bundle.valid() {
		return ExternalAdmission{}, externalIntegrity("bundle capability")
	}
	admission := ExternalAdmission{
		Schema:                 bundle.document.Schema,
		Revision:               bundle.document.Revision,
		Purpose:                bundle.document.Purpose,
		EngineCapabilityDigest: ExternalEngineCapabilityDigest,
		HasRule:                len(bundle.document.Rules) == 1,
		RuleDigest:             bundle.ruleDigest,
	}
	if len(bundle.document.Rules) == 1 {
		admission.EvidenceExpiresAt = bundle.document.Rules[0].Evidence.ValidUntil
		admission.RuleID = bundle.document.Rules[0].ID
	}
	return admission, nil
}

func (bundle ExternalBundle) valid() bool {
	return bundle.seal != nil && digestRE.MatchString(bundle.bundleDigest) &&
		bundle.document.Schema == ExternalBundleSchema &&
		len(bundle.document.RequiredCapabilities) == 1 &&
		bundle.document.RequiredCapabilities[0].ID == ExternalEngineCapabilityID &&
		bundle.document.RequiredCapabilities[0].Digest == ExternalEngineCapabilityDigest &&
		len(bundle.document.Rules) <= 1
}

// ParseExternalArtifact applies only the rule selected from bundle. The result
// cannot later be evaluated with a different bundle or rule.
func ParseExternalArtifact(raw []byte, expectedDigest string, bundle ExternalBundle) (ExternalArtifact, error) {
	if !bundle.valid() {
		return ExternalArtifact{}, externalIntegrity("bundle capability")
	}
	digest, root, err := parseValuesRoot(raw, expectedDigest)
	if err != nil {
		return ExternalArtifact{}, err
	}
	var paths []string
	if len(bundle.document.Rules) == 1 {
		paths = bundle.document.Rules[0].RemovedPaths
	}
	matches, resolved := inspectPaths(root, paths)
	return ExternalArtifact{
		digest: digest, matches: matches, shapeResolved: resolved,
		bundleDigest: bundle.bundleDigest, ruleDigest: bundle.ruleDigest,
		seal: &externalArtifactSeal{},
	}, nil
}

// ReadExternalArtifact applies the same descriptor-relative, no-follow and
// private-file contract as the embedded check before making the rule-bound
// projection.
func ReadExternalArtifact(path, expectedDigest string, bundle ExternalBundle) (ExternalArtifact, error) {
	raw, err := readPrivateValues(path)
	if err != nil {
		return ExternalArtifact{}, err
	}
	return ParseExternalArtifact(raw, expectedDigest, bundle)
}

// EvaluateExternalProjection evaluates only declarative data. evaluatedAt must
// come from the verifier-backed orchestration layer for a current check, or from
// the recorded receipt for a separately labeled historical replay.
func EvaluateExternalProjection(req ExternalRequest, bundle ExternalBundle, evaluatedAt time.Time) (ExternalProjection, error) {
	if !bundle.valid() || req.Values.seal == nil || req.Values.bundleDigest != bundle.bundleDigest || req.Values.ruleDigest != bundle.ruleDigest || !digestRE.MatchString(req.Values.digest) {
		return ExternalProjection{}, externalIntegrity("external evaluation capability")
	}
	if evaluatedAt.IsZero() {
		return ExternalProjection{}, externalIntegrity("evaluation time")
	}
	if len(req.From) > 32 || len(req.To) > 32 || !versionRE.MatchString(req.From) || !versionRE.MatchString(req.To) {
		return ExternalProjection{}, fmt.Errorf("chart version syntax: %w", ErrInvalid)
	}
	if req.SchemaValidation == "" {
		req.SchemaValidation = "required"
	}
	if req.SchemaValidation != "required" && req.SchemaValidation != "disabled" {
		return ExternalProjection{}, fmt.Errorf("schema validation policy: %w", ErrInvalid)
	}

	projection := ExternalProjection{
		Schema: ExternalBundleSchema, Revision: bundle.document.Revision,
		Purpose: bundle.document.Purpose, BundleDigest: bundle.bundleDigest,
		EngineCapabilityID: ExternalEngineCapabilityID, EngineCapabilityDigest: ExternalEngineCapabilityDigest,
		EvaluatedAt:  evaluatedAt.UTC().Format(time.RFC3339Nano),
		Inputs:       Inputs{ValuesDigest: req.Values.digest, KnowledgeRevisionDigest: bundle.bundleDigest},
		Policy:       Policy{SchemaValidation: req.SchemaValidation, Meaning: "required means Helm target schema rejection is enforced; disabled means removed overrides may render but are ignored by target templates"},
		Omissions:    []string{"FULL_TARGET_HELM_SCHEMA_NOT_EVALUATED", "RUNTIME_BEHAVIOR_NOT_EVALUATED", "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED"},
		Truth:        Truth{Offline: true},
		MatchedPaths: []string{}, Sources: []Source{},
	}
	if len(bundle.document.Rules) == 0 {
		projection.EvidenceFreshness = "missing"
		projection.Question = "Is this cert-manager transition covered by the selected external removed-monitor-values knowledge revision?"
		projection.Scope = "selected external cert-manager removed-monitor-values coverage only; no embedded knowledge is used"
		projection.Transition = Transition{Component: externalComponent, DeclaredTransitionState: "unsupported", IdentityAssumption: "the selected external revision contains no cert-manager rule"}
		projection.Claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_KNOWLEDGE_RULE_MISSING", Reason: "the selected external revision contains no compatible cert-manager removed-monitor-values rule", Remediation: "select a complete reviewed external revision that covers the intended transition"}
		return projection, nil
	}

	rule := bundle.document.Rules[0]
	projection.RuleID = rule.ID
	projection.RuleDigest = bundle.ruleDigest
	projection.EvidenceReviewedAt = rule.Evidence.ReviewedAt
	projection.EvidenceValidUntil = rule.Evidence.ValidUntil
	projection.EvidenceState = rule.Evidence.State
	projection.Question = fmt.Sprintf("Does the exact proposed merged values object contain any of the %s curated monitoring keys removed by cert-manager %s?", countName(len(rule.RemovedPaths)), rule.Target.Version)
	projection.Scope = fmt.Sprintf("presence of %s curated removed values only; not full Helm schema validation, runtime behavior, or whole-upgrade compatibility", countName(len(rule.RemovedPaths)))
	projection.Transition = Transition{Component: rule.Component, DeclaredTransitionState: "exact_reviewed", ReviewedFrom: rule.Current.Version, ReviewedTo: rule.Target.Version, CurrentChartManifestDigest: rule.Current.ChartManifestDigest, TargetChartManifestDigest: rule.Target.ChartManifestDigest, IdentityAssumption: "the selected external rule declares reviewed chart versions and digests; this projection does not prove either chart is the user's deployed artifact or independently verify the rule's source claims"}
	projection.MatchedPaths = append([]string(nil), req.Values.matches...)
	projection.ReplacementMetricsPath = rule.ReplacementFacts.MetricsPath
	projection.ReplacementMetricsPortName = rule.ReplacementFacts.MetricsPortName
	projection.Sources = externalSources(rule.Sources)

	if req.CurrentChartDigest != "" && req.CurrentChartDigest != rule.Current.ChartManifestDigest {
		return ExternalProjection{}, fmt.Errorf("current chart digest assertion: %w", ErrIntegrity)
	}
	if req.TargetChartDigest != "" && req.TargetChartDigest != rule.Target.ChartManifestDigest {
		return ExternalProjection{}, fmt.Errorf("target chart digest assertion: %w", ErrIntegrity)
	}

	projection.Claim = removedMonitorClaim(req.Values.shapeResolved, req.Values.matches, req.SchemaValidation, len(rule.RemovedPaths), rule.ReplacementFacts.MetricsPath, rule.ReplacementFacts.MetricsPortName)
	if req.From != rule.Current.Version || req.To != rule.Target.Version {
		projection.Transition.DeclaredTransitionState = "unsupported"
		projection.Transition.IdentityAssumption = "the declared transition is outside the selected external knowledge revision"
		projection.Claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_TRANSITION_NOT_REVIEWED", Reason: "the declared semantic-version transition is not covered by the selected external knowledge revision", Remediation: fmt.Sprintf("use the reviewed %s to %s transition or select a reviewed external revision for the intended versions", rule.Current.Version, rule.Target.Version)}
	}

	now := evaluatedAt.UTC()
	switch {
	case rule.Evidence.State == "withdrawn":
		projection.EvidenceFreshness = "withdrawn"
		projection.Claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_KNOWLEDGE_EVIDENCE_WITHDRAWN", Reason: "the selected rule evidence has been withdrawn", Remediation: "select a later reviewed external revision or perform the check manually"}
	case now.Before(bundle.reviewedAt):
		projection.EvidenceFreshness = "clock_before_review"
		projection.Claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_KNOWLEDGE_TIME_UNVERIFIED", Reason: "the evaluation clock is before the rule review time", Remediation: "correct the local clock and repeat the current verified selection"}
	case !now.Before(bundle.validUntil):
		projection.EvidenceFreshness = "stale"
		projection.Claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_KNOWLEDGE_EVIDENCE_STALE", Reason: "the selected rule evidence is outside its reviewed validity window", Remediation: "select a later reviewed external revision or perform the check manually"}
	default:
		projection.EvidenceFreshness = "current"
	}
	return projection, nil
}

func validateExternalHeader(document externalBundleDocument) error {
	if document.Schema != ExternalBundleSchema || !externalRevisionRE.MatchString(document.Revision) {
		return externalIntegrity("bundle schema or revision")
	}
	revision, err := strconv.ParseInt(document.Revision, 10, 32)
	if err != nil || revision <= 0 || revision > maxRevisionOrdinal {
		return externalIntegrity("bundle revision")
	}
	if document.Purpose != "operator_provided" && document.Purpose != "synthetic_test_only" {
		return externalIntegrity("bundle purpose")
	}
	if len(document.RequiredCapabilities) != 1 || document.RequiredCapabilities[0].ID != ExternalEngineCapabilityID || document.RequiredCapabilities[0].Digest != ExternalEngineCapabilityDigest {
		return externalIntegrity("required capability")
	}
	if len(document.Rules) > 1 {
		return externalIntegrity("rule count")
	}
	return nil
}

func validateExternalRule(rule externalRuleDocument) (time.Time, time.Time, error) {
	if !validExternalID(rule.ID) || rule.Operator != ExternalEngineCapabilityID || rule.Component != externalComponent {
		return time.Time{}, time.Time{}, externalIntegrity("rule identity")
	}
	if !versionRE.MatchString(rule.Current.Version) || !versionRE.MatchString(rule.Target.Version) || !digestRE.MatchString(rule.Current.ChartManifestDigest) || !digestRE.MatchString(rule.Target.ChartManifestDigest) {
		return time.Time{}, time.Time{}, externalIntegrity("rule transition")
	}
	if err := validateExternalPaths(rule.RemovedPaths); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !externalMetricPathRE.MatchString(rule.ReplacementFacts.MetricsPath) || strings.Contains(rule.ReplacementFacts.MetricsPath, "//") || strings.Contains(rule.ReplacementFacts.MetricsPath, "/../") || strings.HasSuffix(rule.ReplacementFacts.MetricsPath, "/..") || !externalPortNameRE.MatchString(rule.ReplacementFacts.MetricsPortName) {
		return time.Time{}, time.Time{}, externalIntegrity("replacement facts")
	}
	if len(rule.Sources) == 0 || len(rule.Sources) > maxExternalSources {
		return time.Time{}, time.Time{}, externalIntegrity("rule source count")
	}
	sourceIDs := make(map[string]struct{}, len(rule.Sources))
	for _, source := range rule.Sources {
		if err := validateExternalSource(source); err != nil {
			return time.Time{}, time.Time{}, err
		}
		if _, exists := sourceIDs[source.ID]; exists {
			return time.Time{}, time.Time{}, externalIntegrity("duplicate source ID")
		}
		sourceIDs[source.ID] = struct{}{}
	}
	reviewedAt, err := parseExternalTime(rule.Evidence.ReviewedAt)
	if err != nil {
		return time.Time{}, time.Time{}, externalIntegrity("evidence review time")
	}
	validUntil, err := parseExternalTime(rule.Evidence.ValidUntil)
	if err != nil || !validUntil.After(reviewedAt) || !digestRE.MatchString(rule.Evidence.TestVectorDigest) {
		return time.Time{}, time.Time{}, externalIntegrity("evidence validity")
	}
	switch rule.Evidence.State {
	case "active":
		if rule.Evidence.Withdrawal != nil {
			return time.Time{}, time.Time{}, externalIntegrity("active evidence withdrawal")
		}
	case "withdrawn":
		withdrawal := rule.Evidence.Withdrawal
		if withdrawal == nil || !externalReasonRE.MatchString(withdrawal.ReasonCode) {
			return time.Time{}, time.Time{}, externalIntegrity("withdrawal")
		}
		if _, exists := sourceIDs[withdrawal.SourceID]; !exists {
			return time.Time{}, time.Time{}, externalIntegrity("withdrawal source")
		}
	default:
		return time.Time{}, time.Time{}, externalIntegrity("evidence state")
	}
	return reviewedAt, validUntil, nil
}

func validateExternalPaths(paths []string) error {
	if len(paths) == 0 || len(paths) > len(removedPaths) {
		return externalIntegrity("removed path count")
	}
	allowedIndex := make(map[string]int, len(removedPaths))
	for index, path := range removedPaths {
		allowedIndex[path] = index
	}
	last := -1
	for _, path := range paths {
		index, ok := allowedIndex[path]
		if !ok || index <= last {
			return externalIntegrity("removed path grammar or order")
		}
		last = index
	}
	return nil
}

func validateExternalSource(source externalSourceDocument) error {
	if !validExternalID(source.ID) || len(source.URL) == 0 || len(source.URL) > maxExternalURLBytes || !externalGitRevRE.MatchString(source.Revision) || !digestRE.MatchString(source.ContentDigest) || source.LicensingDisposition != "reference-only" {
		return externalIntegrity("source fields")
	}
	parsed, err := url.Parse(source.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || !strings.Contains(parsed.EscapedPath(), "/"+source.Revision+"/") {
		return externalIntegrity("source URL")
	}
	if len(source.Spans) > maxExternalSpans {
		return externalIntegrity("source span count")
	}
	lastEnd := 0
	for _, span := range source.Spans {
		match := externalSpanRE.FindStringSubmatch(span)
		if match == nil {
			return externalIntegrity("source span")
		}
		start, _ := strconv.Atoi(match[1])
		end := start
		if match[2] != "" {
			end, _ = strconv.Atoi(match[2])
		}
		if end < start || start <= lastEnd {
			return externalIntegrity("source span order")
		}
		lastEnd = end
	}
	return nil
}

func parseExternalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrIntegrity
	}
	return parsed, nil
}

func validExternalID(value string) bool {
	return len(value) <= maxExternalIDBytes && externalIDRE.MatchString(value)
}

func decodeClosed(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func externalSources(sources []externalSourceDocument) []Source {
	result := make([]Source, len(sources))
	for index, source := range sources {
		result[index] = Source{ID: source.ID, URL: source.URL, ContentDigest: source.ContentDigest, Spans: append([]string(nil), source.Spans...)}
	}
	return result
}

func externalIntegrity(part string) error {
	return fmt.Errorf("external knowledge %s: %w", part, ErrIntegrity)
}
