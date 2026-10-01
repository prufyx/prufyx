// SPDX-License-Identifier: AGPL-3.0-only

// Package constraintengine evaluates a deliberately small, data-only set of
// source-referenced compatibility constraints. It has no reader, downloader, or
// cluster capability: callers must explicitly declare minimized facts.
package constraintengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	InputSchema = "prufyx.io/operator-declared-constraint-input/v1alpha1"
	RulesSchema = "prufyx.io/deterministic-constraint-rules/v1alpha1"
	// RulesSchemaRanged is carried by, and only by, a rule document holding at
	// least one rule with a reviewed version range. Binaries that predate
	// ranges reject it outright rather than reading a range as its anchor.
	RulesSchemaRanged = "prufyx.io/deterministic-constraint-rules/v1alpha2"
	ReportSchema      = "prufyx.io/deterministic-constraint-report/v1alpha1"
	InputAuthority    = "OPERATOR_DECLARED_MINIMIZED"
	RulesAuthority    = "DECLARED_RULE_SOURCE_REFERENCES"
	EngineVersion     = "deterministic-constraint-engine-v1"

	// ScopeDeclaration is the caller's statement that the declared component
	// set is exactly the set under evaluation. It is checked against the
	// bundle at parse time; it is never accepted on assertion alone.
	ScopeDeclaration = "OPERATOR_DECLARED_COMPLETE_COMPONENT_SET"
	// CorpusAttestation is the rule maintainer's statement that, at this rule
	// revision, the document holds every reviewed rule whose subject is one of
	// the listed components. It is a statement about the corpus, not a
	// compatibility claim about any project.
	CorpusAttestation = "COMPLETE_REVIEWED_RULES_FOR_LISTED_COMPONENTS"
	// ScopeContractVersion identifies the scope-completeness contract. It is
	// deliberately separate from EngineVersion: the four constraint operators
	// and their semantics are unchanged by this mechanism.
	ScopeContractVersion = "scope-completeness-contract-v1"
	// ScopeContractVersionRanged adds the anchor-review condition for rule
	// documents that carry ranges. Exact-only documents keep the v1 contract
	// and its digest, so their reports replay byte-identically.
	ScopeContractVersionRanged = "scope-completeness-contract-v2"

	// AssessmentUnknown is the only aggregate a report without genuine
	// scope-completeness evidence may carry.
	AssessmentUnknown = "UNKNOWN"
	// AssessmentBlocked reports at least one applicable, decided blocker.
	AssessmentBlocked = "BLOCKED"
	// AssessmentScopeCompletePass states only that every constraint applicable
	// to the declared component set was evaluated and passed. It is not SAFE
	// and it makes no statement about anything outside the declared scope.
	AssessmentScopeCompletePass = "SCOPE_COMPLETE_PASS"

	ApplicabilityApplicable    = "APPLICABLE"
	ApplicabilityNotApplicable = "NOT_APPLICABLE"
	ApplicabilityUndetermined  = "UNDETERMINED"
	applicabilityOutOfScope    = "OUT_OF_SCOPE"

	omissionDeclaredInput          = "OPERATOR_DECLARED_INPUT_NOT_LIVE_OBSERVATION"
	omissionWholeUpgradeNotChecked = "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED"
	omissionWholeUpgradeScoped     = "WHOLE_UPGRADE_COMPATIBILITY_LIMITED_TO_DECLARED_COMPONENT_SCOPE"

	unresolvedComponentNotAttested = "SCOPE_COMPONENT_NOT_ATTESTED"
	unresolvedApplicability        = "APPLICABILITY_UNDETERMINED"
	unresolvedNoApplicableRule     = "NO_APPLICABLE_RULE_FOR_COMPONENT"

	maxInputBytes            = 1 << 20
	maxRulesBytes            = 1 << 20
	maxComponents            = 128
	maxFacts                 = 64
	maxCompiledRegistryFacts = 256
	maxRules                 = 512
	maxSources               = 8
	maxStringBytes           = 256
)

var (
	ErrInvalid   = errors.New("invalid constraint engine input")
	ErrIntegrity = errors.New("constraint engine integrity failure")

	digestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	componentRE = regexp.MustCompile(`^pkg:[a-z0-9][a-z0-9+._/-]{2,255}$`)
	versionRE   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	idRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	reasonRE    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	factIDRE    = regexp.MustCompile(`^component\.[a-z0-9][a-z0-9_-]{0,63}\.[a-z0-9][a-z0-9_-]{0,127}$`)
	gitRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type FactType string

const (
	FactBool FactType = "bool"
	FactEnum FactType = "enum"
)

// FactDefinition is compiled into the executable. Rules may reference only
// facts supplied by this registry; signed rule data cannot expand collection.
type FactDefinition struct {
	ID         string   `json:"id"`
	Component  string   `json:"component"`
	Type       FactType `json:"type"`
	EnumTokens []string `json:"enumTokens"`
}

type Registry struct {
	definitions map[string]FactDefinition
	digest      string
}

// EmptyRegistry is the shipping default until reviewed project facts are added
// in a separate change.
func EmptyRegistry() Registry {
	registry := Registry{definitions: map[string]FactDefinition{}}
	registry.digest = registryDigest(registry.definitions)
	return registry
}

// NewRegistry accepts at most maxFacts definitions. This generic constructor
// also bounds per-component input facts and enum tokens through maxFacts.
func NewRegistry(definitions []FactDefinition) (Registry, error) {
	return newRegistry(definitions, maxFacts)
}

// NewCompiledRegistry accepts the fixed larger compiled-profile definition
// bound. It does not change input fact, enum-token, rule, or source limits.
// Signed rule data cannot select a capacity or add definitions.
func NewCompiledRegistry(definitions []FactDefinition) (Registry, error) {
	return newRegistry(definitions, maxCompiledRegistryFacts)
}

func newRegistry(definitions []FactDefinition, definitionLimit int) (Registry, error) {
	if len(definitions) > definitionLimit {
		return Registry{}, fmt.Errorf("fact registry cardinality: %w", ErrInvalid)
	}
	result := EmptyRegistry()
	for _, definition := range definitions {
		if !factIDRE.MatchString(definition.ID) || !componentRE.MatchString(definition.Component) || len(definition.ID) > maxStringBytes {
			return Registry{}, fmt.Errorf("fact id: %w", ErrInvalid)
		}
		if _, exists := result.definitions[definition.ID]; exists {
			return Registry{}, fmt.Errorf("duplicate fact id: %w", ErrInvalid)
		}
		copy := FactDefinition{ID: definition.ID, Component: definition.Component, Type: definition.Type, EnumTokens: append([]string(nil), definition.EnumTokens...)}
		switch copy.Type {
		case FactBool:
			if len(copy.EnumTokens) != 0 {
				return Registry{}, fmt.Errorf("boolean enum tokens: %w", ErrInvalid)
			}
		case FactEnum:
			if len(copy.EnumTokens) == 0 || len(copy.EnumTokens) > maxFacts {
				return Registry{}, fmt.Errorf("enum token count: %w", ErrInvalid)
			}
			sort.Strings(copy.EnumTokens)
			for i, token := range copy.EnumTokens {
				if !idRE.MatchString(token) || len(token) > maxStringBytes || (i > 0 && token == copy.EnumTokens[i-1]) {
					return Registry{}, fmt.Errorf("enum token: %w", ErrInvalid)
				}
			}
		default:
			return Registry{}, fmt.Errorf("fact type: %w", ErrInvalid)
		}
		result.definitions[copy.ID] = copy
	}
	result.digest = registryDigest(result.definitions)
	return result, nil
}

func (r Registry) definition(id string) (FactDefinition, bool) {
	definition, ok := r.definitions[id]
	return definition, ok
}

func (r Registry) Digest() string { return r.digest }

func registryDigest(definitions map[string]FactDefinition) string {
	values := make([]FactDefinition, 0, len(definitions))
	for _, definition := range definitions {
		values = append(values, definition)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return digestJSON(struct {
		Facts []FactDefinition `json:"facts"`
	}{Facts: values})
}

type inputDocument struct {
	Schema    string    `json:"schema"`
	Authority string    `json:"authority"`
	Current   inputSide `json:"current"`
	Proposed  inputSide `json:"proposed"`
	// Scope is optional. When absent the document marshals exactly as it did
	// before this field existed, so every previously issued input digest,
	// report digest, and replay is unchanged.
	Scope *inputScope `json:"scope,omitempty"`
}

type inputScope struct {
	Declaration string   `json:"declaration"`
	Components  []string `json:"components"`
}

type inputSide struct {
	Components []inputComponent `json:"components"`
}

type inputComponent struct {
	Component string      `json:"component"`
	Version   string      `json:"version"`
	Facts     []inputFact `json:"facts"`
}

type inputFact struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue,omitempty"`
	EnumValue string `json:"enumValue,omitempty"`
}

// Input is an opaque parser-issued capability. Its seal establishes only that
// minimized declared data parsed and bound to a registry; it is not evidence
// of live-cluster observation.
type Input struct {
	document       inputDocument
	digest         string
	registryDigest string
	seal           *inputSeal
}
type inputSeal struct{}

func (i Input) Valid() bool { return i.seal != nil && i.digest == digestJSON(i.document) }
func (i Input) Digest() (string, error) {
	if !i.Valid() {
		return "", ErrIntegrity
	}
	return i.digest, nil
}

type ruleDocument struct {
	Schema       string `json:"schema"`
	Revision     string `json:"revision"`
	PolicyID     string `json:"policyId"`
	PolicyDigest string `json:"policyDigest"`
	Rules        []rule `json:"rules"`
	// Corpus is optional and carries the same digest-stability property as
	// inputDocument.Scope. A rule document assembled by filtering a larger
	// pack must not carry it.
	Corpus *ruleCorpus `json:"corpus,omitempty"`
}

type ruleCorpus struct {
	Completeness string   `json:"completeness"`
	Components   []string `json:"components"`
}

type rule struct {
	ID       string     `json:"id"`
	Operator string     `json:"operator"`
	Subject  transition `json:"subject"`
	// Range is optional. When absent the rule marshals, digests, and matches
	// exactly as it did before ranges existed.
	Range        *VersionRange   `json:"range,omitempty"`
	Condition    *factCondition  `json:"condition,omitempty"`
	AppliesWhen  []factCondition `json:"appliesWhen,omitempty"`
	Dependency   *componentCheck `json:"dependency,omitempty"`
	Intermediate string          `json:"intermediate,omitempty"`
	Evidence     evidence        `json:"evidence"`
	ReasonCode   string          `json:"reasonCode"`
	NextAction   string          `json:"nextAction"`
}

type transition struct {
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
}

type factCondition struct {
	Side      string `json:"side"`
	Component string `json:"component"`
	FactID    string `json:"factId"`
	BoolValue *bool  `json:"boolValue,omitempty"`
	EnumValue string `json:"enumValue,omitempty"`
}

type componentCheck struct {
	Side       string `json:"side"`
	Component  string `json:"component"`
	Comparison string `json:"comparison"`
	Version    string `json:"version"`
}

type evidence struct {
	State      string           `json:"state"`
	ReviewedAt string           `json:"reviewedAt"`
	ValidUntil string           `json:"validUntil"`
	Sources    []SourceEvidence `json:"sources"`
}

type SourceEvidence struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	Revision      string `json:"revision"`
	ContentDigest string `json:"contentDigest"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
}

type RuleSet struct {
	document       ruleDocument
	digest         string
	registryDigest string
	ranged         bool
	seal           *ruleSetSeal
}
type ruleSetSeal struct{}

func (r RuleSet) Valid() bool { return r.seal != nil && r.digest == digestJSON(r.document) }
func (r RuleSet) Digest() (string, error) {
	if !r.Valid() {
		return "", ErrIntegrity
	}
	return r.digest, nil
}

type Claim struct {
	RuleID             string           `json:"ruleId"`
	RuleDigest         string           `json:"ruleDigest"`
	Operator           string           `json:"operator"`
	Status             string           `json:"status"`
	ReasonCode         string           `json:"reasonCode"`
	NextAction         string           `json:"nextAction"`
	EvidenceReviewedAt string           `json:"evidenceReviewedAt"`
	EvidenceValidUntil string           `json:"evidenceValidUntil"`
	EvidenceFreshness  string           `json:"evidenceFreshness"`
	RequiredFacts      []RequiredFact   `json:"requiredFacts"`
	Sources            []SourceEvidence `json:"sources"`
	// SubjectMatch is present only when the transition matched the rule's
	// reviewed range rather than its exact anchor pair. Exact matches omit it,
	// so exact-rule claims serialize exactly as before ranges existed.
	SubjectMatch *SubjectMatch `json:"subjectMatch,omitempty"`
}

// SubjectMatch discloses a range match: the reviewed anchor pair and the
// reviewed bounds the declared transition fell inside.
type SubjectMatch struct {
	Mode       string       `json:"mode"`
	AnchorFrom string       `json:"anchorFrom"`
	AnchorTo   string       `json:"anchorTo"`
	From       VersionBound `json:"from"`
	To         VersionBound `json:"to"`
}

type RequiredFact struct {
	Side      string `json:"side"`
	Component string `json:"component"`
	FactID    string `json:"factId"`
}

type Report struct {
	Schema         string `json:"schema"`
	Assessment     string `json:"assessment"`
	InputAuthority string `json:"inputAuthority"`
	RulesAuthority string `json:"rulesAuthority"`
	EvaluatedAt    string `json:"evaluatedAt"`
	InputDigest    string `json:"inputDigest"`
	RuleSetDigest  string `json:"ruleSetDigest"`
	// Policy fields bind the declared rule-source reference only; they
	// are not proof that an external policy authority approved this report.
	PolicyID             string   `json:"policyId"`
	PolicyDigest         string   `json:"policyDigest"`
	EngineContractDigest string   `json:"engineContractDigest"`
	RegistryDigest       string   `json:"registryDigest"`
	Claims               []Claim  `json:"claims"`
	Omissions            []string `json:"omissions"`
	// ScopeCompleteness is present only when the caller declared a component
	// scope and the rule document attested its own completeness. It is the
	// sole evidence under which Assessment may be anything but UNKNOWN.
	ScopeCompleteness *ScopeCompleteness `json:"scopeCompleteness,omitempty"`
	seal              *reportSeal
	digest            string
}
type reportSeal struct{}

// ScopeCompleteness enumerates, per declared component, which reviewed rules
// were evaluated and which were not. The not-evaluated list is the point: a
// completeness statement that cannot name what it skipped is not auditable.
type ScopeCompleteness struct {
	Declaration       string           `json:"declaration"`
	CorpusAttestation string           `json:"corpusAttestation"`
	ContractDigest    string           `json:"contractDigest"`
	RuleSetRevision   string           `json:"ruleSetRevision"`
	Resolved          bool             `json:"resolved"`
	UnresolvedReason  string           `json:"unresolvedReason,omitempty"`
	OutOfScopeRules   int              `json:"outOfScopeRules"`
	Components        []ComponentScope `json:"components"`
}

type ComponentScope struct {
	Component        string             `json:"component"`
	From             string             `json:"from"`
	To               string             `json:"to"`
	CorpusAttested   bool               `json:"corpusAttested"`
	EvaluatedRuleIDs []string           `json:"evaluatedRuleIds"`
	NotEvaluated     []NotEvaluatedRule `json:"notEvaluated"`
}

// NotEvaluatedRule records one reviewed rule that produced no verdict for this
// component. NOT_APPLICABLE always rests on a declared version or declared
// fact value that excludes the rule; UNDETERMINED means the engine could not
// establish applicability or could not evaluate an applicable rule, and it
// always forces the aggregate back to UNKNOWN.
type NotEvaluatedRule struct {
	RuleID        string `json:"ruleId"`
	Applicability string `json:"applicability"`
	ReasonCode    string `json:"reasonCode"`
}

func engineContractDigest() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchema + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version"))
}

// engineContractDigestRanged identifies the contract under which a rule
// document with ranges is evaluated. It is a separate identity rather than a
// replacement: a report over an exact-only document keeps the original digest
// and replays byte-identically on this binary.
func engineContractDigestRanged() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchemaRanged + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version\nsubject:exact\nsubject:range\nclaim:subjectMatch\n" + rangeWidthPolicy + "\n" + basisVocabulary()))
}

// EngineContractDigest exposes the immutable scalar contract identity without
// exposing mutable parser or registry state. It is the identity of the
// exact-only contract.
func EngineContractDigest() string { return engineContractDigest() }

// EngineContractDigestRanged exposes the contract identity for rule documents
// that carry reviewed version ranges.
func EngineContractDigestRanged() string { return engineContractDigestRanged() }

func (r RuleSet) engineDigest() string {
	if r.ranged {
		return engineContractDigestRanged()
	}
	return engineContractDigest()
}

// scopeContractDigest binds the scope-completeness vocabulary separately from
// engineContractDigest, so reports that do not use scope keep byte-identical
// identity while reports that do carry the contract they depend on.
func scopeContractDigest() string {
	return digestBytes([]byte(ScopeContractVersion + "\n" + ScopeDeclaration + "\n" + CorpusAttestation + "\n" + AssessmentUnknown + "\n" + AssessmentBlocked + "\n" + AssessmentScopeCompletePass + "\n" + ApplicabilityApplicable + "\n" + ApplicabilityNotApplicable + "\n" + ApplicabilityUndetermined + "\n" + omissionWholeUpgradeScoped))
}

// ScopeContractDigest exposes the scope-completeness contract identity.
func ScopeContractDigest() string { return scopeContractDigest() }

// scopeContractDigestRanged adds the anchor-review condition to the v1
// vocabulary. It is used only with the ranged engine contract.
func scopeContractDigestRanged() string {
	return digestBytes([]byte(ScopeContractVersionRanged + "\n" + ScopeDeclaration + "\n" + CorpusAttestation + "\n" + AssessmentUnknown + "\n" + AssessmentBlocked + "\n" + AssessmentScopeCompletePass + "\n" + ApplicabilityApplicable + "\n" + ApplicabilityNotApplicable + "\n" + ApplicabilityUndetermined + "\n" + omissionWholeUpgradeScoped + "\n" + unresolvedTransitionNotAnchor))
}

// ScopeContractDigestRanged exposes the ranged scope-completeness identity.
func ScopeContractDigestRanged() string { return scopeContractDigestRanged() }

// scopeDigestFor returns the scope contract that pairs with an engine
// contract, or "" for an unknown engine contract.
func scopeDigestFor(engineDigest string) string {
	switch engineDigest {
	case engineContractDigest():
		return scopeContractDigest()
	case engineContractDigestRanged():
		return scopeContractDigestRanged()
	}
	return ""
}

func digestJSON(value any) string { raw, _ := json.Marshal(value); return digestBytes(raw) }
func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func contains(values []string, wanted string) bool {
	return sort.SearchStrings(values, wanted) < len(values) && values[sort.SearchStrings(values, wanted)] == wanted
}
func publicText(value string) bool {
	if value == "" || len(value) > maxStringBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

type numericVersion [3]uint32

func parseVersion(value string) (numericVersion, bool) {
	if !versionRE.MatchString(value) {
		return numericVersion{}, false
	}
	parts := strings.Split(value, ".")
	var parsed numericVersion
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return numericVersion{}, false
		}
		parsed[index] = uint32(number)
	}
	return parsed, true
}

func validVersion(value string) bool { _, ok := parseVersion(value); return ok }

func compareVersions(left, right string) (int, bool) {
	leftVersion, ok := parseVersion(left)
	if !ok {
		return 0, false
	}
	rightVersion, ok := parseVersion(right)
	if !ok {
		return 0, false
	}
	for index := range leftVersion {
		if leftVersion[index] < rightVersion[index] {
			return -1, true
		}
		if leftVersion[index] > rightVersion[index] {
			return 1, true
		}
	}
	return 0, true
}
