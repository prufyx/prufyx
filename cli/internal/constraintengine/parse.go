// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseInput accepts a local caller-supplied byte slice. It never opens a
// pathname and retains only typed component identity and reviewed fact tokens.
func ParseInput(raw []byte, registry Registry) (Input, error) {
	if err := gateJSON(raw, maxInputBytes); err != nil {
		return Input{}, err
	}
	if err := validateInputShape(raw); err != nil {
		return Input{}, err
	}
	var document inputDocument
	if err := decodeStrict(raw, &document); err != nil {
		return Input{}, err
	}
	if document.Schema != InputSchema || document.Authority != InputAuthority {
		return Input{}, fmt.Errorf("input identity: %w", ErrInvalid)
	}
	if err := validateSide(document.Current, registry); err != nil {
		return Input{}, err
	}
	if err := validateSide(document.Proposed, registry); err != nil {
		return Input{}, err
	}
	if err := validateScope(document); err != nil {
		return Input{}, err
	}
	return Input{document: document, digest: digestJSON(document), registryDigest: registry.Digest(), seal: &inputSeal{}}, nil
}

// validateScope checks the declared component set against the bundle it
// claims to describe. A declaration that does not match the bundle is a
// caller error, not an evidence gap: it fails as ErrInvalid rather than
// disappearing into the honest-uncertainty channel.
func validateScope(document inputDocument) error {
	if document.Scope == nil {
		return nil
	}
	scope := document.Scope
	if scope.Declaration != ScopeDeclaration || len(scope.Components) == 0 || len(scope.Components) > maxComponents {
		return fmt.Errorf("scope declaration: %w", ErrInvalid)
	}
	declared := make(map[string]struct{}, len(scope.Components))
	for index, component := range scope.Components {
		if !componentRE.MatchString(component) || (index > 0 && scope.Components[index-1] >= component) {
			return fmt.Errorf("scope component identity or order: %w", ErrInvalid)
		}
		declared[component] = struct{}{}
	}
	for _, side := range []inputSide{document.Current, document.Proposed} {
		if len(side.Components) != len(declared) {
			return fmt.Errorf("scope cardinality: %w", ErrInvalid)
		}
		for _, component := range side.Components {
			if _, ok := declared[component.Component]; !ok {
				return fmt.Errorf("scope omits a declared bundle component: %w", ErrInvalid)
			}
		}
	}
	return nil
}

func validateSide(side inputSide, registry Registry) error {
	if len(side.Components) > maxComponents {
		return fmt.Errorf("component count: %w", ErrInvalid)
	}
	for i, component := range side.Components {
		if !componentRE.MatchString(component.Component) || !validVersion(component.Version) || (i > 0 && side.Components[i-1].Component >= component.Component) {
			return fmt.Errorf("component identity or order: %w", ErrInvalid)
		}
		if len(component.Facts) > maxFacts {
			return fmt.Errorf("fact count: %w", ErrInvalid)
		}
		for j, fact := range component.Facts {
			if (j > 0 && component.Facts[j-1].ID >= fact.ID) || validateFact(fact, component.Component, registry) != nil {
				return fmt.Errorf("fact: %w", ErrInvalid)
			}
		}
	}
	return nil
}

func validateFact(fact inputFact, component string, registry Registry) error {
	definition, ok := registry.definition(fact.ID)
	if !ok || definition.Component != component {
		return ErrInvalid
	}
	switch fact.State {
	case "declared":
		switch definition.Type {
		case FactBool:
			if fact.BoolValue == nil || fact.EnumValue != "" {
				return ErrInvalid
			}
		case FactEnum:
			if fact.BoolValue != nil || !contains(definition.EnumTokens, fact.EnumValue) {
				return ErrInvalid
			}
		}
	case "missing", "unsupported", "conflict":
		if fact.BoolValue != nil || fact.EnumValue != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// ParseRuleSet strictly parses declared source-reference data. A signature
// verifier may bind this parser output later; this package does not claim one.
func ParseRuleSet(raw []byte, registry Registry) (RuleSet, error) {
	if err := gateJSON(raw, maxRulesBytes); err != nil {
		return RuleSet{}, err
	}
	if err := validateRuleShape(raw); err != nil {
		return RuleSet{}, err
	}
	var document ruleDocument
	if err := decodeStrict(raw, &document); err != nil {
		return RuleSet{}, err
	}
	if (document.Schema != RulesSchema && document.Schema != RulesSchemaRanged) || !idRE.MatchString(document.Revision) || !idRE.MatchString(document.PolicyID) || !digestRE.MatchString(document.PolicyDigest) || len(document.Rules) > maxRules {
		return RuleSet{}, fmt.Errorf("ruleset identity: %w", ErrInvalid)
	}
	ranged := false
	for i, rule := range document.Rules {
		if i > 0 && document.Rules[i-1].ID >= rule.ID {
			return RuleSet{}, fmt.Errorf("rule order: %w", ErrInvalid)
		}
		if err := validateRule(rule, registry); err != nil {
			return RuleSet{}, fmt.Errorf("rule: %w", err)
		}
		ranged = ranged || rule.Range != nil
	}
	// The schema string states whether the document carries ranges, and it
	// must be right in both directions: an exact-only schema never admits a
	// range, and the ranged schema is never used without one, so every
	// document has exactly one schema and one engine contract.
	if ranged != (document.Schema == RulesSchemaRanged) {
		return RuleSet{}, fmt.Errorf("ruleset schema does not match range use: %w", ErrInvalid)
	}
	if ranged {
		if err := validateRangeOverlaps(document.Rules); err != nil {
			return RuleSet{}, err
		}
	}
	if err := validateCorpus(document); err != nil {
		return RuleSet{}, err
	}
	return RuleSet{document: document, digest: digestJSON(document), registryDigest: registry.Digest(), ranged: ranged, seal: &ruleSetSeal{}}, nil
}

// validateCorpus admits a completeness attestation only when the document can
// support it. An attestation covering a component with no rule in the document
// would make completeness vacuously true; that is the "no applicable rule
// becomes a pass" hole, and it is closed here rather than downstream.
func validateCorpus(document ruleDocument) error {
	if document.Corpus == nil {
		return nil
	}
	corpus := document.Corpus
	if corpus.Completeness != CorpusAttestation || len(corpus.Components) == 0 || len(corpus.Components) > maxComponents {
		return fmt.Errorf("corpus attestation: %w", ErrInvalid)
	}
	subjects := make(map[string]int, len(document.Rules))
	for _, rule := range document.Rules {
		subjects[rule.Subject.Component]++
	}
	for index, component := range corpus.Components {
		if !componentRE.MatchString(component) || (index > 0 && corpus.Components[index-1] >= component) {
			return fmt.Errorf("corpus component identity or order: %w", ErrInvalid)
		}
		if subjects[component] == 0 {
			return fmt.Errorf("corpus attests a component with no reviewed rule: %w", ErrInvalid)
		}
	}
	return nil
}

func validateRule(rule rule, registry Registry) error {
	if !idRE.MatchString(rule.ID) || !reasonRE.MatchString(rule.ReasonCode) || !publicText(rule.NextAction) || !componentRE.MatchString(rule.Subject.Component) || !validVersion(rule.Subject.From) || !validVersion(rule.Subject.To) || sameVersion(rule.Subject.From, rule.Subject.To) {
		return fmt.Errorf("rule base fields: %w", ErrInvalid)
	}
	if err := validateEvidence(rule.Evidence); err != nil {
		return fmt.Errorf("rule evidence: %w", err)
	}
	if err := validateRange(rule); err != nil {
		return err
	}
	if len(rule.AppliesWhen) > 8 {
		return fmt.Errorf("applicability count: %w", ErrInvalid)
	}
	seenConditions := map[string]struct{}{}
	for _, condition := range rule.AppliesWhen {
		if err := validateCondition(condition, registry); err != nil {
			return fmt.Errorf("applicability condition: %w", err)
		}
		key := condition.Side + "\x00" + condition.Component + "\x00" + condition.FactID
		if _, exists := seenConditions[key]; exists {
			return fmt.Errorf("duplicate applicability condition: %w", ErrInvalid)
		}
		seenConditions[key] = struct{}{}
	}
	switch rule.Operator {
	case "forbid_predicate_value":
		if rule.Condition == nil || rule.Dependency != nil || rule.Intermediate != "" {
			return fmt.Errorf("forbid predicate structure: %w", ErrInvalid)
		}
		return validateCondition(*rule.Condition, registry)
	case "require_component_version":
		if rule.Condition != nil || rule.Dependency == nil || rule.Intermediate != "" {
			return fmt.Errorf("dependency structure: %w", ErrInvalid)
		}
		return validateDependency(*rule.Dependency)
	case "require_intermediate_version":
		if rule.Condition != nil || rule.Dependency != nil || !validVersion(rule.Intermediate) || sameVersion(rule.Intermediate, rule.Subject.From) || sameVersion(rule.Intermediate, rule.Subject.To) {
			return fmt.Errorf("intermediate structure: %w", ErrInvalid)
		}
		// With a range the intermediate must lie strictly between every
		// matched pair: from.lt <= intermediate < to.gte.
		if rule.Range != nil {
			low, lowOK := compareVersions(rule.Range.From.Lt, rule.Intermediate)
			high, highOK := compareVersions(rule.Intermediate, rule.Range.To.Gte)
			if !lowOK || !highOK || low > 0 || high >= 0 {
				return fmt.Errorf("intermediate outside range gap: %w", ErrInvalid)
			}
		}
	case "forbid_target_version":
		if rule.Condition != nil || rule.Dependency != nil || rule.Intermediate != "" {
			return fmt.Errorf("target structure: %w", ErrInvalid)
		}
	default:
		return fmt.Errorf("operator: %w", ErrInvalid)
	}
	return nil
}

func validateCondition(condition factCondition, registry Registry) error {
	if (condition.Side != "current" && condition.Side != "proposed") || !componentRE.MatchString(condition.Component) {
		return ErrInvalid
	}
	definition, ok := registry.definition(condition.FactID)
	if !ok || definition.Component != condition.Component {
		return ErrInvalid
	}
	switch definition.Type {
	case FactBool:
		if condition.BoolValue == nil || condition.EnumValue != "" {
			return ErrInvalid
		}
	case FactEnum:
		if condition.BoolValue != nil || !contains(definition.EnumTokens, condition.EnumValue) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateDependency(dependency componentCheck) error {
	if (dependency.Side != "current" && dependency.Side != "proposed") || !componentRE.MatchString(dependency.Component) || !validVersion(dependency.Version) || (dependency.Comparison != "eq" && dependency.Comparison != "gte" && dependency.Comparison != "lte" && dependency.Comparison != "lt") {
		return ErrInvalid
	}
	return nil
}

func validateEvidence(evidence evidence) error {
	if evidence.State != "active" && evidence.State != "withdrawn" {
		return fmt.Errorf("evidence state: %w", ErrInvalid)
	}
	reviewed, err := parseUTC(evidence.ReviewedAt)
	if err != nil {
		return fmt.Errorf("review time: %w", err)
	}
	validUntil, err := parseUTC(evidence.ValidUntil)
	if err != nil || !validUntil.After(reviewed) {
		return fmt.Errorf("validity time: %w", ErrInvalid)
	}
	if len(evidence.Sources) == 0 || len(evidence.Sources) > maxSources {
		return fmt.Errorf("source count: %w", ErrInvalid)
	}
	for i, source := range evidence.Sources {
		if i > 0 && evidence.Sources[i-1].ID >= source.ID {
			return fmt.Errorf("source order: %w", ErrInvalid)
		}
		if !idRE.MatchString(source.ID) {
			return fmt.Errorf("source id: %w", ErrInvalid)
		}
		if !gitRevision.MatchString(source.Revision) {
			return fmt.Errorf("source revision: %w", ErrInvalid)
		}
		if !digestRE.MatchString(source.ContentDigest) {
			return fmt.Errorf("source digest: %w", ErrInvalid)
		}
		if source.StartLine < 1 || source.EndLine < source.StartLine || source.EndLine > 1_000_000 {
			return fmt.Errorf("source span: %w", ErrInvalid)
		}
		if !immutableGitURL(source.URL, source.Revision) {
			return fmt.Errorf("source URL: %w", ErrInvalid)
		}
	}
	return nil
}

func immutableGitURL(value, revision string) bool {
	if len(value) == 0 || len(value) > 2048 || !gitRevision.MatchString(revision) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	if strings.Contains(value, "%") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Host != "github.com" && parsed.Host != "raw.githubusercontent.com") {
		return false
	}
	path := strings.TrimPrefix(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parsed.EscapedPath() != parsed.Path || parts[0] == "" || parts[1] == "" {
		return false
	}
	if !gitPathPartRE.MatchString(parts[0]) || !gitPathPartRE.MatchString(parts[1]) {
		return false
	}
	if parsed.Host == "github.com" {
		if parts[2] != "blob" || parts[3] != revision || len(parts) < 5 {
			return false
		}
		parts = parts[4:]
	} else if parts[2] != revision {
		return false
	} else {
		parts = parts[3:]
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || !publicPathPartRE.MatchString(part) {
			return false
		}
	}
	return true
}

// encoding/json accepts case-insensitive field names. These exact-shape gates
// run before struct decoding so aliases, null required objects, and untyped
// arrays cannot enter a parser-issued capability.
func validateInputShape(raw []byte) error {
	root, err := exactObject(raw, []string{"schema", "authority", "current", "proposed"}, []string{"scope"})
	if err != nil {
		return err
	}
	if scope, ok := root["scope"]; ok {
		if err := validateTokenListShape(scope, "declaration", maxComponents); err != nil {
			return err
		}
	}
	for _, sideName := range []string{"current", "proposed"} {
		side, err := exactObject(root[sideName], []string{"components"}, nil)
		if err != nil {
			return err
		}
		components, err := exactArray(side["components"])
		if err != nil || len(components) > maxComponents {
			return ErrInvalid
		}
		for _, componentRaw := range components {
			component, err := exactObject(componentRaw, []string{"component", "version", "facts"}, nil)
			if err != nil {
				return err
			}
			facts, err := exactArray(component["facts"])
			if err != nil || len(facts) > maxFacts {
				return ErrInvalid
			}
			for _, factRaw := range facts {
				fact, err := exactObject(factRaw, []string{"id", "state"}, []string{"boolValue", "enumValue"})
				if err != nil {
					return err
				}
				if !validFactValuePresence(fact) {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}

func validateRuleShape(raw []byte) error {
	root, err := exactObject(raw, []string{"schema", "revision", "policyId", "policyDigest", "rules"}, []string{"corpus"})
	if err != nil {
		return err
	}
	if corpus, ok := root["corpus"]; ok {
		if err := validateTokenListShape(corpus, "completeness", maxComponents); err != nil {
			return err
		}
	}
	rules, err := exactArray(root["rules"])
	if err != nil || len(rules) > maxRules {
		return ErrInvalid
	}
	for _, ruleRaw := range rules {
		rule, err := exactObject(ruleRaw, []string{"id", "operator", "subject", "evidence", "reasonCode", "nextAction"}, []string{"condition", "appliesWhen", "dependency", "intermediate", "range"})
		if err != nil {
			return err
		}
		if _, err := exactObject(rule["subject"], []string{"component", "from", "to"}, nil); err != nil {
			return err
		}
		if rangeRaw, ok := rule["range"]; ok {
			if err := validateRangeShape(rangeRaw); err != nil {
				return err
			}
		}
		if condition, ok := rule["condition"]; ok {
			if err := validateConditionShape(condition); err != nil {
				return err
			}
		}
		if appliesWhen, ok := rule["appliesWhen"]; ok {
			conditions, err := exactArray(appliesWhen)
			if err != nil || len(conditions) > 8 {
				return ErrInvalid
			}
			for _, condition := range conditions {
				if err := validateConditionShape(condition); err != nil {
					return err
				}
			}
		}
		if dependency, ok := rule["dependency"]; ok {
			if _, err := exactObject(dependency, []string{"side", "component", "comparison", "version"}, nil); err != nil {
				return err
			}
		}
		evidence, err := exactObject(rule["evidence"], []string{"state", "reviewedAt", "validUntil", "sources"}, nil)
		if err != nil {
			return err
		}
		sources, err := exactArray(evidence["sources"])
		if err != nil || len(sources) > maxSources {
			return ErrInvalid
		}
		for _, sourceRaw := range sources {
			if _, err := exactObject(sourceRaw, []string{"id", "url", "revision", "contentDigest", "startLine", "endLine"}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateRangeShape gates the exact range shape: both sides with both
// bounds, and exactly four bound citations, with no aliases, nulls, or extra
// keys. Semantic checks follow in validateRange.
func validateRangeShape(raw json.RawMessage) error {
	object, err := exactObject(raw, []string{"from", "to", "bounds"}, nil)
	if err != nil {
		return err
	}
	for _, side := range []string{"from", "to"} {
		bound, err := exactObject(object[side], []string{"gte", "lt"}, nil)
		if err != nil {
			return err
		}
		for _, key := range []string{"gte", "lt"} {
			var value string
			if json.Unmarshal(bound[key], &value) != nil {
				return ErrInvalid
			}
		}
	}
	bounds, err := exactArray(object["bounds"])
	if err != nil || len(bounds) != len(boundOrder) {
		return ErrInvalid
	}
	for _, boundRaw := range bounds {
		bound, err := exactObject(boundRaw, []string{"bound", "basis", "sourceId"}, nil)
		if err != nil {
			return err
		}
		for _, key := range []string{"bound", "basis", "sourceId"} {
			var value string
			if json.Unmarshal(bound[key], &value) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

// validateTokenListShape gates the shared {<tokenField>, components} shape of
// the scope declaration and the corpus attestation before struct decoding, so
// field aliases and untyped arrays cannot enter a parser-issued capability.
func validateTokenListShape(raw json.RawMessage, tokenField string, limit int) error {
	object, err := exactObject(raw, []string{tokenField, "components"}, nil)
	if err != nil {
		return err
	}
	components, err := exactArray(object["components"])
	if err != nil || len(components) == 0 || len(components) > limit {
		return ErrInvalid
	}
	for _, component := range components {
		var value string
		if json.Unmarshal(component, &value) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func validFactValuePresence(fact map[string]json.RawMessage) bool {
	var state string
	if err := json.Unmarshal(fact["state"], &state); err != nil {
		return false
	}
	_, hasBool := fact["boolValue"]
	_, hasEnum := fact["enumValue"]
	if state == "declared" {
		return hasBool != hasEnum
	}
	return !hasBool && !hasEnum
}

func validateConditionShape(raw json.RawMessage) error {
	condition, err := exactObject(raw, []string{"side", "component", "factId"}, []string{"boolValue", "enumValue"})
	if err != nil {
		return err
	}
	_, hasBool := condition["boolValue"]
	_, hasEnum := condition["enumValue"]
	if hasBool == hasEnum {
		return ErrInvalid
	}
	return nil
}

func exactObject(raw json.RawMessage, required, optional []string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, ErrInvalid
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if value, exists := object[key]; !exists || bytes.Equal(value, []byte("null")) {
			return nil, ErrInvalid
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key, value := range object {
		if _, ok := allowed[key]; !ok || bytes.Equal(value, []byte("null")) {
			return nil, ErrInvalid
		}
	}
	return object, nil
}

func exactArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, ErrInvalid
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, ErrInvalid
	}
	return values, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("JSON fields: %w", ErrInvalid)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("JSON trailing data: %w", ErrInvalid)
	}
	return nil
}

func gateJSON(raw []byte, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder, 0); err != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]struct{}{}
			for count := 0; decoder.More(); count++ {
				if count >= 4096 {
					return ErrInvalid
				}
				key, err := decoder.Token()
				if err != nil {
					return ErrInvalid
				}
				name, ok := key.(string)
				if !ok || len(name) > maxStringBytes {
					return ErrInvalid
				}
				if _, duplicate := seen[name]; duplicate {
					return ErrInvalid
				}
				seen[name] = struct{}{}
				if err := consumeJSON(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for count := 0; decoder.More(); count++ {
				if count >= 4096 || consumeJSON(decoder, depth+1) != nil {
					return ErrInvalid
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case string:
		if len(value) > maxStringBytes {
			return ErrInvalid
		}
	case nil, bool, json.Number:
	default:
		return ErrInvalid
	}
	return nil
}

var (
	gitPathPartRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// .github is a public, immutable repository path segment. Keep the narrow
	// exception explicit so other dot-prefixed path segments remain rejected.
	publicPathPartRE = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._+@=,-]*|\.github)$`)
)
