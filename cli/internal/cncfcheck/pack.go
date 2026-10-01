// SPDX-License-Identifier: AGPL-3.0-only

// Package cncfcheck exposes an embedded, source-reviewed constraint preview.
// Operator declarations are not observations or runtime reproduction evidence.
package cncfcheck

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

//go:embed data/landscape-projects.json data/priority-portfolio.json data/rules.json
var packagedFiles embed.FS

var (
	ErrInvalid    = errors.New("invalid CNCF check request")
	ErrIntegrity  = errors.New("CNCF check integrity failure")
	slugPattern   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type projectIdentity struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	RepositoryURL string `json:"repositoryURL"`
	CNCFStage     string `json:"cncfStage"`
}

type landscapeDocument struct {
	Schema              string            `json:"schema"`
	Revision            string            `json:"revision"`
	SourceURL           string            `json:"sourceURL"`
	LandscapeFileDigest string            `json:"landscapeFileDigest"`
	Projects            []projectIdentity `json:"projects"`
}

type priorityDocument struct {
	Schema              string   `json:"schema"`
	LandscapeFileDigest string   `json:"landscapeFileDigest"`
	Priority            []string `json:"priority"`
}

// Fact describes a compiled public projection, never a raw configuration value.
type Fact struct {
	Side        string                    `json:"side"`
	ID          string                    `json:"id"`
	Component   string                    `json:"component"`
	Type        constraintengine.FactType `json:"type"`
	EnumTokens  []string                  `json:"enumTokens"`
	Description string                    `json:"description"`
}

type Entry struct {
	Project       string          `json:"project"`
	Description   string          `json:"description"`
	RequiredFacts []Fact          `json:"requiredFacts"`
	Rule          json.RawMessage `json:"rule"`
}

type rulePack struct {
	Schema              string  `json:"schema"`
	Revision            string  `json:"revision"`
	PolicyID            string  `json:"policyId"`
	PolicyDigest        string  `json:"policyDigest"`
	LandscapeFileDigest string  `json:"landscapeFileDigest"`
	RegistryDigest      string  `json:"registryDigest"`
	Entries             []Entry `json:"entries"`
}

type bundle struct {
	landscape       landscapeDocument
	priority        priorityDocument
	pack            rulePack
	registry        constraintengine.Registry
	packDigest      string
	catalogueDigest string
}

func load() (bundle, error) {
	var result bundle
	landscapeRaw, err := packagedFiles.ReadFile("data/landscape-projects.json")
	if err != nil || strictJSON(landscapeRaw, &result.landscape) != nil {
		return bundle{}, ErrIntegrity
	}
	priorityRaw, err := packagedFiles.ReadFile("data/priority-portfolio.json")
	if err != nil || strictJSON(priorityRaw, &result.priority) != nil {
		return bundle{}, ErrIntegrity
	}
	packRaw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil || strictJSON(packRaw, &result.pack) != nil {
		return bundle{}, ErrIntegrity
	}
	result.registry, err = compiledRegistry()
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	result.packDigest, result.catalogueDigest = digest(packRaw), digest(landscapeRaw)
	if result.landscape.Schema != "prufyx.io/cncf-landscape/v1" || len(result.landscape.Projects) != 255 || !digestPattern.MatchString(result.landscape.LandscapeFileDigest) || result.priority.Schema != "prufyx.io/cncf-priority/v1" || len(result.priority.Priority) != 30 || result.priority.LandscapeFileDigest != result.landscape.LandscapeFileDigest || !validPackSchema(result.pack) || result.pack.LandscapeFileDigest != result.landscape.LandscapeFileDigest || result.pack.RegistryDigest != result.registry.Digest() {
		return bundle{}, ErrIntegrity
	}
	identities := map[string]projectIdentity{}
	for index, project := range result.landscape.Projects {
		parsed, err := url.Parse(project.RepositoryURL)
		// The pinned Landscape omits a repository for archived Curiefense.
		// Preserve that absence instead of inventing a canonical identity.
		missingArchivedRepository := project.RepositoryURL == "" && project.CNCFStage == "archived"
		if !slugPattern.MatchString(project.Slug) || project.Name == "" || (!missingArchivedRepository && (err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil)) || (index > 0 && result.landscape.Projects[index-1].Slug >= project.Slug) {
			return bundle{}, ErrIntegrity
		}
		identities[project.Slug] = project
	}
	for index, slug := range result.priority.Priority {
		if _, found := identities[slug]; !found || (index > 0 && result.priority.Priority[index-1] >= slug) {
			return bundle{}, ErrIntegrity
		}
	}
	definitions := map[string]constraintengine.FactDefinition{}
	for _, definition := range compiledDefinitions() {
		definitions[definition.ID] = definition
	}
	if result.pack.PolicyID != "cncf-source-preview-v1" || result.pack.PolicyDigest != digest([]byte(PolicyDeclaration)) {
		return bundle{}, ErrIntegrity
	}
	for _, entry := range result.pack.Entries {
		if _, found := identities[entry.Project]; !found || entry.Description == "" || len(entry.Description) > 2048 {
			return bundle{}, ErrIntegrity
		}
		seenFacts := map[string]bool{}
		for _, fact := range entry.RequiredFacts {
			definition, found := definitions[fact.ID]
			key := fact.Side + "/" + fact.Component + "/" + fact.ID
			if seenFacts[key] || (fact.Side != "current" && fact.Side != "proposed") || !found || definition.Component != fact.Component || definition.Type != fact.Type || fact.Description == "" || len(fact.Description) > 2048 || !sameStrings(definition.EnumTokens, fact.EnumTokens) {
				return bundle{}, ErrIntegrity
			}
			seenFacts[key] = true
		}
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil || shape.Subject.Component != subjectComponent(entry.Project, identities[entry.Project].RepositoryURL) {
			return bundle{}, ErrIntegrity
		}
		conditions := append([]conditionShape(nil), shape.AppliesWhen...)
		if shape.Condition != nil {
			conditions = append(conditions, *shape.Condition)
		}
		required := map[string]bool{}
		for _, condition := range conditions {
			required[condition.Side+"/"+condition.Component+"/"+condition.FactID] = true
		}
		if len(required) != len(seenFacts) {
			return bundle{}, ErrIntegrity
		}
		for key := range required {
			if !seenFacts[key] {
				return bundle{}, ErrIntegrity
			}
		}
	}
	if _, err := result.ruleSet(""); err != nil {
		return bundle{}, ErrIntegrity
	}
	return result, nil
}

const (
	packSchema       = "prufyx.io/cncf-source-rule-pack/v1alpha1"
	packSchemaRanged = "prufyx.io/cncf-source-rule-pack/v1alpha2"
)

// validPackSchema requires the pack schema to state whether the pack holds a
// reviewed version range. A pack with no range keeps the original schema, so
// its bytes and digest are unchanged; a pack with one carries the new schema,
// which binaries that predate ranges reject.
func validPackSchema(pack rulePack) bool {
	rules := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		rules = append(rules, entry.Rule)
	}
	ranged, err := constraintengine.AnyRanged(rules)
	if err != nil {
		return false
	}
	if ranged {
		return pack.Schema == packSchemaRanged
	}
	return pack.Schema == packSchema
}

func (b bundle) ruleSet(project string) (constraintengine.RuleSet, error) {
	rules := make([]json.RawMessage, 0)
	for _, entry := range b.pack.Entries {
		if project == "" || entry.Project == project {
			rules = append(rules, entry.Rule)
		}
	}
	return b.parseRules(rules)
}

func (b bundle) parseRules(rules []json.RawMessage) (constraintengine.RuleSet, error) {
	return b.parseRulesCorpus(rules, nil)
}

// parseRulesCorpus is the single seam through which every CNCF rule document
// reaches the engine. corpus, when non-empty, attaches the maintainer's
// completeness attestation; a filtered selection must always pass nil, because
// a narrowed document cannot honestly claim it holds every reviewed rule.
func (b bundle) parseRulesCorpus(rules []json.RawMessage, corpus []string) (constraintengine.RuleSet, error) {
	if err := validateCNCFReviewWindows(rules); err != nil {
		return constraintengine.RuleSet{}, err
	}
	raw, err := b.ruleDocumentBytes(rules, corpus)
	if err != nil {
		return constraintengine.RuleSet{}, err
	}
	return constraintengine.ParseRuleSet(raw, b.registry)
}

// ruleDocumentBytes renders the rule document exactly as the engine will see
// it. It is separate from parseRulesCorpus so the corpus tests can hand a
// document straight to constraintengine.ParseRuleSet and observe the engine's
// own verdict on it, independently of this package's checks.
func (b bundle) ruleDocumentBytes(rules []json.RawMessage, corpus []string) ([]byte, error) {
	type corpusBlock struct {
		Completeness string   `json:"completeness"`
		Components   []string `json:"components"`
	}
	document := struct {
		Schema       string            `json:"schema"`
		Revision     string            `json:"revision"`
		PolicyID     string            `json:"policyId"`
		PolicyDigest string            `json:"policyDigest"`
		Rules        []json.RawMessage `json:"rules"`
		Corpus       *corpusBlock      `json:"corpus,omitempty"`
	}{"", b.pack.Revision, b.pack.PolicyID, b.pack.PolicyDigest, rules, nil}
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		return nil, ErrIntegrity
	}
	document.Schema = schema
	if len(corpus) > 0 {
		document.Corpus = &corpusBlock{Completeness: constraintengine.CorpusAttestation, Components: corpus}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}

const maxCNCFReviewWindow = 90 * 24 * time.Hour

// validateCNCFReviewWindows enforces the interval declared by the CNCF
// source-preview policy. It is deliberately at this bundle seam so embedded
// and externally transported CNCF rule packs share the same policy without
// changing the generic constraint engine's evidence contract.
func validateCNCFReviewWindows(rules []json.RawMessage) error {
	for _, raw := range rules {
		var shape struct {
			Evidence struct {
				ReviewedAt string `json:"reviewedAt"`
				ValidUntil string `json:"validUntil"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(raw, &shape); err != nil {
			return ErrInvalid
		}
		reviewed, err := parseCNCFUTC(shape.Evidence.ReviewedAt)
		if err != nil {
			return ErrInvalid
		}
		validUntil, err := parseCNCFUTC(shape.Evidence.ValidUntil)
		if err != nil || !validUntil.After(reviewed) || validUntil.Sub(reviewed) > maxCNCFReviewWindow {
			return ErrInvalid
		}
	}
	return nil
}

func parseCNCFUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

// Only public identities are read here, after the engine admitted the complete
// input. No unvalidated input participates in rule dispatch.
type identityShape struct {
	Component string `json:"component"`
	Version   string `json:"version"`
}
type sideShape struct {
	Components []identityShape `json:"components"`
}
type conditionShape struct {
	Side      string `json:"side"`
	Component string `json:"component"`
	FactID    string `json:"factId"`
}
type ruleShape struct {
	Subject struct {
		Component string `json:"component"`
		From      string `json:"from"`
		To        string `json:"to"`
	} `json:"subject"`
	Condition   *conditionShape  `json:"condition"`
	AppliesWhen []conditionShape `json:"appliesWhen"`
}

func (b bundle) rulesForAdmittedInput(project string, raw []byte) (constraintengine.RuleSet, error) {
	var input struct {
		Current  sideShape `json:"current"`
		Proposed sideShape `json:"proposed"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return constraintengine.RuleSet{}, ErrIntegrity
	}
	versions := func(side sideShape) map[string]string {
		values := map[string]string{}
		for _, identity := range side.Components {
			values[identity.Component] = identity.Version
		}
		return values
	}
	current, proposed := versions(input.Current), versions(input.Proposed)
	matched := make([]json.RawMessage, 0)
	for _, entry := range b.pack.Entries {
		if entry.Project != project {
			continue
		}
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			return constraintengine.RuleSet{}, ErrIntegrity
		}
		if subject.Match(current[subject.Component], proposed[subject.Component]) != constraintengine.MatchNone {
			matched = append(matched, entry.Rule)
		}
	}
	if len(matched) == 0 {
		return b.ruleSet(project)
	}
	return b.parseRules(matched)
}

// factFamilyRuleSet selects the project's rules whose condition and
// applicability facts all belong to facts, narrowed to the rules whose
// transition matches the input when any does.
func (b bundle) factFamilyRuleSet(project string, facts []string, raw []byte) (constraintengine.RuleSet, error) {
	allowed := map[string]bool{}
	for _, fact := range facts {
		allowed[fact] = true
	}
	var input struct {
		Current  sideShape `json:"current"`
		Proposed sideShape `json:"proposed"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return constraintengine.RuleSet{}, ErrIntegrity
	}
	versions := func(side sideShape) map[string]string {
		values := map[string]string{}
		for _, identity := range side.Components {
			values[identity.Component] = identity.Version
		}
		return values
	}
	current, proposed := versions(input.Current), versions(input.Proposed)
	family := make([]json.RawMessage, 0)
	matched := make([]json.RawMessage, 0)
	for _, entry := range b.pack.Entries {
		if entry.Project != project {
			continue
		}
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return constraintengine.RuleSet{}, ErrIntegrity
		}
		conditions := append([]conditionShape(nil), shape.AppliesWhen...)
		if shape.Condition != nil {
			conditions = append(conditions, *shape.Condition)
		}
		inFamily := len(conditions) > 0
		for _, condition := range conditions {
			inFamily = inFamily && allowed[condition.FactID]
		}
		if !inFamily {
			continue
		}
		family = append(family, entry.Rule)
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			return constraintengine.RuleSet{}, ErrIntegrity
		}
		if subject.Match(current[subject.Component], proposed[subject.Component]) != constraintengine.MatchNone {
			matched = append(matched, entry.Rule)
		}
	}
	if len(matched) == 0 {
		return b.parseRules(family)
	}
	return b.parseRules(matched)
}

func (b bundle) selectedRuleSet(project, ruleID string) (constraintengine.RuleSet, error) {
	selected := make([]json.RawMessage, 0, 1)
	for _, entry := range b.pack.Entries {
		if entry.Project != project {
			continue
		}
		var shape struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return constraintengine.RuleSet{}, ErrIntegrity
		}
		if shape.ID == ruleID {
			selected = append(selected, entry.Rule)
		}
	}
	return b.parseRules(selected)
}

func (b bundle) ownsRuleID(project, ruleID string) (bool, error) {
	for _, entry := range b.pack.Entries {
		var shape struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return false, ErrIntegrity
		}
		if shape.ID == ruleID {
			return entry.Project == project, nil
		}
	}
	return false, nil
}

func subjectComponent(project, repository string) string {
	if project == "opentelemetry" {
		return "pkg:github/open-telemetry/opentelemetry-collector"
	}
	if project == "buildpacks" {
		return "pkg:oci/buildpacksio/lifecycle"
	}
	// The pinned Landscape preserves CubeFS's mixed-case GitHub organization,
	// while package URLs admitted by the constraint engine are lowercase.
	if project == "cubefs" {
		return "pkg:github/cubefs/cubefs"
	}
	if project == "kubeflow" {
		return "pkg:pypi/kfp"
	}
	// This rule identifies the versioned CNI configuration specification, not
	// the Go library or plugins hosted in the Landscape repository.
	if project == "container-network-interface-cni" {
		return "pkg:generic/cni-configuration-spec"
	}
	const prefix = "https://github.com/"
	if len(repository) <= len(prefix) || repository[:len(prefix)] != prefix {
		return ""
	}
	return "pkg:github/" + repository[len(prefix):]
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(value[:])
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for index := range aa {
		if aa[index] != bb[index] {
			return false
		}
	}
	return true
}
