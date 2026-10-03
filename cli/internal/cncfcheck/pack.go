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
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
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
	// LineAttestations is the optional line attestation section. A pack
	// that carries it uses the attested pack schema, which binaries that
	// predate attestations reject; a pack without it is byte-identical to
	// one built before attestations existed.
	LineAttestations json.RawMessage `json:"lineAttestations,omitempty"`
	// PathPolicies is the optional upgrade-path policy section, under the
	// same rule: a pack that carries it uses the path-policy pack schema.
	PathPolicies json.RawMessage `json:"pathPolicies,omitempty"`
}

type bundle struct {
	landscape       landscapeDocument
	priority        priorityDocument
	pack            rulePack
	registry        constraintengine.Registry
	packDigest      string
	catalogueDigest string
	attestations    lineattest.Index
	pathPolicies    upgradepath.Index
}

func load() (bundle, error) {
	landscapeRaw, err := packagedFiles.ReadFile("data/landscape-projects.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	priorityRaw, err := packagedFiles.ReadFile("data/priority-portfolio.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	packRaw, err := packagedRulePack()
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	return assemble(landscapeRaw, priorityRaw, packRaw, compiledDefinitions())
}

// assemble admits the landscape, priority list and rule pack against a fact
// registry built from definitions. Every check of the packaged knowledge is
// here, so tests can hold synthetic knowledge to exactly the same rules.
func assemble(landscapeRaw, priorityRaw, packRaw []byte, factDefinitions []constraintengine.FactDefinition) (bundle, error) {
	var result bundle
	// Pack member names are checked exactly before decoding, and the
	// attestation section is taken from the same function every other
	// reader of a pack's attestations uses.
	attestationSection, attested, err := lineattest.PackSection(packRaw)
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	if strictJSON(landscapeRaw, &result.landscape) != nil || strictJSON(priorityRaw, &result.priority) != nil || strictJSON(packRaw, &result.pack) != nil {
		return bundle{}, ErrIntegrity
	}
	if attested != (len(result.pack.LineAttestations) > 0) || !bytes.Equal(attestationSection, result.pack.LineAttestations) {
		return bundle{}, ErrIntegrity
	}
	policySection, hasPolicies, err := lineattest.PackMemberSection(packRaw, upgradepath.PackMember)
	if err != nil || hasPolicies != (len(result.pack.PathPolicies) > 0) || !bytes.Equal(policySection, result.pack.PathPolicies) {
		return bundle{}, ErrIntegrity
	}
	result.registry, err = constraintengine.NewCompiledRegistry(factDefinitions)
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
	for _, definition := range factDefinitions {
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
		conditions := shape.conditions()
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
	if result.attestations, err = admitAttestations(attestationSection, attested, result.pack.Entries); err != nil {
		return bundle{}, err
	}
	if result.pathPolicies, err = admitPathPolicies(policySection, hasPolicies, result.landscape.Projects); err != nil {
		return bundle{}, err
	}
	return result, nil
}

// admitAttestations parses the pack's line attestation section (as
// lineattest.PackSection located it) strictly and requires every attestation
// to list exactly the pack's rules for its component, line and fact family,
// each of them matching every transition into the line. Any problem rejects
// the whole pack: an attestation that leaves out a rule, or lists one that
// is silent on part of the line, would let a gap pass as covered.
func admitAttestations(section json.RawMessage, present bool, entries []Entry) (lineattest.Index, error) {
	if !present {
		return lineattest.NewIndex(nil), nil
	}
	atts, err := lineattest.Parse(section)
	if err != nil {
		return lineattest.Index{}, ErrIntegrity
	}
	rules := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		rules = append(rules, entry.Rule)
	}
	problems, err := lineattest.CheckRuleSets(atts, rules)
	if err != nil || len(problems) > 0 {
		return lineattest.Index{}, ErrIntegrity
	}
	return lineattest.NewIndex(atts), nil
}

// AttestationsFor returns the embedded pack's line attestations for one
// component, minor release line and fact family, each with its freshness at
// now. An empty result means the line is not attested for that family; only
// an attestation whose freshness is current may be relied on. The caller's
// contract is that of lineattest.Index.AttestationsFor: a listed rule that
// does not match the hop being evaluated makes the hop a gap, never covered.
func AttestationsFor(component, line, family string, now time.Time) ([]lineattest.Status, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	return b.attestations.AttestationsFor(component, line, family, now), nil
}

const (
	packSchema       = "prufyx.io/cncf-source-rule-pack/v1alpha1"
	packSchemaRanged = "prufyx.io/cncf-source-rule-pack/v1alpha2"
	packSchemaSet    = "prufyx.io/cncf-source-rule-pack/v1alpha3"
	// packSchemaAttested is the level of a pack holding line attestations.
	packSchemaAttested = "prufyx.io/cncf-source-rule-pack/v1alpha4"
	// packSchemaPathPolicies is the level of a pack holding upgrade-path
	// policies.
	packSchemaPathPolicies = "prufyx.io/cncf-source-rule-pack/v1alpha5"
)

// packFeature is one pack feature and the schema that introduced it.
type packFeature struct {
	schema  string
	present func(pack rulePack, rules []json.RawMessage) (bool, error)
}

// packFeatureLevels lists the pack features in ascending schema level. A
// pack carries exactly the schema of the highest-level feature it uses, and
// the original schema when it uses none, so a pack without a newer feature
// keeps its bytes and digest, and a binary that predates a feature rejects
// every pack that uses it (unknown schema). A new feature adds one row.
var packFeatureLevels = []packFeature{
	{packSchemaRanged, func(_ rulePack, rules []json.RawMessage) (bool, error) { return constraintengine.AnyRanged(rules) }},
	{packSchemaSet, func(_ rulePack, rules []json.RawMessage) (bool, error) { return constraintengine.AnySetRule(rules) }},
	{packSchemaAttested, func(pack rulePack, _ []json.RawMessage) (bool, error) { return len(pack.LineAttestations) > 0, nil }},
	{packSchemaPathPolicies, func(pack rulePack, _ []json.RawMessage) (bool, error) { return len(pack.PathPolicies) > 0, nil }},
}

// requiredPackSchema is the schema of the highest-level feature the pack
// uses.
func requiredPackSchema(pack rulePack) (string, error) {
	rules := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		rules = append(rules, entry.Rule)
	}
	schema := packSchema
	for _, feature := range packFeatureLevels {
		present, err := feature.present(pack, rules)
		if err != nil {
			return "", err
		}
		if present {
			schema = feature.schema
		}
	}
	return schema, nil
}

// validPackSchema requires the pack schema to be exactly the level of the
// highest-level feature the pack uses (packFeatureLevels).
func validPackSchema(pack rulePack) bool {
	schema, err := requiredPackSchema(pack)
	return err == nil && pack.Schema == schema
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
	Condition    *conditionShape  `json:"condition"`
	SetCondition *conditionShape  `json:"setCondition"`
	AppliesWhen  []conditionShape `json:"appliesWhen"`
}

// conditions lists every fact a rule reads: its applicability facts, its
// predicate condition and its set condition.
func (s ruleShape) conditions() []conditionShape {
	conditions := append([]conditionShape(nil), s.AppliesWhen...)
	if s.Condition != nil {
		conditions = append(conditions, *s.Condition)
	}
	if s.SetCondition != nil {
		conditions = append(conditions, *s.SetCondition)
	}
	return conditions
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
		conditions := shape.conditions()
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
