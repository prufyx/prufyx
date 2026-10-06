// SPDX-License-Identifier: AGPL-3.0-only

// Package rulecheck validates a community-contributed rule candidate against
// the same structural, pattern and evidence rules the compiled engine
// applies to a published pack entry.
//
// It never writes to a rules.json file and never publishes, adds or changes
// a compatibility claim. It only reports what is wrong with a candidate so a
// maintainer can review a well-formed proposal instead of a malformed one.
//
// Reuse discipline: every check the constraint engine (internal/constraintengine)
// already exports — NewRegistry, ParseRuleSet — is called directly rather than
// re-implemented. A handful of engine validation patterns are not exported
// (contracts.go: idRE, gitRevision, digestRE, versionRE). Where this package
// needs a precise, per-field failure message rather than the engine's single
// wrapped error, those patterns are mirrored verbatim below, each annotated
// with its source, and constraintengine.ParseRuleSet is still run afterwards
// as the authoritative final gate.
package rulecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Mirrored verbatim from internal/constraintengine/contracts.go (unexported
// there). Kept byte-for-byte identical on purpose: a candidate that satisfies
// these but is later rejected by constraintengine.ParseRuleSet indicates the
// two have drifted, and the ParseRuleSet call below still catches it.
var (
	ruleIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	reasonCodePatt  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	gitHostPathPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	publicPathPart  = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._+@=,-]*|\.github)$`)
)

// maxPublicTextBytes mirrors constraintengine's maxStringBytes (unexported):
// the byte bound the engine applies to nextAction. This package applies the
// same bound to the contributor-facing description fields the engine does
// not itself constrain, so a candidate cannot sneak an oversized field past
// review just because it isn't the one field the engine happens to check.
const maxPublicTextBytes = 256

// Entry is one candidate contribution, in exactly the schema a published
// pack entry uses (see internal/projectcheck/data/rules.json or
// internal/cncfcheck/data/rules.json for real examples).
type Entry struct {
	Project       string          `json:"project"`
	Description   string          `json:"description"`
	RequiredFacts []Fact          `json:"requiredFacts"`
	Rule          json.RawMessage `json:"rule"`
}

// Fact is one entry in requiredFacts.
type Fact struct {
	Side        string   `json:"side"`
	ID          string   `json:"id"`
	Component   string   `json:"component"`
	Type        string   `json:"type"`
	EnumTokens  []string `json:"enumTokens"`
	Description string   `json:"description"`
}

// The following mirror the unexported rule/evidence shape in
// internal/constraintengine/contracts.go so this package can strict-decode a
// candidate's rule object field-by-field before handing it to ParseRuleSet.
type ruleBody struct {
	ID       string     `json:"id"`
	Operator string     `json:"operator"`
	Subject  transition `json:"subject"`
	// Range is optional, exactly as the engine's own rule schema has it. A
	// maintainer adds it when publishing a reviewed range; a community
	// contribution carrying one is rejected in checkEntry unless the caller
	// opts in with Options.AllowRange (see there for the reuse discipline:
	// the actual structural validation still runs through the engine's own
	// constraintengine.ParseRuleSet, never reimplemented here).
	Range        *constraintengine.VersionRange `json:"range,omitempty"`
	Condition    *factCondition                 `json:"condition,omitempty"`
	SetCondition *setCondition                  `json:"setCondition,omitempty"`
	AppliesWhen  []factCondition                `json:"appliesWhen,omitempty"`
	Dependency   *componentCheck                `json:"dependency,omitempty"`
	Intermediate string                         `json:"intermediate,omitempty"`
	// Severity is optional ("unsupported" on a support-range rule); the
	// engine decides whether it is valid.
	Severity string `json:"severity,omitempty"`
	// Crossing is optional, exactly as the engine's own rule schema has it:
	// a removal at release C blocks every strict hop A < C <= B below a
	// cited, finite horizon. The gate below checks the contribution
	// requirements; the engine's ParseRuleSet remains the authority.
	Crossing   *constraintengine.CrossingSpec `json:"crossing,omitempty"`
	Evidence   evidenceBody                   `json:"evidence"`
	ReasonCode string                         `json:"reasonCode"`
	NextAction string                         `json:"nextAction"`
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

// setCondition mirrors the engine's forbid_set_member condition: the set fact
// read and the members the rule forbids.
type setCondition struct {
	Side      string   `json:"side"`
	Component string   `json:"component"`
	FactID    string   `json:"factId"`
	Members   []string `json:"members"`
}

type componentCheck struct {
	Side       string `json:"side"`
	Component  string `json:"component"`
	Comparison string `json:"comparison"`
	Version    string `json:"version"`
}

type evidenceBody struct {
	State string `json:"state"`
	// Basis, Extractor and DerivedAt are the optional provenance of a rule
	// the engine parses strictly: reviewed by a maintainer (absent) or
	// derived from pinned source by a versioned extractor (mechanical).
	Basis      string                            `json:"basis,omitempty"`
	Extractor  *constraintengine.Extractor       `json:"extractor,omitempty"`
	DerivedAt  string                            `json:"derivedAt,omitempty"`
	ReviewedAt string                            `json:"reviewedAt"`
	ValidUntil string                            `json:"validUntil"`
	Sources    []constraintengine.SourceEvidence `json:"sources"`
}

// Finding is one precise, actionable validation failure.
type Finding struct {
	EntryIndex int    `json:"entryIndex"`
	RuleID     string `json:"ruleId,omitempty"`
	Check      string `json:"check"`
	Message    string `json:"message"`
}

// Span is one cited evidence span, printed for reviewer reading convenience
// with --print-span. It never fetches anything itself.
type Span struct {
	EntryIndex int    `json:"entryIndex"`
	RuleID     string `json:"ruleId"`
	SourceID   string `json:"sourceId"`
	URL        string `json:"url"`
	Revision   string `json:"revision"`
	StartLine  int    `json:"startLine"`
	EndLine    int    `json:"endLine"`
}

// Result is the full validation report for one candidate file.
type Result struct {
	Schema     string    `json:"schema"`
	Valid      bool      `json:"valid"`
	EntryCount int       `json:"entryCount"`
	Findings   []Finding `json:"findings"`
	Spans      []Span    `json:"spans,omitempty"`
}

// ResultSchema identifies this validator's report shape.
const ResultSchema = "prufyx.io/community-rule-candidate-validation/v1alpha1"

// Fetcher downloads a raw blob for the online --fetch check. Tests inject a
// fake; production wires HTTPFetcher. Never called unless the caller opts in.
type Fetcher interface {
	FetchRawBlob(ctx context.Context, rawURL string) ([]byte, error)
}

// Options configures validation.
type Options struct {
	// Fetch enables the online check: downloading the raw blob at each
	// source's revision and comparing its whole-file sha256 to
	// contentDigest, and checking endLine against the file's line count.
	// Offline (false) is the default and requires no network access.
	Fetch bool
	// Fetcher is required when Fetch is true.
	Fetcher Fetcher
	// PrintSpan requests that Result.Spans be populated with the cited line
	// ranges. It never fetches by itself; combine with Fetch to also read
	// the live lines (see PrintSpanLines).
	PrintSpan bool
	// ExistingRulesPaths are published pack files (e.g. cncfcheck and
	// projectcheck rules.json) to check candidate rule IDs against for
	// collisions. A candidate ID equal to any published rule ID, or to
	// another candidate ID in the same file, is rejected.
	ExistingRulesPaths []string
	// AllowRange opts in to accepting a rule.range field. It is for the
	// maintainer's own publish-time self-check against already-published,
	// reviewed packs, never for the public "rule validate" CLI a community
	// contributor runs: a community candidate's range is accepted only in the
	// release-boundary shape of communityRangeProblems (finite, cited bounds
	// pinning the crossed release C) and is otherwise rejected with a clear
	// message; the maintainer path is not restricted to that shape.
	// When true, a candidate's range is not re-validated by hand here; it is checked exactly as the compiled engine checks a published
	// rule, via constraintengine.ParseRuleSet in runEngineParse below.
	AllowRange bool
}

// Validate parses and checks every entry in a candidate file. It returns a
// Result even when validation fails; the caller decides how to report or
// exit. The returned error is non-nil only for a malformed candidate file
// that could not be decoded into the pack entry schema at all.
func Validate(raw []byte, opts Options) (Result, error) {
	entries, findings, err := decodeCandidates(raw)
	if err != nil {
		return Result{}, err
	}
	result := Result{Schema: ResultSchema, EntryCount: len(entries)}
	result.Findings = append(result.Findings, findings...)

	existingIDs, err := loadExistingRuleIDs(opts.ExistingRulesPaths)
	if err != nil {
		return Result{}, fmt.Errorf("read existing rule packs: %w", err)
	}

	seenInBatch := map[string]int{}
	for index, entry := range entries {
		bodyFindings, ruleID, valid := checkEntry(index, entry, opts)
		result.Findings = append(result.Findings, bodyFindings...)
		if !valid {
			continue
		}
		if ruleID != "" {
			if firstIndex, duplicate := seenInBatch[ruleID]; duplicate {
				result.Findings = append(result.Findings, Finding{
					EntryIndex: index, RuleID: ruleID, Check: "rule-id-collision",
					Message: fmt.Sprintf("rule id %q duplicates entry %d in this same candidate file", ruleID, firstIndex),
				})
			} else {
				seenInBatch[ruleID] = index
			}
			if _, published := existingIDs[ruleID]; published {
				result.Findings = append(result.Findings, Finding{
					EntryIndex: index, RuleID: ruleID, Check: "rule-id-collision",
					Message: fmt.Sprintf("rule id %q already exists in a published pack; choose a new, unique rule id", ruleID),
				})
			}
		}
		if opts.PrintSpan {
			result.Spans = append(result.Spans, spansFor(index, entry)...)
		}
	}

	if opts.Fetch {
		onlineFindings, err := checkOnline(context.Background(), entries, opts.Fetcher)
		if err != nil {
			return Result{}, err
		}
		result.Findings = append(result.Findings, onlineFindings...)
	}

	result.Valid = len(result.Findings) == 0
	return result, nil
}

func decodeCandidates(raw []byte) ([]Entry, []Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, fmt.Errorf("candidate file is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var entries []Entry
	if err := decoder.Decode(&entries); err != nil {
		return nil, nil, fmt.Errorf("candidate file does not decode as a JSON array of pack entries (schema, description, requiredFacts, rule): %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("candidate file has trailing data after the JSON array")
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("candidate file declares zero entries")
	}
	return entries, nil, nil
}

// checkEntry runs every offline check against one candidate entry. It
// returns the rule ID (empty if the rule body itself did not even decode)
// and whether the entry is well-formed enough to be considered for
// collision checking and span printing.
func checkEntry(index int, entry Entry, opts Options) ([]Finding, string, bool) {
	var findings []Finding
	add := func(check, format string, args ...any) {
		findings = append(findings, Finding{EntryIndex: index, Check: check, Message: fmt.Sprintf(format, args...)})
	}
	addRule := func(ruleID, check, format string, args ...any) {
		findings = append(findings, Finding{EntryIndex: index, RuleID: ruleID, Check: check, Message: fmt.Sprintf(format, args...)})
	}

	if strings.TrimSpace(entry.Project) == "" {
		add("project", "project must not be empty")
	}
	// entry.Description and each fact.Description are contributor-facing
	// pack-schema fields, not one of the engine's own byte-limited fields
	// (only rule.nextAction is): published entries legitimately carry
	// descriptions longer than 256 bytes. They still must be non-empty and
	// free of control characters.
	if !nonEmptyNoControl(entry.Description) {
		add("description", "description must be non-empty with no control characters")
	}
	// requiredFacts may legitimately be empty: an operator such as
	// require_component_version or forbid_target_version carries no fact
	// condition at all. Whether a condition/appliesWhen entry has a matching
	// requiredFacts declaration is checked below, once the rule body is
	// decoded, via checkFactReference.

	// A fact ID may legitimately appear twice in requiredFacts: once per side
	// (current and proposed), when the same underlying fact is checked on
	// both. The compiled registry keys a fact definition by ID alone (side
	// lives on the condition, not the definition), so only the first
	// occurrence of a given ID is added to the registry; later occurrences
	// must agree with it on component, type and enum tokens.
	factDefs := make([]constraintengine.FactDefinition, 0, len(entry.RequiredFacts))
	factKeys := map[string]struct{}{}
	seenFactDef := map[string]constraintengine.FactDefinition{}
	for factIndex, fact := range entry.RequiredFacts {
		if fact.Side != "current" && fact.Side != "proposed" {
			add("requiredFacts", "requiredFacts[%d].side must be \"current\" or \"proposed\", got %q", factIndex, fact.Side)
		}
		if !nonEmptyNoControl(fact.Description) {
			add("requiredFacts", "requiredFacts[%d].description must be non-empty with no control characters", factIndex)
		}
		var factType constraintengine.FactType
		switch fact.Type {
		case "bool":
			factType = constraintengine.FactBool
		case "enum":
			factType = constraintengine.FactEnum
		case "set":
			factType = constraintengine.FactSet
		default:
			add("requiredFacts", "requiredFacts[%d].type must be \"bool\", \"enum\" or \"set\", got %q", factIndex, fact.Type)
			continue
		}
		definition := constraintengine.FactDefinition{ID: fact.ID, Component: fact.Component, Type: factType, EnumTokens: fact.EnumTokens}
		if previous, exists := seenFactDef[fact.ID]; exists {
			if previous.Component != definition.Component || previous.Type != definition.Type || !equalTokens(previous.EnumTokens, definition.EnumTokens) {
				add("requiredFacts", "requiredFacts[%d] redeclares fact %q with a different component, type, or enumTokens than an earlier entry", factIndex, fact.ID)
			}
		} else {
			seenFactDef[fact.ID] = definition
			factDefs = append(factDefs, definition)
		}
		factKeys[fact.Side+"\x00"+fact.Component+"\x00"+fact.ID] = struct{}{}
	}

	registry, err := constraintengine.NewRegistry(factDefs)
	if err != nil {
		add("requiredFacts", "requiredFacts do not form a valid fact registry (duplicate, malformed, or oversized fact id/component/enum tokens): %v", err)
		return findings, "", false
	}

	var body ruleBody
	bodyDecoder := json.NewDecoder(bytes.NewReader(entry.Rule))
	bodyDecoder.DisallowUnknownFields()
	if err := bodyDecoder.Decode(&body); err != nil {
		add("rule-schema", "rule object does not decode as the closed rule schema (id, operator, subject, condition/setCondition/appliesWhen/dependency/intermediate/severity, evidence, reasonCode, nextAction): %v", err)
		return findings, "", false
	}
	if _, err := bodyDecoder.Token(); err != io.EOF {
		add("rule-schema", "rule object has trailing data")
		return findings, "", false
	}

	ruleID := body.ID

	if body.Range != nil && !opts.AllowRange {
		for _, problem := range communityRangeProblems(body) {
			addRule(ruleID, "range", "rule.range is not accepted from a community contribution: %s", problem)
		}
	}

	if body.Crossing != nil {
		for _, problem := range crossingProblems(body) {
			addRule(ruleID, "crossing", "rule.crossing is not acceptable: %s", problem)
		}
	}

	if !ruleIDPattern.MatchString(body.ID) {
		addRule(ruleID, "rule-id", "rule.id %q does not match the engine's id pattern ^[a-z0-9][a-z0-9._-]{0,127}$", body.ID)
	}
	if !reasonCodePatt.MatchString(body.ReasonCode) {
		addRule(ruleID, "reason-code", "rule.reasonCode %q does not match ^[A-Z][A-Z0-9_]{0,127}$", body.ReasonCode)
	}
	if !publicText(body.NextAction) {
		addRule(ruleID, "next-action", "rule.nextAction must be 1-%d bytes with no control characters", maxPublicTextBytes)
	}
	if !versionPattern.MatchString(body.Subject.From) {
		addRule(ruleID, "version", "rule.subject.from %q is not strict semver (major.minor.patch, no leading zeros)", body.Subject.From)
	}
	if !versionPattern.MatchString(body.Subject.To) {
		addRule(ruleID, "version", "rule.subject.to %q is not strict semver (major.minor.patch, no leading zeros)", body.Subject.To)
	}
	if body.Subject.From != "" && body.Subject.From == body.Subject.To {
		addRule(ruleID, "version", "rule.subject.from and rule.subject.to must differ, both are %q", body.Subject.From)
	}

	// Every fact referenced by condition/appliesWhen must be declared in
	// requiredFacts under the same side and component, mirroring
	// projectcheck.requiredFact's own-entry-only lookup.
	checkFactReference := func(label string, condition *factCondition) {
		if condition == nil {
			return
		}
		key := condition.Side + "\x00" + condition.Component + "\x00" + condition.FactID
		if _, ok := factKeys[key]; !ok {
			addRule(ruleID, "fact-reference", "%s references fact %q (side=%s, component=%s) which is not declared in requiredFacts", label, condition.FactID, condition.Side, condition.Component)
		}
	}
	checkFactReference("rule.condition", body.Condition)
	if body.SetCondition != nil {
		checkFactReference("rule.setCondition", &factCondition{Side: body.SetCondition.Side, Component: body.SetCondition.Component, FactID: body.SetCondition.FactID})
		for memberIndex, member := range body.SetCondition.Members {
			if !constraintengine.ValidSetMember(member) {
				addRule(ruleID, "set-member", "rule.setCondition.members[%d] %q must be 1-%d bytes of [A-Za-z0-9._/-] starting with a letter or digit", memberIndex, member, constraintengine.MaxSetMemberBytes)
			} else if memberIndex > 0 && body.SetCondition.Members[memberIndex-1] >= member {
				addRule(ruleID, "set-member", "rule.setCondition.members must be strictly ascending with no duplicates; %q follows %q", member, body.SetCondition.Members[memberIndex-1])
			}
		}
		if len(body.SetCondition.Members) == 0 || len(body.SetCondition.Members) > constraintengine.MaxForbiddenMembers {
			addRule(ruleID, "set-member", "rule.setCondition.members must name 1-%d forbidden members, got %d", constraintengine.MaxForbiddenMembers, len(body.SetCondition.Members))
		}
	}
	for i := range body.AppliesWhen {
		checkFactReference(fmt.Sprintf("rule.appliesWhen[%d]", i), &body.AppliesWhen[i])
	}
	if index, ok := contradictingApplicability(body); ok {
		addRule(ruleID, "vacuous-condition", "rule.condition and rule.appliesWhen[%d] read the same fact %q (side=%s, component=%s) with different values, so the rule applies only when its condition cannot match and can never block; drop the guard or fix the value", index, body.Condition.FactID, body.Condition.Side, body.Condition.Component)
	}

	// A community candidate must always declare active evidence: submitting
	// a brand-new rule as already withdrawn makes no sense. AllowRange (see
	// its doc comment) marks this call as the maintainer's own self-check
	// against an already-published, reviewed pack, where a rule may have
	// been withdrawn after publication; that path also accepts "withdrawn".
	if body.Evidence.State != "active" && !(opts.AllowRange && body.Evidence.State == "withdrawn") {
		addRule(ruleID, "evidence-state", "rule.evidence.state must be \"active\" for a new candidate, got %q", body.Evidence.State)
	}
	if err := constraintengine.ValidateBasis(body.Evidence.Basis, body.Evidence.Extractor, body.Evidence.DerivedAt); err != nil {
		addRule(ruleID, "evidence-basis", "rule.evidence.basis must be \"mechanical\" or \"reviewed\" (or absent, meaning reviewed); a mechanical rule requires evidence.extractor {id, version, codeDigest sha256:<64 lowercase hex>} and a UTC RFC3339 evidence.derivedAt, and any other rule must carry neither: %v", err)
	}
	if body.Evidence.Basis == constraintengine.BasisMechanical && !opts.AllowRange {
		addRule(ruleID, "evidence-basis", "rule.evidence.basis \"mechanical\" is not accepted from a community contribution; only the maintainers' derivation tooling produces mechanical rules")
	}
	if len(body.Evidence.Sources) == 0 {
		addRule(ruleID, "evidence-sources", "rule.evidence.sources must cite at least one source")
	}
	for sourceIndex, source := range body.Evidence.Sources {
		label := fmt.Sprintf("rule.evidence.sources[%d]", sourceIndex)
		if !revisionPattern.MatchString(source.Revision) {
			addRule(ruleID, "revision", "%s.revision %q is not 40 lowercase hex characters", label, source.Revision)
		}
		if !digestPattern.MatchString(source.ContentDigest) {
			addRule(ruleID, "content-digest", "%s.contentDigest %q is not sha256:<64 lowercase hex> (must be the whole file's digest, not the cited span's)", label, source.ContentDigest)
		}
		if source.StartLine < 1 {
			addRule(ruleID, "line-range", "%s.startLine must be >= 1, got %d", label, source.StartLine)
		} else if source.EndLine < source.StartLine {
			addRule(ruleID, "line-range", "%s.endLine (%d) must be >= startLine (%d)", label, source.EndLine, source.StartLine)
		}
		if owner, repo, blobRevision, ok := githubBlobURL(source.URL); !ok {
			addRule(ruleID, "url", "%s.url %q is not a pinned GitHub URL (https://github.com/<owner>/<repo>/blob/<40-hex-revision>/<path> or https://raw.githubusercontent.com/<owner>/<repo>/<40-hex-revision>/<path>) with no query or fragment", label, source.URL)
		} else if blobRevision != source.Revision {
			addRule(ruleID, "url", "%s.url embeds commit %s but revision is %s; a rule must cite a pinned commit, never a branch, and the two must match", label, blobRevision, source.Revision)
		} else {
			_ = owner
			_ = repo
		}
	}

	// Final authoritative gate: run the engine's own parser over a
	// synthetic single-rule document built from this entry. Anything this
	// package's own checks missed, or any drift between the mirrored
	// patterns above and the real engine, is still caught here.
	if engineErr := runEngineParse(entry.Rule, registry); engineErr != nil {
		addRule(ruleID, "engine-rejected", "the constraint engine's own parser rejected this rule: %v", engineErr)
	}

	valid := true
	for _, f := range findings {
		if f.Check != "" {
			valid = false
			break
		}
	}
	return findings, ruleID, valid
}

// runEngineParse wraps one candidate rule in a synthetic ruleDocument and
// calls the exported constraintengine.ParseRuleSet, so every check that
// package performs is applied to the candidate exactly as it would be to a
// published rule. The wrapper's own schema/revision/policy fields are
// synthetic placeholders that satisfy ParseRuleSet's document-level shape;
// they carry no meaning about the candidate itself.
func runEngineParse(ruleRaw json.RawMessage, registry constraintengine.Registry) error {
	placeholderRevision := "0000000000000000000000000000000000000c"
	placeholderPolicyID := "community-rule-candidate-validator"
	placeholderPolicyDigest := digestOf([]byte("prufyx community rule candidate validation placeholder policy"))
	rules := []json.RawMessage{ruleRaw}
	// The document's own schema tag must match whether this rule carries a
	// range, exactly as the engine requires of a real published document;
	// reuse the engine's own RulesSchemaFor rather than re-deriving it here.
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		return err
	}
	document := struct {
		Schema       string            `json:"schema"`
		Revision     string            `json:"revision"`
		PolicyID     string            `json:"policyId"`
		PolicyDigest string            `json:"policyDigest"`
		Rules        []json.RawMessage `json:"rules"`
	}{schema, placeholderRevision, placeholderPolicyID, placeholderPolicyDigest, rules}
	raw, err := json.Marshal(document)
	if err != nil {
		return err
	}
	_, err = constraintengine.ParseRuleSet(raw, registry)
	return err
}

// contradictingApplicability mirrors the engine's unexported
// conditionContradictsApplicability (internal/constraintengine/parse.go): a
// forbid_predicate_value condition and an appliesWhen entry on the same side,
// component and fact id with different values make the rule vacuous. It
// returns the index of the first such appliesWhen entry. The engine parse
// below still rejects the rule; this gives the author a precise message.
func contradictingApplicability(body ruleBody) (int, bool) {
	if body.Operator != "forbid_predicate_value" || body.Condition == nil {
		return 0, false
	}
	condition := *body.Condition
	for index, applicability := range body.AppliesWhen {
		if applicability.Side != condition.Side || applicability.Component != condition.Component || applicability.FactID != condition.FactID {
			continue
		}
		sameBool := (applicability.BoolValue == nil) == (condition.BoolValue == nil) && (applicability.BoolValue == nil || *applicability.BoolValue == *condition.BoolValue)
		if !sameBool || applicability.EnumValue != condition.EnumValue {
			return index, true
		}
	}
	return 0, false
}

func digestOf(data []byte) string {
	return "sha256:" + fmt.Sprintf("%x", sha256Sum(data))
}

func spansFor(index int, entry Entry) []Span {
	var body ruleBody
	if json.Unmarshal(entry.Rule, &body) != nil {
		return nil
	}
	spans := make([]Span, 0, len(body.Evidence.Sources))
	for _, source := range body.Evidence.Sources {
		spans = append(spans, Span{
			EntryIndex: index, RuleID: body.ID, SourceID: source.ID, URL: source.URL,
			Revision: source.Revision, StartLine: source.StartLine, EndLine: source.EndLine,
		})
	}
	return spans
}

func equalTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonEmptyNoControl checks a contributor-facing text field the engine itself
// does not byte-limit: non-empty, no control characters, no length cap.
func nonEmptyNoControl(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// publicText mirrors constraintengine's unexported publicText: non-empty,
// at most maxPublicTextBytes, no control characters.
func publicText(value string) bool {
	if value == "" || len(value) > maxPublicTextBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// githubBlobURL mirrors constraintengine's unexported immutableGitURL in
// full: https scheme, no user/port/query/fragment, no percent-encoding, and
// either host github.com with path <owner>/<repo>/blob/<revision>/<path...>,
// or host raw.githubusercontent.com with path <owner>/<repo>/<revision>/<path...>.
// The task's own published packs cite both forms, so both are accepted here
// exactly as the engine accepts them; a rule may still cite only a pinned
// commit, never a branch, in either form.
func githubBlobURL(value string) (owner, repo, revision string, ok bool) {
	if value == "" || len(value) > 2048 || strings.Contains(value, "%") {
		return "", "", "", false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", "", "", false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", "", false
	}
	if parsed.Host != "github.com" && parsed.Host != "raw.githubusercontent.com" {
		return "", "", "", false
	}
	path := strings.TrimPrefix(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parsed.EscapedPath() != parsed.Path || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if !gitHostPathPart.MatchString(parts[0]) || !gitHostPathPart.MatchString(parts[1]) {
		return "", "", "", false
	}
	var rest []string
	if parsed.Host == "github.com" {
		if len(parts) < 5 || parts[2] != "blob" || !revisionPattern.MatchString(parts[3]) {
			return "", "", "", false
		}
		revision = parts[3]
		rest = parts[4:]
	} else {
		if !revisionPattern.MatchString(parts[2]) {
			return "", "", "", false
		}
		revision = parts[2]
		rest = parts[3:]
	}
	for _, part := range rest {
		if part == "" || part == "." || part == ".." || !publicPathPart.MatchString(part) {
			return "", "", "", false
		}
	}
	return parts[0], parts[1], revision, true
}

// rawBlobURL returns the raw.githubusercontent.com URL to fetch for a given
// (already-validated) evidence URL: unchanged if it is already a raw URL,
// otherwise the github.com/.../blob/... form converted to its raw equivalent.
func rawBlobURL(owner, repo, revision, value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if parsed.Host == "raw.githubusercontent.com" {
		return value, true
	}
	path := strings.TrimPrefix(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		return "", false
	}
	filePath := strings.Join(parts[4:], "/")
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, revision, filePath), true
}

func checkOnline(ctx context.Context, entries []Entry, fetcher Fetcher) ([]Finding, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("--fetch requires a Fetcher")
	}
	var findings []Finding
	for index, entry := range entries {
		var body ruleBody
		if json.Unmarshal(entry.Rule, &body) != nil {
			continue
		}
		findings = append(findings, checkOnlineSources(ctx, index, body.ID, "rule.evidence.sources", body.Evidence.Sources, fetcher)...)
	}
	return findings, nil
}

// checkOnlineSources downloads each pinned source and compares its
// whole-file digest and line count with the citation. It is the one online
// check for every cited source, a rule's or a record's; label names the
// source list in findings. A source whose URL does not pin its revision is
// skipped here (the offline checks report it).
func checkOnlineSources(ctx context.Context, index int, id, label string, sources []constraintengine.SourceEvidence, fetcher Fetcher) []Finding {
	var findings []Finding
	for sourceIndex, source := range sources {
		label := fmt.Sprintf("%s[%d]", label, sourceIndex)
		owner, repo, revision, ok := githubBlobURL(source.URL)
		if !ok || revision != source.Revision {
			continue // already reported offline
		}
		raw, ok := rawBlobURL(owner, repo, revision, source.URL)
		if !ok {
			findings = append(findings, Finding{EntryIndex: index, RuleID: id, Check: "fetch-url", Message: fmt.Sprintf("%s.url could not be converted to a raw.githubusercontent.com URL", label)})
			continue
		}
		content, err := fetcher.FetchRawBlob(ctx, raw)
		if err != nil {
			findings = append(findings, Finding{EntryIndex: index, RuleID: id, Check: "fetch-failed", Message: fmt.Sprintf("%s: could not fetch %s: %v", label, raw, err)})
			continue
		}
		gotDigest := digestOf(content)
		if gotDigest != source.ContentDigest {
			findings = append(findings, Finding{EntryIndex: index, RuleID: id, Check: "content-digest-mismatch", Message: fmt.Sprintf("%s.contentDigest is %s but the whole-file sha256 of %s at revision %s is %s", label, source.ContentDigest, raw, revision, gotDigest)})
		}
		lineCount := countLines(content)
		if source.EndLine > lineCount {
			findings = append(findings, Finding{EntryIndex: index, RuleID: id, Check: "line-range-fetched", Message: fmt.Sprintf("%s.endLine is %d but %s has only %d lines at revision %s", label, source.EndLine, raw, lineCount, revision)})
		}
	}
	return findings
}

func countLines(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte("\n"))
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}

// PrintSpanLines fetches and returns the cited lines for one span, for
// --print-span reviewer output. It is only called when both --print-span and
// --fetch are set; without --fetch spans are reported without their text.
func PrintSpanLines(ctx context.Context, fetcher Fetcher, span Span, owner, repo string) ([]string, error) {
	raw, ok := rawBlobURL(owner, repo, span.Revision, span.URL)
	if !ok {
		return nil, fmt.Errorf("could not derive raw URL for %s", span.URL)
	}
	content, err := fetcher.FetchRawBlob(ctx, raw)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	if span.StartLine < 1 || span.EndLine > len(lines) || span.StartLine > span.EndLine {
		return nil, fmt.Errorf("line range %d-%d is out of bounds for a %d-line file", span.StartLine, span.EndLine, len(lines))
	}
	return lines[span.StartLine-1 : span.EndLine], nil
}

func loadExistingRuleIDs(paths []string) (map[string]struct{}, error) {
	ids := map[string]struct{}{}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		raw, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var doc struct {
			Entries []struct {
				Rule struct {
					ID string `json:"id"`
				} `json:"rule"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, entry := range doc.Entries {
			if entry.Rule.ID != "" {
				ids[entry.Rule.ID] = struct{}{}
			}
		}
	}
	return ids, nil
}

// sortedFindingChecks is a small stable helper used by CLI formatting.
func SortedChecks(findings []Finding) []string {
	set := map[string]struct{}{}
	for _, f := range findings {
		set[f.Check] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for check := range set {
		out = append(out, check)
	}
	sort.Strings(out)
	return out
}

// readFile is a var so tests can substitute file I/O without touching disk.
var readFile = os.ReadFile

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// communityRangeProblems is the contribution-time gate for rule.range. A
// community rule may widen its anchor only to the shape "this change release C
// lies in (from, to]": from.lt and to.gte are both the same version C under
// REMOVED_IN_RELEASE or CHANGED_IN_RELEASE, so every matched hop A -> B has
// A < C <= B. All four bounds must be finite versions, each cited to one of
// the rule's own evidence sources, and the anchor must sit inside the range.
// The engine's own ParseRuleSet check (width cap of one minor line per side,
// basis structure, strict-upgrade guarantee) still runs afterwards on the same
// rule; this gate only adds the contribution-specific requirements and
// readable messages. It returns no problem for an acceptable range.
func communityRangeProblems(body ruleBody) []string {
	r := body.Range
	var problems []string
	finite := func(name, v string) bool {
		if v == "" || !constraintengine.SameVersion(v, v) {
			problems = append(problems, fmt.Sprintf("range bound %s %q is missing or not a release version; open-ended ranges are rejected", name, v))
			return false
		}
		return true
	}
	ok := finite("from.gte", r.From.Gte)
	ok = finite("from.lt", r.From.Lt) && ok
	ok = finite("to.gte", r.To.Gte) && ok
	ok = finite("to.lt", r.To.Lt) && ok
	sources := map[string]bool{}
	for _, source := range body.Evidence.Sources {
		sources[source.ID] = true
	}
	want := []string{"from.gte", "from.lt", "to.gte", "to.lt"}
	if len(r.Bounds) != len(want) {
		problems = append(problems, "range.bounds must cite all four bounds (from.gte, from.lt, to.gte, to.lt) in that order")
	} else {
		for i, bound := range r.Bounds {
			if bound.Bound != want[i] {
				problems = append(problems, fmt.Sprintf("range.bounds[%d].bound is %q, want %q", i, bound.Bound, want[i]))
			}
			if bound.SourceID == "" || !sources[bound.SourceID] {
				problems = append(problems, fmt.Sprintf("range.bounds[%d].sourceId %q does not name one of the rule's evidence sources; an uncited bound is rejected", i, bound.SourceID))
			}
		}
		release := func(basis string) bool {
			return basis == constraintengine.BasisRemovedInRelease || basis == constraintengine.BasisChangedInRelease
		}
		if !release(r.Bounds[1].Basis) || r.Bounds[1].Basis != r.Bounds[2].Basis {
			problems = append(problems, "range.bounds from.lt and to.gte must both carry basis REMOVED_IN_RELEASE or CHANGED_IN_RELEASE (the same one): a community range must pin the release C that the upgrade crosses")
		}
	}
	if ok {
		if r.From.Lt != r.To.Gte {
			problems = append(problems, "range.from.lt and range.to.gte must be the same change version C so every matched hop satisfies from < C <= to")
		}
		if !r.From.Contains(body.Subject.From) || !r.To.Contains(body.Subject.To) {
			problems = append(problems, "the anchor subject.from/subject.to must lie inside the range")
		}
	}
	return problems
}

// crossingProblems is the contribution-time gate for rule.crossing. A
// crossing blocks every strict hop A < C <= B below a horizon, so it is only
// as sound as its citations: it is accepted only on a forbid operator, only
// as a removal (REMOVED_IN_RELEASE), and only with a finite horizon
// (REVIEWED_THROUGH_MINOR_LINE) cited to one of the rule's own evidence
// sources. The engine's ParseRuleSet check (minor-line starts, anchor inside
// the crossing region, restored below the horizon, distributions in the
// reviewed closed list) still runs afterwards on the same rule; this gate
// adds the contribution-specific requirements and readable messages.
func crossingProblems(body ruleBody) []string {
	c := body.Crossing
	var problems []string
	if body.Operator != "forbid_predicate_value" && body.Operator != constraintengine.OperatorForbidSetMember {
		problems = append(problems, fmt.Sprintf("crossing is only valid on forbid_predicate_value or forbid_set_member, got operator %q", body.Operator))
	}
	if body.Evidence.Basis == constraintengine.BasisConsensus || body.Evidence.Basis == constraintengine.BasisLead {
		problems = append(problems, "crossing cannot sit on a consensus or lead rule")
	}
	sources := map[string]bool{}
	for _, source := range body.Evidence.Sources {
		sources[source.ID] = true
	}
	finite := func(name, v string) bool {
		if v == "" || !constraintengine.SameVersion(v, v) {
			problems = append(problems, fmt.Sprintf("crossing %s %q is missing or not a release version; an infinite or open-ended horizon is rejected", name, v))
			return false
		}
		return true
	}
	cited := func(name, id string) {
		if id == "" || !sources[id] {
			problems = append(problems, fmt.Sprintf("crossing %s.sourceId %q does not name one of the rule's evidence sources; an uncited %s is rejected", name, id, name))
		}
	}
	if c.Change.Basis != constraintengine.BasisRemovedInRelease {
		problems = append(problems, fmt.Sprintf("crossing.change.basis is %q, want %s", c.Change.Basis, constraintengine.BasisRemovedInRelease))
	}
	if c.Horizon.Basis != constraintengine.BasisReviewedThroughMinorLine {
		problems = append(problems, fmt.Sprintf("crossing.horizon.basis is %q, want %s", c.Horizon.Basis, constraintengine.BasisReviewedThroughMinorLine))
	}
	changeOK := finite("change.version", c.Change.Version)
	horizonOK := finite("horizon.lt", c.Horizon.Lt)
	cited("change", c.Change.SourceID)
	cited("horizon", c.Horizon.SourceID)
	if changeOK && horizonOK && !constraintengine.VersionLess(c.Change.Version, c.Horizon.Lt) {
		problems = append(problems, "crossing.horizon.lt must be above crossing.change.version")
	}
	if c.Restored != nil {
		if c.Restored.Basis != constraintengine.BasisRestoredInRelease {
			problems = append(problems, fmt.Sprintf("crossing.restored.basis is %q, want %s", c.Restored.Basis, constraintengine.BasisRestoredInRelease))
		}
		restoredOK := finite("restored.version", c.Restored.Version)
		cited("restored", c.Restored.SourceID)
		if restoredOK && horizonOK && constraintengine.VersionLess(c.Horizon.Lt, c.Restored.Version) {
			problems = append(problems, "crossing.restored.version must not be above crossing.horizon.lt")
		}
	}
	if c.Distributions != nil {
		if len(c.Distributions) == 0 {
			problems = append(problems, "crossing.distributions must be non-empty when present")
		}
		for i, name := range c.Distributions {
			switch {
			case !constraintengine.ReviewedDistribution(name):
				problems = append(problems, fmt.Sprintf("crossing.distributions[%d] %q is not a reviewed distribution (%s)", i, name, strings.Join(constraintengine.ReviewedDistributions(), ", ")))
			case i > 0 && c.Distributions[i-1] >= name:
				problems = append(problems, "crossing.distributions must be strictly ascending without duplicates")
			}
		}
	}
	return problems
}
