// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"embed"
	"encoding/json"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The scope-completeness path evaluates the WHOLE embedded CNCF rule corpus,
// never a filtered view of it.
//
// rulesForAdmittedInput and selectedRuleSet (see pack.go) narrow the pack to a
// single project — and, when an exact pair matches, to that pair — before
// ParseRuleSet ever sees it. A document assembled that way cannot honestly
// carry a completeness attestation: the engine would have no way to tell "this
// is every reviewed rule that applies" from "this is the rule the caller's
// native route selected". So the document built here carries every entry in the
// pack, and applicability is decided inside the engine — by declared versions
// and declared fact values — rather than by a pre-parse filter.
//
// The CNCF pack is not fully routed: 31 of its 167 reviewed rules have no
// EXACT_PAIR_NATIVE_ROUTE descriptor in checkroutemetadata. Routing is a
// property of the CLI's config-file parsers, not of the corpus, and it plays no
// part anywhere in this file. An unrouted rule is carried into the document,
// into the applicable set, and into the per-component enumeration exactly like
// a routed one; when its facts were not declared it lands in NotEvaluated as
// UNDETERMINED and forces the aggregate back to UNKNOWN. Dropping it would
// manufacture a SCOPE_COMPLETE_PASS over constraints nobody evaluated.
const (
	// CorpusAttestationSchema identifies the maintainer's attestation over the
	// unfiltered embedded CNCF pack.
	CorpusAttestationSchema = "prufyx.io/cncf-corpus-attestation/v1alpha1"
	// ScopeReportSchema identifies a CNCF scope-completeness assessment report.
	ScopeReportSchema = "prufyx.io/cncf-scope-assessment/v1alpha1"

	// AttestationPath is the embedded attestation asset, as the maintainer
	// command writes it.
	AttestationPath = "data/corpus-attestation.json"
)

//go:embed data/corpus-attestation.json
var attestationAsset embed.FS

// Attestation is the rule maintainer's statement that, at this pack revision,
// the embedded CNCF pack holds every reviewed rule whose subject is one of the
// listed components.
//
// It is a statement about the corpus, not a compatibility claim about any
// project: it authors no new claim, weakens none, and asserts nothing about the
// upstream projects' actual behaviour or about their CNCF standing. Its only
// effect is to let the engine tell a complete applicable set apart from a
// selected one.
type Attestation struct {
	Schema      string `json:"schema"`
	Attestation string `json:"attestation"`
	Revision    string `json:"revision"`
	// PackDigest is the digest of the embedded pack file's own bytes.
	PackDigest string `json:"packDigest"`
	// RuleSetDigest binds the attestation to the pack it describes. It is the
	// engine's own Report.RuleSetDigest concept — constraintengine.RuleSet
	// .Digest() over the UNFILTERED document, assembled without the corpus
	// block — so an attestation cannot be moved onto a different or narrowed
	// pack.
	RuleSetDigest string   `json:"ruleSetDigest"`
	RuleCount     int      `json:"ruleCount"`
	Components    []string `json:"components"`
	Limitations   []string `json:"limitations"`
}

// AttestationLimitations are fixed, deterministic and part of the document.
// They are word for word the community pack's, because the statement being
// made is the same one over a different corpus.
func AttestationLimitations() []string {
	return []string{
		"this attestation states only that every reviewed rule the maintainer holds for each listed component is present in this pack at this revision; it authors no compatibility claim and changes none",
		"it is not a statement that the listed upstream projects have no other incompatibilities, only that this corpus is not silently missing a rule the maintainer already reviewed",
		"components absent from this list are outside the attestation; a scope naming one can never reach a completeness verdict",
	}
}

// ScopeReportLimitations are fixed, deterministic and part of every report.
func ScopeReportLimitations() []string {
	return []string{
		"the aggregate covers only the declared component scope; it is never SAFE and is not a whole-upgrade verdict",
		"the declared scope was validated against the caller's own declared bundle and against compiled Landscape identities; it was NOT cross-checked against observed cluster state",
		"completeness rests on the maintainer's corpus attestation for the listed components at this pack revision; absence of evidence is reported as UNKNOWN, never as a pass",
		"reviewed rules with no native CLI descriptor are evaluated from declared facts like any other; when those facts were not declared the rule is enumerated as not evaluated and the aggregate stays UNKNOWN",
	}
}

// CorpusInventory is the maintainer-facing view of the unfiltered embedded
// pack. It is derived from the pack, never declared alongside it.
type CorpusInventory struct {
	Revision      string
	PackDigest    string
	RuleSetDigest string
	RuleCount     int
	Components    []string
}

// UnfilteredCorpus computes the inventory the maintainer attestation is built
// from. It reads every entry in the embedded pack.
func UnfilteredCorpus() (CorpusInventory, error) {
	b, err := load()
	if err != nil {
		return CorpusInventory{}, err
	}
	return b.unfilteredCorpus()
}

func (b bundle) unfilteredCorpus() (CorpusInventory, error) {
	components, err := b.corpusComponents()
	if err != nil {
		return CorpusInventory{}, err
	}
	digest, err := b.unfilteredRuleSetDigest()
	if err != nil {
		return CorpusInventory{}, err
	}
	return CorpusInventory{
		Revision: b.pack.Revision, PackDigest: b.packDigest, RuleSetDigest: digest,
		RuleCount: len(b.pack.Entries), Components: components,
	}, nil
}

// corpusComponents is the sorted, deduplicated set of subject components that
// actually have at least one reviewed rule in the pack. It is the upper bound
// on what any attestation may list.
func (b bundle) corpusComponents() ([]string, error) {
	seen := map[string]struct{}{}
	for _, entry := range b.pack.Entries {
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil || shape.Subject.Component == "" {
			return nil, ErrIntegrity
		}
		seen[shape.Subject.Component] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, ErrIntegrity
	}
	components := make([]string, 0, len(seen))
	for component := range seen {
		components = append(components, component)
	}
	sort.Strings(components)
	return components, nil
}

// componentIdentities is the set of component identities this pack compiles
// from the pinned Landscape. A scope may only name one of these; naming
// anything else is a caller error, not an evidence gap.
func (b bundle) componentIdentities() map[string]struct{} {
	identities := make(map[string]struct{}, len(b.landscape.Projects))
	for _, project := range b.landscape.Projects {
		if component := subjectComponent(project.Slug, project.RepositoryURL); component != "" {
			identities[component] = struct{}{}
		}
	}
	return identities
}

// unfilteredRules is every entry in the pack, in one ascending rule-id order.
//
// The community pack's entries are ordered by (project, rule id) and had to be
// re-sorted for ParseRuleSet, which demands a single ascending rule-id order
// across the whole document. The CNCF pack is already in one ascending rule-id
// order — load() proves it by parsing the whole pack unfiltered through
// ruleSet("") — so this sort is a no-op today. It is kept because the invariant
// ParseRuleSet enforces belongs at the seam that builds the document, not in an
// assumption about how the asset happens to be laid out.
func (b bundle) unfilteredRules() ([]json.RawMessage, error) {
	type ordered struct {
		id  string
		raw json.RawMessage
	}
	items := make([]ordered, 0, len(b.pack.Entries))
	for _, entry := range b.pack.Entries {
		var shape struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil || shape.ID == "" {
			return nil, ErrIntegrity
		}
		items = append(items, ordered{id: shape.ID, raw: entry.Rule})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	rules := make([]json.RawMessage, 0, len(items))
	for index, item := range items {
		if index > 0 && items[index-1].id == item.id {
			return nil, ErrIntegrity
		}
		rules = append(rules, item.raw)
	}
	return rules, nil
}

// unfilteredRuleDocument renders the whole pack as the bytes the engine parses.
// corpus, when non-empty, attaches the maintainer's completeness attestation;
// with nil it produces the bare document whose digest the attestation binds
// itself to.
func (b bundle) unfilteredRuleDocument(corpus []string) ([]byte, error) {
	rules, err := b.unfilteredRules()
	if err != nil {
		return nil, err
	}
	return b.ruleDocumentBytes(rules, corpus)
}

// unfilteredRuleSet parses the whole pack, optionally carrying the corpus
// attestation. It routes through parseRulesCorpus so the CNCF review-window
// policy applies to the completeness path exactly as it does to every other
// CNCF rule document.
func (b bundle) unfilteredRuleSet(corpus []string) (constraintengine.RuleSet, error) {
	rules, err := b.unfilteredRules()
	if err != nil {
		return constraintengine.RuleSet{}, err
	}
	return b.parseRulesCorpus(rules, corpus)
}

func (b bundle) unfilteredRuleSetDigest() (string, error) {
	parsed, err := b.unfilteredRuleSet(nil)
	if err != nil {
		return "", ErrIntegrity
	}
	digest, err := parsed.Digest()
	if err != nil {
		return "", ErrIntegrity
	}
	return digest, nil
}

// ParseAttestation strictly decodes an attestation document. It validates the
// document's own shape only; binding it to a pack is attestedRuleSet's job.
func ParseAttestation(raw []byte) (Attestation, error) {
	var attestation Attestation
	if strictJSON(raw, &attestation) != nil {
		return Attestation{}, ErrInvalid
	}
	if attestation.Schema != CorpusAttestationSchema || attestation.Attestation != constraintengine.CorpusAttestation {
		return Attestation{}, ErrInvalid
	}
	if attestation.Revision == "" || !digestPattern.MatchString(attestation.PackDigest) || !digestPattern.MatchString(attestation.RuleSetDigest) || attestation.RuleCount < 1 {
		return Attestation{}, ErrInvalid
	}
	if len(attestation.Components) == 0 {
		return Attestation{}, ErrInvalid
	}
	for index, component := range attestation.Components {
		if component == "" || (index > 0 && attestation.Components[index-1] >= component) {
			return Attestation{}, ErrInvalid
		}
	}
	if len(attestation.Limitations) != len(AttestationLimitations()) {
		return Attestation{}, ErrInvalid
	}
	for index, limitation := range AttestationLimitations() {
		if attestation.Limitations[index] != limitation {
			return Attestation{}, ErrInvalid
		}
	}
	return attestation, nil
}

// BuildAttestation returns the attestation document the maintainer command
// emits for the current embedded pack. Every field is derived from the pack.
func BuildAttestation() (Attestation, error) {
	inventory, err := UnfilteredCorpus()
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{
		Schema: CorpusAttestationSchema, Attestation: constraintengine.CorpusAttestation,
		Revision: inventory.Revision, PackDigest: inventory.PackDigest, RuleSetDigest: inventory.RuleSetDigest,
		RuleCount: inventory.RuleCount, Components: inventory.Components, Limitations: AttestationLimitations(),
	}, nil
}

// attestedRuleSet binds an attestation to the embedded pack and returns the
// unfiltered rule document carrying it.
//
// The vacuity check is the load-bearing one. An attestation that named a
// component with no reviewed rule in this pack would make completeness
// trivially true for that component — nothing to evaluate, therefore nothing
// unevaluated. ParseRuleSet refuses such a document (constraintengine
// validateCorpus), and the subset check below refuses it before that, so the
// rejection does not depend on either one alone.
func (b bundle) attestedRuleSet(attestationRaw []byte) (constraintengine.RuleSet, Attestation, error) {
	attestation, err := ParseAttestation(attestationRaw)
	if err != nil {
		return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
	}
	if attestation.Revision != b.pack.Revision || attestation.PackDigest != b.packDigest || attestation.RuleCount != len(b.pack.Entries) {
		return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
	}
	digest, err := b.unfilteredRuleSetDigest()
	if err != nil || digest != attestation.RuleSetDigest {
		return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
	}
	present, err := b.corpusComponents()
	if err != nil {
		return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
	}
	known := make(map[string]struct{}, len(present))
	for _, component := range present {
		known[component] = struct{}{}
	}
	for _, component := range attestation.Components {
		if _, ok := known[component]; !ok {
			return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
		}
	}
	parsed, err := b.unfilteredRuleSet(attestation.Components)
	if err != nil {
		return constraintengine.RuleSet{}, Attestation{}, ErrIntegrity
	}
	return parsed, attestation, nil
}

// ScopeReport is a scope-completeness assessment over the declared component
// set. Assessment is UNKNOWN, BLOCKED or SCOPE_COMPLETE_PASS; it is never SAFE,
// and it is always the engine's own recomputed aggregate.
type ScopeReport struct {
	Schema              string                  `json:"schema"`
	Assessment          string                  `json:"assessment"`
	KnowledgeOrigin     string                  `json:"knowledgeOrigin"`
	KnowledgeRevision   string                  `json:"knowledgeRevision"`
	KnowledgePackDigest string                  `json:"knowledgePackDigest"`
	CatalogueDigest     string                  `json:"catalogueDigest"`
	CorpusRuleSetDigest string                  `json:"corpusRuleSetDigest"`
	CorpusRuleCount     int                     `json:"corpusRuleCount"`
	AttestedComponents  []string                `json:"attestedComponents"`
	ScopeComponents     []string                `json:"scopeComponents"`
	InputFileDigest     string                  `json:"inputFileDigest"`
	SourceAuthority     string                  `json:"sourceAuthority"`
	RuntimeReproduced   int                     `json:"runtimeReproduced"`
	NetworkUsed         bool                    `json:"networkUsed"`
	NextAction          string                  `json:"nextAction"`
	Limitations         []string                `json:"limitations"`
	Check               constraintengine.Report `json:"check"`
	seal                *reportSeal
	digest              string
}

// AssessScope evaluates a caller-declared component scope against the whole
// attested embedded CNCF corpus.
//
// The caller's scope declaration is an input to validate, never a statement to
// trust: constraintengine.ParseInput already refuses a declaration that does
// not exactly match the caller's own declared bundle, and every declared
// component must additionally be one this pack compiles from the pinned
// Landscape. Nothing here consults cluster state, and nothing infers a fact the
// caller did not declare.
func AssessScope(inputRaw []byte, now time.Time) (ScopeReport, error) {
	b, err := load()
	if err != nil {
		return ScopeReport{}, err
	}
	attestationRaw, err := attestationAsset.ReadFile(AttestationPath)
	if err != nil {
		return ScopeReport{}, ErrIntegrity
	}
	return assessScopeWith(b, attestationRaw, inputRaw, now)
}

func assessScopeWith(b bundle, attestationRaw, inputRaw []byte, now time.Time) (ScopeReport, error) {
	rules, attestation, err := b.attestedRuleSet(attestationRaw)
	if err != nil {
		return ScopeReport{}, ErrIntegrity
	}
	declared, ok := declaredScope(inputRaw)
	if !ok || len(declared) == 0 {
		return ScopeReport{}, ErrInvalid
	}
	identities := b.componentIdentities()
	for _, component := range declared {
		if _, known := identities[component]; !known {
			return ScopeReport{}, ErrInvalid
		}
	}
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		return ScopeReport{}, ErrInvalid
	}
	result, err := constraintengine.Evaluate(input, rules, now)
	if err != nil {
		return ScopeReport{}, ErrInvalid
	}
	// The engine's own publication gate. It recomputes the aggregate from the
	// enumerated scope block and refuses anything it cannot re-derive, so a
	// report that survives this call is one the engine itself stands behind.
	if _, err := constraintengine.MarshalReport(result); err != nil {
		return ScopeReport{}, ErrIntegrity
	}
	nextAction := "review each enumerated claim and every rule listed as not evaluated; the aggregate covers the declared component scope only"
	if result.Assessment == constraintengine.AssessmentUnknown {
		nextAction = "the declared scope did not resolve; read scopeCompleteness.unresolvedReason and the per-component notEvaluated list, then declare the missing facts or narrow the scope"
	}
	report := ScopeReport{
		Schema: ScopeReportSchema, Assessment: result.Assessment, KnowledgeOrigin: "embedded",
		KnowledgeRevision: b.pack.Revision, KnowledgePackDigest: b.packDigest, CatalogueDigest: b.catalogueDigest,
		CorpusRuleSetDigest: attestation.RuleSetDigest, CorpusRuleCount: attestation.RuleCount,
		AttestedComponents: append([]string(nil), attestation.Components...), ScopeComponents: declared,
		InputFileDigest: digest(inputRaw),
		SourceAuthority: "PACKAGED_MAINTAINER_REVIEWED_SOURCE_RULES_NOT_RUNTIME_PROOF",
		NextAction:      nextAction, Limitations: ScopeReportLimitations(), Check: result,
	}
	report.seal = &reportSeal{}
	raw, err := json.Marshal(report)
	if err != nil {
		return ScopeReport{}, ErrIntegrity
	}
	report.digest = digest(raw)
	return report, nil
}

// MarshalScopeReport seals a scope report for publication. It never trusts the
// scalar it carries: the aggregate must equal the engine's own, and the engine
// report must itself pass constraintengine.MarshalReport.
func MarshalScopeReport(report ScopeReport) ([]byte, error) {
	if report.seal == nil || report.Schema != ScopeReportSchema || report.KnowledgeOrigin != "embedded" || report.NetworkUsed || report.RuntimeReproduced != 0 {
		return nil, ErrIntegrity
	}
	switch report.Assessment {
	case constraintengine.AssessmentUnknown, constraintengine.AssessmentBlocked, constraintengine.AssessmentScopeCompletePass:
	default:
		return nil, ErrIntegrity
	}
	if report.Assessment != report.Check.Assessment {
		return nil, ErrIntegrity
	}
	if _, err := constraintengine.MarshalReport(report.Check); err != nil {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digest(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

// declaredScope reads the caller's scope declaration without widening what the
// engine's own parser accepts; ParseInput remains the authority on validity.
func declaredScope(inputRaw []byte) ([]string, bool) {
	var document struct {
		Scope *struct {
			Declaration string   `json:"declaration"`
			Components  []string `json:"components"`
		} `json:"scope"`
	}
	if json.Unmarshal(inputRaw, &document) != nil || document.Scope == nil {
		return nil, false
	}
	if document.Scope.Declaration != constraintengine.ScopeDeclaration {
		return nil, false
	}
	return append([]string(nil), document.Scope.Components...), true
}
