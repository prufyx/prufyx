// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	// externalBundleSchema is the envelope of a target that carries rules
	// only. A target without records keeps exactly this schema and its bytes.
	externalBundleSchema = "prufyx.io/operator-cncf-knowledge/v1alpha1"
	// externalBundleSchemaRecords is the envelope of a target whose pack
	// carries per-scope records besides its rules: line attestations,
	// upgrade-path policies and served-API lists. A binary that predates it
	// refuses such a target (unknown schema and unknown pack members), so
	// a record is never read as absent by a client that cannot check it.
	externalBundleSchemaRecords = "prufyx.io/operator-cncf-knowledge/v1alpha2"
	externalSourceAuthority  = "DECLARED_RULE_SOURCE_REFERENCES"
	externalProfileName      = "cncf"
	externalTargetPath       = "knowledge/constraints.v1.json"
	maxExternalBundleBytes   = 1 << 20
	maxExternalEntries       = 512
	maxExternalFacts         = 64
	maxExternalJSONDepth     = 32
	maxExternalObjectMembers = 4096
	maxExternalArrayItems    = 4096
	maxExternalStringBytes   = 4096
)

var externalRevisionPattern = regexp.MustCompile(`^[1-9][0-9]*$`)

// ExternalBundle is an opaque parser-issued capability. It contains only
// bounded data that passed the compiled registry, policy, landscape, and
// constraint-engine checks. It carries no signature or source-truth claim.
type ExternalBundle struct {
	raw             []byte
	document        externalBundleDocument
	pack            rulePack
	registry        constraintengine.Registry
	bundleDigest    string
	documentDigest  string
	packDigest      string
	admission       ExternalAdmission
	admissionDigest string
	seal            *externalBundleSeal
	// policy is the caller's trust policy (WithTrustPolicy). It is not part
	// of the admitted bundle and changes none of its digests.
	policy TrustPolicy
}

type externalBundleSeal struct{}

type externalBundleDocument struct {
	Schema                 string          `json:"schema"`
	Revision               string          `json:"revision"`
	Purpose                string          `json:"purpose"`
	EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
	Pack                   json.RawMessage `json:"pack"`
}

// ExternalAdmission is the bounded semantic identity attached to a parsed
// external target. TUF or another transport layer supplies transport trust
// separately; this value does not claim signing or maintainer review.
type ExternalAdmission struct {
	Revision               string
	Purpose                string
	EngineCapabilityDigest string
	HasRule                bool
	// HasRecords is true for a records envelope (externalBundleSchemaRecords):
	// its pack carries at least one record section.
	HasRecords bool
	// RuleDigest is the semantic digest of the target's rules. For a target
	// with records it binds the rules and the records together
	// (knowledgeContentDigest), so every receipt or index entry that records
	// it commits to both.
	RuleDigest string
	// EvidenceExpiresAt is the earliest validUntil over the target's rules
	// and records.
	EvidenceExpiresAt string
}

// ProfileRequirements contains copied scalar identities for constructing an
// external fixture or transport envelope. Callers cannot provide these values
// back to the parser as a trust or registry override.
type ProfileRequirements struct {
	Schema                 string
	PackSchema             string
	EngineCapabilityDigest string
	PolicyID               string
	PolicyDigest           string
	RegistryDigest         string
	LandscapeFileDigest    string
}

// ExternalProfileContract is the public scalar construction contract enforced
// for an external CNCF target. It is not trust material and grants no feed,
// signing, or source-review authority.
type ExternalProfileContract struct {
	Profile                 string
	TargetPath              string
	Purpose                 string
	Requirements            ProfileRequirements
	MaxBundleBytes          int
	MaxEntries              int
	MaxFactsPerEntry        int
	ExplicitSelectionOnly   bool
	RequiresIndependentRoot bool
}

// ParseExternalBundle admits a complete operator-provided target envelope.
// It performs no source fetch, signature verification, or network operation.
func ParseExternalBundle(raw []byte) (ExternalBundle, error) {
	return parseExternalBundle(raw, nil)
}

// parseExternalBundle admits raw against base, loading the compiled bundle
// when base is nil. Callers that admit many targets in one operation pass the
// base they already loaded; every check is identical.
func parseExternalBundle(raw []byte, base *bundle) (ExternalBundle, error) {
	if err := scanExternalJSON(raw); err != nil || validateExternalEnvelopeShape(raw) != nil {
		return ExternalBundle{}, ErrInvalid
	}
	var document externalBundleDocument
	if err := json.Unmarshal(raw, &document); err != nil || (document.Schema != externalBundleSchema && document.Schema != externalBundleSchemaRecords) || !validExternalRevision(document.Revision) || (document.Purpose != "operator_provided" && document.Purpose != "synthetic_test_only") {
		return ExternalBundle{}, ErrInvalid
	}
	records := document.Schema == externalBundleSchemaRecords
	if base == nil {
		loaded, err := load()
		if err != nil {
			return ExternalBundle{}, err
		}
		base = &loaded
	}
	capability, err := externalCapabilityDigest(*base)
	if err != nil || document.EngineCapabilityDigest != capability {
		return ExternalBundle{}, ErrIntegrity
	}
	var packValue rulePack
	if err := json.Unmarshal(document.Pack, &packValue); err != nil {
		return ExternalBundle{}, ErrInvalid
	}
	if err := validateExternalPack(*base, packValue, document.Revision, records); err != nil {
		return ExternalBundle{}, err
	}
	if records {
		if err := admitExternalRecords(*base, document.Pack, packValue); err != nil {
			return ExternalBundle{}, err
		}
	}
	candidate := bundle{landscape: base.landscape, priority: base.priority, pack: packValue, registry: base.registry, packDigest: digest(raw), catalogueDigest: base.catalogueDigest}
	rules, err := candidate.parseRulesCorpus(candidate.packRules(), nil)
	if err != nil {
		return ExternalBundle{}, ErrIntegrity
	}
	admission := ExternalAdmission{Revision: document.Revision, Purpose: document.Purpose, EngineCapabilityDigest: document.EngineCapabilityDigest, HasRule: len(packValue.Entries) > 0, HasRecords: records}
	if admission.HasRule || admission.HasRecords {
		admission.RuleDigest, err = rules.Digest()
		if err != nil {
			return ExternalBundle{}, ErrIntegrity
		}
		admission.EvidenceExpiresAt, err = earliestExternalExpiry(packValue)
		if err != nil {
			return ExternalBundle{}, ErrIntegrity
		}
	}
	if admission.HasRecords {
		admission.RuleDigest, err = knowledgeContentDigest(admission.RuleDigest, packValue)
		if err != nil {
			return ExternalBundle{}, ErrIntegrity
		}
	}
	return ExternalBundle{raw: append([]byte(nil), raw...), document: document, pack: packValue, registry: base.registry, bundleDigest: digest(raw), documentDigest: externalDigestJSON(document), packDigest: externalDigestJSON(packValue), admission: admission, admissionDigest: externalDigestJSON(admission), seal: &externalBundleSeal{}}, nil
}

// ExternalCapabilityDigest identifies this compiled parser/engine/registry and
// its pinned policy and landscape. It is not a signing key or source digest.
func ExternalCapabilityDigest() (string, error) {
	base, err := load()
	if err != nil {
		return "", err
	}
	return externalCapabilityDigest(base)
}

// ExternalProfileRequirements returns the compiled scalar profile identities;
// it never exposes the registry, catalogue, or embedded rule bytes.
func ExternalProfileRequirements() (ProfileRequirements, error) {
	base, err := load()
	if err != nil {
		return ProfileRequirements{}, err
	}
	capability, err := externalCapabilityDigest(base)
	if err != nil {
		return ProfileRequirements{}, err
	}
	// PackSchema is the exact-only pack schema, whatever the embedded pack
	// carries: an external pack uses the ranged schema if and only if it
	// holds a rule with a reviewed range (validPackSchema).
	return ProfileRequirements{
		Schema: externalBundleSchema, PackSchema: packSchema,
		EngineCapabilityDigest: capability, PolicyID: base.pack.PolicyID,
		PolicyDigest: base.pack.PolicyDigest, RegistryDigest: base.registry.Digest(),
		LandscapeFileDigest: base.landscape.LandscapeFileDigest,
	}, nil
}

// ExternalProfileContractForCNCF exposes the fixed public construction
// contract for an operator-provided CNCF target. It reads only embedded bytes.
func ExternalProfileContractForCNCF() (ExternalProfileContract, error) {
	requirements, err := ExternalProfileRequirements()
	if err != nil {
		return ExternalProfileContract{}, err
	}
	return ExternalProfileContract{
		Profile: externalProfileName, TargetPath: externalTargetPath,
		Purpose: "operator_provided", Requirements: requirements,
		MaxBundleBytes: maxExternalBundleBytes, MaxEntries: maxExternalEntries,
		MaxFactsPerEntry: maxExternalFacts, ExplicitSelectionOnly: true,
		RequiresIndependentRoot: true,
	}, nil
}

// ExportEmbeddedExternalBundle returns a complete unsigned operator-provided
// target made from the embedded public CNCF pack. The caller supplies the
// positive semantic revision. It never signs, fetches, or exports a local
// store, trust root, selection, or operator input.
func ExportEmbeddedExternalBundle(revision string) ([]byte, error) {
	if !validExternalRevision(revision) {
		return nil, ErrInvalid
	}
	base, err := load()
	if err != nil {
		return nil, err
	}
	capability, err := externalCapabilityDigest(base)
	if err != nil {
		return nil, ErrIntegrity
	}
	pack := base.pack
	pack.Revision = revision
	raw, err := json.Marshal(struct {
		Schema                 string   `json:"schema"`
		Revision               string   `json:"revision"`
		Purpose                string   `json:"purpose"`
		EngineCapabilityDigest string   `json:"engineCapabilityDigest"`
		Pack                   rulePack `json:"pack"`
	}{envelopeSchemaFor(pack), revision, "operator_provided", capability, pack})
	if err != nil {
		return nil, ErrIntegrity
	}
	if _, err := ParseExternalBundle(raw); err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

// Admission returns the parser-issued semantic summary.
func (b ExternalBundle) Admission() (ExternalAdmission, error) {
	if !b.valid() {
		return ExternalAdmission{}, ErrIntegrity
	}
	return b.admission, nil
}

// BundleDigest identifies the exact external envelope bytes.
func (b ExternalBundle) BundleDigest() string {
	if !b.valid() {
		return ""
	}
	return b.bundleDigest
}

// WithTrustPolicy returns the bundle evaluating under policy. The zero
// policy is the default one.
func (b ExternalBundle) WithTrustPolicy(policy TrustPolicy) ExternalBundle {
	b.policy = policy
	return b
}

// Evaluate applies only the rules in this parsed external bundle. It never
// falls back to the embedded pack and makes no source, signature, or runtime
// authority claim.
func (b ExternalBundle) Evaluate(project string, inputRaw []byte, now time.Time) (Report, error) {
	return b.evaluate(project, "", inputRaw, now)
}

// EvaluateRule applies one closed rule selection without embedded fallback.
// The compiled pack must establish that the requested rule belongs to project;
// the selected external pack may omit it, in which case the report has no
// claims and remains UNKNOWN.
func (b ExternalBundle) EvaluateRule(project, ruleID string, inputRaw []byte, now time.Time) (Report, error) {
	if ruleID == "" {
		return Report{}, ErrInvalid
	}
	return b.evaluate(project, ruleID, inputRaw, now)
}

func (b ExternalBundle) evaluate(project, selectedRuleID string, inputRaw []byte, now time.Time) (Report, error) {
	if !b.valid() {
		return Report{}, ErrIntegrity
	}
	base, err := load()
	if err != nil {
		return Report{}, err
	}
	if !base.hasProject(project) {
		return Report{}, ErrInvalid
	}
	if selectedRuleID != "" {
		owned, ownershipErr := base.ownsRuleID(project, selectedRuleID)
		if ownershipErr != nil {
			return Report{}, ErrIntegrity
		}
		if !owned {
			return Report{}, ErrInvalid
		}
	}
	selected := bundle{landscape: base.landscape, priority: base.priority, pack: b.pack, registry: b.registry, packDigest: b.bundleDigest, catalogueDigest: base.catalogueDigest, policy: b.policy}
	input, err := constraintengine.ParseInput(inputRaw, selected.registry)
	if err != nil {
		return Report{}, ErrInvalid
	}
	var rules selection
	if selectedRuleID != "" {
		rules, err = selected.selectRule(project, selectedRuleID)
	} else {
		rules, err = selected.selectForInput(project, inputRaw)
	}
	if err != nil {
		return Report{}, ErrIntegrity
	}
	result, err := constraintengine.Evaluate(input, rules.rules, now)
	if err != nil {
		return Report{}, ErrInvalid
	}
	if _, err := constraintengine.MarshalReport(result); err != nil {
		return Report{}, ErrIntegrity
	}
	report := Report{
		Schema: "prufyx.io/cncf-source-check/v1alpha1", Project: project, Assessment: "UNKNOWN",
		KnowledgeOrigin: "external_declared", KnowledgeRevision: b.document.Revision, KnowledgePackDigest: b.bundleDigest,
		CatalogueDigest: base.catalogueDigest, InputFileDigest: digest(inputRaw), SourceAuthority: externalSourceAuthority,
		RequestedRuleID:   selectedRuleID,
		RuntimeReproduced: 0, NetworkUsed: false,
		NextAction:  "review each scoped claim; whole-upgrade behavior and runtime evidence remain unverified",
		Check:       result,
		TrustPolicy: b.policy.disclosure(rules),
	}
	if selectedRuleID != "" && len(result.Claims) == 1 && result.Claims[0].RuleID == selectedRuleID {
		report.SelectedRuleID = selectedRuleID
		report.NextAction = "review the selected native-input claim; other project rules, configuration and whole-upgrade behavior remain unassessed"
	}
	if len(result.Claims) == 0 {
		if selectedRuleID != "" {
			report.NextAction = "the selected external revision has no exact rule for this native-input capability; retain UNKNOWN with no embedded fallback"
		} else {
			report.NextAction = "no rules are packaged for this project; retain UNKNOWN and request reviewed coverage: " + constraintengine.RequestCoverageURL
		}
		if rules.excluded > 0 {
			report.NextAction = trustPolicyNextAction
		}
	}
	report.seal = &reportSeal{}
	encoded, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	report.digest = digest(encoded)
	return report, nil
}

func (b ExternalBundle) valid() bool {
	return b.seal != nil && digest(b.raw) == b.bundleDigest && externalDigestJSON(b.document) == b.documentDigest && externalDigestJSON(b.pack) == b.packDigest && externalDigestJSON(b.admission) == b.admissionDigest
}

func externalDigestJSON(value any) string {
	raw, _ := json.Marshal(value)
	return digest(raw)
}

func validExternalRevision(value string) bool {
	if !externalRevisionPattern.MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseUint(value, 10, 31)
	return err == nil && parsed > 0
}

// validateExternalPack checks an envelope's pack against the compiled
// knowledge. records says whether the envelope is a records envelope: only
// such an envelope may carry line attestations, upgrade-path policies and
// served-API lists, and it must carry at least one of them, so the envelope
// schema is exactly the level its content needs. No envelope carries
// distribution records: they are not scoped to one project and have no
// target yet, so a pack holding them is refused rather than admitted
// without them.
func validateExternalPack(base bundle, packValue rulePack, revision string, records bool) error {
	if len(packValue.Distributions) > 0 {
		return ErrIntegrity
	}
	if hasRecordSections(packValue) != records {
		return ErrIntegrity
	}
	// Nor one-way notices: an external pack holding one is refused.
	rules := make([]json.RawMessage, 0, len(packValue.Entries))
	for _, entry := range packValue.Entries {
		rules = append(rules, entry.Rule)
	}
	if notice, err := constraintengine.AnyNoticeRule(rules); err != nil || notice {
		return ErrIntegrity
	}
	// Nor consensus or lead rules: an external pack holding one is refused.
	if basis, err := constraintengine.AnyBasisRule(rules); err != nil || basis {
		return ErrIntegrity
	}
	// Nor support-range rules (severity): an external pack holding one is
	// refused.
	if severity, err := constraintengine.AnySeverityRule(rules); err != nil || severity {
		return ErrIntegrity
	}
	// Nor removal-crossing rules: they carry the owner's signature only.
	if crossing, err := constraintengine.AnyCrossingRule(rules); err != nil || crossing {
		return ErrIntegrity
	}
	if !validPackSchema(packValue) || packValue.Revision != revision || packValue.PolicyID != base.pack.PolicyID || packValue.PolicyDigest != base.pack.PolicyDigest || packValue.LandscapeFileDigest != base.landscape.LandscapeFileDigest || packValue.RegistryDigest != base.registry.Digest() || len(packValue.Entries) > maxExternalEntries {
		return ErrIntegrity
	}
	definitions := map[string]constraintengine.FactDefinition{}
	for _, definition := range compiledDefinitions() {
		definitions[definition.ID] = definition
	}
	for _, entry := range packValue.Entries {
		if _, found := base.identities()[entry.Project]; !found || entry.Description == "" || len(entry.Description) > 2048 {
			return ErrInvalid
		}
		seenFacts := map[string]bool{}
		for _, fact := range entry.RequiredFacts {
			definition, found := definitions[fact.ID]
			key := fact.Side + "/" + fact.Component + "/" + fact.ID
			if seenFacts[key] || (fact.Side != "current" && fact.Side != "proposed") || !found || definition.Component != fact.Component || definition.Type != fact.Type || fact.Description == "" || len(fact.Description) > 2048 || !sameStrings(definition.EnumTokens, fact.EnumTokens) {
				return ErrInvalid
			}
			seenFacts[key] = true
		}
		var shape ruleShape
		if json.Unmarshal(entry.Rule, &shape) != nil || shape.Subject.Component != subjectComponent(entry.Project, base.identities()[entry.Project].RepositoryURL) {
			return ErrIntegrity
		}
		conditions := shape.conditions()
		required := map[string]bool{}
		for _, condition := range conditions {
			required[condition.Side+"/"+condition.Component+"/"+condition.FactID] = true
		}
		if len(required) != len(seenFacts) {
			return ErrInvalid
		}
		for key := range required {
			if !seenFacts[key] {
				return ErrInvalid
			}
		}
	}
	return nil
}

func (b bundle) identities() map[string]projectIdentity {
	identities := make(map[string]projectIdentity, len(b.landscape.Projects))
	for _, project := range b.landscape.Projects {
		identities[project.Slug] = project
	}
	return identities
}

// earliestExternalExpiry is the earliest evidence validUntil over the pack's
// rules and records.
func earliestExternalExpiry(pack rulePack) (string, error) {
	var earliest time.Time
	type evidenceShape struct {
		Evidence struct {
			ValidUntil string `json:"validUntil"`
		} `json:"evidence"`
	}
	documents := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		documents = append(documents, entry.Rule)
	}
	for _, section := range []json.RawMessage{pack.LineAttestations, pack.PathPolicies, pack.ServedAPIs} {
		if len(section) == 0 {
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(section, &items); err != nil {
			return "", ErrIntegrity
		}
		documents = append(documents, items...)
	}
	for _, document := range documents {
		var shape evidenceShape
		if err := json.Unmarshal(document, &shape); err != nil {
			return "", ErrIntegrity
		}
		value, err := time.Parse(time.RFC3339, shape.Evidence.ValidUntil)
		if err != nil || value.Location() != time.UTC || value.Format(time.RFC3339) != shape.Evidence.ValidUntil {
			return "", ErrIntegrity
		}
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	if earliest.IsZero() {
		return "", ErrIntegrity
	}
	return earliest.Format(time.RFC3339), nil
}

type externalCapabilityDocument struct {
	Schema               string `json:"schema"`
	EngineContractDigest string `json:"engineContractDigest"`
	RegistryDigest       string `json:"registryDigest"`
	PolicyID             string `json:"policyId"`
	PolicyDigest         string `json:"policyDigest"`
	LandscapeRevision    string `json:"landscapeRevision"`
	LandscapeFileDigest  string `json:"landscapeFileDigest"`
}

func externalCapabilityDigest(base bundle) (string, error) {
	document := externalCapabilityDocument{Schema: externalBundleSchema, EngineContractDigest: constraintengine.EngineContractDigest(), RegistryDigest: base.registry.Digest(), PolicyID: base.pack.PolicyID, PolicyDigest: base.pack.PolicyDigest, LandscapeRevision: base.landscape.Revision, LandscapeFileDigest: base.landscape.LandscapeFileDigest}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", ErrIntegrity
	}
	return digest(raw), nil
}

// scanExternalJSON rejects duplicate/case-alias members and nulls before any
// case-insensitive encoding/json struct matching. The legacy rule-pack format
// uses enumTokens:null for boolean facts, so that one optional shape is allowed
// and then checked against the compiled fact type.
func scanExternalJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxExternalBundleBytes || !utf8.Valid(raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeExternalJSON(decoder, 0, false); err != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func consumeExternalJSON(decoder *json.Decoder, depth int, allowNull bool) error {
	if depth > maxExternalJSONDepth {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	switch value := token.(type) {
	case nil:
		if !allowNull {
			return ErrInvalid
		}
	case string:
		if len(value) > maxExternalStringBytes {
			return ErrInvalid
		}
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]bool{}
			for count := 0; decoder.More(); count++ {
				if count >= maxExternalObjectMembers {
					return ErrInvalid
				}
				key, err := decoder.Token()
				if err != nil {
					return ErrInvalid
				}
				name, ok := key.(string)
				if !ok || name == "" || len(name) > maxExternalStringBytes {
					return ErrInvalid
				}
				// The same fold as Go's struct decoding (and every other strict
				// reader): Unicode simple case folding, not only lower-casing.
				folded := strictjson.FoldKey(name)
				if seen[folded] {
					return ErrInvalid
				}
				seen[folded] = true
				if err := consumeExternalJSON(decoder, depth+1, name == "enumTokens"); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for count := 0; decoder.More(); count++ {
				if count >= maxExternalArrayItems || consumeExternalJSON(decoder, depth+1, false) != nil {
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
	case bool, json.Number:
	default:
		return ErrInvalid
	}
	return nil
}

func validateExternalEnvelopeShape(raw []byte) error {
	root, err := externalObject(raw, []string{"schema", "revision", "purpose", "engineCapabilityDigest", "pack"})
	if err != nil {
		return err
	}
	// Only a records envelope may hold the record sections, each optional;
	// their content is checked by the strict section parsers.
	var schema string
	if json.Unmarshal(root["schema"], &schema) != nil {
		return ErrInvalid
	}
	var optional []string
	if schema == externalBundleSchemaRecords {
		optional = externalRecordMembers
	}
	pack, err := externalObjectWith(root["pack"], []string{"schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "entries"}, optional)
	if err != nil {
		return err
	}
	for _, member := range optional {
		if value, ok := pack[member]; ok {
			if items, err := externalArray(value); err != nil || len(items) == 0 {
				return ErrInvalid
			}
		}
	}
	entries, err := externalArray(pack["entries"])
	if err != nil || len(entries) > maxExternalEntries {
		return ErrInvalid
	}
	for _, entryRaw := range entries {
		entry, err := externalObject(entryRaw, []string{"project", "description", "requiredFacts", "rule"})
		if err != nil {
			return err
		}
		facts, err := externalArray(entry["requiredFacts"])
		if err != nil || len(facts) > maxExternalFacts {
			return ErrInvalid
		}
		for _, factRaw := range facts {
			if _, err := externalObject(factRaw, []string{"side", "id", "component", "type", "enumTokens", "description"}); err != nil {
				return err
			}
		}
		if _, err := externalObject(entry["rule"], nil); err != nil {
			return err
		}
	}
	return nil
}

func externalObject(raw json.RawMessage, required []string) (map[string]json.RawMessage, error) {
	return externalObjectWith(raw, required, nil)
}

// externalObjectWith is externalObject that also allows the optional
// members, each at most once and never null.
func externalObjectWith(raw json.RawMessage, required, optional []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range optional {
		allowed[key] = true
	}
	for _, key := range required {
		allowed[key] = true
		value, exists := object[key]
		if !exists || string(value) == "null" && key != "enumTokens" {
			return nil, ErrInvalid
		}
	}
	for key, value := range object {
		if !allowed[key] && !(len(required) == 0 && len(optional) == 0) || string(value) == "null" && key != "enumTokens" {
			return nil, ErrInvalid
		}
	}
	return object, nil
}

func externalArray(raw json.RawMessage) ([]json.RawMessage, error) {
	var values []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, ErrInvalid
	}
	return values, nil
}
