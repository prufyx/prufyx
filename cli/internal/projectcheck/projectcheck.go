// SPDX-License-Identifier: AGPL-3.0-only

// Package projectcheck exposes a closed embedded source-rule preview for
// explicitly reviewed community projects. It does not assert CNCF membership.
package projectcheck

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const PolicyDeclaration = "Prufyx community project source-constraint preview v1: exact reviewed external project identity and current/proposed endpoints; native caller-supplied configuration, workload, or selected current metadata reduced to compiled facts; scoped PASS/BLOCKED/UNKNOWN; whole-upgrade assessment remains UNKNOWN; no CNCF membership, runtime, signature, external feed, or upload authority. Maintainer source reviews expire after 90 days."

const (
	lokiCompactorRuleID          = "loki.compactor-shared-store.2-9-to-3-0"
	lokiStructuredMetadataRuleID = "loki.structured-metadata-tsdb-v13.2-9-8-to-3-0-0"
)

var (
	ErrInvalid   = errors.New("invalid community project check request")
	ErrIntegrity = errors.New("community project check integrity failure")
	slugRE       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

//go:embed data/projects.json data/rules.json
var packaged embed.FS

type identity struct {
	Slug              string `json:"slug"`
	Name              string `json:"name"`
	RepositoryURL     string `json:"repositoryURL"`
	Component         string `json:"component"`
	IdentityAuthority string `json:"identityAuthority"`
	CNCFMembership    string `json:"cncfMembership"`
}
type registryDocument struct {
	Schema   string     `json:"schema"`
	Revision string     `json:"revision"`
	Projects []identity `json:"projects"`
}
type fact struct {
	Side        string                    `json:"side"`
	ID          string                    `json:"id"`
	Component   string                    `json:"component"`
	Type        constraintengine.FactType `json:"type"`
	EnumTokens  []string                  `json:"enumTokens"`
	Description string                    `json:"description"`
}
type entry struct {
	Project       string          `json:"project"`
	Description   string          `json:"description"`
	RequiredFacts []fact          `json:"requiredFacts"`
	Rule          json.RawMessage `json:"rule"`
}
type ruleBinding struct {
	ID       string `json:"id"`
	Operator string `json:"operator"`
	Subject  struct {
		Component string `json:"component"`
		From      string `json:"from"`
		To        string `json:"to"`
	} `json:"subject"`
	Condition   *factBinding  `json:"condition"`
	AppliesWhen []factBinding `json:"appliesWhen"`
	// Severity and Dependency are read only to classify a support-range rule;
	// the engine's ParseRuleSet remains the authority on their validity.
	Severity   string `json:"severity"`
	Dependency *struct {
		Component string `json:"component"`
	} `json:"dependency"`
	Evidence struct {
		ReviewedAt string `json:"reviewedAt"`
		ValidUntil string `json:"validUntil"`
	} `json:"evidence"`
}
type factBinding struct {
	Side      string `json:"side"`
	Component string `json:"component"`
	FactID    string `json:"factId"`
}
type packDocument struct {
	Schema       string  `json:"schema"`
	Revision     string  `json:"revision"`
	PolicyID     string  `json:"policyId"`
	PolicyDigest string  `json:"policyDigest"`
	Entries      []entry `json:"entries"`
}
type bundle struct {
	registryDocument           registryDocument
	pack                       packDocument
	registry                   constraintengine.Registry
	identities                 map[string]identity
	packDigest, registryDigest string
}

type Report struct {
	Schema                string                  `json:"schema"`
	Project               string                  `json:"project"`
	RequestedRuleID       string                  `json:"requestedRuleId,omitempty"`
	SelectedRuleID        string                  `json:"selectedRuleId,omitempty"`
	Assessment            string                  `json:"assessment"`
	KnowledgeOrigin       string                  `json:"knowledgeOrigin"`
	KnowledgeRevision     string                  `json:"knowledgeRevision"`
	KnowledgePackDigest   string                  `json:"knowledgePackDigest"`
	ProjectRegistryDigest string                  `json:"projectRegistryDigest"`
	InputFileDigest       string                  `json:"inputFileDigest"`
	SourceAuthority       string                  `json:"sourceAuthority"`
	RuntimeReproduced     int                     `json:"runtimeReproduced"`
	NetworkUsed           bool                    `json:"networkUsed"`
	NextAction            string                  `json:"nextAction"`
	Check                 constraintengine.Report `json:"check"`
	seal                  *reportSeal
	digest                string
}

// RuleIdentity is the stable public identity of one rule already admitted by
// the embedded community pack. It contains no caller input or evidence bytes.
type RuleIdentity struct {
	Project   string `json:"project"`
	Component string `json:"component"`
	RuleID    string `json:"ruleId"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Range is present only for a rule with a reviewed version range.
	Range *constraintengine.VersionRange `json:"range,omitempty"`
}

// Transition returns the identity's reviewed subject for the shared matcher.
func (r RuleIdentity) Transition() constraintengine.RuleTransition {
	return constraintengine.RuleTransition{Component: r.Component, From: r.From, To: r.To, Range: r.Range}
}

// EmbeddedRuleIdentities returns every integrity-checked embedded community
// rule in stable project/rule order without evaluating it.
func EmbeddedRuleIdentities() ([]RuleIdentity, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	result := make([]RuleIdentity, 0, len(b.pack.Entries))
	for _, entry := range b.pack.Entries {
		var binding ruleBinding
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil || json.Unmarshal(entry.Rule, &binding) != nil || binding.ID == "" || subject.Component == "" || subject.From == "" || subject.To == "" {
			return nil, ErrIntegrity
		}
		result = append(result, RuleIdentity{Project: entry.Project, Component: subject.Component, RuleID: binding.ID, From: subject.From, To: subject.To, Range: subject.Range})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Project != result[j].Project {
			return result[i].Project < result[j].Project
		}
		return result[i].RuleID < result[j].RuleID
	})
	return result, nil
}

type reportSeal struct{}

func definitions() []constraintengine.FactDefinition {
	return []constraintengine.FactDefinition{
		{ID: "component.argo-workflows.server_legacy_basehref_flag_present", Component: "pkg:github/argoproj/argo-workflows", Type: constraintengine.FactBool},
		{ID: "component.ceph.selected_current_osd_filestore", Component: "pkg:github/ceph/ceph", Type: constraintengine.FactBool},
		{ID: "component.grafana.legacy_alerting_explicitly_enabled", Component: "pkg:github/grafana/grafana", Type: constraintengine.FactBool},
		{ID: "component.fluent_bit.proposed_http2_enabled", Component: "pkg:github/fluent/fluent-bit", Type: constraintengine.FactBool},
		{ID: "component.fluent_bit.target_required_http2_enabled", Component: "pkg:github/fluent/fluent-bit", Type: constraintengine.FactBool},
		{ID: "component.kibana.full_status_without_monitor_required", Component: "pkg:github/elastic/kibana", Type: constraintengine.FactBool},
		{ID: "component.kibana.reporting_roles_allow_present", Component: "pkg:github/elastic/kibana", Type: constraintengine.FactBool},
		{ID: "component.kibana.status_page_authentication_required", Component: "pkg:github/elastic/kibana", Type: constraintengine.FactBool},
		{ID: "component.kibana.status_page_bypass_monitor_privilege", Component: "pkg:github/elastic/kibana", Type: constraintengine.FactBool},
		{ID: "component.loki.compactor_legacy_shared_store_present", Component: "pkg:github/grafana/loki", Type: constraintengine.FactBool},
		{ID: "component.loki.structured_metadata_requires_tsdb_v13", Component: "pkg:github/grafana/loki", Type: constraintengine.FactBool},
		{ID: "component.mariadb.innodb_defragmentation_required", Component: "pkg:github/mariadb/server", Type: constraintengine.FactBool},
		{ID: "component.mariadb.upstream_distribution", Component: "pkg:github/mariadb/server", Type: constraintengine.FactBool},
		{ID: "component.mariadb_operator.auto_update_data_plane", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: constraintengine.FactBool},
		{ID: "component.mariadb_operator.galera_enabled", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: constraintengine.FactBool},
		{ID: "component.mariadb_operator.pre_operator_update", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: constraintengine.FactBool},
		{ID: "component.mariadb_operator.replication_enabled", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: constraintengine.FactBool},
		{ID: "component.mariadb_operator.resource_complete", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: constraintengine.FactBool},
	}
}

func load() (bundle, error) {
	registryRaw, err := packaged.ReadFile("data/projects.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	packRaw, err := packaged.ReadFile("data/rules.json")
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	return loadRaw(registryRaw, packRaw, definitions())
}

func loadRaw(registryRaw, packRaw []byte, factDefinitions []constraintengine.FactDefinition) (bundle, error) {
	var b bundle
	if strictjson.Check(packRaw) != nil || strict(registryRaw, &b.registryDocument) != nil || strict(packRaw, &b.pack) != nil {
		return bundle{}, ErrIntegrity
	}
	var err error
	b.registry, err = constraintengine.NewRegistry(factDefinitions)
	if err != nil {
		return bundle{}, ErrIntegrity
	}
	b.registryDigest, b.packDigest = digest(registryRaw), digest(packRaw)
	if b.registryDocument.Schema != "prufyx.io/community-project-registry/v1alpha1" || !validPackSchema(b.pack) || b.pack.PolicyID != "community-project-source-preview-v1" || b.pack.PolicyDigest != digest([]byte(PolicyDeclaration)) || len(b.registryDocument.Projects) != 8 || len(b.pack.Entries) < len(b.registryDocument.Projects) {
		return bundle{}, ErrIntegrity
	}
	b.identities = map[string]identity{}
	for i, p := range b.registryDocument.Projects {
		if !slugRE.MatchString(p.Slug) || p.Name == "" || p.RepositoryURL == "" || p.Component == "" || p.IdentityAuthority != "MAINTAINER_REVIEWED_EXTERNAL_REPOSITORY" || p.CNCFMembership != "NOT_ASSERTED" || (i > 0 && b.registryDocument.Projects[i-1].Slug >= p.Slug) {
			return bundle{}, ErrIntegrity
		}
		b.identities[p.Slug] = p
	}
	defs := map[string]constraintengine.FactDefinition{}
	for _, d := range factDefinitions {
		defs[d.ID] = d
	}
	entryCounts := map[string]int{}
	seenRuleIDs := map[string]struct{}{}
	previousProject, previousRuleID := "", ""
	for i, e := range b.pack.Entries {
		id, ok := b.identities[e.Project]
		if !ok || e.Description == "" || len(e.RequiredFacts) > 8 {
			return bundle{}, ErrIntegrity
		}
		required := map[string]struct{}{}
		for _, f := range e.RequiredFacts {
			d, ok := defs[f.ID]
			key := f.Side + "\x00" + f.Component + "\x00" + f.ID
			if !ok || (f.Side != "current" && f.Side != "proposed") || f.Component != id.Component || d.Component != f.Component || d.Type != f.Type || len(f.EnumTokens) != 0 || f.Description == "" {
				return bundle{}, ErrIntegrity
			}
			if _, duplicate := required[key]; duplicate {
				return bundle{}, ErrIntegrity
			}
			required[key] = struct{}{}
		}
		var binding ruleBinding
		if json.Unmarshal(e.Rule, &binding) != nil || binding.ID == "" || binding.Subject.Component != id.Component || !admittedRuleShape(binding, required, len(e.RequiredFacts)) {
			return bundle{}, ErrIntegrity
		}
		for _, guard := range binding.AppliesWhen {
			if !requiredFact(required, guard) {
				return bundle{}, ErrIntegrity
			}
		}
		if _, duplicate := seenRuleIDs[binding.ID]; duplicate || i > 0 && (previousProject > e.Project || previousProject == e.Project && previousRuleID >= binding.ID) {
			return bundle{}, ErrIntegrity
		}
		seenRuleIDs[binding.ID] = struct{}{}
		previousProject, previousRuleID = e.Project, binding.ID
		entryCounts[e.Project]++
		reviewed, reviewedErr := time.Parse(time.RFC3339, binding.Evidence.ReviewedAt)
		validUntil, validUntilErr := time.Parse(time.RFC3339, binding.Evidence.ValidUntil)
		if reviewedErr != nil || validUntilErr != nil || validUntil.Sub(reviewed) > 90*24*time.Hour {
			return bundle{}, ErrIntegrity
		}
	}
	for project := range b.identities {
		if entryCounts[project] == 0 {
			return bundle{}, ErrIntegrity
		}
		if _, _, err := b.ruleSet(project, "", ""); err != nil {
			return bundle{}, ErrIntegrity
		}
	}
	return b, nil
}

// admittedRuleShape is the community pack's closed set of rule shapes:
//
//   - forbid_predicate_value: a verdict rule over a declared fact; it needs
//     its condition fact and at least one required fact.
//   - notice_one_way: a verdict-neutral one-way notice. It has no condition
//     of its own; it may declare facts only for its appliesWhen guards.
//   - require_component_version carrying severity "unsupported": a
//     support-range rule. It names a dependency component and no fact
//     condition; it may declare facts only for its appliesWhen guards. A
//     require_component_version rule without the severity is a blocking
//     version rule, which this pack does not admit.
//
// Anything else is refused, and the engine's ParseRuleSet (run for every
// project at load) decides the rest, such as the severity's own reason code.
func admittedRuleShape(binding ruleBinding, required map[string]struct{}, facts int) bool {
	switch binding.Operator {
	case "forbid_predicate_value":
		return facts > 0 && binding.Condition != nil && binding.Severity == "" && binding.Dependency == nil && requiredFact(required, *binding.Condition)
	case constraintengine.OperatorNoticeOneWay:
		return binding.Condition == nil && binding.Severity == "" && binding.Dependency == nil
	case "require_component_version":
		return binding.Condition == nil && binding.Severity == constraintengine.SeverityUnsupported && binding.Dependency != nil
	}
	return false
}

func requiredFact(required map[string]struct{}, binding factBinding) bool {
	_, ok := required[binding.Side+"\x00"+binding.Component+"\x00"+binding.FactID]
	return ok
}

func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	var extra any
	if d.Decode(&extra) == nil {
		return ErrInvalid
	}
	return nil
}

func (b bundle) ruleSet(project, from, to string) (constraintengine.RuleSet, int, error) {
	rules, count, _, err := b.ruleSetSelected(project, from, to, "")
	return rules, count, err
}

func (b bundle) ruleSetSelected(project, from, to, requestedRuleID string) (constraintengine.RuleSet, int, string, error) {
	rules := make([]json.RawMessage, 0, 2)
	selectedRuleID := ""
	for _, e := range b.pack.Entries {
		if e.Project != project {
			continue
		}
		var binding ruleBinding
		subject, err := constraintengine.RuleTransitionOf(e.Rule)
		if err != nil || json.Unmarshal(e.Rule, &binding) != nil {
			return constraintengine.RuleSet{}, 0, "", ErrIntegrity
		}
		if (from == "" && to == "" || subject.Match(from, to) != constraintengine.MatchNone || subject.CrossesUnreviewed(from, to)) && (requestedRuleID == "" || binding.ID == requestedRuleID) {
			rules = append(rules, e.Rule)
			if requestedRuleID != "" {
				selectedRuleID = binding.ID
			}
		}
	}
	doc := struct {
		Schema       string            `json:"schema"`
		Revision     string            `json:"revision"`
		PolicyID     string            `json:"policyId"`
		PolicyDigest string            `json:"policyDigest"`
		Rules        []json.RawMessage `json:"rules"`
	}{"", b.pack.Revision, b.pack.PolicyID, b.pack.PolicyDigest, rules}
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		return constraintengine.RuleSet{}, 0, "", ErrIntegrity
	}
	doc.Schema = schema
	raw, err := json.Marshal(doc)
	if err != nil {
		return constraintengine.RuleSet{}, 0, "", ErrIntegrity
	}
	parsed, err := constraintengine.ParseRuleSet(raw, b.registry)
	return parsed, len(rules), selectedRuleID, err
}

func Check(project string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := load()
	if err != nil {
		return Report{}, err
	}
	return checkWithBundle(b, project, inputRaw, now)
}

// ValidateCanonicalInput verifies a prepared neutral community-project input
// against the compiled registry without evaluating a rule or reading external state.
func ValidateCanonicalInput(project string, inputRaw []byte) error {
	b, err := load()
	if err != nil {
		return err
	}
	if _, ok := b.identities[project]; !ok {
		return ErrInvalid
	}
	if _, err := constraintengine.ParseInput(inputRaw, b.registry); err != nil {
		return ErrInvalid
	}
	return nil
}

// CheckRule evaluates one rule selected by a native input route. The caller
// cannot supply a rule through the CLI; routes bind this ID in code before
// evaluation. Check remains the generic all-rules evaluator.
func CheckRule(project string, inputRaw []byte, now time.Time, requestedRuleID string) (Report, error) {
	if (project != "loki" && project != "mariadb-operator") || (project == "loki" && requestedRuleID != lokiCompactorRuleID && requestedRuleID != lokiStructuredMetadataRuleID) || (project == "mariadb-operator" && requestedRuleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite") {
		return Report{}, ErrInvalid
	}
	b, err := load()
	if err != nil {
		return Report{}, err
	}
	known := false
	for _, candidate := range b.pack.Entries {
		var binding ruleBinding
		if json.Unmarshal(candidate.Rule, &binding) != nil {
			return Report{}, ErrIntegrity
		}
		if binding.ID == requestedRuleID {
			known = true
			break
		}
	}
	if !known {
		return Report{}, ErrInvalid
	}
	return checkWithBundleRule(b, project, inputRaw, now, requestedRuleID)
}

func checkWithBundle(b bundle, project string, inputRaw []byte, now time.Time) (Report, error) {
	return checkWithBundleRule(b, project, inputRaw, now, "")
}

func checkWithBundleRule(b bundle, project string, inputRaw []byte, now time.Time, requestedRuleID string) (Report, error) {
	identity, ok := b.identities[project]
	if !ok {
		return Report{}, ErrInvalid
	}
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		return Report{}, ErrInvalid
	}
	from, to, ok := requestedTransition(inputRaw, identity.Component)
	if !ok {
		return Report{}, ErrInvalid
	}
	rules, selected, selectedRuleID, err := b.ruleSetSelected(project, from, to, requestedRuleID)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	result, err := constraintengine.Evaluate(input, rules, now)
	if err != nil {
		return Report{}, ErrInvalid
	}
	nextAction := "review each scoped claim; whole-upgrade behavior, runtime evidence, and external signed updates remain unavailable"
	if selected == 0 {
		nextAction = "no reviewed rule matches this exact project transition; retain UNKNOWN or add independently reviewed embedded rule metadata"
	}
	report := Report{Schema: "prufyx.io/community-project-source-check/v1alpha1", Project: project, RequestedRuleID: requestedRuleID, SelectedRuleID: selectedRuleID, Assessment: "UNKNOWN", KnowledgeOrigin: "embedded_only", KnowledgeRevision: b.pack.Revision, KnowledgePackDigest: b.packDigest, ProjectRegistryDigest: b.registryDigest, InputFileDigest: digest(inputRaw), SourceAuthority: "PACKAGED_MAINTAINER_REVIEWED_EXTERNAL_PROJECT_RULES_NOT_RUNTIME_PROOF", NextAction: nextAction, Check: result}
	report.seal = &reportSeal{}
	raw, _ := json.Marshal(report)
	report.digest = digest(raw)
	return report, nil
}

func requestedTransition(inputRaw []byte, component string) (string, string, bool) {
	type componentVersion struct {
		Component string `json:"component"`
		Version   string `json:"version"`
	}
	type side struct {
		Components []componentVersion `json:"components"`
	}
	var document struct {
		Current  side `json:"current"`
		Proposed side `json:"proposed"`
	}
	if json.Unmarshal(inputRaw, &document) != nil {
		return "", "", false
	}
	find := func(components []componentVersion) (string, bool) {
		for _, candidate := range components {
			if candidate.Component == component {
				return candidate.Version, true
			}
		}
		return "", false
	}
	from, current := find(document.Current.Components)
	to, proposed := find(document.Proposed.Components)
	return from, to, current && proposed
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Schema != "prufyx.io/community-project-source-check/v1alpha1" || report.Assessment != "UNKNOWN" || report.KnowledgeOrigin != "embedded_only" || report.NetworkUsed || report.RuntimeReproduced != 0 {
		return nil, ErrIntegrity
	}
	if report.RequestedRuleID == "" && report.SelectedRuleID != "" || report.RequestedRuleID != "" && report.SelectedRuleID != "" && report.RequestedRuleID != report.SelectedRuleID {
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

// ClaimExit concerns only the verdict claims. Claims of one-way notice rules
// are informational and never take part: a report holding nothing else exits
// as one without claims (11). An UNSUPPORTED claim (a combination outside a
// documented support range) is neither a pass nor a blocker: it exits as
// unknown (11), and a blocker still exits 10. This is the same rule as the
// CNCF route's ClaimExit.
func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	decided, unknown := 0, false
	for _, c := range report.Check.Claims {
		if c.IsVerdictNeutral() {
			continue
		}
		decided++
		switch c.Status {
		case "BLOCKED":
			return 10
		case "PASS":
		default:
			unknown = true
		}
	}
	if decided == 0 || unknown {
		return 11
	}
	return 0
}

func Projects() ([]string, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(b.identities))
	for p := range b.identities {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// Component returns the immutable compiled component identity for a project.
func Component(project string) (string, error) {
	b, err := load()
	if err != nil {
		return "", err
	}
	identity, ok := b.identities[project]
	if !ok {
		return "", ErrInvalid
	}
	return identity.Component, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

const (
	packSchema       = "prufyx.io/community-project-source-rule-pack/v1alpha1"
	packSchemaRanged = "prufyx.io/community-project-source-rule-pack/v1alpha2"
	// packSchemaNotice is the level of a pack holding a one-way notice rule.
	packSchemaNotice = "prufyx.io/community-project-source-rule-pack/v1alpha3"
	// packSchemaSeverity is the level of a pack holding a support-range rule
	// (a rule with a severity). It also admits notices and reviewed ranges.
	packSchemaSeverity = "prufyx.io/community-project-source-rule-pack/v1alpha4"
)

// validPackSchema requires the pack schema to state the highest feature the
// pack holds, exactly as the CNCF pack does: the original schema when it
// holds none (its digest and bytes are unchanged), the ranged schema for a
// reviewed version range, the notice schema for a one-way notice, and the
// severity schema for a support-range rule. A level admits every feature of
// the lower ones, and binaries that predate a level reject a pack carrying
// it. Consensus and lead rules and removal crossings are not admitted by any
// community pack schema.
func validPackSchema(pack packDocument) bool {
	rules := make([]json.RawMessage, 0, len(pack.Entries))
	for _, e := range pack.Entries {
		rules = append(rules, e.Rule)
	}
	if basis, err := constraintengine.AnyBasisRule(rules); err != nil || basis {
		return false
	}
	if crossing, err := constraintengine.AnyCrossingRule(rules); err != nil || crossing {
		return false
	}
	notice, err := constraintengine.AnyNoticeRule(rules)
	if err != nil {
		return false
	}
	severity, err := constraintengine.AnySeverityRule(rules)
	if err != nil {
		return false
	}
	ranged, err := constraintengine.AnyRanged(rules)
	if err != nil {
		return false
	}
	want := packSchema
	switch {
	case severity:
		want = packSchemaSeverity
	case notice:
		want = packSchemaNotice
	case ranged:
		want = packSchemaRanged
	}
	return pack.Schema == want
}
