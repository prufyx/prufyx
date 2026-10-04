// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// ScanKnowledge is one admitted snapshot of the embedded knowledge, loaded
// once for a whole scan: every hop, attestation and path-policy lookup of the
// scan reads the same pack, and nothing is assembled twice. It is read-only.
type ScanKnowledge struct {
	b     bundle
	rules map[string][]ScanRule
	// selected is nil for the embedded knowledge, whose bundle b serves
	// every project. For knowledge selected from a verified store it holds
	// the bundle of each opened project, and b carries only the compiled
	// catalog and registry, never a rule, a line review or a policy.
	selected map[string]bundle
}

// ScanRule is the selection view of one admitted rule: its scope for line
// attestations (id, subject component, line, fact families, reviewed
// transition), the facts it reads, whether it is a one-way notice, its
// rule-provided description and its next action.
type ScanRule struct {
	Project string
	Scope   lineattest.RuleScope
	Facts   []string
	Notice  bool
	// Basis is the rule's effective evidence basis.
	Basis string
	// Severity is "unsupported" for a support-range rule, else empty.
	Severity    string
	Description string
	NextAction  string
}

// NewScanRule reads the selection view of one raw rule. It does not
// validate the rule: only admitted rules reach a scan.
func NewScanRule(project, description string, raw json.RawMessage) (ScanRule, error) {
	scope, err := lineattest.ScopeOf(raw)
	if err != nil {
		return ScanRule{}, ErrIntegrity
	}
	var shape ruleShape
	var action struct {
		NextAction string `json:"nextAction"`
		Severity   string `json:"severity"`
		Evidence   struct {
			Basis string `json:"basis"`
		} `json:"evidence"`
	}
	if json.Unmarshal(raw, &shape) != nil || json.Unmarshal(raw, &action) != nil {
		return ScanRule{}, ErrIntegrity
	}
	// Only the one-way notice operator; a lead is told by its basis.
	notice, err := constraintengine.AnyNoticeRule([]json.RawMessage{raw})
	if err != nil {
		return ScanRule{}, ErrIntegrity
	}
	rule := ScanRule{Project: project, Scope: scope, Notice: notice, Basis: constraintengine.EffectiveBasis(action.Evidence.Basis), Severity: action.Severity, Description: description, NextAction: action.NextAction}
	for _, condition := range shape.conditions() {
		rule.Facts = append(rule.Facts, condition.FactID)
	}
	sort.Strings(rule.Facts)
	return rule, nil
}

// LoadScanKnowledge admits the embedded knowledge exactly as every check
// does and indexes its rules by project.
func LoadScanKnowledge() (*ScanKnowledge, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	k := &ScanKnowledge{b: b, rules: map[string][]ScanRule{}}
	for _, entry := range b.pack.Entries {
		rule, err := NewScanRule(entry.Project, entry.Description, entry.Rule)
		if err != nil {
			return nil, err
		}
		k.rules[entry.Project] = append(k.rules[entry.Project], rule)
	}
	for project := range k.rules {
		rules := k.rules[project]
		sort.Slice(rules, func(i, j int) bool { return rules[i].Scope.ID < rules[j].Scope.ID })
	}
	return k, nil
}

// Origin is where the knowledge came from: "embedded", or
// "external_signed_local" for knowledge selected from a verified store.
func (k *ScanKnowledge) Origin() string {
	if k.selected != nil {
		return "external_signed_local"
	}
	return "embedded"
}

// Revision is the pack revision.
func (k *ScanKnowledge) Revision() string { return k.b.pack.Revision }

// PackDigest is the digest of the pack bytes.
func (k *ScanKnowledge) PackDigest() string { return k.b.packDigest }

// Projects lists every catalog project slug in order.
func (k *ScanKnowledge) Projects() []string { return catalogProjects(k.b) }

// Component returns the subject component of a catalog project.
func (k *ScanKnowledge) Component(slug string) (string, bool) { return catalogComponent(k.b, slug) }

func catalogProjects(b bundle) []string {
	out := make([]string, 0, len(b.landscape.Projects))
	for _, project := range b.landscape.Projects {
		out = append(out, project.Slug)
	}
	return out
}

func catalogComponent(b bundle, slug string) (string, bool) {
	if !b.hasProject(slug) {
		return "", false
	}
	for _, project := range b.landscape.Projects {
		if project.Slug == slug {
			component := subjectComponent(project.Slug, project.RepositoryURL)
			return component, component != ""
		}
	}
	return "", false
}

// Rules lists the project's rules in rule-id order.
func (k *ScanKnowledge) Rules(project string) []ScanRule {
	rules := k.rules[project]
	out := make([]ScanRule, len(rules))
	copy(out, rules)
	return out
}

// CheckFacts is CheckFacts over this snapshot.
func (k *ScanKnowledge) CheckFacts(project string, facts []string, inputRaw []byte, now time.Time) (Report, error) {
	b, ok := k.bundleFor(project)
	if !ok {
		return Report{}, ErrIntegrity
	}
	return b.checkFacts(project, facts, inputRaw, now)
}

// CheckFactsWithPolicy is Checker.CheckFacts under policy, over this
// snapshot.
func (k *ScanKnowledge) CheckFactsWithPolicy(policy TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Report, error) {
	b, ok := k.bundleFor(project)
	if !ok {
		return Report{}, ErrIntegrity
	}
	b.policy = policy
	return b.checkFacts(project, facts, inputRaw, now)
}

// AttestationsFor is AttestationsFor over this snapshot, with the same
// contract: only a current attestation may be relied on.
func (k *ScanKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	b, ok := k.bundleForComponent(component)
	if !ok {
		return nil
	}
	return b.attestations.AttestationsFor(component, line, family, now)
}

// PathPolicyFor is PathPolicyFor over this snapshot, with the same contract:
// only Status.Policy may be used to plan.
func (k *ScanKnowledge) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	b, ok := k.bundleForComponent(component)
	if !ok {
		return upgradepath.Status{}
	}
	return b.pathPolicyFor(component, now)
}
