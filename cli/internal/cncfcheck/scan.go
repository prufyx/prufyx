// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// ScanKnowledge is one admitted snapshot of the embedded knowledge, loaded
// once for a whole scan: every hop, attestation and path-policy lookup of the
// scan reads the same pack, and nothing is assembled twice. It is read-only.
type ScanKnowledge struct {
	b     bundle
	rules map[string][]ScanRule
}

// ScanRule is the selection view of one admitted rule: its scope for line
// attestations (id, subject component, line, fact families, reviewed
// transition) and its rule-provided description.
type ScanRule struct {
	Project     string
	Scope       lineattest.RuleScope
	Description string
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
		scope, err := lineattest.ScopeOf(entry.Rule)
		if err != nil {
			return nil, ErrIntegrity
		}
		k.rules[entry.Project] = append(k.rules[entry.Project], ScanRule{Project: entry.Project, Scope: scope, Description: entry.Description})
	}
	for project := range k.rules {
		rules := k.rules[project]
		sort.Slice(rules, func(i, j int) bool { return rules[i].Scope.ID < rules[j].Scope.ID })
	}
	return k, nil
}

// Origin is where the knowledge came from: always "embedded".
func (k *ScanKnowledge) Origin() string { return "embedded" }

// Revision is the pack revision.
func (k *ScanKnowledge) Revision() string { return k.b.pack.Revision }

// PackDigest is the digest of the pack bytes.
func (k *ScanKnowledge) PackDigest() string { return k.b.packDigest }

// Projects lists every catalog project slug in order.
func (k *ScanKnowledge) Projects() []string {
	out := make([]string, 0, len(k.b.landscape.Projects))
	for _, project := range k.b.landscape.Projects {
		out = append(out, project.Slug)
	}
	return out
}

// Component returns the subject component of a catalog project.
func (k *ScanKnowledge) Component(slug string) (string, bool) {
	if !k.b.hasProject(slug) {
		return "", false
	}
	for _, project := range k.b.landscape.Projects {
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
	return k.b.checkFacts(project, facts, inputRaw, now)
}

// AttestationsFor is AttestationsFor over this snapshot, with the same
// contract: only a current attestation may be relied on.
func (k *ScanKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.b.attestations.AttestationsFor(component, line, family, now)
}

// PathPolicyFor is PathPolicyFor over this snapshot, with the same contract:
// only Status.Policy may be used to plan.
func (k *ScanKnowledge) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	return k.b.pathPolicyFor(component, now)
}
