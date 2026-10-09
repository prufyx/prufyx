// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// RuleIdentity is the stable public identity of one rule already admitted by
// the embedded pack. It deliberately omits facts, evidence, and input values.
type RuleIdentity struct {
	Project   string `json:"project"`
	Component string `json:"component"`
	RuleID    string `json:"ruleId"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Range is present only for a rule with a reviewed version range.
	Range *constraintengine.VersionRange `json:"range,omitempty"`
	// Crossing is present only for a rule with a reviewed removal crossing.
	Crossing *constraintengine.CrossingSpec `json:"crossing,omitempty"`
	// Withdrawn is true for a rule whose evidence was withdrawn: it stays in
	// the pack so that it answers UNKNOWN, and it decides nothing.
	Withdrawn bool `json:"withdrawn,omitempty"`
	// Kind is present only for a rule that is not a plain verdict rule: a
	// one-way notice or a support range (constraintengine.RuleKind*).
	Kind string `json:"kind,omitempty"`
}

// Transition returns the identity's reviewed subject for the shared matcher.
func (r RuleIdentity) Transition() constraintengine.RuleTransition {
	return constraintengine.RuleTransition{Component: r.Component, From: r.From, To: r.To, Range: r.Range, Crossing: r.Crossing}
}

// EmbeddedRuleIdentities returns every integrity-checked embedded rule in a
// stable order. It performs no evaluation or source-input access.
func EmbeddedRuleIdentities() ([]RuleIdentity, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	result := make([]RuleIdentity, 0, len(b.pack.Entries))
	for _, entry := range b.pack.Entries {
		var shape struct {
			ID       string `json:"id"`
			Evidence struct {
				State string `json:"state"`
			} `json:"evidence"`
		}
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil || json.Unmarshal(entry.Rule, &shape) != nil || shape.ID == "" || subject.Component == "" || subject.From == "" || subject.To == "" {
			return nil, ErrIntegrity
		}
		kind, err := constraintengine.RawRuleKind(entry.Rule)
		if err != nil {
			return nil, ErrIntegrity
		}
		result = append(result, RuleIdentity{Project: entry.Project, Component: subject.Component, RuleID: shape.ID, From: subject.From, To: subject.To, Range: subject.Range, Crossing: subject.Crossing, Withdrawn: shape.Evidence.State == ruleStateWithdrawn, Kind: kind})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Project != result[j].Project {
			return result[i].Project < result[j].Project
		}
		return result[i].RuleID < result[j].RuleID
	})
	return result, nil
}

// ruleStateWithdrawn is the evidence state of a rule that no longer decides.
const ruleStateWithdrawn = "withdrawn"

// EntryWithdrawn reports whether the pack entry's evidence is withdrawn.
func EntryWithdrawn(entry Entry) bool {
	var shape struct {
		Evidence struct {
			State string `json:"state"`
		} `json:"evidence"`
	}
	return json.Unmarshal(entry.Rule, &shape) == nil && shape.Evidence.State == ruleStateWithdrawn
}

type Project struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	RepositoryURL   string `json:"repositoryURL"`
	CNCFStage       string `json:"cncfStage"`
	Priority        bool   `json:"priority"`
	GenericCoverage string `json:"genericCoverage"`
	// SourceRuleCount counts the active rules only. A withdrawn rule decides
	// nothing, so it is neither a rule nor coverage; WithdrawnRuleCount counts
	// them apart.
	SourceRuleCount    int      `json:"sourceRuleCount"`
	WithdrawnRuleCount int      `json:"withdrawnRuleCount"`
	RuntimeReproduced  int      `json:"runtimeReproduced"`
	ExistingChecks     []string `json:"existingChecks"`
	Checks             []Entry  `json:"checks"`
}

type Catalogue struct {
	Schema              string    `json:"schema"`
	LandscapeRevision   string    `json:"landscapeRevision"`
	LandscapeSourceURL  string    `json:"landscapeSourceURL"`
	LandscapeFileDigest string    `json:"landscapeFileDigest"`
	CatalogueDigest     string    `json:"catalogueDigest"`
	KnowledgeRevision   string    `json:"knowledgeRevision"`
	KnowledgePackDigest string    `json:"knowledgePackDigest"`
	Catalogued          int       `json:"catalogued"`
	PriorityProjects    int       `json:"priorityProjects"`
	SourceRuleCovered   int       `json:"sourceRuleCovered"`
	RuntimeReproduced   int       `json:"runtimeReproduced"`
	CoverageScope       string    `json:"coverageScope"`
	Projects            []Project `json:"projects"`
}

// Component returns the compiled package identity for one admitted project.
// It is a binding helper for callers that already validate canonical inputs;
// it does not expose mutable registry state.
func Component(project string) (string, error) {
	b, err := load()
	if err != nil {
		return "", err
	}
	for _, identity := range b.landscape.Projects {
		if identity.Slug == project {
			return subjectComponent(identity.Slug, identity.RepositoryURL), nil
		}
	}
	return "", ErrInvalid
}

// Catalog separates landscape identity from source-rule and runtime coverage.
// Counters describe the full embedded generic pack, even in a filtered listing.
func Catalog(priorityOnly bool, selectedProject string) (Catalogue, error) {
	b, err := load()
	if err != nil {
		return Catalogue{}, err
	}
	if selectedProject != "" && !b.hasProject(selectedProject) {
		return Catalogue{}, ErrInvalid
	}
	result := Catalogue{
		Schema:            "prufyx.io/cncf-catalogue/v1alpha1",
		LandscapeRevision: b.landscape.Revision, LandscapeSourceURL: b.landscape.SourceURL,
		LandscapeFileDigest: b.landscape.LandscapeFileDigest, CatalogueDigest: b.catalogueDigest,
		KnowledgeRevision: b.pack.Revision, KnowledgePackDigest: b.packDigest,
		Catalogued: len(b.landscape.Projects), PriorityProjects: len(b.priority.Priority),
		CoverageScope: "sourceRuleCovered and runtimeReproduced describe only the generic source-constraint preview; existing named checks are listed separately; priority is maintainer selection, not an adoption ranking",
		Projects:      make([]Project, 0),
	}
	covered := map[string]bool{}
	for _, entry := range b.pack.Entries {
		if !EntryWithdrawn(entry) {
			covered[entry.Project] = true
		}
	}
	result.SourceRuleCovered = len(covered)
	for _, identity := range b.landscape.Projects {
		priority := sort.SearchStrings(b.priority.Priority, identity.Slug)
		isPriority := priority < len(b.priority.Priority) && b.priority.Priority[priority] == identity.Slug
		if priorityOnly && !isPriority || selectedProject != "" && selectedProject != identity.Slug {
			continue
		}
		project := Project{Slug: identity.Slug, Name: identity.Name, RepositoryURL: identity.RepositoryURL, CNCFStage: identity.CNCFStage, Priority: isPriority, GenericCoverage: "catalogued_only", ExistingChecks: make([]string, 0), Checks: make([]Entry, 0)}
		for _, entry := range b.pack.Entries {
			if entry.Project == identity.Slug {
				project.Checks = append(project.Checks, entry)
			}
		}
		for _, check := range project.Checks {
			if EntryWithdrawn(check) {
				project.WithdrawnRuleCount++
			}
		}
		project.SourceRuleCount = len(project.Checks) - project.WithdrawnRuleCount
		switch {
		case project.SourceRuleCount > 0:
			project.GenericCoverage = "source_rule_preview"
		case project.WithdrawnRuleCount > 0:
			project.GenericCoverage = "withdrawn_only"
		}
		switch identity.Slug {
		case "cert-manager":
			project.ExistingChecks = []string{"prufyx check cert-manager-values --help"}
		case "prometheus":
			project.ExistingChecks = []string{"prufyx check prometheus-mode --help"}
		}
		result.Projects = append(result.Projects, project)
	}
	return result, nil
}

func (b bundle) hasProject(slug string) bool {
	index := sort.Search(len(b.landscape.Projects), func(i int) bool { return b.landscape.Projects[i].Slug >= slug })
	return index < len(b.landscape.Projects) && b.landscape.Projects[index].Slug == slug
}

// ClosestProjects returns up to limit catalogued project slugs nearest to
// name by edit distance, ties broken lexically, so a mistyped slug can be
// answered with the slug that was probably meant.
func ClosestProjects(name string, limit int) []string {
	b, err := load()
	if err != nil {
		return nil
	}
	type scored struct {
		slug     string
		distance int
	}
	list := make([]scored, 0, len(b.landscape.Projects))
	for _, identity := range b.landscape.Projects {
		list = append(list, scored{identity.Slug, editDistance(name, identity.Slug)})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].distance != list[j].distance {
			return list[i].distance < list[j].distance
		}
		return list[i].slug < list[j].slug
	})
	out := make([]string, 0, limit)
	// A slug that shares almost nothing with the name is noise, not a guess.
	closeEnough := max(2, (len(name)+1)/3)
	for index := 0; index < len(list) && index < limit; index++ {
		if list[index].distance > closeEnough {
			break
		}
		out = append(out, list[index].slug)
	}
	return out
}

// editDistance is the Levenshtein distance over bytes.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}
