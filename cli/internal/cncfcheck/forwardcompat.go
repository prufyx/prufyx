// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Forward compatibility of the per-project feed.
//
// The engine capability digest binds engine contract, fact registry, policy
// and landscape. A feed that registers one more fact, or lists one more
// project, therefore has another capability digest than every earlier build,
// and an exact comparison made every such build refuse the whole package.
//
// An index may also carry baseCapabilityDigest: the digest of the part a
// client cannot extend (engine contract, policy, pack schema). A build whose
// base digest equals it reads the package in compat mode:
//
//   - the index still has to parse strictly and its signed entries are bound
//     to the TUF targets role exactly as before;
//   - an entry for a project this build does not know is verified as an entry
//     but its target is neither parsed nor stored nor evaluated: the project
//     has no knowledge in this build, which every check reports as UNKNOWN;
//   - in a target of a known project, a rule whose required facts include one
//     this build does not register (or registers differently) is deferred:
//     it is never given to the engine, never produces a claim, never a PASS,
//     and every report of the project says that N rules were not evaluated;
//   - the registry and landscape digests of the pack header are not compared
//     (they cannot be recomputed), everything else is checked as before;
//   - the semantic rule digest of a target that holds deferred rules is not
//     compared (it covers rules this build cannot parse); the target bytes
//     remain bound to the signed length and sha256.
//
// A differing engine contract or policy is still a capability mismatch.
// Only the split per-project layout uses this mode; ParseExternalBundle and
// the single-target profiles stay exact.

type baseCapabilityDocument struct {
	Schema               string `json:"schema"`
	EngineContractDigest string `json:"engineContractDigest"`
	PolicyID             string `json:"policyId"`
	PolicyDigest         string `json:"policyDigest"`
}

// baseCapabilityDigest is the part of the capability a client cannot extend.
func baseCapabilityDigest(base bundle) string {
	raw, err := json.Marshal(baseCapabilityDocument{Schema: externalBundleSchema + "#base", EngineContractDigest: constraintengine.EngineContractDigest(), PolicyID: base.pack.PolicyID, PolicyDigest: base.pack.PolicyDigest})
	if err != nil {
		return ""
	}
	return digest(raw)
}

// admitIndexCapability decides how an index of the given capability is read:
// exactly (compat false), in compat mode, or not at all.
func admitIndexCapability(base bundle, indexCapability, indexBase, ownCapability string) (compat bool, err error) {
	own := baseCapabilityDigest(base)
	if own == "" {
		return false, ErrIntegrity
	}
	if indexCapability == ownCapability {
		if indexBase != "" && indexBase != own {
			return false, ErrInvalid
		}
		return false, nil
	}
	if indexBase != "" && indexBase == own && digestPattern.MatchString(indexCapability) {
		return true, nil
	}
	return false, errors.Join(ErrIntegrity, ErrCapabilityMismatch)
}

// futureProjectEntryShape checks an index entry of a project this build does
// not know: only its path shape and catalog marker, which the strict index
// parser and the TUF targets role bind the rest of.
func futureProjectEntryShape(entry ExternalIndexEntry) bool {
	var slug string
	switch entry.TargetPath {
	case ExternalProjectTargetPrefix + entry.Project + ExternalProjectTargetSuffix:
		if entry.Catalog != "" {
			return false
		}
	case ExternalCommunityTargetPrefix + entry.Project + ExternalProjectTargetSuffix:
		if entry.Catalog != CatalogCommunity {
			return false
		}
	default:
		return false
	}
	if m := externalProjectTargetRE.FindStringSubmatch(entry.TargetPath); m != nil {
		slug = m[1]
	} else if m := externalCommunityTargetRE.FindStringSubmatch(entry.TargetPath); m != nil {
		slug = m[1]
	}
	return slug == entry.Project && len(slug) <= 64
}

// futureFactShape reports whether a required fact is a well-formed
// definition, so a deferred rule still names real, bounded facts.
func futureFactShape(fact Fact) bool {
	_, err := constraintengine.NewRegistry([]constraintengine.FactDefinition{{ID: fact.ID, Component: fact.Component, Type: fact.Type, EnumTokens: fact.EnumTokens}})
	return err == nil
}

// Compat reports whether the index is read in compat mode.
func (x ExternalIndex) Compat() bool { return x.seal != nil && x.compat }

// Readable reports whether this build can read the target of project: the
// project is known to it. In exact mode every entry is.
func (x ExternalIndex) Readable(project string) bool {
	if x.seal == nil || x.base == nil {
		return false
	}
	return x.base.hasKnowledgeProject(project)
}

// compatCapability is the capability digest the project targets must carry
// in compat mode, or "" in exact mode.
func (x ExternalIndex) compatCapability() string {
	if !x.compat {
		return ""
	}
	return x.document.EngineCapabilityDigest
}

// DeferredRule is a rule of a signed target that this build did not
// evaluate because it needs facts the build does not register.
type DeferredRule struct {
	Project      string   `json:"project"`
	RuleID       string   `json:"ruleId"`
	MissingFacts []string `json:"missingFacts"`
}

func hasDeferred(pack rulePack) bool {
	for _, entry := range pack.Entries {
		if entry.deferred != nil {
			return true
		}
	}
	return false
}

func (b ExternalBundle) hasDeferred() bool { return hasDeferred(b.pack) }

// DeferredRules lists the rules of the target this build did not evaluate.
func (b ExternalBundle) DeferredRules() []DeferredRule {
	if !b.valid() {
		return nil
	}
	return deferredOf(b.pack, "")
}

func deferredOf(pack rulePack, project string) []DeferredRule {
	var out []DeferredRule
	for _, entry := range pack.Entries {
		if entry.deferred == nil || (project != "" && entry.Project != project) {
			continue
		}
		id, _ := ruleEntryID(entry)
		out = append(out, DeferredRule{Project: entry.Project, RuleID: id, MissingFacts: append([]string(nil), entry.deferred...)})
	}
	return out
}

func (b bundle) deferredCount(project string) int { return len(deferredOf(b.pack, project)) }

const deferredNextAction = "some rules of this project need facts this prufyx build does not know; they were not evaluated and stay UNKNOWN; upgrade prufyx to evaluate them"

// TargetDigest is the digest a signed index records for target bytes.
func TargetDigest(raw []byte) string { return digest(raw) }
