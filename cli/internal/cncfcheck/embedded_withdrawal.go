// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"time"
)

// A withdrawal in the embedded pack binds every evaluation of knowledge
// selected from a store: a store package signed before this build withdrew a
// rule still carries it as active, and would otherwise answer with it.
//
// The comparison is per rule id. A store rule whose id the embedded pack holds
// as withdrawn stays active only when its evidence.reviewedAt is strictly after
// the embedded rule's evidence.reviewedAt: a review recorded after the one the
// withdrawal stands on. Withdrawing a rule does not move reviewedAt, so a
// package from before the withdrawal has an equal or earlier date and never
// wins. Nothing else re-activates the rule: not the store revision, its
// publication or import time, the other rules' review dates, a later
// validUntil, or different rule content.

type ruleReview struct {
	ID       string `json:"id"`
	Evidence struct {
		State      string `json:"state"`
		ReviewedAt string `json:"reviewedAt"`
	} `json:"evidence"`
}

const evidenceStateWithdrawn = "withdrawn"

// reviewOf reads the id, evidence state and review time of a rule. A rule
// that lacks any of them, or whose review time is not whole-second UTC
// (RFC 3339 with Z), is an integrity failure.
func reviewOf(raw json.RawMessage) (ruleReview, time.Time, error) {
	var review ruleReview
	if json.Unmarshal(raw, &review) != nil || review.ID == "" || review.Evidence.State == "" {
		return ruleReview{}, time.Time{}, ErrIntegrity
	}
	at, err := time.Parse(time.RFC3339, review.Evidence.ReviewedAt)
	if err != nil || at.UTC().Format(time.RFC3339) != review.Evidence.ReviewedAt {
		return ruleReview{}, time.Time{}, ErrIntegrity
	}
	return review, at, nil
}

// packWithEmbeddedWithdrawals is external with every rule the embedded pack
// withdraws, and external holds without a strictly newer review, marked
// withdrawn. The rule keeps the scope the store gives it, so the transition the
// store would have decided answers UNKNOWN (RULE_EVIDENCE_WITHDRAWN). It is
// matched by id in whatever project holds it. A rule external does not hold is
// not added. external's own entries are never changed; the result is for
// selection only and is never encoded or published.
func packWithEmbeddedWithdrawals(embedded, external rulePack) (rulePack, error) {
	withdrawn := map[string]time.Time{}
	for _, entry := range embedded.Entries {
		review, at, err := reviewOf(entry.Rule)
		if err != nil {
			return rulePack{}, err
		}
		if review.Evidence.State == evidenceStateWithdrawn {
			withdrawn[review.ID] = at
		}
	}
	if len(withdrawn) == 0 {
		return external, nil
	}
	entries := append([]Entry(nil), external.Entries...)
	for index, entry := range entries {
		review, at, err := reviewOf(entry.Rule)
		if err != nil {
			return rulePack{}, err
		}
		embeddedAt, held := withdrawn[review.ID]
		if !held || review.Evidence.State == evidenceStateWithdrawn || at.After(embeddedAt) {
			continue
		}
		if entries[index].Rule, err = withdrawnRule(entry.Rule); err != nil {
			return rulePack{}, err
		}
	}
	external.Entries = entries
	return external, nil
}

// withdrawnRule is raw with evidence.state set to withdrawn. The two members
// must be spelled exactly, and the result must read back as withdrawn.
func withdrawnRule(raw json.RawMessage) (json.RawMessage, error) {
	var rule, evidence map[string]json.RawMessage
	if json.Unmarshal(raw, &rule) != nil || json.Unmarshal(rule["evidence"], &evidence) != nil || evidence["state"] == nil {
		return nil, ErrIntegrity
	}
	evidence["state"] = json.RawMessage(`"` + evidenceStateWithdrawn + `"`)
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, ErrIntegrity
	}
	rule["evidence"] = encoded
	out, err := json.Marshal(rule)
	if err != nil {
		return nil, ErrIntegrity
	}
	if review, _, err := reviewOf(out); err != nil || review.Evidence.State != evidenceStateWithdrawn {
		return nil, ErrIntegrity
	}
	return out, nil
}

// storeSelectionPack is the pack a store target of project is evaluated with:
// the store's rules under the embedded withdrawals, plus the embedded
// removal-crossing rules of the project.
func storeSelectionPack(embedded, external rulePack, project string) (rulePack, error) {
	held, err := packWithEmbeddedWithdrawals(embedded, external)
	if err != nil {
		return rulePack{}, err
	}
	return packWithEmbeddedCrossing(embedded, held, project)
}
