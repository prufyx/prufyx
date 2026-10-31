// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"sort"
	"time"
)

// EvidenceHighWater is the latest evidence.reviewedAt over the envelope's
// rules: the date its newest review was recorded. It is the zero time for an
// envelope without rules. A date that does not parse was refused at
// admission and is left out.
func (b ExternalBundle) EvidenceHighWater() time.Time {
	return evidenceHighWater(b.pack.Entries)
}

func evidenceHighWater(entries []Entry) time.Time {
	var latest time.Time
	for _, entry := range entries {
		var shape struct {
			Evidence struct {
				ReviewedAt string `json:"reviewedAt"`
			} `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			continue
		}
		if at, err := time.Parse(time.RFC3339, shape.Evidence.ReviewedAt); err == nil && at.After(latest) {
			latest = at.UTC()
		}
	}
	return latest
}

// contentDigest identifies what an envelope says about its project, without
// the revision label: its rules and its record sections.
func (b ExternalBundle) contentDigest() string {
	return externalDigestJSON(struct {
		Entries          []Entry         `json:"entries"`
		LineAttestations json.RawMessage `json:"lineAttestations"`
		PathPolicies     json.RawMessage `json:"pathPolicies"`
		ServedAPIs       json.RawMessage `json:"servedApis"`
	}{b.pack.Entries, b.pack.LineAttestations, b.pack.PathPolicies, b.pack.ServedAPIs})
}

// EmbeddedComparison sets the evidence of a verified store against the
// evidence of the embedded pack for the same projects.
type EmbeddedComparison struct {
	// StoreEvidenceAt and EmbeddedEvidenceAt are the latest reviewedAt over
	// the compared projects' rules on each side.
	StoreEvidenceAt    time.Time
	EmbeddedEvidenceAt time.Time
	// StaleProject names the first compared project (in name order) whose
	// store evidence is older than its embedded evidence; empty when there is
	// none. When it is set the two dates above are that project's, so a
	// message can state the dates of the project that decides the choice.
	StaleProject string
	// Identical is true when every compared project has the same rules and
	// records on both sides (the revision label is not part of it).
	Identical bool
}

// CompareWithEmbedded compares the verified store targets of the named
// projects (a project the store lacks is an empty envelope) with the embedded
// pack's rules and records for the same projects. It reads only data that is
// already verified; it grants no trust.
func CompareWithEmbedded(store map[string]ExternalBundle) (EmbeddedComparison, error) {
	base, err := load()
	if err != nil {
		return EmbeddedComparison{}, err
	}
	records, err := splitRecords(base.pack, base.knowledgeProjects())
	if err != nil {
		return EmbeddedComparison{}, ErrIntegrity
	}
	byProject := map[string][]Entry{}
	for _, entry := range base.pack.Entries {
		byProject[entry.Project] = append(byProject[entry.Project], entry)
	}
	out := EmbeddedComparison{Identical: true}
	projects := make([]string, 0, len(store))
	for project := range store {
		projects = append(projects, project)
	}
	sort.Strings(projects)
	var staleStoreAt, staleEmbeddedAt time.Time
	for _, project := range projects {
		bundle := store[project]
		if !bundle.valid() {
			return EmbeddedComparison{}, ErrIntegrity
		}
		raw, err := encodeExternalEnvelopeWithRecords(base, "1", "operator_provided", byProject[project], records[project])
		if err != nil {
			return EmbeddedComparison{}, err
		}
		embedded, err := parseExternalBundle(raw, &base)
		if err != nil {
			return EmbeddedComparison{}, err
		}
		// The embedded evidence counts every embedded rule of the project,
		// the removal-crossing rules too: a store target never carries them
		// (external_pack.go), so the store must be strictly newer to win.
		embeddedAt, storeAt := evidenceHighWater(byProject[project]), bundle.EvidenceHighWater()
		if embeddedAt.After(out.EmbeddedEvidenceAt) {
			out.EmbeddedEvidenceAt = embeddedAt
		}
		if storeAt.After(out.StoreEvidenceAt) {
			out.StoreEvidenceAt = storeAt
		}
		if storeAt.Before(embeddedAt) && out.StaleProject == "" {
			out.StaleProject, staleStoreAt, staleEmbeddedAt = project, storeAt, embeddedAt
		}
		if embedded.contentDigest() != bundle.contentDigest() {
			out.Identical = false
		}
	}
	if out.StaleProject != "" {
		out.StoreEvidenceAt, out.EmbeddedEvidenceAt = staleStoreAt, staleEmbeddedAt
	}
	return out, nil
}
