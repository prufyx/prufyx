// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// A rule pack may carry, besides its rules, records that cite sources the
// same way a rule does: line attestations (lineattest.PackMember) and
// upgrade-path policies (upgradepath.PackMember). Their citations are
// monitored for drift like a rule's, under a record ID that stands in for a
// rule ID wherever a worklist or a re-attestation statement names one.
//
// A record ID is "line-attestation." or "path-policy." followed by 24 hex
// digits of a domain-separated sha256 over the record's scope. It matches
// the rule ID syntax (so review records and file names can carry it) but
// is derived from the scope alone, so it is stable across renewals; a pack
// whose rule ID equals a record ID is rejected (see LoadCitations).
const (
	// RecordProjectLineAttestations and RecordProjectPathPolicies stand in
	// for a rule's project on a record's citations.
	RecordProjectLineAttestations = "line-attestations"
	RecordProjectPathPolicies     = "path-policies"

	recordIDDomain = "prufyx.io/pack-record-id/v1\x00"
)

// LineAttestationRecordID is the record ID of the line attestation for
// (component, factFamily, line).
func LineAttestationRecordID(component, factFamily, line string) string {
	return "line-attestation." + recordIDHash("line-attestation", component, factFamily, line)
}

// PathPolicyRecordID is the record ID of a component's path-policy record.
func PathPolicyRecordID(component string) string {
	return "path-policy." + recordIDHash("path-policy", component)
}

func recordIDHash(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(recordIDDomain))
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// PackRecord is one line attestation or path-policy record of a rule pack,
// with its exact bytes in the pack section.
type PackRecord struct {
	// ID is the record ID (LineAttestationRecordID or PathPolicyRecordID).
	ID string
	// Project is RecordProjectLineAttestations or RecordProjectPathPolicies.
	Project string
	// Scope names the record for a person: its component, and for an
	// attestation its fact family and line.
	Scope string
	// Raw is the record's exact bytes in its pack section.
	Raw json.RawMessage
	// Evidence is the record's evidence block (lineattest.Evidence or
	// upgradepath.Evidence, both with the members of a rule's evidence).
	Basis, ReviewedAt, ValidUntil string
	// State is the record's evidence state; a line attestation has no state
	// member (one in the pack is in force; it is withdrawn by deleting it),
	// so it reports upgradepath.StateActive.
	State   string
	Sources []SourceRef
	// Mechanical is true for a record an extractor derived.
	Mechanical bool
}

// SourceRef is one cited source of a record.
type SourceRef struct {
	ID, URL, Revision, ContentDigest string
	StartLine, EndLine               int
}

// PackRecords locates a rule pack's line attestation and path-policy
// sections by their exact member names (lineattest.PackMemberSection, so a
// case variant or a repeated or unknown member is an error rather than an
// unread section), parses each strictly, and returns every record in
// section order: line attestations first, then path policies. A pack
// without either section has no records. The attestations' rule sets are
// not checked here (that needs the engine's view of the rules; the pack
// loaders and evidence reattest do it).
func PackRecords(raw []byte) ([]PackRecord, error) {
	var out []PackRecord
	section, present, err := lineattest.PackMemberSection(raw, lineattest.PackMember)
	if err != nil {
		return nil, err
	}
	if present {
		atts, err := lineattest.Parse(section)
		if err != nil {
			return nil, err
		}
		items, err := splitSection(section, len(atts))
		if err != nil {
			return nil, err
		}
		for i, a := range atts {
			out = append(out, PackRecord{
				ID: LineAttestationRecordID(a.Component, a.FactFamily, a.Line), Project: RecordProjectLineAttestations,
				Scope: "line attestation " + a.Component + " " + a.FactFamily + " " + a.Line, Raw: items[i],
				Basis: a.Evidence.Basis, ReviewedAt: a.Evidence.ReviewedAt, ValidUntil: a.Evidence.ValidUntil,
				State: upgradepath.StateActive, Sources: sourceRefs(a.Evidence.Sources), Mechanical: a.Evidence.Basis == constraintengine.BasisMechanical,
			})
		}
	}
	section, present, err = lineattest.PackMemberSection(raw, upgradepath.PackMember)
	if err != nil {
		return nil, err
	}
	if present {
		records, err := upgradepath.Parse(section)
		if err != nil {
			return nil, err
		}
		items, err := splitSection(section, len(records))
		if err != nil {
			return nil, err
		}
		for i, r := range records {
			out = append(out, PackRecord{
				ID: PathPolicyRecordID(r.Component), Project: RecordProjectPathPolicies,
				Scope: "path policy " + r.Component, Raw: items[i],
				Basis: r.Evidence.Basis, ReviewedAt: r.Evidence.ReviewedAt, ValidUntil: r.Evidence.ValidUntil,
				State: r.Evidence.State, Sources: sourceRefs(r.Evidence.Sources), Mechanical: r.Evidence.Basis == constraintengine.BasisMechanical,
			})
		}
	}
	return out, nil
}

// splitSection returns the exact bytes of each element of a parsed section.
func splitSection(section json.RawMessage, want int) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(section, &items); err != nil || len(items) != want {
		return nil, fmt.Errorf("%w: pack section does not split into its records", errRejected)
	}
	return items, nil
}

func sourceRefs(sources []constraintengine.SourceEvidence) []SourceRef {
	out := make([]SourceRef, 0, len(sources))
	for _, s := range sources {
		out = append(out, SourceRef{ID: s.ID, URL: s.URL, Revision: s.Revision, ContentDigest: s.ContentDigest, StartLine: s.StartLine, EndLine: s.EndLine})
	}
	return out
}
