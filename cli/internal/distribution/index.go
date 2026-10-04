// SPDX-License-Identifier: AGPL-3.0-only

package distribution

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
)

// Lookup statuses (Applicability.Status, plus the two a lookup adds).
const (
	// LookupUpstream: the distribution is upstream Kubernetes by definition
	// (official_upstream, kubeadm); every family applies without a record.
	LookupUpstream = "upstream"
	// LookupAbsent: no record for the distribution, or no statement for the
	// family. The family is a gap for that distribution.
	LookupAbsent        = "absent"
	LookupApplies       = StatusApplies
	LookupNotApplicable = StatusNotApplicable
)

// ApplicabilityStatus is the answer for one (distribution, family) at a
// time.
type ApplicabilityStatus struct {
	Distribution string `json:"distribution"`
	Family       string `json:"family"`
	// Status is LookupUpstream, LookupAbsent, or the statement's status.
	Status string `json:"status"`
	// Freshness is the freshness of the statement together with its
	// distribution's record (the first of the two that is not current);
	// empty for LookupUpstream and LookupAbsent.
	Freshness string `json:"freshness,omitempty"`
	// Reason is the statement's reason, if any.
	Reason string `json:"reason,omitempty"`
}

// Applies is the one test a caller may use to treat the family as checked
// for the distribution as for upstream Kubernetes: true for an
// upstream-equivalent distribution and a known family, or for a current
// "applies" statement whose distribution record is current too. Everything
// else (no record, no statement, not_applicable, stale, withdrawn, reviewed
// after now) is a gap; a not_applicable statement is a gap with a reason,
// never a PASS.
func (s ApplicabilityStatus) Applies() bool {
	switch s.Status {
	case LookupUpstream:
		return ValidFamily(s.Family)
	case LookupApplies:
		return s.Freshness == FreshnessCurrent
	}
	return false
}

// StatementNotCurrent reports a statement that exists but may not be used
// (it or its distribution's record is stale, withdrawn or reviewed after
// the lookup time).
func (s ApplicabilityStatus) StatementNotCurrent() bool {
	return (s.Status == LookupApplies || s.Status == LookupNotApplicable) && s.Freshness != FreshnessCurrent
}

// MappingStatus is the answer for one OpenShift line at a time.
type MappingStatus struct {
	Line string `json:"line"`
	// Found is false when there is no OpenShift record or the record does
	// not map the line.
	Found bool `json:"found"`
	// Kubernetes is the mapped Kubernetes line ("1.M"); patch unknown.
	Kubernetes string `json:"kubernetes,omitempty"`
	// Freshness is the OpenShift record's freshness when Found.
	Freshness string `json:"freshness,omitempty"`
}

// Minor returns the Kubernetes line to use, only for a found mapping whose
// record is current.
func (s MappingStatus) Minor() (string, bool) {
	if !s.Found || s.Freshness != FreshnessCurrent {
		return "", false
	}
	return s.Kubernetes, true
}

type familyKey struct{ distribution, family string }

// Index looks a validated section up. Build it only from a validated
// section (Parse or Validate); the zero Index holds nothing.
type Index struct {
	records    map[string]Record
	statements map[familyKey]Applicability
}

// NewIndex indexes a section.
func NewIndex(s Section) Index {
	ix := Index{records: make(map[string]Record, len(s.Records)), statements: make(map[familyKey]Applicability, len(s.Applicability))}
	for _, r := range s.Records {
		ix.records[r.Distribution] = copyRecord(r)
	}
	for _, a := range s.Applicability {
		a.Evidence = copyEvidence(a.Evidence)
		ix.statements[familyKey{a.Distribution, a.Family}] = a
	}
	return ix
}

// Len is the number of indexed records.
func (ix Index) Len() int { return len(ix.records) }

// Record returns a distribution's identity record with its freshness at
// now; found is false when there is none.
func (ix Index) Record(distribution string, now time.Time) (record Record, freshness string, found bool) {
	r, ok := ix.records[distribution]
	if !ok {
		return Record{}, "", false
	}
	return copyRecord(r), r.Evidence.Freshness(now), true
}

// ApplicabilityFor answers whether family applies to distribution at now.
// An unknown distribution or family, a distribution without a record and a
// family without a statement are all LookupAbsent; only official_upstream
// and kubeadm are upstream without a record. Use ApplicabilityStatus.Applies
// to decide.
func (ix Index) ApplicabilityFor(distribution, family string, now time.Time) ApplicabilityStatus {
	out := ApplicabilityStatus{Distribution: distribution, Family: family, Status: LookupAbsent}
	if !ValidFamily(family) || !k8sversion.Known(distribution) {
		return out
	}
	if UpstreamEquivalent(distribution) {
		out.Status = LookupUpstream
		return out
	}
	record, ok := ix.records[distribution]
	if !ok {
		return out
	}
	statement, ok := ix.statements[familyKey{distribution, family}]
	if !ok {
		return out
	}
	out.Status, out.Reason = statement.Status, statement.Reason
	out.Freshness = record.Evidence.Freshness(now)
	if out.Freshness == FreshnessCurrent {
		out.Freshness = statement.Evidence.Freshness(now)
	}
	return out
}

// OpenShiftMinor returns the Kubernetes line the OpenShift line ("4.N") is
// based on, with the OpenShift record's freshness at now.
func (ix Index) OpenShiftMinor(line string, now time.Time) MappingStatus {
	out := MappingStatus{Line: line}
	record, ok := ix.records[string(k8sversion.OpenShift)]
	if !ok {
		return out
	}
	for _, m := range record.KubernetesMapping {
		if m.Line == line {
			out.Found, out.Kubernetes, out.Freshness = true, m.Kubernetes, record.Evidence.Freshness(now)
			return out
		}
	}
	return out
}

// OpenShiftTable is the OpenShift mapping as k8sversion.ParseWith reads it,
// holding only what may be used at now: nil unless the OpenShift record
// exists, maps at least one line and is current.
func (ix Index) OpenShiftTable(now time.Time) k8sversion.OpenShiftMap {
	record, ok := ix.records[string(k8sversion.OpenShift)]
	if !ok || len(record.KubernetesMapping) == 0 || record.Evidence.Freshness(now) != FreshnessCurrent {
		return nil
	}
	table := make(k8sversion.OpenShiftMap, len(record.KubernetesMapping))
	for _, m := range record.KubernetesMapping {
		_, line, ok1 := ParseLine(m.Line)
		_, kube, ok2 := ParseLine(m.Kubernetes)
		if ok1 && ok2 {
			table[line] = kube
		}
	}
	return table
}

func copyRecord(r Record) Record {
	r.KubernetesMapping = append([]Mapping(nil), r.KubernetesMapping...)
	r.Evidence = copyEvidence(r.Evidence)
	return r
}

func copyEvidence(e Evidence) Evidence {
	e.Sources = append([]constraintengine.SourceEvidence(nil), e.Sources...)
	if e.Extractor != nil {
		x := *e.Extractor
		e.Extractor = &x
	}
	return e
}
