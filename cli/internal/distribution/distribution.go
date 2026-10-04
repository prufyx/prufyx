// SPDX-License-Identifier: AGPL-3.0-only

// Package distribution holds reviewed knowledge about Kubernetes
// distributions: one identity record per distribution (its control-plane
// model and, for OpenShift, the OpenShift-to-Kubernetes minor mapping) and
// per-distribution applicability statements for rule families. A rule pack
// carries the records in its PackMember section.
//
// Absence is a gap. A distribution without a current record, and a rule
// family without a current "applies" statement for that distribution, is
// never treated as equivalent to upstream Kubernetes. Only official_upstream
// and kubeadm (upstream tooling with the upstream binaries) need no record.
// A "not_applicable" statement never removes a family from a check: the
// caller reports it as a gap, so it can never contribute to a PASS.
//
// Parsing is pure (no I/O), strict and deterministic.
package distribution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// PackMember is the rule pack member that holds the distribution section.
const PackMember = "distributions"

// Limits.
const (
	MaxRecords       = 64
	MaxApplicability = 512
	MaxMapping       = 64
	// MaxText bounds every free-text string (a statement's reason).
	MaxText = 256
	// MaxWindow is the longest validity window, the same as a rule's in a
	// CNCF pack.
	MaxWindow = 90 * 24 * time.Hour
)

// Control-plane models.
const (
	ControlPlaneManaged     = "managed"
	ControlPlaneSelfManaged = "self_managed"
)

// Applicability statuses a statement may carry.
const (
	StatusApplies       = "applies"
	StatusNotApplicable = "not_applicable"
)

// Rule families an applicability statement may name: a closed vocabulary.
const (
	FamilyRemovedServedGVK = lineattest.FamilyKubernetesRemovedServedGVK
	FamilyFlowControlAPI   = "kubernetes.flow_control_api"
	FamilyComponentFlags   = "kubernetes.component_flags"
	FamilyFeatureGates     = "kubernetes.feature_gates"
	FamilyComponentConfig  = "kubernetes.component_config"
	FamilyNode             = "kubernetes.node"
)

var families = map[string]bool{
	FamilyRemovedServedGVK: true, FamilyFlowControlAPI: true, FamilyComponentFlags: true,
	FamilyFeatureGates: true, FamilyComponentConfig: true, FamilyNode: true,
}

// Families lists the family vocabulary in ascending order.
func Families() []string {
	out := make([]string, 0, len(families))
	for f := range families {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ValidFamily reports whether family is in the closed vocabulary.
func ValidFamily(family string) bool { return families[family] }

// UpstreamEquivalent reports whether a distribution is upstream Kubernetes
// by definition (official_upstream, kubeadm). Such a distribution needs no
// record, and a section may not hold one for it.
func UpstreamEquivalent(distribution string) bool {
	return distribution == string(k8sversion.OfficialUpstream) || distribution == string(k8sversion.Kubeadm)
}

// controlPlanes fixes the control-plane model of the distributions whose
// model is part of their identity; OpenShift may be either (self-managed or
// a managed service).
var controlPlanes = map[string]string{
	string(k8sversion.EKS): ControlPlaneManaged, string(k8sversion.GKE): ControlPlaneManaged, string(k8sversion.AKS): ControlPlaneManaged,
	string(k8sversion.K3s): ControlPlaneSelfManaged, string(k8sversion.RKE2): ControlPlaneSelfManaged, string(k8sversion.Talos): ControlPlaneSelfManaged,
}

// Evidence states, as a rule's.
const (
	StateActive    = "active"
	StateWithdrawn = "withdrawn"
)

// Freshness values, the same tokens a rule claim reports.
const (
	FreshnessCurrent           = "current"
	FreshnessStale             = "stale"
	FreshnessWithdrawn         = "withdrawn"
	FreshnessClockBeforeReview = "clock_before_review"
)

// ErrInvalid marks a malformed distribution section.
var ErrInvalid = errors.New("invalid distribution section")

// Evidence is a record's provenance and validity window, with the members
// and meaning of a rule's evidence: an absent basis means a maintainer
// reviewed it; a mechanical record names its extractor and derivation time.
// Sources are pinned Git sources, checked exactly as a rule's.
type Evidence struct {
	State      string                            `json:"state"`
	Basis      string                            `json:"basis,omitempty"`
	Extractor  *constraintengine.Extractor       `json:"extractor,omitempty"`
	DerivedAt  string                            `json:"derivedAt,omitempty"`
	ReviewedAt string                            `json:"reviewedAt"`
	ValidUntil string                            `json:"validUntil"`
	Sources    []constraintengine.SourceEvidence `json:"sources"`
}

// Mapping is one OpenShift line and the Kubernetes minor line it is based
// on, both as "major.minor".
type Mapping struct {
	Line       string `json:"line"`
	Kubernetes string `json:"kubernetes"`
}

// Record is one distribution's identity record.
type Record struct {
	Distribution string `json:"distribution"`
	ControlPlane string `json:"controlPlane"`
	// KubernetesMapping is OpenShift's only, optional, and never empty when
	// present: OpenShift lines and their Kubernetes lines, both strictly
	// increasing.
	KubernetesMapping []Mapping `json:"kubernetesMapping,omitempty"`
	Evidence          Evidence  `json:"evidence"`
}

// Applicability is one statement that a rule family applies, or does not
// apply, to a distribution.
type Applicability struct {
	Distribution string   `json:"distribution"`
	Family       string   `json:"family"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason,omitempty"`
	Evidence     Evidence `json:"evidence"`
}

// Section is the pack's distribution section in exactly its pack form:
// identity records in ascending distribution order, and applicability
// statements in ascending (distribution, family) order, each for a
// distribution that has a record.
type Section struct {
	Records       []Record        `json:"records"`
	Applicability []Applicability `json:"applicability"`
}

// Parse decodes and validates a distribution section. Decoding is exact:
// the document has one reading (strictjson), member names match
// case-sensitively, every member is required unless documented optional, no
// value is null and nothing trails the object.
func Parse(raw []byte) (Section, error) {
	if err := strictjson.Check(raw); err != nil {
		return Section{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := checkShape(raw); err != nil {
		return Section{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Section
	if err := dec.Decode(&s); err != nil {
		return Section{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Section{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := Validate(s); err != nil {
		return Section{}, err
	}
	return s, nil
}

// Validate checks a section: 1 to MaxRecords records, one per distribution,
// in strictly ascending order, none for an upstream-equivalent distribution;
// 0 to MaxApplicability statements, one per (distribution, family), in
// strictly ascending order, each for a distribution with a record.
func Validate(s Section) error {
	if len(s.Records) == 0 || len(s.Records) > MaxRecords {
		return fmt.Errorf("%w: a section holds 1-%d records, got %d", ErrInvalid, MaxRecords, len(s.Records))
	}
	if s.Applicability == nil {
		return fmt.Errorf("%w: applicability is required (an empty list states nothing)", ErrInvalid)
	}
	if len(s.Applicability) > MaxApplicability {
		return fmt.Errorf("%w: a section holds at most %d applicability statements, got %d", ErrInvalid, MaxApplicability, len(s.Applicability))
	}
	recorded := make(map[string]bool, len(s.Records))
	for i, r := range s.Records {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("record %d (%s): %w", i, r.Distribution, err)
		}
		if i > 0 {
			prev := s.Records[i-1].Distribution
			if prev == r.Distribution {
				return fmt.Errorf("%w: two records for %s", ErrInvalid, r.Distribution)
			}
			if prev > r.Distribution {
				return fmt.Errorf("%w: records are not in ascending order: %s follows %s", ErrInvalid, r.Distribution, prev)
			}
		}
		recorded[r.Distribution] = true
	}
	for i, a := range s.Applicability {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("applicability %d (%s %s): %w", i, a.Distribution, a.Family, err)
		}
		if !recorded[a.Distribution] {
			return fmt.Errorf("%w: applicability %d names %s, which has no record", ErrInvalid, i, a.Distribution)
		}
		if i > 0 {
			prev := s.Applicability[i-1]
			if prev.Distribution == a.Distribution && prev.Family == a.Family {
				return fmt.Errorf("%w: two applicability statements for %s %s", ErrInvalid, a.Distribution, a.Family)
			}
			if prev.Distribution > a.Distribution || (prev.Distribution == a.Distribution && prev.Family > a.Family) {
				return fmt.Errorf("%w: applicability is not in ascending (distribution, family) order: %s %s follows %s %s", ErrInvalid, a.Distribution, a.Family, prev.Distribution, prev.Family)
			}
		}
	}
	return nil
}

func validDistribution(id string) error {
	if !k8sversion.Known(id) {
		return fmt.Errorf("%w: distribution %q is not a known distribution id", ErrInvalid, id)
	}
	if UpstreamEquivalent(id) {
		return fmt.Errorf("%w: %s is upstream Kubernetes and takes no record", ErrInvalid, id)
	}
	return nil
}

// Validate checks one identity record on its own.
func (r Record) Validate() error {
	if err := validDistribution(r.Distribution); err != nil {
		return err
	}
	if r.ControlPlane != ControlPlaneManaged && r.ControlPlane != ControlPlaneSelfManaged {
		return fmt.Errorf("%w: controlPlane must be %q or %q", ErrInvalid, ControlPlaneManaged, ControlPlaneSelfManaged)
	}
	if fixed, ok := controlPlanes[r.Distribution]; ok && r.ControlPlane != fixed {
		return fmt.Errorf("%w: the control plane of %s is %s", ErrInvalid, r.Distribution, fixed)
	}
	if r.KubernetesMapping != nil {
		if r.Distribution != string(k8sversion.OpenShift) {
			return fmt.Errorf("%w: kubernetesMapping is for openshift only", ErrInvalid)
		}
		if err := validateMapping(r.KubernetesMapping); err != nil {
			return err
		}
	}
	return r.Evidence.validate()
}

// Validate checks one applicability statement on its own.
func (a Applicability) Validate() error {
	if err := validDistribution(a.Distribution); err != nil {
		return err
	}
	if !ValidFamily(a.Family) {
		return fmt.Errorf("%w: family %q is not one of %s", ErrInvalid, a.Family, strings.Join(Families(), ", "))
	}
	if a.Status != StatusApplies && a.Status != StatusNotApplicable {
		return fmt.Errorf("%w: status must be %q or %q", ErrInvalid, StatusApplies, StatusNotApplicable)
	}
	if a.Reason != "" && !publicText(a.Reason) {
		return fmt.Errorf("%w: reason must be 1-%d bytes of printable UTF-8 text without surrounding space", ErrInvalid, MaxText)
	}
	return a.Evidence.validate()
}

func publicText(s string) bool {
	if s == "" || len(s) > MaxText || !utf8.ValidString(s) || s != strings.TrimSpace(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// ParseLine reads a canonical "major.minor" line (no leading zeros, at most
// six digits per part).
func ParseLine(line string) (major, minor int, ok bool) {
	a, b, found := strings.Cut(line, ".")
	if !found {
		return 0, 0, false
	}
	major, ok1 := canonicalNumber(a)
	minor, ok2 := canonicalNumber(b)
	return major, minor, ok1 && ok2
}

func canonicalNumber(s string) (int, bool) {
	if s == "" || len(s) > 6 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// validateMapping: 1 to MaxMapping entries; line "4.N", kubernetes "1.M";
// both strictly increasing.
func validateMapping(mapping []Mapping) error {
	if len(mapping) == 0 || len(mapping) > MaxMapping {
		return fmt.Errorf("%w: kubernetesMapping holds 1-%d entries when present", ErrInvalid, MaxMapping)
	}
	prevLine, prevKube := -1, -1
	for i, m := range mapping {
		major, minor, ok := ParseLine(m.Line)
		if !ok || major != 4 {
			return fmt.Errorf("%w: kubernetesMapping %d: line %q is not an OpenShift 4.N line", ErrInvalid, i, m.Line)
		}
		kmajor, kminor, ok := ParseLine(m.Kubernetes)
		if !ok || kmajor != 1 {
			return fmt.Errorf("%w: kubernetesMapping %d: kubernetes %q is not a Kubernetes 1.M line", ErrInvalid, i, m.Kubernetes)
		}
		if minor <= prevLine || kminor <= prevKube {
			return fmt.Errorf("%w: kubernetesMapping must be strictly increasing in both lines (entry %d)", ErrInvalid, i)
		}
		prevLine, prevKube = minor, kminor
	}
	return nil
}

func (e Evidence) validate() error {
	if e.State != StateActive && e.State != StateWithdrawn {
		return fmt.Errorf("%w: evidence.state must be %q or %q", ErrInvalid, StateActive, StateWithdrawn)
	}
	if err := constraintengine.ValidateReviewedOrMechanicalBasis(e.Basis, e.Extractor, e.DerivedAt); err != nil {
		return fmt.Errorf("%w: evidence.basis: %v", ErrInvalid, err)
	}
	reviewed, err := constraintengine.ParseUTC(e.ReviewedAt)
	if err != nil {
		return fmt.Errorf("%w: evidence.reviewedAt must be a UTC RFC 3339 time", ErrInvalid)
	}
	until, err := constraintengine.ParseUTC(e.ValidUntil)
	if err != nil || !until.After(reviewed) || until.Sub(reviewed) > MaxWindow {
		return fmt.Errorf("%w: evidence.validUntil must be a UTC RFC 3339 time after reviewedAt and at most %s later", ErrInvalid, MaxWindow)
	}
	if e.DerivedAt != "" {
		if derived, err := constraintengine.ParseUTC(e.DerivedAt); err != nil || !derived.Before(until) {
			return fmt.Errorf("%w: evidence.derivedAt must be before validUntil", ErrInvalid)
		}
	}
	if err := constraintengine.ValidateSources(e.Sources); err != nil {
		return fmt.Errorf("%w: evidence.sources: %v", ErrInvalid, err)
	}
	return nil
}

// Freshness evaluates evidence at now exactly as the engine evaluates a
// rule's: withdrawn first, then before reviewedAt (clock_before_review),
// then at or after validUntil (stale). Unreadable times are stale.
func (e Evidence) Freshness(now time.Time) string {
	if e.State != StateActive {
		return FreshnessWithdrawn
	}
	reviewed, err1 := constraintengine.ParseUTC(e.ReviewedAt)
	until, err2 := constraintengine.ParseUTC(e.ValidUntil)
	if err1 != nil || err2 != nil {
		return FreshnessStale
	}
	if now.Before(reviewed) {
		return FreshnessClockBeforeReview
	}
	if !now.Before(until) {
		return FreshnessStale
	}
	return FreshnessCurrent
}

// Marshal renders a section in canonical order after validating it.
func Marshal(s Section) ([]byte, error) {
	out := Section{Records: append([]Record(nil), s.Records...), Applicability: append([]Applicability{}, s.Applicability...)}
	sort.SliceStable(out.Records, func(i, j int) bool { return out.Records[i].Distribution < out.Records[j].Distribution })
	sort.SliceStable(out.Applicability, func(i, j int) bool {
		a, b := out.Applicability[i], out.Applicability[j]
		if a.Distribution != b.Distribution {
			return a.Distribution < b.Distribution
		}
		return a.Family < b.Family
	})
	if err := Validate(out); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
