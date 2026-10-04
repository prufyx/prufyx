// SPDX-License-Identifier: AGPL-3.0-only

package distribution

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
)

// Every record here is synthetic test data (OpenShift 4.99 -> Kubernetes
// 1.99 and so on); none is a statement about a real distribution.

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func testEvidence() Evidence {
	return Evidence{
		State: StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + testRevision + "/versions.md", Revision: testRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
	}
}

func testSection() Section {
	return Section{
		Records: []Record{
			{Distribution: "eks", ControlPlane: ControlPlaneManaged, Evidence: testEvidence()},
			{Distribution: "k3s", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()},
			{Distribution: "openshift", ControlPlane: ControlPlaneSelfManaged, KubernetesMapping: []Mapping{{"4.98", "1.98"}, {"4.99", "1.99"}}, Evidence: testEvidence()},
		},
		Applicability: []Applicability{
			{Distribution: "eks", Family: FamilyComponentFlags, Status: StatusNotApplicable, Reason: "The provider operates the control plane.", Evidence: testEvidence()},
			{Distribution: "eks", Family: FamilyRemovedServedGVK, Status: StatusApplies, Evidence: testEvidence()},
			{Distribution: "k3s", Family: FamilyRemovedServedGVK, Status: StatusApplies, Evidence: testEvidence()},
		},
	}
}

func marshalSection(t testing.TB, s Section) []byte {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseValidAndCanonical(t *testing.T) {
	raw, err := Marshal(testSection())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, testSection()) {
		t.Fatalf("round trip %+v", s)
	}
	again, err := Marshal(s)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("not canonical: %v", err)
	}
	// Marshal sorts.
	shuffled := testSection()
	shuffled.Records[0], shuffled.Records[2] = shuffled.Records[2], shuffled.Records[0]
	shuffled.Applicability[0], shuffled.Applicability[2] = shuffled.Applicability[2], shuffled.Applicability[0]
	sorted, err := Marshal(shuffled)
	if err != nil || !bytes.Equal(sorted, raw) {
		t.Fatalf("Marshal does not sort: %v", err)
	}
	// An empty applicability list is a valid section stating nothing.
	empty := testSection()
	empty.Applicability = []Applicability{}
	if _, err := Parse(marshalSection(t, empty)); err != nil {
		t.Fatalf("empty applicability: %v", err)
	}
}

// replace applies one textual edit to the valid section.
func replace(t testing.TB, old, new string) []byte {
	raw := marshalSection(t, testSection())
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("%q not in the section", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(new), 1)
}

func TestParseStrictness(t *testing.T) {
	section := func(mutate func(*Section)) []byte {
		s := testSection()
		mutate(&s)
		return marshalSection(t, s)
	}
	// sorted applies mutate and restores canonical order, so a case fails
	// for its own defect, never for order.
	sorted := func(mutate func(*Section)) []byte {
		s := testSection()
		mutate(&s)
		sort.SliceStable(s.Records, func(i, j int) bool { return s.Records[i].Distribution < s.Records[j].Distribution })
		sort.SliceStable(s.Applicability, func(i, j int) bool {
			a, b := s.Applicability[i], s.Applicability[j]
			return a.Distribution < b.Distribution || (a.Distribution == b.Distribution && a.Family < b.Family)
		})
		return marshalSection(t, s)
	}
	evidence := func(mutate func(*Evidence)) []byte {
		return section(func(s *Section) { mutate(&s.Records[0].Evidence) })
	}
	statementEvidence := func(mutate func(*Evidence)) []byte {
		return section(func(s *Section) { mutate(&s.Applicability[1].Evidence) })
	}
	cases := map[string][]byte{
		"not an object":               []byte(`[]`),
		"null":                        []byte(`null`),
		"trailing data":               append(marshalSection(t, testSection()), []byte(` {}`)...),
		"unknown section member":      replace(t, `{"records":`, `{"notes":"x","records":`),
		"missing records":             []byte(`{"applicability":[]}`),
		"missing applicability":       replace(t, `,"applicability":[`, `,"x":[`),
		"null applicability":          []byte(strings.SplitN(string(marshalSection(t, testSection())), `,"applicability":`, 2)[0] + `,"applicability":null}`),
		"no records":                  section(func(s *Section) { s.Records = []Record{}; s.Applicability = []Applicability{} }),
		"unknown record member":       replace(t, `"controlPlane":"managed"`, `"controlPlane":"managed","pattern":"^v1"`),
		"unknown evidence member":     replace(t, `"state":"active"`, `"state":"active","owner":"x"`),
		"unknown source member":       replace(t, `"startLine":1`, `"startLine":1,"page":2`),
		"unknown mapping member":      replace(t, `"line":"4.98"`, `"line":"4.98","patch":"1"`),
		"case variant member":         replace(t, `"controlPlane"`, `"ControlPlane"`),
		"case variant section member": replace(t, `"records"`, `"Records"`),
		"folded member":               replace(t, `"status"`, `"ſtatus"`),
		"repeated member":             replace(t, `"controlPlane":"managed"`, `"controlPlane":"self_managed","controlPlane":"managed"`),
		"null member":                 replace(t, `"reason":"The provider operates the control plane."`, `"reason":null`),
		"empty reason":                replace(t, `"reason":"The provider operates the control plane."`, `"reason":""`),
		"empty basis":                 replace(t, `"state":"active"`, `"state":"active","basis":""`),
		"empty mapping":               replace(t, `"kubernetesMapping":[{"line":"4.98","kubernetes":"1.98"},{"line":"4.99","kubernetes":"1.99"}]`, `"kubernetesMapping":[]`),
		"unknown distribution":        sorted(func(s *Section) { s.Records[1].Distribution = "minikube"; s.Applicability = s.Applicability[:2] }),
		"distribution case":           section(func(s *Section) { s.Records[0].Distribution = "EKS"; s.Applicability = []Applicability{} }),
		"record for upstream": sorted(func(s *Section) {
			s.Records = append([]Record{{Distribution: "kubeadm", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()}}, s.Records...)
		}),
		"record for official upstream": sorted(func(s *Section) {
			s.Records = append(s.Records, Record{Distribution: "official_upstream", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()})
		}),
		"statement for upstream": sorted(func(s *Section) {
			s.Records = append(s.Records, Record{Distribution: "kubeadm", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()})
			s.Applicability[0].Distribution = "kubeadm"
		}),
		"unknown control plane":         section(func(s *Section) { s.Records[1].ControlPlane = "hosted" }),
		"managed k3s":                   section(func(s *Section) { s.Records[1].ControlPlane = ControlPlaneManaged }),
		"self-managed eks":              section(func(s *Section) { s.Records[0].ControlPlane = ControlPlaneSelfManaged }),
		"mapping on eks":                section(func(s *Section) { s.Records[0].KubernetesMapping = []Mapping{{"4.99", "1.99"}} }),
		"mapping line not 4.N":          section(func(s *Section) { s.Records[2].KubernetesMapping[0].Line = "3.11" }),
		"mapping line leading zero":     section(func(s *Section) { s.Records[2].KubernetesMapping[0].Line = "4.098" }),
		"mapping line with patch":       section(func(s *Section) { s.Records[2].KubernetesMapping[0].Line = "4.98.1" }),
		"mapping kubernetes not 1.M":    section(func(s *Section) { s.Records[2].KubernetesMapping[0].Kubernetes = "2.98" }),
		"mapping kubernetes with patch": section(func(s *Section) { s.Records[2].KubernetesMapping[0].Kubernetes = "1.98.0" }),
		"mapping line not increasing":   section(func(s *Section) { s.Records[2].KubernetesMapping[1].Line = "4.98" }),
		"mapping line decreasing":       section(func(s *Section) { s.Records[2].KubernetesMapping[1].Line = "4.97" }),
		"mapping kubernetes not increasing": section(func(s *Section) {
			s.Records[2].KubernetesMapping[1].Kubernetes = "1.98"
		}),
		"mapping kubernetes decreasing": section(func(s *Section) { s.Records[2].KubernetesMapping[1].Kubernetes = "1.97" }),
		"unknown family":                sorted(func(s *Section) { s.Applicability[1].Family = "kubernetes.addons" }),
		"unknown family sorting last":   sorted(func(s *Section) { s.Applicability[1].Family = "kubernetes.workloads" }),
		"unknown status":                section(func(s *Section) { s.Applicability[1].Status = "partial" }),
		"status case":                   section(func(s *Section) { s.Applicability[1].Status = "Applies" }),
		"statement without record": section(func(s *Section) {
			s.Applicability = append(s.Applicability, Applicability{Distribution: "rke2", Family: FamilyNode, Status: StatusApplies, Evidence: testEvidence()})
		}),
		"unsorted records":    section(func(s *Section) { s.Records[0], s.Records[1] = s.Records[1], s.Records[0] }),
		"duplicate record":    section(func(s *Section) { s.Records[1] = s.Records[0] }),
		"unsorted statements": section(func(s *Section) { s.Applicability[0], s.Applicability[1] = s.Applicability[1], s.Applicability[0] }),
		"statements unsorted by distribution": section(func(s *Section) {
			s.Applicability[0], s.Applicability[2] = s.Applicability[2], s.Applicability[0]
		}),
		"statement distribution before an earlier one": section(func(s *Section) {
			s.Applicability = []Applicability{s.Applicability[2], s.Applicability[0], s.Applicability[1]}
		}),
		"duplicate statement apart": section(func(s *Section) {
			s.Applicability = []Applicability{s.Applicability[1], s.Applicability[2], s.Applicability[1]}
		}),
		"duplicate statement": section(func(s *Section) { s.Applicability[0] = s.Applicability[1] }),
		"reason too long":     section(func(s *Section) { s.Applicability[0].Reason = strings.Repeat("a", MaxText+1) }),
		"reason control":      section(func(s *Section) { s.Applicability[0].Reason = "a\nb" }),
		"reason surrounding":  section(func(s *Section) { s.Applicability[0].Reason = " a" }),
		"reason invalid utf8": section(func(s *Section) { s.Applicability[0].Reason = "a\xffb" }),
		"state":               evidence(func(e *Evidence) { e.State = "draft" }),
		"state case":          evidence(func(e *Evidence) { e.State = "Active" }),
		"basis":               evidence(func(e *Evidence) { e.Basis = "consensus" }),
		"managed openshift":   section(func(s *Section) { s.Records[2].ControlPlane = ControlPlaneManaged }),
		"hosted openshift":    section(func(s *Section) { s.Records[2].ControlPlane = "hosted" }),
		"mechanical derivedAt at validUntil": evidence(func(e *Evidence) {
			e.Basis, e.DerivedAt = constraintengine.BasisMechanical, e.ValidUntil
			e.Extractor = &constraintengine.Extractor{ID: "distribution.versions", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
		}),
		"mechanical no extractor": evidence(func(e *Evidence) { e.Basis = constraintengine.BasisMechanical; e.DerivedAt = e.ReviewedAt }),
		"reviewedAt not UTC":      evidence(func(e *Evidence) { e.ReviewedAt = "2026-10-01T00:00:00+00:00" }),
		"reviewedAt fraction":     evidence(func(e *Evidence) { e.ReviewedAt = "2026-10-01T00:00:00.5Z" }),
		"validUntil before":       evidence(func(e *Evidence) { e.ValidUntil = "2026-09-30T00:00:00Z" }),
		"validUntil equal":        evidence(func(e *Evidence) { e.ValidUntil = e.ReviewedAt }),
		"window over 90 days":     evidence(func(e *Evidence) { e.ValidUntil = "2026-12-30T00:00:01Z" }),
		"bad time":                evidence(func(e *Evidence) { e.ValidUntil = "tomorrow" }),
		"no sources":              evidence(func(e *Evidence) { e.Sources = nil }),
		"non-Git source":          evidence(func(e *Evidence) { e.Sources[0].URL = "https://docs.example.com/versions.html" }),
		"branch source":           evidence(func(e *Evidence) { e.Sources[0].URL = "https://github.com/example/docs/blob/main/versions.md" }),
		"source revision":         evidence(func(e *Evidence) { e.Sources[0].Revision = "main" }),
		"source URL other commit": evidence(func(e *Evidence) {
			e.Sources[0].URL = "https://github.com/example/docs/blob/" + strings.Repeat("1", 40) + "/versions.md"
		}),
		"source digest":       evidence(func(e *Evidence) { e.Sources[0].ContentDigest = "sha256:abc" }),
		"source span":         evidence(func(e *Evidence) { e.Sources[0].StartLine = 0 }),
		"statement non-Git":   statementEvidence(func(e *Evidence) { e.Sources[0].URL = "https://docs.example.com/versions.html" }),
		"statement window":    statementEvidence(func(e *Evidence) { e.ValidUntil = "2027-10-01T00:00:00Z" }),
		"statement bad state": statementEvidence(func(e *Evidence) { e.State = "" }),
	}
	// Model-derived or empirical evidence is never accepted, on a record or a
	// statement, even when it is well formed for a rule (derivedAt set, no
	// extractor): an applies statement can let a family be checked.
	for _, basis := range []string{constraintengine.BasisConsensus, constraintengine.BasisLead, constraintengine.BasisEmpirical} {
		set := func(e *Evidence) { e.Basis, e.DerivedAt = basis, "2026-10-01T00:00:00Z" }
		if err := constraintengine.ValidateBasis(basis, nil, "2026-10-01T00:00:00Z"); err != nil {
			t.Fatalf("fixture: %s evidence is not well formed for a rule: %v", basis, err)
		}
		cases["record basis "+basis] = evidence(set)
		cases["statement basis "+basis] = statementEvidence(set)
	}
	// The mechanical fixture is valid with derivedAt before validUntil, so
	// the row above fails for the bound alone.
	mechanical := testSection()
	mechanical.Records[0].Evidence.Basis, mechanical.Records[0].Evidence.DerivedAt = constraintengine.BasisMechanical, "2026-12-29T23:59:59Z"
	mechanical.Records[0].Evidence.Extractor = &constraintengine.Extractor{ID: "distribution.versions", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
	if _, err := Parse(marshalSection(t, mechanical)); err != nil {
		t.Fatalf("mechanical fixture refused: %v", err)
	}
	tooMany := testSection()
	for len(tooMany.Applicability) <= MaxApplicability {
		tooMany.Applicability = append(tooMany.Applicability, tooMany.Applicability[1])
	}
	cases["too many statements"] = marshalSection(t, tooMany)
	longMapping := testSection()
	longMapping.Records[2].KubernetesMapping = nil
	for i := 0; i <= MaxMapping; i++ {
		longMapping.Records[2].KubernetesMapping = append(longMapping.Records[2].KubernetesMapping, Mapping{"4." + strconv.Itoa(i), "1." + strconv.Itoa(i)})
	}
	cases["mapping too long"] = marshalSection(t, longMapping)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted or wrong error: %v\n%s", err, raw)
			}
		})
	}
}

func TestRecordCountBound(t *testing.T) {
	// Only nine distribution ids exist and two take no record, so the
	// record bound cannot be reached by a valid section; Validate still
	// enforces it.
	s := testSection()
	for len(s.Records) <= MaxRecords {
		s.Records = append(s.Records, s.Records[0])
	}
	if err := Validate(s); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "1-64 records") {
		t.Fatalf("record bound: %v", err)
	}
	// Likewise seven distributions times six families never reach the
	// statement bound.
	s = testSection()
	for len(s.Applicability) <= MaxApplicability {
		s.Applicability = append(s.Applicability, s.Applicability[0])
	}
	if err := Validate(s); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "at most 512") {
		t.Fatalf("statement bound: %v", err)
	}
	// A Go caller must state the applicability list (Marshal writes []).
	s = testSection()
	s.Applicability = nil
	if err := Validate(s); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil applicability: %v", err)
	}
	if raw, err := Marshal(s); err != nil || !bytes.Contains(raw, []byte(`"applicability":[]`)) {
		t.Fatalf("Marshal of nil applicability: %s %v", raw, err)
	}
}

// An index built, against its contract, from an unvalidated section never
// answers for an id outside the distribution vocabulary or for an
// upstream-equivalent id.
func TestUnvalidatedIndexStaysClosed(t *testing.T) {
	s := testSection()
	s.Records = append(s.Records, Record{Distribution: "minikube", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()}, Record{Distribution: "kubeadm", ControlPlane: ControlPlaneSelfManaged, Evidence: testEvidence()})
	s.Applicability = append(s.Applicability, Applicability{Distribution: "minikube", Family: FamilyNode, Status: StatusApplies, Evidence: testEvidence()}, Applicability{Distribution: "kubeadm", Family: FamilyNode, Status: StatusNotApplicable, Evidence: testEvidence()})
	ix := NewIndex(s)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got := ix.ApplicabilityFor("minikube", FamilyNode, now); got.Status != LookupAbsent || got.Applies() {
		t.Fatalf("unknown id answered: %+v", got)
	}
	if got := ix.ApplicabilityFor("kubeadm", FamilyNode, now); got.Status != LookupUpstream || !got.Applies() {
		t.Fatalf("upstream id answered from a record: %+v", got)
	}
}

func TestDistributionFreshness(t *testing.T) {
	s := testSection()
	s.Records[1].Evidence.State = StateWithdrawn
	ix := NewIndex(s)
	at := func(y int, m time.Month, d, h, min, sec int) time.Time {
		return time.Date(y, m, d, h, min, sec, 0, time.UTC)
	}
	for _, c := range []struct {
		name, distribution, family string
		now                        time.Time
		want                       string
	}{
		{"current", "eks", FamilyRemovedServedGVK, at(2026, 11, 1, 0, 0, 0), FreshnessCurrent},
		{"first instant", "eks", FamilyRemovedServedGVK, at(2026, 10, 1, 0, 0, 0), FreshnessCurrent},
		{"last instant", "eks", FamilyRemovedServedGVK, at(2026, 12, 29, 23, 59, 59), FreshnessCurrent},
		{"stale at validUntil", "eks", FamilyRemovedServedGVK, at(2026, 12, 30, 0, 0, 0), FreshnessStale},
		{"long stale", "eks", FamilyRemovedServedGVK, at(2028, 1, 1, 0, 0, 0), FreshnessStale},
		{"clock before review", "eks", FamilyRemovedServedGVK, at(2026, 9, 30, 23, 59, 59), FreshnessClockBeforeReview},
		{"record withdrawn", "k3s", FamilyRemovedServedGVK, at(2026, 11, 1, 0, 0, 0), FreshnessWithdrawn},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := ix.ApplicabilityFor(c.distribution, c.family, c.now)
			if got.Status != LookupApplies || got.Freshness != c.want {
				t.Fatalf("%+v, want applies/%s", got, c.want)
			}
			current := c.want == FreshnessCurrent
			if got.Applies() != current || got.StatementNotCurrent() == current {
				t.Fatalf("Applies %v StatementNotCurrent %v at %s", got.Applies(), got.StatementNotCurrent(), got.Freshness)
			}
		})
	}
	// A withdrawn or stale statement under a current record is never current.
	s = testSection()
	s.Applicability[1].Evidence.State = StateWithdrawn
	s.Applicability[2].Evidence.ReviewedAt, s.Applicability[2].Evidence.ValidUntil = "2026-08-01T00:00:00Z", "2026-10-15T00:00:00Z"
	ix = NewIndex(s)
	now := at(2026, 11, 1, 0, 0, 0)
	if got := ix.ApplicabilityFor("eks", FamilyRemovedServedGVK, now); got.Freshness != FreshnessWithdrawn || got.Applies() {
		t.Fatalf("withdrawn statement: %+v", got)
	}
	if got := ix.ApplicabilityFor("k3s", FamilyRemovedServedGVK, now); got.Freshness != FreshnessStale || got.Applies() {
		t.Fatalf("stale statement: %+v", got)
	}
	// A stale record makes its current statement unusable.
	s = testSection()
	s.Records[0].Evidence.ReviewedAt, s.Records[0].Evidence.ValidUntil = "2026-08-01T00:00:00Z", "2026-10-15T00:00:00Z"
	if got := NewIndex(s).ApplicabilityFor("eks", FamilyRemovedServedGVK, now); got.Freshness != FreshnessStale || got.Applies() {
		t.Fatalf("statement under a stale record: %+v", got)
	}
	// Unreadable or unknown evidence (an index built without validation) is
	// never current.
	for _, e := range []Evidence{
		{State: "Active", ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z"},
		{State: "", ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z"},
		{State: StateActive, ReviewedAt: "x", ValidUntil: "2026-12-30T00:00:00Z"},
		{State: StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "x"},
	} {
		if f := e.Freshness(now); f == FreshnessCurrent {
			t.Fatalf("evidence %+v is current", e)
		}
	}
	// The OpenShift mapping follows its record's freshness.
	s = testSection()
	ix = NewIndex(s)
	if m := ix.OpenShiftMinor("4.99", at(2026, 12, 30, 0, 0, 0)); !m.Found || m.Freshness != FreshnessStale {
		t.Fatalf("stale mapping: %+v", m)
	} else if _, ok := m.Minor(); ok {
		t.Fatal("stale mapping usable")
	}
	if table := ix.OpenShiftTable(at(2026, 12, 30, 0, 0, 0)); table != nil {
		t.Fatalf("stale mapping table %v", table)
	}
	if table := ix.OpenShiftTable(at(2026, 9, 1, 0, 0, 0)); table != nil {
		t.Fatalf("mapping table before review %v", table)
	}
}

func TestApplicabilityAbsenceIsGap(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for name, ix := range map[string]Index{"zero index": {}, "empty index": NewIndex(Section{}), "section": NewIndex(testSection())} {
		t.Run(name, func(t *testing.T) {
			for _, family := range Families() {
				// Upstream-equivalent distributions need no record.
				for _, upstream := range []string{"official_upstream", "kubeadm"} {
					got := ix.ApplicabilityFor(upstream, family, now)
					if got.Status != LookupUpstream || !got.Applies() || got.Freshness != "" {
						t.Fatalf("%s %s: %+v", upstream, family, got)
					}
				}
				// Every other id, and anything unknown, without a record or a
				// statement is absent.
				for _, id := range []string{"gke", "aks", "rke2", "talos", "minikube", "", "EKS", "upstream-compatible"} {
					got := ix.ApplicabilityFor(id, family, now)
					if got.Status != LookupAbsent || got.Applies() || got.StatementNotCurrent() {
						t.Fatalf("%q %s: %+v", id, family, got)
					}
				}
			}
			// An unknown family is absent, even for upstream.
			for _, id := range []string{"official_upstream", "kubeadm", "eks"} {
				if got := ix.ApplicabilityFor(id, "kubernetes.addons", now); got.Status != LookupAbsent || got.Applies() {
					t.Fatalf("unknown family for %s: %+v", id, got)
				}
			}
		})
	}
	ix := NewIndex(testSection())
	// A record without a statement for the family: absent.
	for _, family := range []string{FamilyFlowControlAPI, FamilyFeatureGates, FamilyComponentConfig, FamilyNode} {
		if got := ix.ApplicabilityFor("eks", family, now); got.Status != LookupAbsent || got.Applies() {
			t.Fatalf("eks %s: %+v", family, got)
		}
	}
	// openshift has a record and no statement at all.
	for _, family := range Families() {
		if got := ix.ApplicabilityFor("openshift", family, now); got.Status != LookupAbsent || got.Applies() {
			t.Fatalf("openshift %s: %+v", family, got)
		}
	}
	// not_applicable is a gap with a reason, never applies.
	got := ix.ApplicabilityFor("eks", FamilyComponentFlags, now)
	if got.Status != LookupNotApplicable || got.Freshness != FreshnessCurrent || got.Applies() || got.Reason == "" {
		t.Fatalf("not_applicable: %+v", got)
	}
	// A current applies statement is the only way a family applies.
	if got := ix.ApplicabilityFor("eks", FamilyRemovedServedGVK, now); !got.Applies() {
		t.Fatalf("current applies: %+v", got)
	}
	// A record alone, whatever its control plane, never makes a family
	// apply.
	recordsOnly := testSection()
	recordsOnly.Applicability = []Applicability{}
	ix = NewIndex(recordsOnly)
	for _, id := range []string{"eks", "k3s", "openshift"} {
		for _, family := range Families() {
			if got := ix.ApplicabilityFor(id, family, now); got.Applies() {
				t.Fatalf("record alone applies %s %s", id, family)
			}
		}
	}
	// Every k8sversion id other than the two upstream ones needs a record.
	for _, id := range []k8sversion.Distribution{k8sversion.EKS, k8sversion.GKE, k8sversion.AKS, k8sversion.K3s, k8sversion.RKE2, k8sversion.Talos, k8sversion.OpenShift} {
		if UpstreamEquivalent(string(id)) {
			t.Fatalf("%s is upstream-equivalent", id)
		}
	}
	// Applies is decided on the status, not on the presence of a reason or
	// any other field.
	for _, s := range []ApplicabilityStatus{
		{Family: FamilyNode, Status: LookupAbsent, Freshness: FreshnessCurrent},
		{Family: FamilyNode, Status: LookupNotApplicable, Freshness: FreshnessCurrent},
		{Family: FamilyNode, Status: "", Freshness: FreshnessCurrent},
		{Family: FamilyNode, Status: LookupApplies, Freshness: ""},
		{Family: "x", Status: LookupUpstream},
	} {
		if s.Applies() {
			t.Fatalf("%+v applies", s)
		}
	}
}

func TestOpenShiftMinorAndTable(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ix := NewIndex(testSection())
	m := ix.OpenShiftMinor("4.99", now)
	if k, ok := m.Minor(); !ok || k != "1.99" || m.Freshness != FreshnessCurrent {
		t.Fatalf("4.99: %+v", m)
	}
	for _, line := range []string{"4.97", "4.099", "4.99.3", "", "1.99"} {
		if m := ix.OpenShiftMinor(line, now); m.Found {
			t.Fatalf("%q found: %+v", line, m)
		}
	}
	table := ix.OpenShiftTable(now)
	if !reflect.DeepEqual(table, k8sversion.OpenShiftMap{98: 98, 99: 99}) {
		t.Fatalf("table %v", table)
	}
	v, err := k8sversion.ParseWith("4.99.3", "openshift", table)
	if err != nil || v.Upstream.String() != "1.99" || v.Upstream.PatchKnown || v.Confidence != k8sversion.ConfidenceMapped {
		t.Fatalf("ParseWith: %+v %v", v, err)
	}
	// No OpenShift record, or one without a mapping: no table.
	noOpenShift := testSection()
	noOpenShift.Records = noOpenShift.Records[:2]
	if table := NewIndex(noOpenShift).OpenShiftTable(now); table != nil {
		t.Fatalf("table without a record: %v", table)
	}
	noMapping := testSection()
	noMapping.Records[2].KubernetesMapping = nil
	if _, err := Parse(marshalSection(t, noMapping)); err != nil {
		t.Fatalf("openshift record without a mapping: %v", err)
	}
	if table := NewIndex(noMapping).OpenShiftTable(now); table != nil {
		t.Fatalf("table without a mapping: %v", table)
	}
	if m := NewIndex(noMapping).OpenShiftMinor("4.99", now); m.Found {
		t.Fatalf("mapping without entries: %+v", m)
	}
	// A nil table leaves Parse's behaviour.
	if _, err := k8sversion.ParseWith("4.99.3", "openshift", NewIndex(noMapping).OpenShiftTable(now)); !errors.Is(err, k8sversion.ErrUnknownOpenShift) {
		t.Fatalf("nil table: %v", err)
	}
}

func TestIndexCopies(t *testing.T) {
	s := testSection()
	ix := NewIndex(s)
	s.Records[2].KubernetesMapping[1].Kubernetes = "1.5"
	s.Records[0].Evidence.Sources[0].ID = "changed"
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if k, _ := ix.OpenShiftMinor("4.99", now).Minor(); k != "1.99" {
		t.Fatalf("index shares the caller's mapping: %s", k)
	}
	r, _, _ := ix.Record("eks", now)
	if r.Evidence.Sources[0].ID != "statement" {
		t.Fatal("index shares the caller's sources")
	}
	r.Evidence.Sources[0].ID = "again"
	if r2, _, _ := ix.Record("eks", now); r2.Evidence.Sources[0].ID != "statement" {
		t.Fatal("Record returns shared sources")
	}
	if _, _, found := ix.Record("gke", now); found {
		t.Fatal("record found for gke")
	}
	if ix.Len() != 3 {
		t.Fatalf("Len %d", ix.Len())
	}
}

func TestFamilies(t *testing.T) {
	want := []string{"kubernetes.component_config", "kubernetes.component_flags", "kubernetes.feature_gates", "kubernetes.flow_control_api", "kubernetes.node", "kubernetes.removed_served_gvk"}
	if !reflect.DeepEqual(Families(), want) {
		t.Fatalf("families %v", Families())
	}
}

func FuzzDistributions(f *testing.F) {
	f.Add(marshalSection(f, testSection()))
	f.Add([]byte(`{"records":[],"applicability":[]}`))
	f.Add(replace(f, `"controlPlane"`, `"ControlPlane"`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := Parse(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error not ErrInvalid: %v", err)
			}
			return
		}
		// Whatever parses validates, is canonical, and round-trips.
		if err := Validate(s); err != nil {
			t.Fatal(err)
		}
		out, err := Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(out)
		if err != nil || !reflect.DeepEqual(again, s) {
			t.Fatalf("round trip: %v", err)
		}
		now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		ix := NewIndex(s)
		for _, id := range []string{"gke", "aks", "eks", "k3s", "rke2", "talos", "openshift"} {
			for _, family := range Families() {
				got := ix.ApplicabilityFor(id, family, now)
				if got.Applies() && got.Status != LookupApplies {
					t.Fatalf("%s %s applies with status %s", id, family, got.Status)
				}
			}
		}
	})
}

// Lookups report the evidence basis of the statement and of its record, so
// a caller can apply a trust policy before relying on Applies.
func TestLookupBasis(t *testing.T) {
	s := testSection()
	extractor := &constraintengine.Extractor{ID: "distribution.versions", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
	s.Applicability[1].Evidence.Basis, s.Applicability[1].Evidence.DerivedAt, s.Applicability[1].Evidence.Extractor = constraintengine.BasisMechanical, "2026-10-01T00:00:00Z", extractor
	s.Records[2].Evidence.Basis, s.Records[2].Evidence.DerivedAt, s.Records[2].Evidence.Extractor = constraintengine.BasisMechanical, "2026-10-01T00:00:00Z", extractor
	if _, err := Parse(marshalSection(t, s)); err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(s)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got := ix.ApplicabilityFor("eks", FamilyRemovedServedGVK, now); got.Basis != constraintengine.BasisMechanical || got.RecordBasis != constraintengine.BasisReviewed {
		t.Fatalf("mechanical statement under a reviewed record: %+v", got)
	}
	if got := ix.ApplicabilityFor("eks", FamilyComponentFlags, now); got.Basis != constraintengine.BasisReviewed || got.RecordBasis != constraintengine.BasisReviewed {
		t.Fatalf("reviewed statement: %+v", got)
	}
	for _, got := range []ApplicabilityStatus{ix.ApplicabilityFor("gke", FamilyNode, now), ix.ApplicabilityFor("kubeadm", FamilyNode, now), ix.ApplicabilityFor("eks", FamilyNode, now)} {
		if got.Basis != "" || got.RecordBasis != "" {
			t.Fatalf("basis without a statement: %+v", got)
		}
	}
	if m := ix.OpenShiftMinor("4.99", now); m.Basis != constraintengine.BasisMechanical {
		t.Fatalf("mapping basis: %+v", m)
	}
	if m := NewIndex(testSection()).OpenShiftMinor("4.99", now); m.Basis != constraintengine.BasisReviewed {
		t.Fatalf("reviewed mapping basis: %+v", m)
	}
	if m := ix.OpenShiftMinor("4.97", now); m.Basis != "" {
		t.Fatalf("basis without a mapping: %+v", m)
	}
}
