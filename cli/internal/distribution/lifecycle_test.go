// SPDX-License-Identifier: AGPL-3.0-only

package distribution

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Synthetic data only: no value here is a statement about a real provider.

func bp(b bool) *bool { return &b }

func factSection() Section {
	s := testSection()
	s.Records[0].Lifecycle = []Lifecycle{
		{Line: "1.98", GA: "2026-01-10", StandardEnd: "2027-01-10", ExtendedEnd: "2028-01-10", ExtendedRequiresOptIn: bp(false), Precision: PrecisionDay},
		{Line: "1.99", GA: "2026-04", StandardEnd: "2027-04", MaintenanceStart: "2026-12", ForcedUpgrade: &ForcedUpgrade{Date: "2028-04", SentenceID: "s-12"}, Precision: PrecisionMonth},
		{Line: "1.100", Precision: PrecisionTBD},
	}
	s.Records[0].Deprecations = []Deprecation{{ID: "addon-x-removed", Summary: "Add-on X is removed.", FirstLine: "1.99"}}
	s.Records[1].Lifecycle = []Lifecycle{{Line: "1.99", GA: "2026-Q2", StandardEnd: "2027-Q2", Precision: PrecisionQuarter}}
	return s
}

func TestProviderFactsGoodRecordAccepted(t *testing.T) {
	s := factSection()
	gke := Record{Distribution: "gke", ControlPlane: ControlPlaneManaged, Evidence: testEvidence(),
		Lifecycle: []Lifecycle{{Line: "1.98", GA: "2026-01-10", StandardEnd: "2027-01-10", ExtendedEnd: "2028-01-10", ExtendedRequiresOptIn: bp(true), Precision: PrecisionDay}},
		Channels: []Channel{
			{Line: "1.98", Channel: "rapid", Available: "2026-01-20", AutoUpgrade: "2026-03-01", Precision: PrecisionDay},
			{Line: "1.98", Channel: "stable", Available: "2026-02-20", Precision: PrecisionDay},
			{Line: "1.99", Channel: "rapid", Precision: PrecisionTBD},
		}}
	s.Records = []Record{s.Records[0], gke, s.Records[1], s.Records[2]}
	s.Applicability = []Applicability{}
	raw, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(got)
	if err != nil || string(again) != string(raw) {
		t.Fatalf("not canonical: %v", err)
	}
	if got.Records[0].Lifecycle[0].ExtendedRequiresOptIn == nil || *got.Records[0].Lifecycle[0].ExtendedRequiresOptIn {
		t.Fatal("optIn false must survive a round trip")
	}
}

func TestProviderFactsRejected(t *testing.T) {
	ev := testEvidence()
	cases := map[string]func(*Section){
		"date without precision": func(s *Section) { s.Records[0].Lifecycle[0].Precision = "" },
		"unknown precision":      func(s *Section) { s.Records[0].Lifecycle[0].Precision = "week" },
		"date not of precision":  func(s *Section) { s.Records[0].Lifecycle[0].GA = "2026-01" },
		"impossible day":         func(s *Section) { s.Records[0].Lifecycle[0].GA = "2026-02-30" },
		"tbd with a date":        func(s *Section) { s.Records[0].Lifecycle[2].GA = "2026-01-01" },
		"precision with no date": func(s *Section) { s.Records[0].Lifecycle[2].Precision = PrecisionDay },
		"extendedEnd without optIn": func(s *Section) {
			s.Records[0].Lifecycle[0].ExtendedRequiresOptIn = nil
		},
		"optIn without extendedEnd": func(s *Section) {
			s.Records[0].Lifecycle[1].ExtendedRequiresOptIn = bp(true)
		},
		"mapping conflict: duplicate line": func(s *Section) {
			l := s.Records[0].Lifecycle
			s.Records[0].Lifecycle = []Lifecycle{l[0], l[0]}
		},
		"out of order lines": func(s *Section) {
			l := s.Records[0].Lifecycle
			s.Records[0].Lifecycle = []Lifecycle{l[1], l[0]}
		},
		"dates conflict": func(s *Section) { s.Records[0].Lifecycle[0].StandardEnd = "2025-01-10" },
		"wrong line grammar": func(s *Section) {
			s.Records[0].Lifecycle[0].Line = "v1.98"
		},
		"openshift line grammar": func(s *Section) {
			s.Records[2].Lifecycle = []Lifecycle{{Line: "1.99", GA: "2026-01-01", Precision: PrecisionDay}}
		},
		"forcedUpgrade no text": func(s *Section) { s.Records[0].Lifecycle[1].ForcedUpgrade.SentenceID = "" },
		"unknown channel token": func(s *Section) {
			s.Records[2].Channels = []Channel{{Line: "4.99", Channel: "rapid", Available: "2026-01-01", Precision: PrecisionDay}}
		},
		"channels on a distribution without channels": func(s *Section) {
			s.Records[0].Channels = []Channel{{Line: "1.98", Channel: "stable", Available: "2026-01-01", Precision: PrecisionDay}}
		},
		"unknown deprecation id":   func(s *Section) { s.Records[0].Deprecations[0].ID = "Bad Id" },
		"deprecation no line":      func(s *Section) { s.Records[0].Deprecations[0].FirstLine = "" },
		"deprecation empty text":   func(s *Section) { s.Records[0].Deprecations[0].Summary = " x" },
		"deprecation duplicate id": func(s *Section) { d := s.Records[0].Deprecations[0]; s.Records[0].Deprecations = []Deprecation{d, d} },
		"missing evidence": func(s *Section) {
			s.Records[0].Evidence = Evidence{State: StateActive, ReviewedAt: ev.ReviewedAt, ValidUntil: ev.ValidUntil}
		},
		"bad digest": func(s *Section) {
			s.Records[0].Evidence.Sources = append([]constraintengine.SourceEvidence(nil), ev.Sources...)
			s.Records[0].Evidence.Sources[0].ContentDigest = "sha256:zz"
		},
		"expired window beyond 90 days": func(s *Section) { s.Records[0].Evidence.ValidUntil = "2027-06-01T00:00:00Z" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := factSection()
			mutate(&s)
			err := Validate(s)
			if err == nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
			raw, merr := json.Marshal(s)
			if merr != nil {
				t.Fatal(merr)
			}
			if _, err := Parse(raw); err == nil {
				t.Fatal("Parse accepted")
			}
		})
	}
}

func TestProviderFactsUnknownProviderToken(t *testing.T) {
	s := factSection()
	s.Records[0].Distribution = "eks2"
	if err := Validate(s); err == nil {
		t.Fatal("unknown distribution accepted")
	}
	s = factSection()
	s.Records[0].Distribution = "kubeadm" // upstream tooling takes no record, so no provider facts
	if err := Validate(s); err == nil {
		t.Fatal("upstream-equivalent record with provider facts accepted")
	}
}

func TestProviderFactsShapeStrict(t *testing.T) {
	raw, err := json.Marshal(factSection())
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	bad := map[string]string{
		"unknown lifecycle member": strings.Replace(doc, `"line":"1.98"`, `"line":"1.98","extra":"x"`, 1),
		"null optIn":               strings.Replace(doc, `"extendedRequiresOptIn":false`, `"extendedRequiresOptIn":null`, 1),
		"string optIn":             strings.Replace(doc, `"extendedRequiresOptIn":false`, `"extendedRequiresOptIn":"no"`, 1),
		"empty optional date":      strings.Replace(doc, `"ga":"2026-01-10"`, `"ga":""`, 1),
		"unknown forced member":    strings.Replace(doc, `"sentenceId"`, `"sentence"`, 1),
		"case variant":             strings.Replace(doc, `"standardEnd"`, `"StandardEnd"`, 1),
	}
	bad["empty lifecycle array"] = strings.Replace(strings.Replace(doc, `"deprecations":[{"id":"addon-x-removed","summary":"Add-on X is removed.","firstLine":"1.99"}],`, `"deprecations":[],`, 1), `"evidence"`, `"evidence"`, 1)
	if _, err := Parse(raw); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, d := range bad {
		if d == doc {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := Parse([]byte(d)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestProviderFactsAreAdvisory(t *testing.T) {
	// Provider facts change no applicability or mapping answer: a record with
	// facts answers exactly as one without.
	plain, withFacts := testSection(), factSection()
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	a, b := NewIndex(plain), NewIndex(withFacts)
	for _, d := range []string{"eks", "k3s", "openshift"} {
		for _, f := range Families() {
			x, y := a.ApplicabilityFor(d, f, now), b.ApplicabilityFor(d, f, now)
			if x != y {
				t.Fatalf("%s %s: facts changed the answer: %+v vs %+v", d, f, x, y)
			}
		}
	}
	// Expired evidence stays stale; facts do not extend it.
	late := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	if got := withFacts.Records[0].Evidence.Freshness(late); got != FreshnessStale {
		t.Fatalf("freshness at %v = %s", late, got)
	}
	if r := b.ApplicabilityFor("eks", FamilyRemovedServedGVK, late); r.Applies() {
		t.Fatal("expired record applies")
	}
}

func TestProviderFactsIndexCopies(t *testing.T) {
	s := factSection()
	ix := NewIndex(s)
	s.Records[0].Lifecycle[0].Line = "9.9"
	*s.Records[0].Lifecycle[0].ExtendedRequiresOptIn = true
	s.Records[0].Lifecycle[1].ForcedUpgrade.Date = "1999"
	s.Records[0].Deprecations[0].ID = "mutated"
	rec, _, ok := ix.Record("eks", time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("no record")
	}
	if rec.Lifecycle[0].Line != "1.98" || *rec.Lifecycle[0].ExtendedRequiresOptIn || rec.Lifecycle[1].ForcedUpgrade.Date != "2028-04" || rec.Deprecations[0].ID != "addon-x-removed" {
		t.Fatal("index shares memory with the caller's section")
	}
}
