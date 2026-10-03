// SPDX-License-Identifier: AGPL-3.0-only

package upgradepath

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const testRevision = "1111111111111111111111111111111111111111"

func testRecord(component, policyName string) Record {
	return Record{Component: component, Policy: policyName, Evidence: Evidence{
		State: StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "upgrade-guide", URL: "https://github.com/example/docs/blob/" + testRevision + "/upgrade.md", Revision: testRevision, ContentDigest: "sha256:" + strings.Repeat("a", 64), StartLine: 3, EndLine: 9}},
	}}
}

func testDocument(t *testing.T) []byte {
	t.Helper()
	raw, err := Marshal([]Record{testRecord(k8s, PolicySequentialMinor), testRecord("pkg:github/cilium/cilium", PolicyDirect)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseValidDocument(t *testing.T) {
	raw := testDocument(t)
	records, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Component != "pkg:github/cilium/cilium" || records[1].Policy != PolicySequentialMinor {
		t.Fatalf("records %+v", records)
	}
	again, err := Marshal(records)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("canonical form not stable: %v", err)
	}
	mechanical := testRecord(k8s, PolicySequentialMajor)
	mechanical.Evidence.Basis = constraintengine.BasisMechanical
	mechanical.Evidence.Extractor = &constraintengine.Extractor{ID: "k8s.upgrade-order", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
	mechanical.Evidence.DerivedAt = "2026-10-01T00:00:00Z"
	withdrawn := testRecord("pkg:github/cilium/cilium", PolicyDirect)
	withdrawn.Evidence.State = StateWithdrawn
	withdrawn.Evidence.Basis = constraintengine.BasisReviewed
	if _, err := Marshal([]Record{mechanical, withdrawn}); err != nil {
		t.Fatalf("mechanical and withdrawn records refused: %v", err)
	}
}

// Each mutation of a valid document is refused as a whole.
func TestParseStrictness(t *testing.T) {
	valid := string(testDocument(t))
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	replace := func(old, new string) string {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(valid, old, new, 1)
	}
	record := func(mutate func(*Record)) string {
		r := testRecord(k8s, PolicySequentialMinor)
		mutate(&r)
		raw, _ := json.Marshal([]Record{r})
		return string(raw)
	}
	cases := map[string]string{
		"empty document":          "[]",
		"null document":           "null",
		"object document":         "{}",
		"trailing data":           valid + "[]",
		"unknown record member":   replace(`"policy":"direct"`, `"policy":"direct","note":"x"`),
		"unknown evidence member": replace(`"state":"active"`, `"state":"active","comment":"x"`),
		"unknown source member":   replace(`"startLine":3`, `"startLine":3,"span":"x"`),
		"case variant member":     replace(`"policy":"direct"`, `"Policy":"direct"`),
		"folded member":           replace(`"policy":"direct"`, `"polıcy":"direct"`),
		"repeated member":         replace(`"policy":"direct"`, `"policy":"sequential_minor","policy":"direct"`),
		"missing policy":          replace(`"policy":"direct",`, ``),
		"missing evidence state":  replace(`"state":"active",`, ``),
		"null policy":             replace(`"policy":"direct"`, `"policy":null`),
		"null basis":              replace(`"state":"active"`, `"state":"active","basis":null`),
		"null sources":            record(func(r *Record) { r.Evidence.Sources = nil }),
		"unknown policy":          replace(`"policy":"direct"`, `"policy":"skip_minor"`),
		"empty policy":            replace(`"policy":"direct"`, `"policy":""`),
		"policy case":             replace(`"policy":"direct"`, `"policy":"DIRECT"`),
		"bad component":           record(func(r *Record) { r.Component = "kubernetes" }),
		"unknown state":           record(func(r *Record) { r.Evidence.State = "retired" }),
		"unknown basis":           record(func(r *Record) { r.Evidence.Basis = "guessed" }),
		"reviewed with extractor": record(func(r *Record) { r.Evidence.DerivedAt = "2026-10-01T00:00:00Z" }),
		"mechanical no extractor": record(func(r *Record) { r.Evidence.Basis = constraintengine.BasisMechanical }),
		"non-UTC review":          record(func(r *Record) { r.Evidence.ReviewedAt = "2026-10-01T02:00:00+02:00" }),
		"window inverted":         record(func(r *Record) { r.Evidence.ValidUntil = r.Evidence.ReviewedAt }),
		"window over 90 days":     record(func(r *Record) { r.Evidence.ValidUntil = "2026-12-30T00:00:01Z" }),
		"no sources":              record(func(r *Record) { r.Evidence.Sources = []constraintengine.SourceEvidence{} }),
		"source branch revision":  record(func(r *Record) { r.Evidence.Sources[0].Revision = "main" }),
		"source url not pinned":   record(func(r *Record) { r.Evidence.Sources[0].URL = "https://github.com/example/docs/blob/main/upgrade.md" }),
		"source url other commit": record(func(r *Record) {
			r.Evidence.Sources[0].URL = strings.Replace(r.Evidence.Sources[0].URL, testRevision, strings.Repeat("2", 40), 1)
		}),
		"source digest":             record(func(r *Record) { r.Evidence.Sources[0].ContentDigest = "sha256:abc" }),
		"source span":               record(func(r *Record) { r.Evidence.Sources[0].EndLine = 1 }),
		"source id":                 record(func(r *Record) { r.Evidence.Sources[0].ID = "Upgrade Guide" }),
		"string line number":        replace(`"startLine":3`, `"startLine":"3"`),
		"duplicate component":       mustRaw(t, testRecord(k8s, PolicyDirect), testRecord(k8s, PolicySequentialMinor)),
		"unsorted components":       mustRaw(t, testRecord(k8s, PolicyDirect), testRecord("pkg:github/cilium/cilium", PolicyDirect)),
		"derivedAt after window":    record(mechanicalDerivedAt("2027-01-01T00:00:00Z")),
		"too many records":          manyRecords(t, MaxRecords+1),
		"record is not an object":   `["pkg:github/kubernetes/kubernetes"]`,
		"evidence is not an object": replace(`"evidence":{`, `"evidence":[{`) + "",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted (%v): %s", err, raw)
			}
		})
	}
	if _, err := Parse([]byte(manyRecords(t, MaxRecords))); err != nil {
		t.Fatalf("a document of %d records refused: %v", MaxRecords, err)
	}
}

func mechanicalDerivedAt(derivedAt string) func(*Record) {
	return func(r *Record) {
		r.Evidence.Basis = constraintengine.BasisMechanical
		r.Evidence.Extractor = &constraintengine.Extractor{ID: "k8s.upgrade-order", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
		r.Evidence.DerivedAt = derivedAt
	}
}

// mustRaw encodes records in the given order, without sorting.
func mustRaw(t *testing.T, records ...Record) string {
	t.Helper()
	raw, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func manyRecords(t *testing.T, n int) string {
	t.Helper()
	records := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, testRecord("pkg:github/example/p"+strings.Repeat("0", 4-len(itoa(i)))+itoa(i), PolicyDirect))
	}
	return mustRaw(t, records...)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestPathPolicyFreshness(t *testing.T) {
	r := testRecord(k8s, PolicySequentialMinor)
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	withdrawn := r
	withdrawn.Evidence.State = StateWithdrawn
	cases := []struct {
		name   string
		record Record
		now    time.Time
		want   string
	}{
		{"before review", r, at("2026-09-30T23:59:59Z"), FreshnessClockBeforeReview},
		{"at review", r, at("2026-10-01T00:00:00Z"), FreshnessCurrent},
		{"inside window", r, at("2026-11-15T00:00:00Z"), FreshnessCurrent},
		{"last second", r, at("2026-12-29T23:59:59Z"), FreshnessCurrent},
		{"at validUntil", r, at("2026-12-30T00:00:00Z"), FreshnessStale},
		{"after validUntil", r, at("2027-03-01T00:00:00Z"), FreshnessStale},
		{"withdrawn inside window", withdrawn, at("2026-11-15T00:00:00Z"), FreshnessWithdrawn},
		{"withdrawn before review", withdrawn, at("2026-09-01T00:00:00Z"), FreshnessWithdrawn},
	}
	ix := NewIndex([]Record{r})
	wix := NewIndex([]Record{withdrawn})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.record.Freshness(c.now); got != c.want {
				t.Fatalf("freshness %s, want %s", got, c.want)
			}
			index := ix
			if c.record.Evidence.State == StateWithdrawn {
				index = wix
			}
			status := index.Lookup(k8s, c.now)
			if !status.Found || status.Freshness != c.want {
				t.Fatalf("lookup %+v", status)
			}
			p := status.Policy()
			if (p != nil) != (c.want == FreshnessCurrent) {
				t.Fatalf("policy %v usable at freshness %s", p, c.want)
			}
			if p != nil && (*p != PathPolicy{Component: k8s, Policy: PolicySequentialMinor}) {
				t.Fatalf("policy %+v", p)
			}
		})
	}
	unreadable := r
	unreadable.Evidence.ValidUntil = "soon"
	if unreadable.Freshness(at("2026-11-15T00:00:00Z")) != FreshnessStale {
		t.Fatal("a record with unreadable times is not stale")
	}
	missing := ix.Lookup("pkg:github/cilium/cilium", at("2026-11-15T00:00:00Z"))
	if missing.Found || missing.Policy() != nil {
		t.Fatalf("absent component: %+v", missing)
	}
	// A status that claims current freshness without a record is unusable.
	if (Status{Freshness: FreshnessCurrent}).Policy() != nil {
		t.Fatal("a status without a record yields a policy")
	}
	// The index hands out copies.
	got := ix.Lookup(k8s, at("2026-11-15T00:00:00Z"))
	got.Record.Evidence.Sources[0].ID = "changed"
	if ix.Lookup(k8s, at("2026-11-15T00:00:00Z")).Record.Evidence.Sources[0].ID != "upgrade-guide" {
		t.Fatal("the index shares its records")
	}
}

func FuzzPathPolicies(f *testing.F) {
	valid, _ := Marshal([]Record{testRecord(k8s, PolicySequentialMinor)})
	f.Add(valid)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"component":"pkg:x/y","policy":"direct","evidence":{}}]`))
	f.Add(bytes.Replace(valid, []byte(`"policy"`), []byte(`"Policy"`), 1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		records, err := Parse(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error outside ErrInvalid: %v", err)
			}
			return
		}
		// Whatever is admitted is a valid canonical document that
		// round-trips.
		if err := Validate(records); err != nil {
			t.Fatalf("admitted an invalid document: %v", err)
		}
		again, err := Marshal(records)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(again)
		if err != nil || len(back) != len(records) {
			t.Fatalf("canonical form does not parse: %v", err)
		}
		for _, r := range records {
			if !ValidPolicy(r.Policy) || len(r.Component) > 260 {
				t.Fatalf("admitted record %+v", r)
			}
		}
	})
}
