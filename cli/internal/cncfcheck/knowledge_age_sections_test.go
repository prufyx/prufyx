// SPDX-License-Identifier: AGPL-3.0-only

//go:build !prufyx_synthetic_knowledge

package cncfcheck

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
)

// packMetadataFields are the rule pack fields that carry no dated evidence.
// Adding a name here states that the field never expires.
var packMetadataFields = map[string]bool{
	"Schema": true, "Revision": true, "PolicyID": true, "PolicyDigest": true,
	"LandscapeFileDigest": true, "RegistryDigest": true,
}

// packEvidenceSamples puts, for every rule pack field that carries evidence,
// one active item ending at end into that field alone.
var packEvidenceSamples = map[string]func(t *testing.T, pack *rulePack, end string){
	"Entries": func(_ *testing.T, pack *rulePack, end string) {
		pack.Entries = []Entry{{Rule: json.RawMessage(`{"evidence":{"state":"active","validUntil":"` + end + `"}}`)}}
	},
	"LineAttestations": func(_ *testing.T, pack *rulePack, end string) {
		pack.LineAttestations = sampleSection(end)
	},
	"PathPolicies": func(_ *testing.T, pack *rulePack, end string) {
		pack.PathPolicies = sampleSection(end)
	},
	"ServedAPIs": func(_ *testing.T, pack *rulePack, end string) {
		pack.ServedAPIs = sampleSection(end)
	},
	"Distributions": func(t *testing.T, pack *rulePack, end string) {
		section := testDistributionSection()
		section.Records[0].Evidence.ValidUntil = end
		raw, err := distribution.Marshal(section)
		if err != nil {
			t.Fatal(err)
		}
		pack.Distributions = raw
	},
}

func sampleSection(end string) json.RawMessage {
	return json.RawMessage(`[{"evidence":{"state":"active","validUntil":"` + end + `"}}]`)
}

// unknownPackFields lists the fields of a pack type that are neither metadata
// nor evidence the age report is proven to read.
func unknownPackFields(pack reflect.Type) []string {
	var unknown []string
	for i := 0; i < pack.NumField(); i++ {
		name := pack.Field(i).Name
		if _, evidence := packEvidenceSamples[name]; !evidence && !packMetadataFields[name] {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// embeddedEvidenceAgeOf is EmbeddedEvidenceAge over pack in place of the
// embedded one. Its callers must not be parallel tests.
func embeddedEvidenceAgeOf(t *testing.T, pack rulePack) ([]time.Time, error) {
	t.Helper()
	embeddedMemo.mu.Lock()
	saved := embeddedMemo.load
	embeddedMemo.load = sync.OnceValues(func() (bundle, error) { return bundle{pack: pack}, nil })
	embeddedMemo.mu.Unlock()
	defer func() {
		embeddedMemo.mu.Lock()
		embeddedMemo.load = saved
		embeddedMemo.mu.Unlock()
	}()
	sources, err := EmbeddedEvidenceAge()
	if err != nil {
		return nil, err
	}
	if len(sources) != 1 {
		t.Fatalf("%d sources", len(sources))
	}
	return sources[0].Expiries, nil
}

// TestEvidenceAgeReadsEveryPackSection: a rule pack field the age report does
// not know fails here, and every evidence field is shown to reach the report
// that the release freshness gate reads. It is not parallel: it replaces the
// embedded bundle.
func TestEvidenceAgeReadsEveryPackSection(t *testing.T) {
	if unknown := unknownPackFields(reflect.TypeOf(rulePack{})); len(unknown) > 0 {
		t.Fatalf("rule pack fields %v are unknown to the evidence age report: read their end dates in EmbeddedEvidenceAge and add a sample", unknown)
	}
	end := time.Date(2026, 12, 3, 0, 0, 0, 0, time.UTC)
	for name, sample := range packEvidenceSamples {
		var pack rulePack
		sample(t, &pack, end.Format(time.RFC3339))
		got, err := embeddedEvidenceAgeOf(t, pack)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := false
		for _, at := range got {
			found = found || at.Equal(end)
		}
		if !found {
			t.Errorf("%s: end date %s is not in the age report %v", name, end.Format(time.RFC3339), got)
		}
	}
}

// TestUnknownPackFieldIsReported: the enumeration refuses a field nobody
// classified.
func TestUnknownPackFieldIsReported(t *testing.T) {
	t.Parallel()
	type grown struct {
		Schema     string
		Entries    []Entry
		NewSection json.RawMessage
	}
	got := unknownPackFields(reflect.TypeOf(grown{}))
	if !reflect.DeepEqual(got, []string{"NewSection"}) {
		t.Fatalf("%v", got)
	}
}

// TestEvidenceAgeDistributions: every active record and statement counts,
// withdrawn ones do not, and a section that cannot be read is an error. It is
// not parallel: it replaces the embedded bundle.
func TestEvidenceAgeDistributions(t *testing.T) {
	section := testDistributionSection()
	section.Records[0].Evidence.ValidUntil = "2026-12-01T00:00:00Z"
	section.Records[1].Evidence.ValidUntil = "2026-12-02T00:00:00Z"
	section.Applicability[0].Evidence.ValidUntil = "2026-12-03T00:00:00Z"
	section.Applicability[1].Evidence.ValidUntil = "2026-11-01T00:00:00Z"
	section.Applicability[1].Evidence.State = distribution.StateWithdrawn
	raw, err := distribution.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	got, err := embeddedEvidenceAgeOf(t, rulePack{Distributions: raw})
	if err != nil {
		t.Fatal(err)
	}
	var want []time.Time
	for day := 1; day <= 3; day++ {
		want = append(want, time.Date(2026, 12, day, 0, 0, 0, 0, time.UTC))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	valid := string(validDistributions(t))
	for name, bad := range map[string]string{
		"not json":       `not json`,
		"null":           `null`,
		"empty object":   `{}`,
		"array":          `[]`,
		"unreadable end": strings.Replace(valid, "2026-12-30T00:00:00Z", "soon", 1),
		"missing end":    strings.Replace(valid, `"validUntil":"2026-12-30T00:00:00Z",`, "", 1),
		"unknown state":  strings.Replace(valid, `"state":"active"`, `"state":"paused"`, 1),
		"unknown member": strings.Replace(valid, `{"records"`, `{"extra":[],"records"`, 1),
	} {
		if bad == valid {
			t.Fatalf("%s: the case changed nothing", name)
		}
		if _, err := embeddedEvidenceAgeOf(t, rulePack{Distributions: json.RawMessage(bad)}); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: err=%v, want ErrIntegrity", name, err)
		}
	}
}
