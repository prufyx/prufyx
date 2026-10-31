// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"strings"
	"testing"
)

const claimsCNCF = `{"entries":[
 {"rule":{"evidence":{"state":"active","validUntil":"2026-12-07T12:00:00Z"}}},
 {"rule":{"evidence":{"state":"active","basis":"mechanical","validUntil":"2027-01-26T06:10:52Z"}}},
 {"rule":{"evidence":{"state":"withdrawn","validUntil":"2030-01-01T00:00:00Z"}}}],
 "lineAttestations":[{"evidence":{"basis":"mechanical"}}],
 "servedAPIs":[{"evidence":{"basis":"mechanical"}}]}`
const claimsComm = `{"entries":[{"rule":{"evidence":{"state":"active","basis":"reviewed","validUntil":"2026-12-22T00:00:00Z"}}}]}`

func TestRenderBasisSentence(t *testing.T) {
	t.Parallel()
	got, err := RenderBasisSentence([]byte(claimsCNCF), []byte(claimsComm))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Of the 3 active rules shipped today, 2 with basis `reviewed`, 1 with basis `mechanical`.",
		"The 2 release-line attestations and served-API lists are separate records: 2 with basis `mechanical`.",
		"no person reviewed it rule by rule",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "every rule") || strings.Contains(got, "Every rule") {
		t.Errorf("claims every rule is reviewed: %q", got)
	}
	if _, err := RenderBasisSentence([]byte(`{"entries":[{"rule":{"evidence":{"state":"active","basis":"vibes"}}}]}`)); err == nil {
		t.Error("a basis outside the vocabulary was accepted")
	}
	if _, err := RenderBasisSentence([]byte(`{`)); err == nil {
		t.Error("broken JSON was accepted")
	}
}

func TestRenderValiditySentence(t *testing.T) {
	t.Parallel()
	got, err := RenderValiditySentence([]byte(claimsCNCF), []byte(claimsComm))
	if err != nil {
		t.Fatal(err)
	}
	want := "The 3 active rules shipped today stop being valid, rule by rule, between 2026-12-07 and 2027-01-26 unless"
	if bulk := "1 of the 3 stop being valid on or before 2026-12-12, in the 6 days starting on the earliest."; !strings.Contains(got, bulk) {
		t.Errorf("got %q want %q", got, bulk)
	}
	// Rules that expire within the first 6 days are counted; later ones are not.
	two := `{"entries":[{"rule":{"evidence":{"state":"active","validUntil":"2026-12-07T00:00:00Z"}}},{"rule":{"evidence":{"state":"active","validUntil":"2026-12-12T23:00:00Z"}}},{"rule":{"evidence":{"state":"active","validUntil":"2026-12-13T00:00:00Z"}}}]}`
	if got, err := RenderValiditySentence([]byte(two)); err != nil || !strings.Contains(got, "2 of the 3 stop being valid on or before 2026-12-12") {
		t.Errorf("got %q, %v", got, err)
	}
	if !strings.Contains(got, want) {
		t.Errorf("got %q want prefix %q", got, want)
	}
	for name, d := range map[string]string{
		"no active rule": `{"entries":[{"rule":{"evidence":{"state":"withdrawn"}}}]}`,
		"no validUntil":  `{"entries":[{"rule":{"evidence":{"state":"active"}}}]}`,
		"bad validUntil": `{"entries":[{"rule":{"evidence":{"state":"active","validUntil":"soon"}}}]}`,
	} {
		if _, err := RenderValiditySentence([]byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
