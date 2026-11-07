// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestComputeDigestsCarriesEvidenceExpiry(t *testing.T) {
	first, fr := firstPackage(t)
	next := ciNext(t, first, fr)
	d, err := ComputeDigests(next)
	if err != nil {
		t.Fatal(err)
	}
	if d.EvidenceExpiresAt == "" || d.EvidenceExpiresAt != fr.Receipt.Verification.EvidenceExpiresAt {
		t.Fatalf("evidenceExpiresAt %q, signed receipt carries %q", d.EvidenceExpiresAt, fr.Receipt.Verification.EvidenceExpiresAt)
	}
	if _, err := parseUTC(d.EvidenceExpiresAt); err != nil {
		t.Fatalf("not canonical UTC: %q", d.EvidenceExpiresAt)
	}
	again, err := ComputeDigests(next)
	if err != nil || again != d {
		t.Fatalf("not deterministic: %+v vs %+v (%v)", again, d, err)
	}
	raw, _ := json.Marshal(d)
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || m["evidenceExpiresAt"] != d.EvidenceExpiresAt {
		t.Fatalf("json lacks evidenceExpiresAt: %s", raw)
	}
}

func TestReleaseResultCarriesEvidenceExpiry(t *testing.T) {
	first, fr := firstPackage(t)
	next := ciNext(t, first, fr)
	d, err := ComputeDigests(next)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(next)
	if err != nil {
		t.Fatal(err)
	}
	if r.EvidenceExpiresAt != d.EvidenceExpiresAt || r.EvidenceExpiresAt != r.Receipt.Verification.EvidenceExpiresAt {
		t.Fatalf("result %q digests %q receipt %q", r.EvidenceExpiresAt, d.EvidenceExpiresAt, r.Receipt.Verification.EvidenceExpiresAt)
	}
}

func TestEvidenceExpiryRefusesAbsentOrNonCanonical(t *testing.T) {
	for _, v := range []string{"", "2026-12-01", "2026-12-01T00:00:00+02:00", "2026-12-01T00:00:00.5Z", "garbage"} {
		got, err := evidenceExpiry(v)
		if !errors.Is(err, ErrEvidenceExpiryUnknown) || got != "" {
			t.Errorf("%q: got %q, %v; want typed refusal and no value", v, got, err)
		}
	}
	if got, err := evidenceExpiry("2026-12-01T00:00:00Z"); err != nil || got != "2026-12-01T00:00:00Z" {
		t.Fatalf("canonical value rejected: %q %v", got, err)
	}
}
