// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestInspectConstraintsProjectsTrustAndSourceFreshnessSeparately(t *testing.T) {
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := writeConstraintsStatusFile(t, dir, knowledgefixture.RootName, artifacts.Root)
	pkg := writeConstraintsStatusFile(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	store := filepath.Join(dir, "generic")
	if _, err := ImportConstraints(ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	status, err := InspectConstraints(store)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if status.State != "READY" || !status.CurrentEligible {
		t.Fatalf("status = %+v", status)
	}
	if status.Freshness != "fresh" || status.TrustFreshness != "fresh" {
		t.Fatalf("trust freshness = %+v", status)
	}
	if status.SourceEvidenceFreshness != "not_expired" || status.SourceEvidenceExpiresAt == "" {
		t.Fatalf("source freshness = %+v", status)
	}
}

func TestInspectConstraintsKeepsReadyEligibilityWhenSourceEvidenceMayBeExpired(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateConstraintsWithEvidenceExpiry(now, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := writeConstraintsStatusFile(t, dir, knowledgefixture.RootName, artifacts.Root)
	pkg := writeConstraintsStatusFile(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	store := filepath.Join(dir, "generic")
	imported, err := ImportConstraints(ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	status, err := InspectConstraints(store)
	if err != nil {
		t.Fatalf("inspect expired evidence: %v", err)
	}
	if status.State != "READY" || !status.CurrentEligible || status.Freshness != "fresh" || status.TrustFreshness != "fresh" || status.SourceEvidenceFreshness != "some_or_all_expired" {
		t.Fatalf("status overstates stale evidence: %+v", status)
	}
	if status.SourceEvidenceExpiresAt == "" {
		t.Fatalf("status omitted trusted earliest expiry: %+v", status)
	}
	receiptPath := filepath.Join(store, filepath.FromSlash(imported.AdmissionPath), "trust-receipt.json")
	if err := os.WriteFile(receiptPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := InspectConstraints(store)
	if err != nil {
		t.Fatalf("inspect tampered receipt: %v", err)
	}
	if tampered.State != "INTEGRITY_FAILURE" || tampered.SourceEvidenceFreshness != "not_assessed" || tampered.SourceEvidenceExpiresAt != "" {
		t.Fatalf("integrity failure exposed source expiry: %+v", tampered)
	}
}

func TestProjectSourceEvidenceFreshnessDoesNotOverstateEarliestExpiry(t *testing.T) {
	expires := "2026-09-12T17:00:00Z"
	before := time.Date(2026, 9, 12, 16, 59, 59, 0, time.UTC)
	at := time.Date(2026, 9, 12, 17, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		receipt   TrustReceipt
		now       time.Time
		freshness string
		expiresAt string
	}{
		{name: "no rules", receipt: TrustReceipt{}, now: before, freshness: "no_rules"},
		{name: "earliest future", receipt: TrustReceipt{EvidenceExpiresAt: expires}, now: before, freshness: "not_expired", expiresAt: expires},
		{name: "earliest expired may be some or all", receipt: TrustReceipt{EvidenceExpiresAt: expires}, now: at, freshness: "some_or_all_expired", expiresAt: expires},
		{name: "invalid receipt expiry", receipt: TrustReceipt{EvidenceExpiresAt: "not-a-time"}, now: before, freshness: "not_assessed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := Status{}
			projectSourceEvidenceFreshness(&status, test.receipt, test.now)
			if status.SourceEvidenceFreshness != test.freshness || status.SourceEvidenceExpiresAt != test.expiresAt {
				t.Fatalf("status = %+v, want freshness=%q expiry=%q", status, test.freshness, test.expiresAt)
			}
		})
	}
}
