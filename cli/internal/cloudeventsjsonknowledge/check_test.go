// SPDX-License-Identifier: AGPL-3.0-only

package cloudeventsjsonknowledge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cloudeventsstructuredjson"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

type externalFixture struct {
	store    string
	manifest knowledgefixture.Manifest
	second   string
	third    string
	receipt1 knowledge.ImportReceipt
}

func writeFixtureFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeExternalFixture(t *testing.T) externalFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.GenerateCloudEventsStructuredJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writeFixtureFile(t, dir, knowledgefixture.RootName, artifacts.Root)
	first := writeFixtureFile(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	second := writeFixtureFile(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	third := writeFixtureFile(t, dir, knowledgefixture.Revision3Name, artifacts.Revision3)
	receipt, err := knowledge.ImportCloudEventsStructuredJSON(knowledge.ImportRequest{
		PackagePath: first, StoreRoot: store, BootstrapRootPath: root,
		BootstrapRootDigest: digest(artifacts.Root), ExpectedRevision: "1",
		ExpectedBundleDigest: manifest.Revisions[0].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return externalFixture{store: store, manifest: manifest, second: second, third: third, receipt1: receipt}
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func passingObservation(t *testing.T) cloudeventsstructuredjson.Observation {
	t.Helper()
	o, err := cloudeventsstructuredjson.Observe([]byte(`{"specversion":"1.0","id":"private-id","source":"private-source","type":"example.type"}`))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func selection(f externalFixture, revision, bundle, receipt string) knowledge.SelectionRequest {
	return knowledge.SelectionRequest{StoreRoot: f.store, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt}
}

func TestEmbeddedReportReplayIntegrityAndExpiry(t *testing.T) {
	o := passingObservation(t)
	report, err := EvaluateEmbedded(o, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil || report.Status != "PASS" || ClaimExit(report) != 0 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	raw, err := MarshalReport(report)
	if err != nil || bytes.Contains(raw, []byte("private-")) {
		t.Fatalf("marshal err=%v raw=%s", err, raw)
	}
	replay, err := ReplayEmbedded(o, raw)
	if err != nil || replay.Status != "MATCH" || HistoricalClaimExit(replay) != 0 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	mutated := report
	mutated.Status = "UNKNOWN"
	if _, err := MarshalReport(mutated); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mutated report error=%v", err)
	}
	mutatedReplay := replay
	mutatedReplay.OriginalReport = json.RawMessage(`{}`)
	if _, err := MarshalHistoricalReplay(mutatedReplay); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mutated replay error=%v", err)
	}
	expired, err := EvaluateEmbedded(o, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || expired.Status != "UNKNOWN" || expired.Check.Claim.ReasonCode != "PROFILE_EVIDENCE_EXPIRED" || ClaimExit(expired) != 11 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
}

func TestSelectedKnowledgeEmptyNoFallbackAndHistoricalReplay(t *testing.T) {
	f := makeExternalFixture(t)
	o := passingObservation(t)
	emptyRequest := Request{Selection: selection(f, "1", f.manifest.Revisions[0].BundleDigest, f.receipt1.TrustReceiptDigest), Observation: o}
	empty, err := EvaluateCurrent(emptyRequest)
	if err != nil || empty.Status != "UNKNOWN" || empty.Check.Claim.ReasonCode != "PROFILE_NO_APPLICABLE_RULE" || ClaimExit(empty) != 11 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	if empty.Knowledge.Origin != "external_signed_local" || empty.Knowledge.Revision != "1" || empty.Knowledge.TrustReceiptDigest != f.receipt1.TrustReceiptDigest {
		t.Fatalf("empty binding=%+v", empty.Knowledge)
	}
	r2, err := knowledge.ImportCloudEventsStructuredJSON(knowledge.ImportRequest{PackagePath: f.second, StoreRoot: f.store, ExpectedRevision: "2", ExpectedBundleDigest: f.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	activeRequest := Request{Selection: selection(f, "2", f.manifest.Revisions[1].BundleDigest, r2.TrustReceiptDigest), Observation: o}
	active, err := EvaluateCurrent(activeRequest)
	if err != nil || active.Status != "PASS" || ClaimExit(active) != 0 {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	activeRaw, err := MarshalReport(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := knowledge.ImportCloudEventsStructuredJSON(knowledge.ImportRequest{PackagePath: f.third, StoreRoot: f.store, ExpectedRevision: "3", ExpectedBundleDigest: f.manifest.Revisions[2].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	replay, err := ReplayHistorical(activeRequest, activeRaw)
	if err != nil || replay.Status != "MATCH" || HistoricalClaimExit(replay) != 0 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	for name, bad := range map[string]Request{
		"revision": {Selection: selection(f, "", f.manifest.Revisions[1].BundleDigest, r2.TrustReceiptDigest), Observation: o},
		"bundle":   {Selection: selection(f, "2", "", r2.TrustReceiptDigest), Observation: o},
		"receipt":  {Selection: selection(f, "2", f.manifest.Revisions[1].BundleDigest, ""), Observation: o},
	} {
		if _, err := ReplayHistorical(bad, activeRaw); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("missing %s pin error=%v", name, err)
		}
	}
	wrongObservation := o
	no := false
	wrongObservation.TypeIsNonemptyValidString = &no
	if _, err := ReplayHistorical(Request{Selection: activeRequest.Selection, Observation: wrongObservation}, activeRaw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mismatched observation error=%v", err)
	}
}
