// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestCloudEventsStructuredJSONOwnFileFixAndPrivacy(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	eventPath := filepath.Join(dir, "private-event.json")
	writePrivate(t, eventPath, []byte(`{"specversion":"1.0","id":"PRIVATE-ID-CANARY","source":"PRIVATE-SOURCE-CANARY","data":{"PRIVATE-DATA-CANARY":true}}`))
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	args := []string{"check", "cloudevents-structured-json", "--event", eventPath, "--now", now, "--format", "json"}
	code, out, errout := runCommunity(t, args...)
	if code != ExitBlocked || !strings.Contains(out, "TYPE_REQUIRED_VALID_STRING") || errout != "" {
		t.Fatalf("before code=%d out=%q err=%q", code, out, errout)
	}
	for _, secret := range []string{"PRIVATE-ID-CANARY", "PRIVATE-SOURCE-CANARY", "PRIVATE-DATA-CANARY", eventPath} {
		if strings.Contains(out, secret) {
			t.Fatalf("output leaked %q", secret)
		}
	}
	writePrivate(t, eventPath, []byte(`{"specversion":"1.0","id":"PRIVATE-ID-CANARY","source":"PRIVATE-SOURCE-CANARY","type":"example.fixed","data":{"PRIVATE-DATA-CANARY":true}}`))
	code, out, errout = runCommunity(t, args...)
	if code != ExitOK || !strings.Contains(out, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS") || errout != "" {
		t.Fatalf("after code=%d out=%q err=%q", code, out, errout)
	}
}

func TestCloudEventsStructuredJSONExternalNoFallbackAdvanceReplay(t *testing.T) {
	t.Parallel()
	artifacts, err := knowledgefixture.GenerateCloudEventsStructuredJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	root := writePublic(t, dir, knowledgefixture.RootName, artifacts.Root)
	rev1 := writePublic(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	rev2 := writePublic(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	rev3 := writePublic(t, dir, knowledgefixture.Revision3Name, artifacts.Revision3)
	db := filepath.Join(dir, "store")
	rootDigest := cloudEventsTestDigest(artifacts.Root)
	importRevision := func(path string, bootstrap bool) knowledge.ImportReceipt {
		args := []string{"db", "import", path, "--db-root", db, "--profile", "cloudevents-structured-json", "--format", "json"}
		if bootstrap {
			args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", rootDigest)
		}
		code, out, errout := runCommunity(t, args...)
		if code != ExitOK || errout != "" {
			t.Fatalf("import code=%d out=%q err=%q", code, out, errout)
		}
		var receipt knowledge.ImportReceipt
		if err := json.Unmarshal([]byte(out), &receipt); err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	_ = importRevision(rev1, true)
	eventPath := filepath.Join(dir, "private-event.json")
	first := []byte(`{"specversion":"1.0","id":"PRIVATE-ID-A","source":"PRIVATE-SOURCE-A"}`)
	writePrivate(t, eventPath, first)
	code, out, errout := runCommunity(t, "check", "cloudevents-structured-json", "--event", eventPath, "--knowledge-db", db, "--format", "json")
	if code != ExitUnknown || !strings.Contains(out, "PROFILE_NO_APPLICABLE_RULE") || strings.Contains(out, "TYPE_REQUIRED_VALID_STRING") || errout != "" {
		t.Fatalf("no fallback code=%d out=%q err=%q", code, out, errout)
	}
	r2 := importRevision(rev2, false)
	code, out, errout = runCommunity(t, "check", "cloudevents-structured-json", "--event", eventPath, "--knowledge-db", db, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest, "--format", "json")
	if code != ExitBlocked || !strings.Contains(out, "TYPE_REQUIRED_VALID_STRING") || strings.Contains(out, "PRIVATE-") || strings.Contains(out, cloudEventsTestDigest(first)) || errout != "" {
		t.Fatalf("active code=%d out=%q err=%q", code, out, errout)
	}
	assertTreeExcludes(t, db, []string{"PRIVATE-ID-A", "PRIVATE-SOURCE-A", cloudEventsTestDigest(first), eventPath})
	reportPath := filepath.Join(dir, "saved-report.json")
	writePrivate(t, reportPath, []byte(out))
	_ = importRevision(rev3, false)
	second := []byte(`{"source":"PRIVATE-SOURCE-B","id":"PRIVATE-ID-B","specversion":"1.0","opaque":"PRIVATE-OPAQUE"}`)
	writePrivate(t, eventPath, second)
	code, out, errout = runCommunity(t, "check", "cloudevents-structured-json", "--event", eventPath, "--event-digest", cloudEventsTestDigest(second), "--knowledge-db", db, "--replay-report", reportPath, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest, "--format", "json")
	if code != ExitBlocked || !strings.Contains(out, `"status":"MATCH"`) || strings.Contains(out, "PRIVATE-") || errout != "" {
		t.Fatalf("replay code=%d out=%q err=%q", code, out, errout)
	}
	code, _, _ = runCommunity(t, "check", "cloudevents-structured-json", "--event", eventPath, "--event-digest", cloudEventsTestDigest(first), "--knowledge-db", db, "--replay-report", reportPath, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest)
	if code != ExitIntegrity {
		t.Fatalf("wrong raw pin code=%d", code)
	}
}

func TestCloudEventsStructuredJSONModeAndInputBoundaries(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	eventPath := filepath.Join(dir, "event.json")
	writePrivate(t, eventPath, []byte(`{"specversion":"1.0","id":"a","source":"x","type":"t"}`))
	reportPath := filepath.Join(dir, "report.json")
	writePrivate(t, reportPath, []byte("{}\n"))
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	digest := cloudEventsTestDigest(mustRead(t, eventPath))
	cases := [][]string{
		{"check", "cloudevents-structured-json", "--event", eventPath},
		{"check", "cloudevents-structured-json", "--event", eventPath, "--now", now, "--knowledge-db", filepath.Join(dir, "store")},
		{"check", "cloudevents-structured-json", "--event", eventPath, "--replay-report", reportPath},
		{"check", "cloudevents-structured-json", "--event", eventPath, "--event-digest", digest, "--knowledge-db", filepath.Join(dir, "store"), "--replay-report", reportPath, "--knowledge-revision", "1", "--knowledge-bundle-digest", digest},
	}
	for _, args := range cases {
		if code, _, _ := runCommunity(t, args...); code != ExitUsage {
			t.Fatalf("args=%q code=%d", args, code)
		}
	}
	writePrivate(t, eventPath, []byte("{"))
	if code, _, _ := runCommunity(t, "check", "cloudevents-structured-json", "--event", eventPath, "--now", now); code != ExitUsage {
		t.Fatalf("malformed code=%d", code)
	}
}

func cloudEventsTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestCloudEventsInputRemainsUnchanged(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	p := filepath.Join(dir, "event.json")
	raw := []byte(`{"specversion":"1.0","id":"a","source":"x","type":"t"}`)
	writePrivate(t, p, raw)
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if code, _, _ := runCommunity(t, "check", "cloudevents-structured-json", "--event", p, "--now", now); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("input changed: %v", err)
	}
}
