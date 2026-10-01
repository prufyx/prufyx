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

const tikvArgsTarget = "8.5.8"
const tikvArgsOperation = "gcs-full-backup-wif"

func TestTiKVGCPV2WIFBackupOwnFileFixAndPrivacy(t *testing.T) {
	dir := privateDir(t)
	configPath := filepath.Join(dir, "private-tikv.toml")
	before := []byte("[backup]\ngcp-v2-enable = false\n[server]\naddr = 'PRIVATE-CANARY'\n")
	writePrivate(t, configPath, before)
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	args := []string{"check", "tikv-gcp-v2-wif-backup", "--config", configPath, "--target-version", tikvArgsTarget, "--operation", tikvArgsOperation, "--now", now, "--format", "json"}
	code, out, errout := runCommunity(t, args...)
	if code != ExitBlocked || !strings.Contains(out, "TIKV_GCP_V2_WIF_FULL_BACKUP_SETTING_DISABLED") || errout != "" {
		t.Fatalf("before code=%d out=%q err=%q", code, out, errout)
	}
	for _, secret := range []string{"PRIVATE-CANARY", configPath, tikvTestDigest(before)} {
		if strings.Contains(out, secret) {
			t.Fatalf("output leaked %q", secret)
		}
	}
	after := []byte("[backup]\ngcp-v2-enable = true\n[server]\naddr = 'PRIVATE-CANARY'\n")
	writePrivate(t, configPath, after)
	code, out, errout = runCommunity(t, args...)
	if code != ExitOK || !strings.Contains(out, "TIKV_GCP_V2_WIF_FULL_BACKUP_SETTING_ENABLED") || errout != "" {
		t.Fatalf("after code=%d out=%q err=%q", code, out, errout)
	}
	got, err := os.ReadFile(configPath)
	if err != nil || string(got) != string(after) {
		t.Fatalf("input changed: %v", err)
	}
}

func TestTiKVGCPV2WIFBackupExternalNoFallbackAdvanceReplay(t *testing.T) {
	artifacts, err := knowledgefixture.GenerateTiKVGCPV2WIFBackup(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	root := writePublic(t, dir, knowledgefixture.RootName, artifacts.Root)
	rev1 := writePublic(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	rev2 := writePublic(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	rev3 := writePublic(t, dir, knowledgefixture.Revision3Name, artifacts.Revision3)
	db := filepath.Join(dir, "store")
	rootDigest := tikvTestDigest(artifacts.Root)
	importRevision := func(path string, bootstrap bool) knowledge.ImportReceipt {
		args := []string{"db", "import", path, "--db-root", db, "--profile", "tikv-gcp-v2-wif-backup", "--format", "json"}
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
	configPath := filepath.Join(dir, "private-tikv.toml")
	raw := []byte("[backup]\ngcp_v2_enable = false\n[server]\naddr = 'PRIVATE-CANARY'\n")
	writePrivate(t, configPath, raw)
	base := []string{"check", "tikv-gcp-v2-wif-backup", "--config", configPath, "--target-version", tikvArgsTarget, "--operation", tikvArgsOperation, "--knowledge-db", db, "--format", "json"}
	code, out, errout := runCommunity(t, base...)
	if code != ExitUnknown || !strings.Contains(out, "PROFILE_NO_APPLICABLE_RULE") || strings.Contains(out, "SETTING_DISABLED") || errout != "" {
		t.Fatalf("no fallback code=%d out=%q err=%q", code, out, errout)
	}
	r2 := importRevision(rev2, false)
	pins := []string{"--knowledge-revision", "2", "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest}
	code, out, errout = runCommunity(t, append(base, pins...)...)
	if code != ExitBlocked || !strings.Contains(out, "SETTING_DISABLED") || strings.Contains(out, "PRIVATE-CANARY") || strings.Contains(out, tikvTestDigest(raw)) || errout != "" {
		t.Fatalf("active code=%d out=%q err=%q", code, out, errout)
	}
	assertTreeExcludes(t, db, []string{"PRIVATE-CANARY", tikvTestDigest(raw), configPath})
	reportPath := filepath.Join(dir, "saved-report.json")
	writePrivate(t, reportPath, []byte(out))
	_ = importRevision(rev3, false)
	replayArgs := []string{"check", "tikv-gcp-v2-wif-backup", "--config", configPath, "--target-version", tikvArgsTarget, "--operation", tikvArgsOperation, "--config-digest", tikvTestDigest(raw), "--knowledge-db", db, "--replay-report", reportPath, "--knowledge-revision", "2", "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest, "--format", "json"}
	code, out, errout = runCommunity(t, replayArgs...)
	if code != ExitBlocked || !strings.Contains(out, `"status":"MATCH"`) || strings.Contains(out, "PRIVATE-CANARY") || errout != "" {
		t.Fatalf("replay code=%d out=%q err=%q", code, out, errout)
	}
	replayArgs[9] = tikvTestDigest([]byte("other"))
	if code, _, _ = runCommunity(t, replayArgs...); code != ExitIntegrity {
		t.Fatalf("wrong raw pin code=%d", code)
	}
}

func TestTiKVGCPV2WIFBackupModeAndInputBoundaries(t *testing.T) {
	dir := privateDir(t)
	p := filepath.Join(dir, "tikv.toml")
	writePrivate(t, p, []byte("[backup]\ngcp-v2-enable=true\n"))
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	base := []string{"check", "tikv-gcp-v2-wif-backup", "--config", p, "--target-version", tikvArgsTarget, "--operation", tikvArgsOperation}
	for _, args := range [][]string{
		base,
		append(append([]string{}, base...), "--now", now, "--knowledge-db", filepath.Join(dir, "store")),
		append(append([]string{}, base...), "--now", now, "--operation", tikvArgsOperation),
		{"check", "tikv-gcp-v2-wif-backup", "--config", p, "--target-version", "v8.5.8", "--operation", tikvArgsOperation, "--now", now},
	} {
		if code, _, _ := runCommunity(t, args...); code != ExitUsage {
			t.Fatalf("args=%q code=%d", args, code)
		}
	}
	writePrivate(t, p, []byte("[backup\n"))
	if code, _, _ := runCommunity(t, append(base, "--now", now)...); code != ExitUsage {
		t.Fatalf("malformed code=%d", code)
	}
}

func tikvTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
