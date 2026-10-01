// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

type cubeFSExternalFixture struct {
	store, package2, package3 string
	manifest                  knowledgefixture.Manifest
	revision2                 knowledge.ImportReceipt
}

func makeCubeFSExternalFixture(t *testing.T) cubeFSExternalFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateCubeFSConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if json.Unmarshal(artifacts.Manifest, &manifest) != nil {
		t.Fatal("manifest")
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if os.Mkdir(store, 0700) != nil {
		t.Fatal("store")
	}
	root := writeCNCFFile(t, "cubefs-root.json", artifacts.Root, 0600)
	package1 := writeCNCFFile(t, "cubefs-r1.tar", artifacts.Revision1, 0600)
	package2 := writeCNCFFile(t, "cubefs-r2.tar", artifacts.Revision2, 0600)
	package3 := writeCNCFFile(t, "cubefs-r3.tar", artifacts.Revision3, 0600)
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: package1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	return cubeFSExternalFixture{store: store, package2: package2, package3: package3, manifest: manifest}
}

func (f *cubeFSExternalFixture) import2(t *testing.T) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package2, StoreRoot: f.store, ExpectedRevision: "2", ExpectedBundleDigest: f.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	f.revision2 = receipt
}

func (f *cubeFSExternalFixture) import3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package3, StoreRoot: f.store, ExpectedRevision: "3", ExpectedBundleDigest: f.manifest.Revisions[2].BundleDigest}); err != nil {
		t.Fatal(err)
	}
}

func cubeFSExternalArgs(f cubeFSExternalFixture, path, from, to, format string) []string {
	return []string{"check", "cncf", "--project", "cubefs", "--metanode-config", path, "--from", from, "--to", to, "--phase", "metanode-upgrade", "--knowledge-db", f.store, "--format", format}
}

func TestCubeFSMetaNodeRawExternalAuthorityAndHistoricalReplay(t *testing.T) {
	f := makeCubeFSExternalFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "metanode.json")
	blockedRaw := []byte(`{"role":"metanode","raftSyncSnapFormatVersion":1,"secretKey":"PRIVATE_CUBEFS_EXTERNAL"}`)
	writeCNCFFileAt(t, path, blockedRaw)
	code, output, stderr := runCNCFCLI(t, cubeFSExternalArgs(f, path, "3.2.1", "3.3.2", "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "no embedded rule was used") {
		t.Fatalf("no fallback code=%d err=%q out=%s", code, stderr, output)
	}
	code, output, stderr = runCNCFCLI(t, cubeFSRawArgs(path, "3.2.1", "3.3.2", "metanode-upgrade", "human")...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("embedded code=%d err=%q out=%s", code, stderr, output)
	}

	f.import2(t)
	synthetic := cubeFSExternalArgs(f, path, knowledgefixture.SyntheticCubeFSFrom, knowledgefixture.SyntheticCubeFSTo, "json")
	code, report, stderr := runCNCFCLI(t, append(synthetic, "--metanode-config-digest", digestCommunityBytes(blockedRaw))...)
	if code != ExitBlocked || stderr != "" || !json.Valid([]byte(report)) || strings.Contains(report, "PRIVATE_CUBEFS_EXTERNAL") {
		t.Fatalf("current code=%d err=%q out=%s", code, stderr, report)
	}
	fixedRaw := []byte(`{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS_EXTERNAL"}`)
	writeCNCFFileAt(t, path, fixedRaw)
	code, fixed, stderr := runCNCFCLI(t, append(synthetic, "--metanode-config-digest", digestCommunityBytes(fixedRaw))...)
	if code != ExitOK || stderr != "" || !json.Valid([]byte(fixed)) {
		t.Fatalf("fixed code=%d err=%q out=%s", code, stderr, fixed)
	}

	writeCNCFFileAt(t, path, blockedRaw)
	reportPath := filepath.Join(dir, "report.json")
	writeCNCFFileAt(t, reportPath, []byte(report))
	f.import3(t)
	replay := append(cubeFSExternalArgs(f, path, knowledgefixture.SyntheticCubeFSFrom, knowledgefixture.SyntheticCubeFSTo, "human"), "--metanode-config-digest", digestCommunityBytes(blockedRaw), "--knowledge-revision", "2", "--knowledge-bundle-digest", f.manifest.Revisions[1].BundleDigest, "--knowledge-trust-receipt-digest", f.revision2.TrustReceiptDigest, "--replay-report", reportPath)
	for _, option := range []string{"--metanode-config-digest", "--knowledge-revision", "--knowledge-bundle-digest", "--knowledge-trust-receipt-digest"} {
		incomplete := omitCLIOption(replay, option)
		code, output, stderr = runCNCFCLI(t, incomplete...)
		if code != ExitUsage || output != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("missing %s code=%d stdout=%q stderr=%q", option, code, output, stderr)
		}
	}
	code, output, stderr = runCNCFCLI(t, replay...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(output, "historical external CubeFS MetaNode replay: MATCH") || !strings.Contains(output, "saved report binds the minimized phase and guard observations") {
		t.Fatalf("replay code=%d err=%q out=%s", code, stderr, output)
	}
	assertCubeFSRedacted(t, output, path)
	assertStoreDoesNotContain(t, f.store, []string{"PRIVATE_CUBEFS_EXTERNAL", path, "secretKey"})
}
