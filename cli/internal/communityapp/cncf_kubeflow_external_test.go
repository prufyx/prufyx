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

type kubeflowExternalFixture struct {
	store, package2, package3 string
	manifest                  knowledgefixture.Manifest
	revision2                 knowledge.ImportReceipt
}

func makeKubeflowExternalFixture(t *testing.T) kubeflowExternalFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateKubeflowConstraints(time.Now().UTC().Truncate(time.Second))
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
	root := writeCNCFFile(t, "kubeflow-kfp-root.json", artifacts.Root, 0600)
	package1 := writeCNCFFile(t, "kubeflow-kfp-r1.tar", artifacts.Revision1, 0600)
	package2 := writeCNCFFile(t, "kubeflow-kfp-r2.tar", artifacts.Revision2, 0600)
	package3 := writeCNCFFile(t, "kubeflow-kfp-r3.tar", artifacts.Revision3, 0600)
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: package1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	return kubeflowExternalFixture{store: store, package2: package2, package3: package3, manifest: manifest}
}

func (f *kubeflowExternalFixture) import2(t *testing.T) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package2, StoreRoot: f.store, ExpectedRevision: "2", ExpectedBundleDigest: f.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	f.revision2 = receipt
}

func (f *kubeflowExternalFixture) import3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package3, StoreRoot: f.store, ExpectedRevision: "3", ExpectedBundleDigest: f.manifest.Revisions[2].BundleDigest}); err != nil {
		t.Fatal(err)
	}
}

func kubeflowExternalArgs(t *testing.T, f kubeflowExternalFixture, path, from, to, format string) []string {
	t.Helper()
	return []string{"check", "cncf", "--project", "kubeflow", "--python-source", path, "--from", from, "--to", to, "--knowledge-db", f.store, "--format", format}
}

func TestKubeflowKFPRawExternalAuthorityAndHistoricalReplay(t *testing.T) {
	t.Parallel()
	f := makeKubeflowExternalFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "component.py")
	blockedRaw := []byte("from kfp.components import create_component_from_func\n@create_component_from_func\ndef PRIVATE_COMPONENT():\n    pass\n")
	writeCNCFFileAt(t, path, blockedRaw)
	code, output, stderr := runCNCFCLI(t, kubeflowExternalArgs(t, f, path, "1.8.22", "2.0.0", "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "no embedded rule was used") {
		t.Fatalf("no fallback code=%d err=%q out=%s", code, stderr, output)
	}
	code, output, stderr = runCNCFCLI(t, kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "human")...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("embedded code=%d err=%q out=%s", code, stderr, output)
	}

	f.import2(t)
	synthetic := kubeflowExternalArgs(t, f, path, knowledgefixture.SyntheticKubeflowFrom, knowledgefixture.SyntheticKubeflowTo, "json")
	code, report, stderr := runCNCFCLI(t, append(synthetic, "--python-source-digest", digestCommunityBytes(blockedRaw))...)
	if code != ExitBlocked || stderr != "" || !json.Valid([]byte(report)) || strings.Contains(report, "PRIVATE_COMPONENT") {
		t.Fatalf("current code=%d err=%q out=%s", code, stderr, report)
	}
	fixedRaw := []byte("from kfp import dsl\n@dsl.component\ndef PRIVATE_COMPONENT():\n    pass\n")
	writeCNCFFileAt(t, path, fixedRaw)
	code, fixed, stderr := runCNCFCLI(t, append(synthetic, "--python-source-digest", digestCommunityBytes(fixedRaw))...)
	if code != ExitOK || stderr != "" || !json.Valid([]byte(fixed)) {
		t.Fatalf("fixed code=%d err=%q out=%s", code, stderr, fixed)
	}

	metadataDifferentRaw := []byte("# unrelated private note\nfrom kfp.components import create_component_from_func\n@create_component_from_func\ndef OTHER_PRIVATE_NAME():\n    pass\n")
	writeCNCFFileAt(t, path, metadataDifferentRaw)
	reportPath := filepath.Join(dir, "report.json")
	writeCNCFFileAt(t, reportPath, []byte(report))
	f.import3(t)
	replay := append(kubeflowExternalArgs(t, f, path, knowledgefixture.SyntheticKubeflowFrom, knowledgefixture.SyntheticKubeflowTo, "human"), "--python-source-digest", digestCommunityBytes(metadataDifferentRaw), "--knowledge-revision", "2", "--knowledge-bundle-digest", f.manifest.Revisions[1].BundleDigest, "--knowledge-trust-receipt-digest", f.revision2.TrustReceiptDigest, "--replay-report", reportPath)
	for _, option := range []string{"--python-source-digest", "--knowledge-revision", "--knowledge-bundle-digest", "--knowledge-trust-receipt-digest"} {
		code, output, stderr = runCNCFCLI(t, omitCLIOption(replay, option)...)
		if code != ExitUsage || output != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("missing %s code=%d stdout=%q stderr=%q", option, code, output, stderr)
		}
	}
	code, output, stderr = runCNCFCLI(t, replay...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(output, "historical external KFP Python source replay: MATCH") || !strings.Contains(output, "saved report binds the minimized authoring-form observation") {
		t.Fatalf("replay code=%d err=%q out=%s", code, stderr, output)
	}
	assertKubeflowKFPRedacted(t, output, path, "PRIVATE_COMPONENT", "OTHER_PRIVATE_NAME", "private note")
	assertStoreDoesNotContain(t, f.store, []string{"PRIVATE_COMPONENT", "OTHER_PRIVATE_NAME", "private note", path})
}
