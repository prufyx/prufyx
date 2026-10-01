// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefetch"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func runKnowledgeUpdate(t *testing.T, raw []byte, fetchErr error, args ...string) (int, knowledgeUpdateOutput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	code := r.databaseUpdateWithFetch(context.Background(), args, func(_ context.Context, source string) ([]byte, error) {
		if source != "https://metadata.example.test/knowledge.tar" {
			t.Fatal("local arguments changed download source")
		}
		return raw, fetchErr
	})
	var output knowledgeUpdateOutput
	if stdout.Len() > 0 && json.Unmarshal(stdout.Bytes(), &output) != nil {
		t.Fatalf("invalid update JSON: %s", stdout.String())
	}
	return code, output, stderr.String()
}

func updateCLIArgs(t *testing.T, store, name string) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, name)
	return []string{"--source", "https://metadata.example.test/knowledge.tar", "--package-out", output, "--db-root", store, "--profile", "cncf", "--format", "json"}, output
}

func TestKnowledgeUpdateChangesCoverageWithOneBinaryAndRetainsExactPackage(t *testing.T) {
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "root.json", artifacts.Root, 0o600)
	store := filepath.Join(t.TempDir(), "store")
	input := writeCNCFFile(t, "PRIVATE-input.json", []byte(kyvernoInputTrue), 0o600)
	for i, raw := range [][]byte{artifacts.Revision1, artifacts.Revision2} {
		args, out := updateCLIArgs(t, store, "retained.tar")
		if i == 0 {
			args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest)
		}
		code, output, stderr := runKnowledgeUpdate(t, raw, nil, args...)
		if code != ExitOK || stderr != "" || output.Status != "IMPORTED" || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.PackageDigest != testDigest(raw) || output.ImportReceipt == nil || output.ImportReceipt.TrustReceipt.KnowledgeRevision != manifest.Revisions[i].Revision {
			t.Fatalf("update %d: %d %+v %s", i, code, output, stderr)
		}
		if output.ImportReceipt.TrustReceipt.Purpose != "synthetic_test_only" {
			t.Fatal("lost fixture purpose")
		}
		got, err := os.ReadFile(out)
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatal("retained bytes changed", err)
		}
		info, err := os.Stat(out)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("retained file is not private", err)
		}
		checkCode, report, checkErr := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", input, "--knowledge-db", store, "--format", "json")
		want := ExitUnknown
		if i == 1 {
			want = ExitBlocked
		}
		if checkCode != want || checkErr != "" || !strings.Contains(report, `"assessment":"UNKNOWN"`) {
			t.Fatalf("check %d: %d %s %s", i, checkCode, report, checkErr)
		}
		encoded, _ := json.Marshal(output)
		for _, canary := range []string{input, root, out, store, "metadata.example.test"} {
			if bytes.Contains(encoded, []byte(canary)) {
				t.Fatal("local path or endpoint leaked in output")
			}
		}
	}
}

func TestKnowledgeUpdateTransportFailurePreservesStoreAndRemovesOutput(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	before := snapshotUpdateTree(t, fixture.store)
	for _, err := range []error{knowledgefetch.ErrTransfer, knowledgefetch.ErrOversized, errors.New("PRIVATE-URL-SECRET")} {
		args, out := updateCLIArgs(t, fixture.store, "failed.tar")
		code, output, stderr := runKnowledgeUpdate(t, nil, err, args...)
		if code != ExitIntegrity || stderr != "" || !output.NetworkAttempted || output.TransferCompleted || output.PackageRetained || output.ImportReceipt != nil || output.Rejection != nil {
			t.Fatalf("%d %+v %q", code, output, stderr)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Fatal("failed transfer output remains")
		}
		if !reflect.DeepEqual(before, snapshotUpdateTree(t, fixture.store)) {
			t.Fatal("transport failure mutated store")
		}
		encoded, _ := json.Marshal(output)
		if bytes.Contains(encoded, []byte("PRIVATE-URL-SECRET")) {
			t.Fatal("raw transport error leaked")
		}
	}
}

func TestKnowledgeUpdatePartialTrustFailureKeepsRecoveryPackage(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	// A second independently generated fixture tests semantic rejection with
	// valid TUF signatures. The existing store above also checks isolation.
	before := snapshotUpdateTree(t, fixture.store)
	a, err := knowledgefixture.GenerateConstraintsSemantic(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "semantic-root.json", a.Root, 0o600)
	store := filepath.Join(t.TempDir(), "semantic-store")
	args, _ := updateCLIArgs(t, store, "initial.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", a.RootDigest)
	if code, _, stderr := runKnowledgeUpdate(t, a.Revision1, nil, args...); code != ExitOK {
		t.Fatal(code, stderr)
	}
	args, out := updateCLIArgs(t, store, "rejected.tar")
	code, output, stderr := runKnowledgeUpdate(t, a.Revision2, nil, args...)
	if code != ExitIntegrity || stderr != "" || !output.PackageRetained || output.Rejection == nil || !output.Rejection.TrustStateAdvanced || output.Rejection.SelectionChanged || !strings.Contains(output.NextAction, "retained local package") {
		t.Fatalf("%d %+v %s", code, output, stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, a.Revision2) {
		t.Fatal("rejected exact package lost", err)
	}
	status, err := knowledge.InspectConstraints(store)
	if err != nil || status.SelectedRevision != "1" {
		t.Fatal("semantic rejection changed selection", status, err)
	}
	if !reflect.DeepEqual(before, snapshotUpdateTree(t, fixture.store)) {
		t.Fatal("other store changed")
	}
}

func TestKnowledgeUpdateRejectsUnsafeArgumentsBeforeFetch(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	args, output := updateCLIArgs(t, store, "exists.tar")
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafe := [][]string{args}
	base, _ := updateCLIArgs(t, store, "new.tar")
	unsafe = append(unsafe, append(append([]string{}, base...), "--input", "PRIVATE"))
	unsafe = append(unsafe, append(append([]string{}, base...), "--source", "https://metadata.example.test/duplicate"))
	for _, source := range []string{"http://example.test/", "https://secret:password@example.test/", "https://example.test/?PRIVATE", "https://example.test/#PRIVATE"} {
		bad := append([]string{}, base...)
		bad[1] = source
		unsafe = append(unsafe, bad)
	}
	for _, out := range []string{filepath.Join(store, "package.tar"), store} {
		bad := append([]string{}, base...)
		bad[3] = out
		unsafe = append(unsafe, bad)
	}
	alias := filepath.Join(t.TempDir(), "store-alias")
	if err := os.Symlink(store, alias); err != nil {
		t.Fatal(err)
	}
	bad := append([]string{}, base...)
	bad[3] = filepath.Join(alias, "package.tar")
	unsafe = append(unsafe, bad)
	permissive := t.TempDir()
	if err := os.Chmod(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	bad = append([]string{}, base...)
	bad[3] = filepath.Join(permissive, "package.tar")
	unsafe = append(unsafe, bad)
	for i, args := range unsafe {
		var stdout, stderr bytes.Buffer
		r := runtime{stdout: &stdout, stderr: &stderr}
		code := r.databaseUpdateWithFetch(context.Background(), args, func(context.Context, string) ([]byte, error) { t.Fatal("invalid arguments fetched"); return nil, nil })
		if code != ExitUsage || stdout.Len() != 0 || strings.Contains(stderr.String(), "PRIVATE") {
			t.Fatalf("case %d: %d %s %s", i, code, stdout.String(), stderr.String())
		}
	}
	got, _ := os.ReadFile(output)
	if string(got) != "sentinel" {
		t.Fatal("existing package overwritten")
	}
}

func TestKnowledgeUpdateHelpAndContext(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	if code := r.databaseUpdateWithFetch(context.Background(), []string{"--help"}, func(context.Context, string) ([]byte, error) { t.Fatal("help fetched"); return nil, nil }); code != ExitOK {
		t.Fatal(code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	args, _ := updateCLIArgs(t, filepath.Join(t.TempDir(), "store"), "cancelled.tar")
	if code := r.databaseUpdateWithFetch(ctx, args, func(got context.Context, _ string) ([]byte, error) {
		if got.Err() != context.Canceled {
			t.Fatal("lost context cancellation")
		}
		return nil, knowledgefetch.ErrTransfer
	}); code != ExitIntegrity {
		t.Fatal(code)
	}
}

func TestKnowledgeUpdateReplacementCannotChangeImportedPackage(t *testing.T) {
	a, err := knowledgefixture.GenerateConstraints(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(a.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "root.json", a.Root, 0o600)
	store := filepath.Join(t.TempDir(), "store")
	args, out := updateCLIArgs(t, store, "original.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest)
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	code := r.databaseUpdateWithFetch(context.Background(), args, func(context.Context, string) ([]byte, error) {
		if err := os.Remove(out); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, a.Revision2, 0o600); err != nil {
			t.Fatal(err)
		}
		return a.Revision1, nil
	})
	var output knowledgeUpdateOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if code != ExitIntegrity || stderr.Len() != 0 || output.Status != "RETENTION_INTEGRITY_FAILURE" || output.PackageRetained || output.ImportReceipt != nil || output.PackageDigest != testDigest(a.Revision1) {
		t.Fatalf("%d %+v %s", code, output, stderr.String())
	}
	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Fatal("replacement reached store admission")
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, a.Revision2) {
		t.Fatal("replacement file was overwritten or deleted")
	}
}

func TestKnowledgeUpdateReportsFailedPartialCleanup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires directory permission enforcement for non-root user")
	}
	store := filepath.Join(t.TempDir(), "store")
	args, out := updateCLIArgs(t, store, "partial.tar")
	parent := filepath.Dir(out)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	code := r.databaseUpdateWithFetch(context.Background(), args, func(context.Context, string) ([]byte, error) {
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		return nil, knowledgefetch.ErrTransfer
	})
	var output knowledgeUpdateOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if code != ExitIntegrity || !output.PartialCleanupRequired || output.PackageRetained || output.ReasonCode != "KNOWLEDGE_PARTIAL_PACKAGE_CLEANUP_REQUIRED" {
		t.Fatalf("%d %+v", code, output)
	}
	if _, err := os.Lstat(out); err != nil {
		t.Fatal("test did not leave a partial output", err)
	}
	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Fatal("cleanup failure touched store")
	}
}

func TestKnowledgeUpdateRejectsPhysicalStoreAliases(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "StoreCase")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "storecase")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("case-sensitive filesystem")
	}
	root, _, _, err := reserveKnowledgeDownload(filepath.Join(alias, "out.tar"), store)
	if root != nil {
		root.Close()
	}
	if err == nil {
		t.Fatal("physical output/store alias was admitted")
	}
}

func TestKnowledgeUpdateRejectsMalformedLocalAssertionsBeforeFetch(t *testing.T) {
	base, _ := updateCLIArgs(t, filepath.Join(t.TempDir(), "store"), "out.tar")
	for _, extra := range [][]string{
		{"--expected-revision", "00"},
		{"--expected-bundle-digest", "PRIVATE-bad-digest"},
		{"--bootstrap-root", "PRIVATE-missing-root", "--bootstrap-root-digest", "not-a-digest"},
	} {
		var stdout, stderr bytes.Buffer
		r := runtime{stdout: &stdout, stderr: &stderr}
		code := r.databaseUpdateWithFetch(context.Background(), append(append([]string{}, base...), extra...), func(context.Context, string) ([]byte, error) {
			t.Fatal("malformed local assertion triggered fetch")
			return nil, nil
		})
		if code != ExitUsage || stdout.Len() != 0 || strings.Contains(stderr.String(), "PRIVATE") {
			t.Fatalf("%d %s %s", code, stdout.String(), stderr.String())
		}
	}
}

func snapshotUpdateTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[path] = testDigest(raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
