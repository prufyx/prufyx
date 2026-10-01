// SPDX-License-Identifier: AGPL-3.0-only

package stagingreceipt

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGenerateVerifyAndTamper(t *testing.T) {
	b := t.TempDir()
	sourceSHA := "b" + repeat("0", 39)
	for _, name := range requiredAssets() {
		content := []byte(name + "\n")
		if name == "SOURCE-REVISION" {
			content = []byte(sourceSHA + "\n")
		}
		if err := os.WriteFile(filepath.Join(b, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var sums bytes.Buffer
	for _, name := range requiredAssets() {
		raw, _ := os.ReadFile(filepath.Join(b, name))
		h := sha256.Sum256(raw)
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(b, ChecksumsName), sums.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	id := Identity{BundleDir: b, Repository: Repository, WorkflowPath: WorkflowPath, WorkflowSHA: "a" + repeat("0", 39), Event: Event, RunID: "1234", RunAttempt: "1", Ref: Ref, SourceSHA: sourceSHA, Version: Version}
	if _, err := Generate(Options{Identity: id}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := Verify(Options{Identity: id}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(b, ReceiptName))
	if !bytes.HasSuffix(raw, []byte{'\n'}) {
		t.Fatal("receipt is not canonical newline JSON")
	}
	raw = bytes.Replace(raw, []byte(`"status":"STAGED_BUILD_VERIFIED"`), []byte(`"status":"WRONG"`), 1)
	if err := os.WriteFile(filepath.Join(b, ReceiptName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Options{Identity: id}); err == nil {
		t.Fatal("tampered receipt accepted")
	}
}
func TestExactDirectoryRejectsSymlinkAndExtra(t *testing.T) {
	b := t.TempDir()
	for _, name := range requiredAssets() {
		os.WriteFile(filepath.Join(b, name), []byte("x"), 0600)
	}
	os.WriteFile(filepath.Join(b, ChecksumsName), []byte{}, 0600)
	os.WriteFile(filepath.Join(b, "extra"), []byte("x"), 0600)
	if err := exactDir(b, false); err == nil {
		t.Fatal("extra entry accepted")
	}
}

func TestExactDirectoryRejectsOversizedMetadataBeforeDigestingAssets(t *testing.T) {
	b := t.TempDir()
	for _, name := range requiredAssets() {
		if err := os.WriteFile(filepath.Join(b, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b, ChecksumsName), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, ChecksumsName), make([]byte, MaxMetadataBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exactDir(b, false); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

func TestExactDirectoryAcceptsLargeSourceManifestAndRejectsOversizedReceipt(t *testing.T) {
	b := t.TempDir()
	for _, name := range append(append([]string{}, requiredAssets()...), ChecksumsName, ReceiptName) {
		if err := os.WriteFile(filepath.Join(b, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b, "SOURCE-MANIFEST.json"), make([]byte, MaxMetadataBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exactDir(b, true); err != nil {
		t.Fatalf("large source manifest rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(b, ReceiptName), make([]byte, MaxMetadataBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exactDir(b, true); err == nil {
		t.Fatal("oversized receipt accepted")
	}
}

func TestExactDirectoryRejectsSparseAssetsOverAggregateBeforeHashing(t *testing.T) {
	b := t.TempDir()
	for _, name := range requiredAssets() {
		if err := os.WriteFile(filepath.Join(b, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b, ChecksumsName), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range requiredAssets()[len(requiredAssets())-3:] {
		if err := os.Truncate(filepath.Join(b, name), 200<<20); err != nil {
			t.Fatal(err)
		}
	}
	if err := exactDir(b, false); err == nil {
		t.Fatal("aggregate oversized sparse assets accepted")
	}
}

func TestExtractPublisherZipExtractsExactEntrySet(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "publisher.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	names := append(append([]string{}, requiredAssets()...), ChecksumsName, ReceiptName)
	for _, name := range names {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	digest, err := regularDigestLimit(zipPath, "publisher artifact ZIP", MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "extracted")
	if err := ExtractPublisherZip(zipPath, digest, target); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || string(raw) != name {
			t.Fatalf("extracted %s = %q, %v", name, raw, err)
		}
	}
}
func TestArtifactBinding(t *testing.T) {
	b := t.TempDir()
	p := filepath.Join(b, "metadata.json")
	raw := []byte(`{"artifacts":[{"id":77,"name":"community-staging-bundle","digest":"sha256:` + repeat("d", 64) + `","expired":false,"workflow_run":{"id":1234}}]}`)
	os.WriteFile(p, raw, 0600)
	v, err := ArtifactBinding(ArtifactBindingOptions{Metadata: p, Repository: Repository, RunID: "1234", ArtifactName: ArtifactName})
	if err != nil {
		t.Fatal(err)
	}
	if v["artifactId"] != int64(77) {
		t.Fatalf("unexpected binding: %#v", v)
	}
}

func TestArtifactBindingRejectsNonCanonicalDigestAndMissingWorkflowObject(t *testing.T) {
	b := t.TempDir()
	p := filepath.Join(b, "metadata.json")
	base := map[string]any{"artifacts": []any{map[string]any{"id": int64(77), "name": ArtifactName, "digest": "sha256:" + repeat("d", 63) + "D", "expired": false, "workflow_run": map[string]any{"id": int64(1234)}}}}
	writeJSON(t, p, base)
	options := ArtifactBindingOptions{Metadata: p, Repository: Repository, RunID: "1234", ArtifactName: ArtifactName}
	if _, err := ArtifactBinding(options); err == nil {
		t.Fatal("uppercase artifact digest accepted")
	}
	base["artifacts"].([]any)[0].(map[string]any)["digest"] = "sha256:" + repeat("d", 64)
	base["artifacts"].([]any)[0].(map[string]any)["workflow_run"] = []any{}
	writeJSON(t, p, base)
	if _, err := ArtifactBinding(options); err == nil {
		t.Fatal("missing workflow run object accepted")
	}
}

func TestPublisherHandoffBindsOneVerifiedBundleSnapshot(t *testing.T) {
	id := newVerifiedBundle(t)
	_, _, _, capturedReceipt, err := parseChecksumsSnapshot(id.BundleDir)
	if err != nil {
		t.Fatal(err)
	}
	onDiskReceipt, err := os.ReadFile(filepath.Join(id.BundleDir, ReceiptName))
	if err != nil || !bytes.Equal(capturedReceipt, onDiskReceipt) {
		t.Fatalf("checksum snapshot did not retain receipt bytes: %v", err)
	}
	o := PublisherOptions{Identity: id, PublisherWorkflowSHA: "c" + repeat("0", 39), PublisherRunID: "5678", PublisherRunAttempt: "1", ArtifactID: "77", ArtifactDigest: repeat("d", 64), ArtifactSize: "17"}
	handoff, err := PublisherHandoff(o)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := os.ReadFile(filepath.Join(id.BundleDir, ReceiptName))
	if err != nil {
		t.Fatal(err)
	}
	if handoff["stagingReceiptDigest"] != shaDigest(receipt) || len(handoff["assets"].([]map[string]any)) != len(requiredAssets()) {
		t.Fatalf("handoff did not bind the verified bundle snapshot: %#v", handoff)
	}
}

func TestPublisherHandoffRejectsReceiptWithChangedAsset(t *testing.T) {
	id := newVerifiedBundle(t)
	if err := os.WriteFile(filepath.Join(id.BundleDir, "LICENSE"), []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := PublisherOptions{Identity: id, PublisherWorkflowSHA: "c" + repeat("0", 39), PublisherRunID: "5678", PublisherRunAttempt: "1", ArtifactID: "77", ArtifactDigest: repeat("d", 64), ArtifactSize: "17"}
	if _, err := PublisherHandoff(o); err == nil {
		t.Fatal("publisher handoff accepted a receipt with changed asset bytes")
	}
}

func TestParseFlagsRepeatPreservesAnnotatedTagOrderAndCapsChain(t *testing.T) {
	allowed := map[string]bool{"tag-object-metadata": true, "run-id": true}
	required := map[string]bool{"run-id": true}
	flags, values, err := parseFlagsRepeat([]string{
		"--run-id", "7",
		"--tag-object-metadata", "first.json",
		"--tag-object-metadata", "second.json",
	}, allowed, required, "tag-object-metadata")
	if err != nil || flags["run-id"] != "7" || !reflect.DeepEqual(values, []string{"first.json", "second.json"}) {
		t.Fatalf("repeatable metadata was not preserved: flags=%v values=%v err=%v", flags, values, err)
	}
	tooDeep := make([]string, 0, 18)
	for i := 0; i < 9; i++ {
		tooDeep = append(tooDeep, "--tag-object-metadata", fmt.Sprintf("tag-%d.json", i))
	}
	if _, _, err := parseFlagsRepeat(tooDeep, allowed, nil, "tag-object-metadata"); err == nil {
		t.Fatal("accepted more than eight annotated tag metadata paths")
	}
}

func TestValidateIdentityBindsAllArtifactWorkflowFields(t *testing.T) {
	fixture := newIdentityFixture(t)
	if err := ValidateStagingIdentity(fixture.options()); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	fields := []string{"id", "repository_id", "head_repository_id", "head_sha"}
	for _, field := range fields {
		for _, direct := range []bool{false, true} {
			value := fixture.artifact()
			workflow := value["workflow_run"].(map[string]any)
			if field == "head_sha" {
				workflow[field] = repeat("c", 40)
			} else {
				workflow[field] = int64(999)
			}
			if direct {
				writeJSON(t, fixture.artifactMetadata, value)
			} else {
				writeJSON(t, fixture.artifactList, []any{map[string]any{"total_count": int64(1), "artifacts": []any{value}}})
			}
			if err := ValidateStagingIdentity(fixture.options()); err == nil {
				t.Fatalf("accepted mutated %s in %s artifact projection", field, map[bool]string{false: "list", true: "direct"}[direct])
			}
			fixture.resetArtifacts(t)
		}
	}
}

func TestValidateIdentityAcceptsOrderedAnnotatedTagChain(t *testing.T) {
	fixture := newIdentityFixture(t)
	annotatedSHA := repeat("e", 40)
	writeJSON(t, fixture.tagMetadata, map[string]any{"object": map[string]any{"type": "tag", "sha": annotatedSHA}})
	tagObject := filepath.Join(fixture.bundle, "tag-object.json")
	writeJSON(t, tagObject, map[string]any{"sha": annotatedSHA, "object": map[string]any{"type": "commit", "sha": fixture.sourceSHA}})
	opts := fixture.options()
	opts.TagObjectMetadata = []string{tagObject}
	if err := ValidateStagingIdentity(opts); err != nil {
		t.Fatalf("annotated tag identity rejected: %v", err)
	}
	writeJSON(t, tagObject, map[string]any{"sha": annotatedSHA, "object": map[string]any{"type": "tag", "sha": annotatedSHA}})
	if err := ValidateStagingIdentity(opts); err == nil {
		t.Fatal("cyclic annotated tag chain accepted")
	}
}

type identityFixture struct {
	bundle, runMetadata, tagMetadata, artifactList, artifactMetadata string
	sourceSHA, workflowSHA                                           string
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	dir := t.TempDir()
	f := &identityFixture{bundle: dir, runMetadata: filepath.Join(dir, "run.json"), tagMetadata: filepath.Join(dir, "tag.json"), artifactList: filepath.Join(dir, "list.json"), artifactMetadata: filepath.Join(dir, "artifact.json"), sourceSHA: repeat("b", 40), workflowSHA: repeat("a", 40)}
	writeJSON(t, f.runMetadata, map[string]any{"id": int64(1234), "repository": map[string]any{"id": int64(1360163747), "full_name": Repository}, "head_repository": map[string]any{"id": int64(1360163747), "full_name": Repository}, "path": WorkflowPath, "event": Event, "head_branch": "v0.1.0-alpha.5", "head_sha": f.sourceSHA, "run_attempt": int64(1), "status": "completed", "conclusion": "success"})
	writeJSON(t, f.tagMetadata, map[string]any{"object": map[string]any{"type": "commit", "sha": f.sourceSHA}})
	f.resetArtifacts(t)
	return f
}

func (f *identityFixture) artifact() map[string]any {
	return map[string]any{"id": int64(77), "name": ArtifactName, "digest": "sha256:" + repeat("d", 64), "size_in_bytes": int64(17), "expired": false, "workflow_run": map[string]any{"id": int64(1234), "repository_id": int64(1360163747), "head_repository_id": int64(1360163747), "head_sha": f.sourceSHA}}
}

func (f *identityFixture) resetArtifacts(t *testing.T) {
	t.Helper()
	value := f.artifact()
	writeJSON(t, f.artifactMetadata, value)
	writeJSON(t, f.artifactList, []any{map[string]any{"total_count": int64(1), "artifacts": []any{value}}})
}

func (f *identityFixture) options() StagingIdentityOptions {
	return StagingIdentityOptions{Identity: Identity{BundleDir: f.bundle, Repository: Repository, WorkflowPath: WorkflowPath, WorkflowSHA: f.workflowSHA, Event: Event, RunID: "1234", RunAttempt: "1", Ref: Ref, SourceSHA: f.sourceSHA, Version: Version}, RunMetadata: f.runMetadata, TagMetadata: f.tagMetadata, ArtifactList: f.artifactList, ArtifactMetadata: f.artifactMetadata, ArtifactID: "77", ArtifactDigest: "sha256:" + repeat("d", 64), ArtifactSize: "17", DownloadedSize: "17"}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func newVerifiedBundle(t *testing.T) Identity {
	t.Helper()
	b := t.TempDir()
	sourceSHA := "b" + repeat("0", 39)
	for _, name := range requiredAssets() {
		content := []byte(name + "\n")
		if name == "SOURCE-REVISION" {
			content = []byte(sourceSHA + "\n")
		}
		if err := os.WriteFile(filepath.Join(b, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var sums bytes.Buffer
	for _, name := range requiredAssets() {
		raw, err := os.ReadFile(filepath.Join(b, name))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(b, ChecksumsName), sums.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	id := Identity{BundleDir: b, Repository: Repository, WorkflowPath: WorkflowPath, WorkflowSHA: "a" + repeat("0", 39), Event: Event, RunID: "1234", RunAttempt: "1", Ref: Ref, SourceSHA: sourceSHA, Version: Version}
	if _, err := Generate(Options{Identity: id}); err != nil {
		t.Fatal(err)
	}
	return id
}
