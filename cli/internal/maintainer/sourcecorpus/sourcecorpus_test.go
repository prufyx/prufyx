// SPDX-License-Identifier: AGPL-3.0-only

package sourcecorpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type brokenWriter struct {
	err   error
	short bool
}

func (w brokenWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.short && len(p) > 0 {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func fixturePath(parts ...string) string {
	items := append([]string{"..", "..", "..", "examples"}, parts...)
	path, err := filepath.Abs(filepath.Join(items...))
	if err != nil {
		panic(err)
	}
	return path
}

func TestReadRegularFileAcceptsPublicModeAndRejectsAliases(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "public.json")
	if err := os.WriteFile(path, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadRegularFile(path, 16)
	if err != nil || string(raw) != "public" {
		t.Fatalf("read=%q err=%v", raw, err)
	}
	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(symlink, 16); err == nil {
		t.Fatal("symlink accepted")
	}
	hardlink := filepath.Join(directory, "hardlink.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(path, 16); err == nil {
		t.Fatal("multiply linked file accepted")
	}
}

func decodeReceipt(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVerifySyntheticCorpusDeterministicContract(t *testing.T) {
	manifestPath := fixturePath("corpus", "synthetic-corpus.json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Verify(manifest, fixturePath("corpus", "objects"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Verify(manifest, fixturePath("corpus", "objects"))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("receipt is not deterministic: %v", err)
	}
	receipt := decodeReceipt(t, first)
	if receipt["schema"] != ReceiptSchema || receipt["manifestDigest"] != "sha256:33fbc414cd7a1203b9f22839ede6e0e60e12c4bdf70e15dd3d23e297225899de" || receipt["verification"] != "VERIFIED_RETAINED_BYTES" {
		t.Fatalf("unexpected receipt identity: %#v", receipt)
	}
	if receipt["recordCount"] != json.Number("1") || receipt["aggregateByteLength"] != json.Number("52") {
		t.Fatalf("unexpected receipt counts: %#v", receipt)
	}
	if bytes.Contains(first, []byte("\n")) {
		t.Fatal("canonical receipt contains a literal newline")
	}
}

func TestRunRejectsReceiptWriteFailure(t *testing.T) {
	args := []string{"verify", "--manifest", fixturePath("corpus", "synthetic-corpus.json"), "--object-root", fixturePath("corpus", "objects")}
	for _, output := range []brokenWriter{{err: io.ErrClosedPipe}, {short: true}} {
		var stderr bytes.Buffer
		if status := Run(args, output, &stderr); status == 0 || stderr.String() != "source-corpus: corpus rejected\n" {
			t.Fatalf("write failure returned status=%d stderr=%q", status, stderr.String())
		}
	}
}

func TestDecodeRejectsDuplicateKeysFloatsDepthAndSurrogates(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"a":1.0}`),
		[]byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)),
		[]byte(`{"a":"\ud800"}`),
		{0xff},
	}
	for _, raw := range cases {
		if _, err := DecodeBounded(raw, maxManifestBytes); !errors.Is(err, Error) {
			t.Fatalf("accepted invalid JSON %q: %v", raw, err)
		}
	}
}

func TestVerifyRejectsClosedSchemaDigestSpanAndDuplicateIdentity(t *testing.T) {
	manifestRaw, err := os.ReadFile(fixturePath("corpus", "synthetic-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeBounded(manifestRaw, maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	base := value.(map[string]any)
	mutations := []func(map[string]any){
		func(document map[string]any) { document["extra"] = true },
		func(document map[string]any) {
			record := document["records"].([]any)[0].(map[string]any)
			record["source"].(map[string]any)["fileDigest"] = "sha256:" + strings.Repeat("0", 64)
		},
		func(document map[string]any) {
			record := document["records"].([]any)[0].(map[string]any)
			record["source"].(map[string]any)["spans"].([]any)[0].(map[string]any)["spanDigest"] = "sha256:" + strings.Repeat("0", 64)
		},
		func(document map[string]any) {
			records := document["records"].([]any)
			document["records"] = append(records, records[0])
		},
	}
	for _, mutate := range mutations {
		copyRaw, _ := Canonical(base)
		copyValue, _ := DecodeBounded(copyRaw, maxManifestBytes)
		document := copyValue.(map[string]any)
		mutate(document)
		raw, _ := Canonical(document)
		if _, err := Verify(raw, fixturePath("corpus", "objects")); !errors.Is(err, Error) {
			t.Fatalf("accepted invalid manifest: %v", err)
		}
	}
}

func TestRawLFSpanSemantics(t *testing.T) {
	data := []byte("first\r\n\tsecond\ncaf\xc3\xa9\n")
	selected := []byte("first\r\n\tsecond\ncaf\xc3\xa9")
	spans := []any{map[string]any{"startLine": int64(1), "endLine": int64(3), "spanDigest": SHA(selected)}}
	if _, _, err := VerifySpans(spans, data); err != nil {
		t.Fatal(err)
	}
	final := []any{map[string]any{"startLine": int64(4), "endLine": int64(4), "spanDigest": SHA(nil)}}
	if _, _, err := VerifySpans(final, data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPathRejectsSymlinkAncestorAndHardLinkedObject(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("secure descriptor walk is supported on linux and darwin")
	}
	temporary := t.TempDir()
	real := filepath.Join(temporary, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(fixturePath("corpus", "synthetic-corpus.json"))
	if err := os.WriteFile(filepath.Join(real, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(temporary, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPath(filepath.Join(temporary, "alias", "manifest.json"), fixturePath("corpus", "objects")); !errors.Is(err, Error) {
		t.Fatalf("symlink ancestor accepted: %v", err)
	}
	objects := filepath.Join(temporary, "objects", "sha256")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	digestName := "2aa55d81765ce03e46eaeaa27a4314ed8663bd7ec8fc27e46ab0a5f7dc6e6366"
	data, _ := os.ReadFile(filepath.Join(fixturePath("corpus", "objects", "sha256"), digestName))
	objectPath := filepath.Join(objects, digestName)
	if err := os.WriteFile(objectPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(objectPath, filepath.Join(temporary, "second-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifest, filepath.Join(temporary, "objects")); !errors.Is(err, Error) {
		t.Fatalf("hard-linked object accepted: %v", err)
	}
}

func TestVerifyCollectionDeduplicatesAndEnforcesPrivateTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "collection")
	if err := copyTree(fixturePath("source-corpus-collection"), root); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	first, err := VerifyCollection(root, "collection-index.json")
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyCollection(root, "collection-index.json")
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("collection receipt is not deterministic: %v", err)
	}
	receipt := decodeReceipt(t, first)
	if receipt["indexDigest"] != "sha256:9242fd6149127903909ea9ba485575bbc82fdb7af937acd45048802a84dfe901" || receipt["recordCount"] != json.Number("2") || receipt["projectCount"] != json.Number("2") || receipt["uniqueObjectCount"] != json.Number("1") || receipt["aggregateByteLength"] != json.Number("52") {
		t.Fatalf("unexpected collection receipt: %#v", receipt)
	}
	if err := os.Chmod(filepath.Join(root, "shard-a", "manifest.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCollection(root, "collection-index.json"); !errors.Is(err, Error) {
		t.Fatalf("permissive manifest accepted: %v", err)
	}
}

func copyTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}
