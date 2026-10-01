// SPDX-License-Identifier: AGPL-3.0-only

package releasegate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func TestDecodeStrictRejectsDuplicateAndTrailingValues(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":1} {"b":2}`} {
		if _, err := decodeStrict([]byte(raw)); err == nil {
			t.Fatalf("accepted unsafe JSON %q", raw)
		}
	}
}
func TestSafeRelativeRejectsTraversalAndNonASCII(t *testing.T) {
	for _, value := range []string{"/tmp/x", "../x", "a/../x", "a\\x", "café"} {
		if _, err := safeRelative(value, "path"); err == nil {
			t.Fatalf("accepted unsafe path %q", value)
		}
	}
	if got, err := safeRelative("cli/release/policy.json", "path"); err != nil || got != "cli/release/policy.json" {
		t.Fatalf("valid path rejected: %q %v", got, err)
	}
}
func TestStableReadRejectsSymlinkAndPrivateKey(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "key"), []byte("-----BEGIN "+"PRIVATE KEY-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stableRead(root, "key", false); err == nil || !strings.Contains(err.Error(), "private-key") {
		t.Fatalf("private key accepted: %v", err)
	}
	if err := os.Symlink("key", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stableRead(root, "link", false); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestValidatePolicyClosedAndVersioned(t *testing.T) {
	base := map[string]any{"schemaVersion": SchemaV1, "moduleRoot": "cli", "entrypoints": []any{"./cmd/prufyx-community"}, "binaryName": "prufyx", "buildTargets": []any{"linux/amd64", "linux/arm64"}, "requiredGoVersion": "go1.26.8", "allowExternalModules": false, "requiredPaths": []any{map[string]any{"path": "LICENSE", "role": "legal"}}, "sourceBuildTargets": []any{"linux/amd64", "linux/arm64", "darwin/arm64"}, "testPolicy": map[string]any{"requireDirectTestsForProductionPackages": true, "testTags": []any{"parityreview"}}, "toolchainArchives": map[string]any{"linux/amd64": strings.Repeat("a", 64), "linux/arm64": strings.Repeat("b", 64), "darwin/arm64": strings.Repeat("c", 64)}}
	if _, err := validatePolicy(base); err != nil {
		t.Fatalf("valid v1 rejected: %v", err)
	}
	base["unexpected"] = true
	if _, err := validatePolicy(base); err == nil {
		t.Fatal("unknown policy field accepted")
	}
}

func TestRecursiveRequiredPathRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(root, "docs", "linked")); err != nil {
		t.Fatal(err)
	}
	if err := collectRequiredDirectory(root, "docs", "documentation", map[string]string{}); err == nil {
		t.Fatal("recursive required path accepted a symlink")
	}
}

func TestCollectPackageTestdataIncludesReachableFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "example", "testdata")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vector.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	if err := collectPackageTestdata(root, "internal/example", files); err != nil {
		t.Fatal(err)
	}
	if files["internal/example/testdata/vector.json"] != "testdata" {
		t.Fatalf("package testdata omitted: %#v", files)
	}
}

func TestResolveOutputOutsideRejectsRelativePathInsideSource(t *testing.T) {
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	if _, err := resolveOutputOutside(root, "SOURCE-MANIFEST.json"); err == nil {
		t.Fatal("relative output inside source root was accepted")
	}
}

func TestResolveOutputOutsideRejectsAbsolutePathInsideSource(t *testing.T) {
	root := t.TempDir()
	if _, err := resolveOutputOutside(root, filepath.Join(root, "stage")); err == nil {
		t.Fatal("absolute output inside source root was accepted")
	}
}

func TestRunNativeChecksRejectsUnsafeManifestModuleRoot(t *testing.T) {
	if err := RunNativeChecks(t.TempDir(), Manifest{ModuleRoot: "../outside", Entrypoints: []string{"./cmd/community"}}, "go"); err == nil {
		t.Fatal("unsafe manifest module root was accepted")
	}
}

func TestRunNativeChecksUsesManifestModuleRootAndAllEntrypoints(t *testing.T) {
	stage := t.TempDir()
	moduleRoot := filepath.Join(stage, "alternate-module")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(t.TempDir(), "commands")
	goBin := filepath.Join(t.TempDir(), "recording-go")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\npwd >> %q\nif [ \"$1\" = env ]; then printf 'darwin arm64\\n'; fi\n", record, record)
	if err := os.WriteFile(goBin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{ModuleRoot: "alternate-module", Entrypoints: []string{"./cmd/first", "./cmd/second"}, SourceBuildTargets: []string{"darwin/arm64"}, BuildTargets: []string{"linux/amd64"}, BinaryName: "community"}
	if err := RunNativeChecks(stage, manifest, goBin); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), moduleRoot) || !strings.Contains(string(got), "build -trimpath -buildvcs=false -o ") || !strings.Contains(string(got), "./cmd/first") || !strings.Contains(string(got), "./cmd/second") {
		t.Fatalf("native checks did not build every declared entrypoint: %s", got)
	}
}

func TestBaseEnvForwardsWritableGoCache(t *testing.T) {
	t.Setenv("GOCACHE", "/private/writable-cache")
	found := false
	for _, entry := range baseEnv(true) {
		if entry == "GOCACHE=/private/writable-cache" {
			found = true
		}
	}
	if !found {
		t.Fatal("base environment omitted the caller-selected writable Go cache")
	}
}

func TestVendorPathOrderMatchesLegacyComponentOrder(t *testing.T) {
	paths := []string{
		"cli/vendor/example.org/tool-kit/file.go",
		"cli/vendor/example.org/tool/file.go",
		"cli/vendor/example.org/tool/z.go",
	}
	sort.Slice(paths, func(i, j int) bool { return vendorPathLess(paths[i], paths[j]) })
	want := []string{
		"cli/vendor/example.org/tool/file.go",
		"cli/vendor/example.org/tool/z.go",
		"cli/vendor/example.org/tool-kit/file.go",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("vendor order=%q want=%q", paths, want)
	}
}

func TestDirectTestsIncludesExternalPackageTests(t *testing.T) {
	got := directTests(goPackage{TestGoFiles: []string{"same_test.go"}, XTestGoFiles: []string{"external_test.go"}})
	if strings.Join(got, ",") != "external_test.go,same_test.go" {
		t.Fatalf("direct tests=%q", got)
	}
}

func TestCanonicalNormalizesTypedReceiptsToStrictDecodedKeyOrder(t *testing.T) {
	type nested struct {
		Path     string      `json:"path"`
		Amount   json.Number `json:"amount"`
		Fraction json.Number `json:"fraction"`
	}
	type receipt struct {
		Schema string `json:"schema"`
		Nested nested `json:"nested"`
	}
	typed := receipt{Schema: "test", Nested: nested{Path: "<&é", Amount: json.Number("9007199254740993"), Fraction: json.Number("1.00")}}
	typedBytes, err := canonical(typed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	decodedBytes, err := canonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(typedBytes, decodedBytes) || !bytes.Contains(typedBytes, []byte(`"amount":9007199254740993`)) || !bytes.Contains(typedBytes, []byte(`"fraction":1.00`)) || !bytes.Contains(typedBytes, []byte("<&é")) {
		t.Fatalf("canonical typed=%q decoded=%q", typedBytes, decodedBytes)
	}
}

func TestV2PolicyMatchesCurrentVendorTreeWithLegacyOrder(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "cli", "release", "community-shipping-policy-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := object(v)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = validatePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if policy["vendorTreeDigest"] != "sha256:a79e35a51ea0a9f749d6f69323b218ebb712ffa68a8f488321ccf6c981ecec4f" {
		t.Fatalf("unexpected policy digest %q", policy["vendorTreeDigest"])
	}
	if err := validateVendorTree(root, policy); err != nil {
		t.Fatal(err)
	}
}

func TestMergePackageUnionsProductionFieldsAcrossTargets(t *testing.T) {
	linux := goPackage{ImportPath: "example.test/pkg", GoFiles: []string{"common.go", "linux.go"}, EmbedFiles: []string{"linux.json"}}
	darwin := goPackage{ImportPath: "example.test/pkg", GoFiles: []string{"common.go", "darwin.go"}, EmbedFiles: []string{"darwin.json"}}
	merged := mergePackage(linux, darwin, false)
	if strings.Join(merged.GoFiles, ",") != "common.go,darwin.go,linux.go" || strings.Join(merged.EmbedFiles, ",") != "darwin.json,linux.json" {
		t.Fatalf("production closure was overwritten: %#v", merged)
	}
}

func TestStageWriteRestoresManifestModeUnderRestrictiveUmask(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	entry := FileEntry{Path: "tool", Mode: "0755"}
	if err := writeStageFile(root, entry, []byte("#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(rootPath, entry.Path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("staged mode=%#o want %#o", got, os.FileMode(0o755))
	}
}

func TestCapturedV2BindingsMatchCurrentPolicyAndRejectPolicyMutation(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	policyPath := "cli/release/community-shipping-policy-v2.json"
	policyRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyPath)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeStrict(policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := object(v)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = validatePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string][]byte{policyPath: policyRaw}
	entries := []FileEntry{}
	for _, prefix := range []string{policy["vendorRoot"].(string), policy["moduleRoot"].(string) + "/go.sum"} {
		full := filepath.Join(root, filepath.FromSlash(prefix))
		info, statErr := os.Stat(full)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if !info.IsDir() {
			b, mode, readErr := stableRead(root, prefix, false)
			if readErr != nil {
				t.Fatal(readErr)
			}
			blobs[prefix] = b
			h := sha256.Sum256(b)
			entries = append(entries, FileEntry{Path: prefix, Mode: fmt.Sprintf("%04o", mode.Perm()), SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))})
			continue
		}
		walkErr := filepath.Walk(full, func(path string, item os.FileInfo, walkErr error) error {
			if walkErr != nil || item.IsDir() {
				return walkErr
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			b, mode, readErr := stableRead(root, rel, true)
			if readErr != nil {
				return readErr
			}
			blobs[rel] = b
			h := sha256.Sum256(b)
			entries = append(entries, FileEntry{Path: rel, Mode: fmt.Sprintf("%04o", mode.Perm()), SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))})
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	if err := validateCapturedV2Bindings(entries, blobs, policy, policyPath, policyRaw); err != nil {
		t.Fatalf("current captured closure rejected: %v", err)
	}
	blobs[policyPath] = append([]byte(nil), policyRaw...)
	blobs[policyPath][0] ^= 1
	if err := validateCapturedV2Bindings(entries, blobs, policy, policyPath, policyRaw); err == nil {
		t.Fatal("mutated captured policy was accepted")
	}
}
