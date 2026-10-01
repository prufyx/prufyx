// SPDX-License-Identifier: AGPL-3.0-only

package releasehelpers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRunUsesProvidedStreamsAndRejectsUnsafeFlags(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "metadata.json")
	if err := WriteMetadata(MetadataOptions{Output: meta, Version: "v1.0.0", Revision: strings.Repeat("a", 40), SourceTreeDigest: "sha256:" + strings.Repeat("b", 64), ManifestDigest: "sha256:" + strings.Repeat("c", 64), Target: "linux-amd64", BuildEpoch: "1", GoVersion: "go1.26.8"}); err != nil {
		t.Fatal(err)
	}
	report := `{"result":{"status":"OK"},"data":{"version":"v1.0.0","releaseState":"release","sourceRevision":"` + strings.Repeat("a", 40) + `","sourceTreeDigest":"sha256:` + strings.Repeat("b", 64) + `","allowlistDigest":"sha256:` + strings.Repeat("c", 64) + `","buildProfile":"linux-amd64","goVersion":"go1.26.8","trustRootDigest":"UNPINNED","candidateOnly":true}}`
	var out bytes.Buffer
	if err := Run([]string{"release-verify-version", "--metadata", meta, "--report-stdin"}, strings.NewReader(report), &out, &out); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"release-verify-version", "--metadata", meta}, {"release-verify-version", "--metadata", meta, "--bogus", "x"}, {"release-verify-version", "--metadata", meta, "--report-stdin", "true"}} {
		if err := Run(args, strings.NewReader(report), &out, &out); err == nil {
			t.Fatalf("accepted unsafe args %v", args)
		}
	}
}

func TestRunReleaseMetadataSupportsDarwinTmpAlias(t *testing.T) {
	path := filepath.Join("/tmp", "prufyx-releasehelpers-"+strings.Repeat("a", 16)+".json")
	os.Remove(path)
	defer os.Remove(path)
	args := []string{
		"release-metadata", "--output", path, "--version", "v1.0.0",
		"--revision", strings.Repeat("a", 40), "--source-tree-digest", "sha256:" + strings.Repeat("b", 64),
		"--manifest-digest", "sha256:" + strings.Repeat("c", 64), "--target", "linux-amd64",
		"--build-epoch", "1", "--go-version", "go1.26.8",
	}
	if err := Run(args, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
func TestVerifyDemoRejectsDuplicateJSON(t *testing.T) {
	raw := []byte(`{"aggregate":"UNKNOWN","aggregate":"PASS","status":"SYNTHETIC_DEMONSTRATION","pin":"2.55.1 3.1.0 linux/arm64/v8"}`)
	if err := VerifyDemo(raw); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
}
func TestWriteSBOMIsCanonicalAndNoFirstPartyRuntimeClaim(t *testing.T) {
	p := filepath.Join(t.TempDir(), "SBOM.json")
	if err := WriteSBOM(SBOMOptions{Output: p, Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte{'\n'}) {
		t.Fatal("missing canonical newline")
	}
	if bytes.Contains(raw, []byte(`SPDXRef-Package-Python`)) {
		t.Fatal("retired Python runtime is still represented")
	}
}

func TestWriteSBOMProjectsEveryActivePolicyModule(t *testing.T) {
	policyPath := filepath.Join("..", "..", "..", "release", "community-shipping-policy-v2.json")
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		t.Fatal(err)
	}
	modules, ok := policy["externalModules"].([]any)
	if !ok || len(modules) == 0 {
		t.Fatal("fixture has no external modules")
	}
	out := filepath.Join(t.TempDir(), "SBOM.json")
	if err := WriteSBOM(SBOMOptions{Output: out, Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8", Policy: policyPath}); err != nil {
		t.Fatal(err)
	}
	var sbom map[string]any
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &sbom); err != nil {
		t.Fatal(err)
	}
	packages, _ := sbom["packages"].([]any)
	if len(packages) != len(modules)+2 {
		t.Fatalf("SBOM package count=%d, want %d", len(packages), len(modules)+2)
	}
}

func TestWriteSBOMRejectsMalformedPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSBOM(SBOMOptions{Output: filepath.Join(t.TempDir(), "SBOM.json"), Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8", Policy: policyPath}); err == nil {
		t.Fatal("malformed policy accepted")
	}
}

func TestVerifyArchiveBindsGuideAndLicenseFilesAndRejectsUnsafeMembers(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "LICENSES"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSES", "module.txt"), []byte("module license\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "release.tar.gz")
	writeArchiveFixture(t, archivePath, 17, "", root, BinaryGettingStartedGuide())
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	writeArchiveFixture(t, archivePath, 17, "", root, nil)
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive without GETTING-STARTED.md accepted")
	}
	writeArchiveFixture(t, archivePath, 17, "", root, []byte("altered guide\n"))
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive with altered GETTING-STARTED.md accepted")
	}
	writeArchiveFixture(t, archivePath, 17, "pkg/extra", root, BinaryGettingStartedGuide())
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive with an extra member accepted")
	}
	writeArchiveFixture(t, archivePath, 17, "pkg/../escape", root, BinaryGettingStartedGuide())
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive with a traversal member accepted")
	}
}

func writeArchiveFixture(t *testing.T, path string, epoch int64, extraName, root string, guide []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tarWriter := tar.NewWriter(gz)
	write := func(name string, mode int64, data []byte) {
		header := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	directory := func(name string) {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0755, ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	directory("pkg/")
	write("pkg/LICENSE", 0644, []byte("LICENSE\n"))
	write("pkg/NOTICE", 0644, []byte("NOTICE\n"))
	write("pkg/THIRD-PARTY.md", 0644, []byte("THIRD-PARTY.md\n"))
	write("pkg/RELEASE-METADATA.json", 0644, nil)
	write("pkg/SOURCE-REVISION", 0644, nil)
	write("pkg/prufyx", 0755, nil)
	if guide != nil {
		write("pkg/GETTING-STARTED.md", 0644, guide)
	}
	directory("pkg/LICENSES/")
	write("pkg/LICENSES/module.txt", 0644, []byte("module license\n"))
	if extraName != "" {
		write(extraName, 0644, nil)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_ = root
}

// writeSBOMArtifact places one fake release artifact and returns its SHA-256
// and SHA-1 so a test can assert the SBOM records exact shipped bytes.
func writeSBOMArtifact(t *testing.T, dir, name, body string) (string, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	sum256 := sha256.Sum256([]byte(body))
	sum1 := sha1.Sum([]byte(body))
	return hex.EncodeToString(sum256[:]), hex.EncodeToString(sum1[:])
}

func TestWriteSBOMBindsFinalArtifacts(t *testing.T) {
	artifacts := t.TempDir()
	amdSHA256, amdSHA1 := writeSBOMArtifact(t, artifacts, "prufyx-cli_1.0.0_linux_amd64.tar.gz", "amd64 archive bytes")
	srcSHA256, srcSHA1 := writeSBOMArtifact(t, artifacts, "prufyx-cli_1.0.0_source.tar.gz", "source archive bytes")

	out := filepath.Join(t.TempDir(), "SBOM.json")
	options := SBOMOptions{
		Output: out, Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8",
		ArtifactDir: artifacts,
		Artifacts:   []string{"prufyx-cli_1.0.0_source.tar.gz", "prufyx-cli_1.0.0_linux_amd64.tar.gz"},
	}
	if err := WriteSBOM(options); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	var sbom map[string]any
	if err := json.Unmarshal(raw, &sbom); err != nil {
		t.Fatal(err)
	}
	files, _ := sbom["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("SBOM file count=%d, want 2", len(files))
	}
	// Files are emitted in sorted name order regardless of the caller's order.
	first, _ := files[0].(map[string]any)
	if first["fileName"] != "./prufyx-cli_1.0.0_linux_amd64.tar.gz" {
		t.Fatalf("analyzed files are not sorted by name: %v", first["fileName"])
	}
	for _, want := range []string{amdSHA256, amdSHA1, srcSHA256, srcSHA1} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("SBOM omits artifact checksum %s", want)
		}
	}
	packages, _ := sbom["packages"].([]any)
	described, _ := packages[0].(map[string]any)
	if described["filesAnalyzed"] != true {
		t.Fatal("artifact-bound SBOM must set filesAnalyzed")
	}
	code, _ := described["packageVerificationCode"].(map[string]any)
	value, _ := code["packageVerificationCodeValue"].(string)
	expectedOrder := []string{amdSHA1, srcSHA1}
	sort.Strings(expectedOrder)
	expected := sha1.Sum([]byte(strings.Join(expectedOrder, "")))
	if value != hex.EncodeToString(expected[:]) {
		t.Fatalf("package verification code=%q, want %q", value, hex.EncodeToString(expected[:]))
	}
	hasFiles, _ := described["hasFiles"].([]any)
	if len(hasFiles) != 2 {
		t.Fatalf("described package lists %d files, want 2", len(hasFiles))
	}
	contains := 0
	relationships, _ := sbom["relationships"].([]any)
	for _, item := range relationships {
		if r, ok := item.(map[string]any); ok && r["relationshipType"] == "CONTAINS" {
			contains++
		}
	}
	if contains != 2 {
		t.Fatalf("CONTAINS relationship count=%d, want 2", contains)
	}
}

func TestWriteSBOMArtifactBindingIsDeterministic(t *testing.T) {
	artifacts := t.TempDir()
	writeSBOMArtifact(t, artifacts, "prufyx-cli_1.0.0_source.tar.gz", "source archive bytes")
	options := SBOMOptions{
		Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8",
		ArtifactDir: artifacts, Artifacts: []string{"prufyx-cli_1.0.0_source.tar.gz"},
	}
	first := options
	first.Output = filepath.Join(t.TempDir(), "SBOM.json")
	second := options
	second.Output = filepath.Join(t.TempDir(), "SBOM.json")
	if err := WriteSBOM(first); err != nil {
		t.Fatal(err)
	}
	if err := WriteSBOM(second); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(first.Output)
	b, _ := os.ReadFile(second.Output)
	if !bytes.Equal(a, b) {
		t.Fatal("artifact-bound SBOM is not byte-reproducible; release verify would fail")
	}
}

func TestWriteSBOMRejectsUnsafeOrMissingArtifacts(t *testing.T) {
	artifacts := t.TempDir()
	writeSBOMArtifact(t, artifacts, "present.tar.gz", "bytes")
	cases := map[string]SBOMOptions{
		"missing artifact":      {ArtifactDir: artifacts, Artifacts: []string{"absent.tar.gz"}},
		"path traversal":        {ArtifactDir: artifacts, Artifacts: []string{"../escape"}},
		"nested path":           {ArtifactDir: artifacts, Artifacts: []string{"sub/dir.tar.gz"}},
		"empty name":            {ArtifactDir: artifacts, Artifacts: []string{""}},
		"duplicate artifact":    {ArtifactDir: artifacts, Artifacts: []string{"present.tar.gz", "present.tar.gz"}},
		"artifacts without dir": {Artifacts: []string{"present.tar.gz"}},
		"dir without artifacts": {ArtifactDir: artifacts},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			options := SBOMOptions{
				Output: filepath.Join(t.TempDir(), "SBOM.json"), Version: "v1.0.0",
				Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8",
				ArtifactDir: extra.ArtifactDir, Artifacts: extra.Artifacts,
			}
			if err := WriteSBOM(options); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestRunReleaseSBOMAcceptsArtifactFlags(t *testing.T) {
	artifacts := t.TempDir()
	writeSBOMArtifact(t, artifacts, "prufyx-cli_1.0.0_source.tar.gz", "source archive bytes")
	out := filepath.Join(t.TempDir(), "SBOM.json")
	args := []string{
		"release-sbom", "--output", out, "--version", "v1.0.0", "--revision", strings.Repeat("a", 40),
		"--build-epoch", "0", "--go-version", "go1.26.8",
		"--policy", filepath.Join("..", "..", "..", "release", "community-shipping-policy-v2.json"),
		"--artifact-dir", artifacts, "--artifacts", "prufyx-cli_1.0.0_source.tar.gz",
	}
	if err := Run(args, bytes.NewReader(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("release-sbom with artifact flags: %v", err)
	}
	raw, _ := os.ReadFile(out)
	if !bytes.Contains(raw, []byte(`"files":[`)) {
		t.Fatal("release-sbom did not bind the declared artifacts")
	}
}
