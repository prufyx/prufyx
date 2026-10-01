// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasehelpers"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasesign"
)

func TestVersionAndTargetAdmission(t *testing.T) {
	if !versionOK("v1.2.3-alpha.1") || versionOK("1.2.3") || versionOK("v1.02.3") {
		t.Fatal("version admission mismatch")
	}
	for _, bad := range []string{"v1.2.3-", "v1.2.3-alpha..1", "v1.2.3-01", "v1.2.3+", "v1.2.3+meta+again", "v1.2.3-!"} {
		if versionOK(bad) {
			t.Fatalf("accepted invalid SemVer %q", bad)
		}
	}
	if !versionOK("v1.2.3-alpha.1+build.01") {
		t.Fatal("rejected valid SemVer")
	}
	if _, _, err := target("linux-arm64"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := target("darwin-arm64"); err == nil {
		t.Fatal("accepted unsupported target")
	}
	// The public community release workflow stamps a distinct
	// "community-<os>-<arch>" profile family (see buildidentity). The
	// strict, signed-release pipeline must never accept it as a target.
	if _, _, err := target("community-linux-amd64"); err == nil {
		t.Fatal("accepted a community-release profile as a signed-release target")
	}
}

func TestGoTestCommandKeepsOutputStreamsSeparate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := goTestCommand("go", t.TempDir(), &stdout, &stderr)
	if c.Stdout != &stdout || c.Stderr != &stderr {
		t.Fatal("go test output streams were not preserved")
	}
}

func TestSourceTreeChecksumUsesCanonicalTarLabel(t *testing.T) {
	want := strings.Repeat("a", 64) + "  source-tree.tar\n"
	if got := string(sourceTreeChecksum("sha256:" + strings.Repeat("a", 64))); got != want {
		t.Fatalf("source tree checksum = %q", got)
	}
}

func TestWriteBinaryGettingStartedUsesVerifiedGuideBytes(t *testing.T) {
	pkg := t.TempDir()
	if err := writeBinaryGettingStarted(pkg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pkg, "GETTING-STARTED.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, releasehelpers.BinaryGettingStartedGuide()) {
		t.Fatal("assembled guide differs from archive verifier contract")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatalf("assembled guide mode=%v err=%v", info, err)
	}
}

func TestVerifySumsRequiresExactCanonicalReleaseAssets(t *testing.T) {
	dir := t.TempDir()
	assets := releaseAssets("v1.2.3")
	lines := make([]string, 0, len(assets))
	for _, name := range assets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		digest, err := digest(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.TrimPrefix(digest, "sha256:")+"  "+name)
	}
	write := func(rows []string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(lines)
	if err := verifySums(dir, assets); err != nil {
		t.Fatalf("valid SHA256SUMS rejected: %v", err)
	}
	for name, mutate := range map[string]func([]string) []string{
		"incomplete": func(rows []string) []string { return rows[:len(rows)-1] },
		"duplicate": func(rows []string) []string {
			rows[1] = rows[1][:66] + assets[0]
			return rows
		},
		"traversal": func(rows []string) []string {
			rows[0] = rows[0][:66] + "../" + assets[0]
			return rows
		},
		"uppercase hash": func(rows []string) []string {
			rows[0] = strings.ToUpper(rows[0][:64]) + rows[0][64:]
			return rows
		},
		"unsorted": func(rows []string) []string {
			rows[0], rows[1] = rows[1], rows[0]
			return rows
		},
	} {
		t.Run(name, func(t *testing.T) {
			rows := append([]string(nil), lines...)
			write(mutate(rows))
			if err := verifySums(dir, assets); err == nil {
				t.Fatal("invalid SHA256SUMS accepted")
			}
		})
	}
}

func TestSmokeLayoutRejectsExtraAndSourceMembers(t *testing.T) {
	makeLayout := func(t *testing.T) (string, string) {
		t.Helper()
		work := t.TempDir()
		pkg := filepath.Join(work, "prufyx-cli_1.2.3_linux_arm64")
		if err := os.Mkdir(pkg, 0755); err != nil {
			t.Fatal(err)
		}
		return work, pkg
	}
	t.Run("closed layout", func(t *testing.T) {
		work, pkg := makeLayout(t)
		if err := validateSmokeLayout(work, pkg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("extra top level", func(t *testing.T) {
		work, pkg := makeLayout(t)
		if err := os.WriteFile(filepath.Join(work, "extra"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		if err := validateSmokeLayout(work, pkg); err == nil {
			t.Fatal("accepted an extra top-level archive member")
		}
	})
	for _, name := range []string{"go.mod", ".git"} {
		t.Run(name, func(t *testing.T) {
			work, pkg := makeLayout(t)
			if err := os.WriteFile(filepath.Join(pkg, name), nil, 0644); err != nil {
				t.Fatal(err)
			}
			if err := validateSmokeLayout(work, pkg); err == nil {
				t.Fatalf("accepted forbidden %s", name)
			}
		})
	}
}

func TestGoLaunchersPinLocalOfflineToolchain(t *testing.T) {
	// Source exports intentionally omit .git. Locate these shipped launchers
	// from the compiled test file rather than asking the release-only root()
	// helper to discover a checkout.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source location is unavailable")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	for _, rel := range []string{"scripts/community-release.sh", "cli/examples/community/local-kind/run.sh"} {
		b, err := os.ReadFile(filepath.Join(repo, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, binding := range []string{"GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS='-mod=vendor -buildvcs=false'"} {
			if !strings.Contains(text, binding) {
				t.Fatalf("%s lacks %s", rel, binding)
			}
		}
	}
}

func TestOutputDirRejectsCheckoutBeforeCreation(t *testing.T) {
	repo := t.TempDir()
	inside := filepath.Join(repo, "candidate")
	if _, err := outputDir(repo, inside); err == nil {
		t.Fatal("accepted checkout-contained output")
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatal("created rejected checkout-contained output")
	}
	outside := filepath.Join(t.TempDir(), "candidate")
	directory, err := outputDir(repo, outside)
	if err != nil {
		t.Fatalf("rejected outside output: %v", err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "outside-looking-link")
	if err := os.Symlink(repo, link); err != nil {
		t.Fatal(err)
	}
	if _, err := outputDir(repo, filepath.Join(link, "through-link")); err == nil {
		t.Fatal("accepted checkout-contained symlink target")
	}
	if _, err := os.Stat(filepath.Join(repo, "through-link")); !os.IsNotExist(err) {
		t.Fatal("created rejected symlink-target output")
	}
}
func TestCanonicalArchiveIsStable(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(t.TempDir(), "a.tar.gz")
	b := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := tarGz(root, "prefix", a, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := tarGz(root, "prefix", b, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	ad, _ := os.ReadFile(a)
	bd, _ := os.ReadFile(b)
	if string(ad) != string(bd) {
		t.Fatal("archive bytes differ")
	}
}

func TestDistributableArchivesExcludeDerivedAssets(t *testing.T) {
	got := distributableArchives("v1.2.3")
	want := []string{
		"prufyx-cli_1.2.3_linux_amd64.tar.gz",
		"prufyx-cli_1.2.3_linux_arm64.tar.gz",
		"prufyx-cli_1.2.3_source.tar.gz",
	}
	if len(got) != len(want) {
		t.Fatalf("distributable archive count=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("distributable archive %d=%q, want %q", i, got[i], want[i])
		}
	}
	// A document cannot record its own digest, so the SBOM and SHA256SUMS must
	// never appear in the set the SBOM analyzes.
	for _, name := range got {
		if name == "SBOM.spdx.json" || name == "SHA256SUMS" {
			t.Fatalf("SBOM would be asked to describe itself via %q", name)
		}
	}
}

func TestSignedCoveredAssetsCoverEveryPublishedAsset(t *testing.T) {
	covered := signedCoveredAssets("v1.2.3")
	present := map[string]bool{}
	for _, name := range covered {
		present[name] = true
	}
	for _, name := range append([]string{"SHA256SUMS"}, releaseAssets("v1.2.3")...) {
		if !present[name] {
			t.Fatalf("release statement would not cover %q", name)
		}
	}
	// The statement and its envelope must stay outside their own coverage.
	if present[releasesign.StatementName] || present[releasesign.EnvelopeName] {
		t.Fatal("release statement must not cover itself or its envelope")
	}
	for i := 1; i < len(covered); i++ {
		if covered[i-1] >= covered[i] {
			t.Fatalf("covered asset set is not sorted and unique at %d", i)
		}
	}
}

func TestRunRejectsMalformedSigningInvocations(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"sign"},
		{"sign", "v1.2.3"},
		{"sign", "v1.2.3", "/tmp/out", "/tmp/root"},
		{"verify-signature"},
		{"verify-signature", "v1.2.3", "/tmp/out", "/tmp/root"},
		{"verify-signature", "v1.2.3", "/tmp/out", "/tmp/root", "digest", "extra"},
	} {
		if err := Run(args, &out, &errOut); err == nil {
			t.Fatalf("accepted malformed invocation %v", args)
		}
	}
}

func TestVerifySignatureRejectsBadVersionBeforeTouchingDisk(t *testing.T) {
	var out bytes.Buffer
	if err := verifySignature("1.2.3", t.TempDir(), "/nonexistent-root", "sha256:"+strings.Repeat("a", 64), &out); err == nil {
		t.Fatal("accepted a non-SemVer version")
	}
	if out.Len() != 0 {
		t.Fatal("a rejected verification must not emit a result line")
	}
}

func TestDefaultPassphraseReaderRefusesSigning(t *testing.T) {
	// The workflow package owns no terminal. Without the command layer's
	// installed prompt, signing must fail rather than proceed keyless.
	reader := ReadSigningPassphrase
	t.Cleanup(func() { ReadSigningPassphrase = reader })
	ReadSigningPassphrase = func(io.Writer) ([]byte, error) {
		return nil, errors.New("no reader")
	}
	var out, errOut bytes.Buffer
	// The file content is irrelevant: the passphrase reader is consulted before
	// the key is ever parsed. Community source must never contain key-shaped
	// bytes, so this fixture deliberately holds none.
	key := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(key, []byte("not key material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"sign", "v1.2.3", t.TempDir(), "/tmp/root", key}, &out, &errOut); err == nil {
		t.Fatal("signing proceeded without a passphrase reader")
	}
}

func TestSignRefusesUnverifiedOutput(t *testing.T) {
	// sign() runs the full derivation check first. Outside a clean checkout of
	// the exact release revision it must refuse rather than sign whatever is
	// sitting in the output directory.
	var out bytes.Buffer
	err := sign("v1.2.3", t.TempDir(), "/nonexistent-root", []byte("key"), []byte("passphrase"), &out)
	if err == nil {
		t.Fatal("signed an output that release verify would reject")
	}
	if out.Len() != 0 {
		t.Fatal("a refused signing must not emit a result line")
	}
}

func TestSignWipesPassphraseOnRefusal(t *testing.T) {
	passphrase := []byte("operator passphrase 123")
	var out bytes.Buffer
	_ = sign("v1.2.3", t.TempDir(), "/nonexistent-root", []byte("key"), passphrase, &out)
	for _, b := range passphrase {
		if b != 0 {
			t.Fatal("a refused signing left the passphrase in memory")
		}
	}
}

func TestReadBoundedReleaseRejectsUnsafeInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asset")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRelease(path, 4); err == nil {
		t.Fatal("accepted a file beyond its bound")
	}
	if got, err := readBoundedRelease(path, 64); err != nil || string(got) != "0123456789" {
		t.Fatalf("bounded read failed: %q %v", got, err)
	}
	if _, err := readBoundedRelease(filepath.Join(dir, "absent"), 64); err == nil {
		t.Fatal("accepted a missing file")
	}
	if err := os.Symlink(path, filepath.Join(dir, "link")); err == nil {
		if _, err := readBoundedRelease(filepath.Join(dir, "link"), 64); err == nil {
			t.Fatal("followed a symlink")
		}
	}
}

func TestWriteNewReleaseNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := writeNewRelease(dir, "STATEMENT", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeNewRelease(dir, "STATEMENT", []byte("second")); err == nil {
		t.Fatal("overwrote an existing release asset")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "STATEMENT"))
	if err != nil || string(raw) != "first" {
		t.Fatalf("existing asset was modified: %q %v", raw, err)
	}
}
