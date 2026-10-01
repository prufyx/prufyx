// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func openTestOutput(t *testing.T, path string) *outputDirectory {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	repo := t.TempDir()
	directory, err := openOutputDirectory(repo, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func TestOutputDirectoryRequiresPrivateOwnerMode(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested", "candidate")
	directory := openTestOutput(t, nested)
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("created output mode = %04o", info.Mode().Perm())
	}
	if err := directory.verifyBinding(); err != nil {
		t.Fatal(err)
	}

	unsafe := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutputDirectory(t.TempDir(), unsafe); err == nil {
		t.Fatal("accepted group-writable output directory")
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutputDirectory(t.TempDir(), public); err == nil {
		t.Fatal("accepted non-private output directory")
	}

	target := t.TempDir()
	parent := t.TempDir()
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutputDirectory(t.TempDir(), filepath.Join(link, "candidate")); err == nil {
		t.Fatal("accepted a symlinked output component")
	}
	if _, err := os.Stat(filepath.Join(target, "candidate")); !os.IsNotExist(err) {
		t.Fatal("created output through a rejected symlink")
	}
}

func TestOutputDirectoryPreflightRejectsLinksBeforeWrites(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	canary := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(canary, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := directory.assetPath("SOURCE-REVISION")
	if err := os.Symlink(canary, link); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(
		outputAsset{name: "fresh-archive.tar.gz"},
		outputAsset{name: "SOURCE-REVISION", replace: true},
	); err == nil {
		t.Fatal("accepted preexisting output symlink")
	}
	if _, err := os.Stat(directory.assetPath("fresh-archive.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("wrote an associated asset after failed preflight")
	}
	raw, err := os.ReadFile(canary)
	if err != nil || string(raw) != "unchanged" {
		t.Fatalf("canary changed: %q, %v", raw, err)
	}

	hardlink := directory.assetPath("SOURCE-MANIFEST.json")
	if err := os.Link(canary, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(outputAsset{name: "SOURCE-MANIFEST.json", replace: true}); err == nil {
		t.Fatal("accepted preexisting output hard link")
	}
}

func TestOutputDirectoryExclusiveAndAtomicReplacement(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	if err := directory.preflight(outputAsset{name: "asset"}); err != nil {
		t.Fatal(err)
	}
	if err := directory.create("asset", 0o600, writeBytes([]byte("first"))); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(outputAsset{name: "asset"}); err == nil {
		t.Fatal("accepted an existing exclusive asset")
	}
	before, err := os.Stat(directory.assetPath("asset"))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(outputAsset{name: "asset", replace: true}); err != nil {
		t.Fatal(err)
	}
	if err := directory.replace("asset", 0o644, writeBytes([]byte("second"))); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(directory.assetPath("asset"))
	if err != nil {
		t.Fatal(err)
	}
	beforeStat := before.Sys().(*syscall.Stat_t)
	afterStat := after.Sys().(*syscall.Stat_t)
	if beforeStat.Ino == afterStat.Ino {
		t.Fatal("replacement reused the prior inode")
	}
	if after.Mode().Perm() != 0o644 {
		t.Fatalf("replacement mode = %04o", after.Mode().Perm())
	}
	raw, err := os.ReadFile(directory.assetPath("asset"))
	if err != nil || string(raw) != "second" {
		t.Fatalf("replacement content = %q, %v", raw, err)
	}
	entries, err := os.ReadDir(directory.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".prufyx-release-") {
			t.Fatalf("temporary asset remains: %s", entry.Name())
		}
	}
}

func TestOutputDirectoryRejectsReboundPathBeforeWrite(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "candidate")
	directory := openTestOutput(t, path)
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(outputAsset{name: "asset"}); err == nil {
		t.Fatal("accepted a rebound output path")
	}
	for _, root := range []string{path, moved} {
		if _, err := os.Stat(filepath.Join(root, "asset")); !os.IsNotExist(err) {
			t.Fatalf("wrote through rebound path %s", root)
		}
	}
}

func TestOutputDirectoryExactPreflightRejectsExtrasBeforeWrite(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	if err := os.WriteFile(directory.assetPath("required"), []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory.assetPath("unexpected"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflightExact(
		outputAsset{name: "required", required: true},
		outputAsset{name: "generated", replace: true},
	); err == nil {
		t.Fatal("accepted an unexpected finalization asset")
	}
	if _, err := os.Stat(directory.assetPath("generated")); !os.IsNotExist(err) {
		t.Fatal("wrote a generated asset after failed exact preflight")
	}
}

func TestOutputDirectoryDigestUsesValidatedDescriptor(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	raw := []byte("release asset")
	if err := os.WriteFile(directory.assetPath("asset"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	digest, err := directory.digest("asset")
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:"+hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %s", digest)
	}
	if err := os.Symlink(directory.assetPath("asset"), directory.assetPath("linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.digest("linked"); err == nil {
		t.Fatal("digested a symlinked asset")
	}
}

func TestSourceOutputPreflightPreservesVersionedArchiveContract(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	for _, name := range []string{"SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256"} {
		if err := os.WriteFile(directory.assetPath(name), []byte("prior"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	assets := []outputAsset{
		{name: "prufyx-cli_2.0.0_source.tar.gz"},
		{name: "SOURCE-MANIFEST.json", replace: true},
		{name: "SOURCE-REVISION", replace: true},
		{name: "SOURCE-TREE.sha256", replace: true},
	}
	if err := directory.preflight(assets...); err != nil {
		t.Fatalf("new version with replaceable sidecars rejected: %v", err)
	}
	if err := os.WriteFile(directory.assetPath(assets[0].name), []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := directory.preflight(assets...); err == nil {
		t.Fatal("accepted an existing same-version source archive")
	}
}

func TestOutputDirectoryRemovesIncompleteExclusiveAsset(t *testing.T) {
	directory := openTestOutput(t, t.TempDir())
	err := directory.create("asset", 0o600, func(writer io.Writer) error {
		if _, err := writer.Write([]byte("partial")); err != nil {
			return err
		}
		return syscall.EIO
	})
	if err == nil {
		t.Fatal("accepted an incomplete exclusive write")
	}
	if _, err := os.Stat(directory.assetPath("asset")); !os.IsNotExist(err) {
		t.Fatal("retained an incomplete exclusive asset")
	}
}
