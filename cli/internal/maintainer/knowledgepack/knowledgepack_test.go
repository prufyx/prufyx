// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func fixture(t *testing.T, profile string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	for name, data := range map[string][]byte{
		"metadata/1.root.json": []byte("root"), "metadata/1.snapshot.json": []byte("snapshot"),
		"metadata/1.targets.json": []byte("targets"), "metadata/timestamp.json": []byte("timestamp"),
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	target := []byte("signed-target")
	digest := fmt.Sprintf("%x", sha256.Sum256(target))
	full := filepath.Join(root, "targets", "knowledge", digest+"."+targetSuffix[profile])
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, target, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestKnowledgePack_CanonicalArchive_AllProfiles(t *testing.T) {
	for _, profile := range Profiles() {
		t.Run(profile, func(t *testing.T) {
			root := fixture(t, profile)
			left, err := PackageDirectory(root, profile)
			if err != nil {
				t.Fatal(err)
			}
			right, err := PackageDirectory(root, profile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(left, right) {
				t.Fatal("archive is not deterministic")
			}
			r := tar.NewReader(bytes.NewReader(left))
			count := 0
			for {
				h, err := r.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if h.Mode != 0o644 || h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 0 || h.Typeflag != tar.TypeReg {
					t.Fatalf("non-canonical header: %#v", h)
				}
			}
			if count != 5 {
				t.Fatalf("got %d members", count)
			}
		})
	}
}

func TestKnowledgePack_RejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string)
	}{
		{"missing timestamp", func(root string) {
			if err := os.Remove(filepath.Join(root, "metadata", "timestamp.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown file", func(root string) {
			if err := os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"target digest mismatch", func(root string) {
			names, err := os.ReadDir(filepath.Join(root, "targets", "knowledge"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "targets", "knowledge", names[0].Name()), []byte("changed"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t, "cncf")
			tc.mutate(root)
			if _, err := PackageDirectory(root, "cncf"); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestKnowledgePack_RejectsLinksAndBounds(t *testing.T) {
	root := fixture(t, "cncf")
	original := filepath.Join(root, "metadata", "1.root.json")
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.snapshot.json", original); err != nil {
		t.Fatal(err)
	}
	if _, err := PackageDirectory(root, "cncf"); err == nil {
		t.Fatal("expected symlink rejection")
	}
	root = fixture(t, "cncf")
	if err := os.WriteFile(filepath.Join(root, "metadata", "1.root.json"), bytes.Repeat([]byte("x"), MaxPackageEntry+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PackageDirectory(root, "cncf"); err == nil {
		t.Fatal("expected size rejection")
	}
}

func TestKnowledgePack_WritePrivateAndRefuseOverwrite(t *testing.T) {
	root := fixture(t, "cncf")
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "out.tar")
	if err := WritePackage(root, out, "cncf"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	original, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePackage(root, out, "cncf"); err == nil {
		t.Fatal("expected overwrite rejection")
	}
	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("existing bytes changed")
	}
}

func TestKnowledgePack_RejectsSymlinkedAncestorPaths(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	source := fixture(t, "cncf")
	moved := filepath.Join(real, "source")
	if err := os.Rename(source, moved); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := PackageDirectory(filepath.Join(alias, "source"), "cncf"); err == nil {
		t.Fatal("expected input ancestor symlink rejection")
	}
	private := filepath.Join(real, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePackage(moved, filepath.Join(alias, "private", "out.tar"), "cncf"); err == nil {
		t.Fatal("expected output ancestor symlink rejection")
	}
	if _, err := os.Stat(filepath.Join(private, "out.tar")); !os.IsNotExist(err) {
		t.Fatal("output created through symlink ancestor")
	}
}

func TestKnowledgePack_MatchesGeneratedFixtureBytes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	generators := map[string]func(time.Time) (knowledgefixture.Artifacts, error){
		"cert-manager":                knowledgefixture.Generate,
		"cncf":                        knowledgefixture.GenerateConstraints,
		"spiffe-x509-svid":            knowledgefixture.GenerateSPIFFEX509SVID,
		"cloudevents-structured-json": knowledgefixture.GenerateCloudEventsStructuredJSON,
		"tikv-gcp-v2-wif-backup":      knowledgefixture.GenerateTiKVGCPV2WIFBackup,
	}
	for _, profile := range Profiles() {
		t.Run(profile, func(t *testing.T) {
			artifacts, err := generators[profile](now)
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "unpacked")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			reader := tar.NewReader(bytes.NewReader(artifacts.Revision2))
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if header.Typeflag != tar.TypeReg || filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != header.Name {
					t.Fatalf("unsafe fixture member %q", header.Name)
				}
				name := filepath.Join(root, filepath.FromSlash(header.Name))
				if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			actual, err := PackageDirectory(root, profile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, artifacts.Revision2) {
				t.Fatal("assembled archive differs from Go fixture archive")
			}
		})
	}
}
