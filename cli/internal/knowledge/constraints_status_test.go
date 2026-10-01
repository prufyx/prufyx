// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func writeConstraintsStatusFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func importConstraintsStatusFixture(t *testing.T) (string, knowledgefixture.Manifest) {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := writeConstraintsStatusFile(t, dir, knowledgefixture.RootName, artifacts.Root)
	pkg := writeConstraintsStatusFile(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	store := filepath.Join(dir, "generic")
	if _, err := ImportConstraints(ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	return store, manifest
}

func snapshotConstraintsStatusFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == ".lock" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = raw
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func assertStatusDurableFilesUnchanged(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	for name, raw := range before {
		if name == "clock-floor.json" {
			continue
		}
		if !bytes.Equal(raw, after[name]) {
			t.Fatalf("status changed durable file %s", name)
		}
	}
	for name := range after {
		if name != "clock-floor.json" {
			if _, ok := before[name]; !ok {
				t.Fatalf("status created durable file %s", name)
			}
		}
	}
}

func TestInspectConstraintsReAdmitsGenericTargetAndPreservesStore(t *testing.T) {
	store, _ := importConstraintsStatusFixture(t)
	before := snapshotConstraintsStatusFiles(t, store)
	status, err := InspectConstraints(store)
	if err != nil || status.State != "READY" || !status.CurrentEligible {
		t.Fatalf("valid generic status=%+v err=%v", status, err)
	}
	after := snapshotConstraintsStatusFiles(t, store)
	assertStatusDurableFilesUnchanged(t, before, after)
}

func TestInspectConstraintsRejectsChangedGenericAdmission(t *testing.T) {
	store, _ := importConstraintsStatusFixture(t)
	before := snapshotConstraintsStatusFiles(t, store)
	forced := constraintsProfile()
	forced.admit = func([]byte) (Admission, error) { return Admission{}, ErrIntegrity }
	status, err := inspectProfile(store, forced)
	if err != nil || status.State != "INTEGRITY_FAILURE" || status.CurrentEligible || status.NextAction != genericIntegrityNextAction || status.TrustStateDigest == "" || status.SelectedRevision != "1" {
		t.Fatalf("forced generic admission status=%+v err=%v", status, err)
	}
	assertStatusDurableFilesUnchanged(t, before, snapshotConstraintsStatusFiles(t, store))

	mismatch := constraintsProfile()
	mismatch.admit = func([]byte) (Admission, error) {
		return Admission{Revision: "1", Purpose: "operator_provided", EngineCapabilityDigest: "sha256:" + strings.Repeat("0", 64), HasRule: false}, nil
	}
	status, err = inspectProfile(store, mismatch)
	if err != nil || status.State != "INTEGRITY_FAILURE" || status.CurrentEligible || status.NextAction != genericIntegrityNextAction || status.TrustStateDigest == "" || status.SelectedRevision != "1" {
		t.Fatalf("mismatched generic admission status=%+v err=%v", status, err)
	}
	assertStatusDurableFilesUnchanged(t, before, snapshotConstraintsStatusFiles(t, store))
}

func TestInspectConstraintsFixedProfileStillUsesValidAdmission(t *testing.T) {
	store, _ := importConstraintsStatusFixture(t)
	status, err := inspectProfile(store, constraintsProfile())
	if err != nil || status.State != "READY" || !status.CurrentEligible {
		t.Fatalf("fixed generic profile status=%+v err=%v", status, err)
	}
}
