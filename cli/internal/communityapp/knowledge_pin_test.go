// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func withPin(t *testing.T, digest string) {
	t.Helper()
	old := pinnedRootDigest
	pinnedRootDigest = func(profile string) string {
		if profile == "cncf" {
			return digest
		}
		return ""
	}
	t.Cleanup(func() { pinnedRootDigest = old })
}

func pinFixture(t *testing.T) (knowledgefixture.Artifacts, string, string) {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	return artifacts, writeCNCFFile(t, "root.json", artifacts.Root, 0o600), manifest.BootstrapRoot.Digest
}

func TestKnowledgeUpdatePinnedRootAccepted(t *testing.T) {
	artifacts, root, digest := pinFixture(t)
	withPin(t, digest)
	store := filepath.Join(t.TempDir(), "store")
	// First install: the root file alone; its digest is the pin.
	args, _ := updateCLIArgs(t, store, "first.tar")
	args = append(args, "--bootstrap-root", root)
	if code, out, stderr := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code != ExitOK || out.Status != "IMPORTED" {
		t.Fatalf("code=%d out=%+v stderr=%s", code, out, stderr)
	}
	// Later update: no root flags at all.
	args, _ = updateCLIArgs(t, store, "second.tar")
	if code, out, stderr := runKnowledgeUpdate(t, artifacts.Revision2, nil, args...); code != ExitOK || out.Status != "IMPORTED" {
		t.Fatalf("code=%d out=%+v stderr=%s", code, out, stderr)
	}
}

func TestKnowledgeUpdateWrongRootRejected(t *testing.T) {
	artifacts, root, digest := pinFixture(t)
	other, otherRoot, otherDigest := pinFixture(t)

	// Pin is another root: the explicit root is refused before any download.
	withPin(t, otherDigest)
	store := filepath.Join(t.TempDir(), "store")
	args, _ := updateCLIArgs(t, store, "a.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", digest)
	if code, _, _ := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code != ExitUsage {
		t.Fatalf("explicit digest not the pin: code=%d", code)
	}
	// Root file that does not hash to the pin.
	args, _ = updateCLIArgs(t, store, "b.tar")
	args = append(args, "--bootstrap-root", root)
	if code, out, _ := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code == ExitOK || out.Status == "IMPORTED" {
		t.Fatalf("wrong root file imported: code=%d out=%+v", code, out)
	}
	// No root at all while pinned and the store is empty.
	args, _ = updateCLIArgs(t, store, "c.tar")
	if code, out, _ := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code == ExitOK || out.Status == "IMPORTED" {
		t.Fatalf("rootless import into empty store: code=%d out=%+v", code, out)
	}
	if _, err := knowledge.InspectConstraints(store); err == nil {
		if st, _ := knowledge.InspectConstraints(store); st.State == "READY" {
			t.Fatal("store became ready")
		}
	}

	// A store already established under another root is refused once pinned.
	withPin(t, "")
	store2 := filepath.Join(t.TempDir(), "store2")
	args, _ = updateCLIArgs(t, store2, "d.tar")
	args = append(args, "--bootstrap-root", otherRoot, "--bootstrap-root-digest", otherDigest)
	if code, out, stderr := runKnowledgeUpdate(t, other.Revision1, nil, args...); code != ExitOK || out.Status != "IMPORTED" {
		t.Fatalf("seed code=%d out=%+v stderr=%s", code, out, stderr)
	}
	before, err := knowledge.InspectConstraints(store2)
	if err != nil {
		t.Fatal(err)
	}
	withPin(t, digest)
	args, _ = updateCLIArgs(t, store2, "e.tar")
	if code, out, _ := runKnowledgeUpdate(t, other.Revision2, nil, args...); code == ExitOK || out.Status == "IMPORTED" {
		t.Fatalf("store under unpinned root accepted: code=%d out=%+v", code, out)
	}
	after, err := knowledge.InspectConstraints(store2)
	if err != nil || after.TrustStateDigest != before.TrustStateDigest || after.SelectedRevision != before.SelectedRevision {
		t.Fatalf("store changed: %+v -> %+v err=%v", before, after, err)
	}
}

func TestKnowledgeUpdatePinnedRootRotationChainAccepted(t *testing.T) {
	artifacts, root, digest := pinFixture(t)
	withPin(t, digest)
	store := filepath.Join(t.TempDir(), "store")
	args, _ := updateCLIArgs(t, store, "first.tar")
	args = append(args, "--bootstrap-root", root)
	if code, out, stderr := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code != ExitOK || out.Status != "IMPORTED" {
		t.Fatalf("seed code=%d out=%+v stderr=%s", code, out, stderr)
	}
	// Root version 2 is signed by version 1 and carried in the package, whose
	// other metadata is signed by the new keys.
	rotated := tarWith(t, artifacts.RootV2Continuation, "metadata/2.root.json", tarMember(t, artifacts.RootV2RefreshFailure, "metadata/2.root.json"))
	args, _ = updateCLIArgs(t, store, "rotated.tar")
	if code, out, stderr := runKnowledgeUpdate(t, rotated, nil, args...); code != ExitOK || out.Status != "IMPORTED" || out.ImportReceipt == nil || len(out.ImportReceipt.TrustReceipt.RootHistory) != 2 {
		t.Fatalf("rotation code=%d out=%+v stderr=%s", code, out, stderr)
	}
	// Without the chained root the new keys are not trusted.
	args, _ = updateCLIArgs(t, store, "unchained.tar")
	if code, out, _ := runKnowledgeUpdate(t, artifacts.RootV2RefreshFailure, nil, args...); code == ExitOK || out.Status == "IMPORTED" {
		t.Fatalf("unchained rotation accepted: code=%d out=%+v", code, out)
	}
}

func TestKnowledgeUpdateEmptyPinKeepsExplicitRootBehaviour(t *testing.T) {
	artifacts, root, digest := pinFixture(t)
	withPin(t, "")
	store := filepath.Join(t.TempDir(), "store")
	// A root file without its digest is still a usage error.
	args, _ := updateCLIArgs(t, store, "a.tar")
	if code, _, _ := runKnowledgeUpdate(t, artifacts.Revision1, nil, append(args, "--bootstrap-root", root)...); code != ExitUsage {
		t.Fatalf("lone root accepted: code=%d", code)
	}
	// No root at all is still refused for an empty store.
	args, _ = updateCLIArgs(t, store, "b.tar")
	if code, out, _ := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code == ExitOK || out.Status == "IMPORTED" {
		t.Fatalf("rootless import: code=%d out=%+v", code, out)
	}
	args, _ = updateCLIArgs(t, store, "c.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", digest)
	if code, out, stderr := runKnowledgeUpdate(t, artifacts.Revision1, nil, args...); code != ExitOK || out.Status != "IMPORTED" {
		t.Fatalf("explicit root code=%d out=%+v stderr=%s", code, out, stderr)
	}
}

func TestShippedPinTableMatchesKnownProfiles(t *testing.T) {
	for _, profile := range []string{"cncf-projects"} {
		if !validKnowledgeProfile(profile) {
			t.Fatalf("pinned profile %s unknown", profile)
		}
	}
}

func tarMember(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := r.Next()
		if err != nil {
			t.Fatalf("member %s: %v", name, err)
		}
		if h.Name == name {
			b, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

func tarWith(t *testing.T, archive []byte, name string, data []byte) []byte {
	t.Helper()
	files := map[string][]byte{name: data}
	r := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, n := range names {
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
