// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDescriptorStoreTopLevelAndImmutable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a := []byte("one\n")
	if err = store.write("selection.json", a, true); err != nil {
		t.Fatal(err)
	}
	if got, err := store.read("selection.json", 64); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("read %q %v", got, err)
	}
	if err = store.write("selection.json", []byte("two\n"), true); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("immutable overwrite %v", err)
	}
	if err = store.write("selection.json", []byte("two\n"), false); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorStoreRemainsBoundAfterPathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	retained := filepath.Join(parent, "retained")
	if err = os.Rename(root, retained); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(parent, "other")
	if err = os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(other, root); err != nil {
		t.Fatal(err)
	}
	if err = store.write("selection.json", []byte("bound\n"), true); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(other, "selection.json")); !os.IsNotExist(err) {
		t.Fatal("write followed substituted store path")
	}
	if got, err := os.ReadFile(filepath.Join(retained, "selection.json")); err != nil || string(got) != "bound\n" {
		t.Fatalf("retained=%q err=%v", got, err)
	}
}

func TestVerifiedRevisionDefensiveReceipt(t *testing.T) {
	raw := []byte("x")
	receipt := TrustReceipt{KnowledgeRevision: "1", RootHistory: []RootHistoryEntry{{Version: 1, Digest: digestBytes([]byte("r"))}}}
	rr, _ := marshalCanonical(receipt)
	v := VerifiedRevision{bytes: raw, revision: "1", bundleDigest: digestBytes(raw), trustReceipt: receipt, trustReceiptDigest: digestBytes(rr), verifiedAt: time.Now().UTC(), mode: SelectionCurrent, seal: &verifiedSeal{}}
	if !v.Valid() {
		t.Fatal("valid capability rejected")
	}
	copy := v.TrustReceipt()
	copy.RootHistory[0].Version = 2
	if v.TrustReceipt().RootHistory[0].Version != 1 {
		t.Fatal("receipt slice leaked")
	}
}

func TestEstablishedClockFloorDeletionFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if err = persistClockFloor(store, now); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(root, "clock-floor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = loadClockFloor(store); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing floor accepted: %v", err)
	}
	store.Close()
}

func TestTrustStateRequiresInitialRootBinding(t *testing.T) {
	d1 := digestBytes([]byte("one"))
	d2 := digestBytes([]byte("two"))
	s := trustState{APIVersion: trustStateAPIVersion, InitialRootDigest: d1, RootHistory: []RootHistoryEntry{{Version: 1, Digest: d2}}, Root: RoleReceipt{Version: 1, Digest: d2, Expires: "2030-01-01T00:00:00Z"}}
	if err := validateTrustState(s); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mismatched initial pin accepted: %v", err)
	}
}

type tarEntry struct {
	name string
	data []byte
}

func packageEntries() []tarEntry {
	id := strings.Repeat("a", 64)
	sig := strings.Repeat("a", 128)
	meta := []byte(`{"signatures":[{"keyid":"` + id + `","sig":"` + sig + `"}],"signed":{"_type":"root","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","consistent_snapshot":true,"keys":{"` + id + `":{"keytype":"ed25519","scheme":"ed25519","keyval":{"public":"` + id + `"}}},"roles":{"root":{"keyids":["` + id + `"],"threshold":1},"timestamp":{"keyids":["` + id + `"],"threshold":1},"snapshot":{"keyids":["` + id + `"],"threshold":1},"targets":{"keyids":["` + id + `"],"threshold":1}}}}`)
	return []tarEntry{{"metadata/1.snapshot.json", meta}, {"metadata/1.targets.json", meta}, {"metadata/timestamp.json", meta}, {"targets/knowledge/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cert-manager.v1.json", []byte("{}")}}
}
func tarBytes(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(e.data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCanonicalPackageAdmission(t *testing.T) {
	raw := tarBytes(t, packageEntries())
	p := filepath.Join(t.TempDir(), "package.tar")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readImportPackage(p); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]tarEntry, []byte) []byte{"trailing": func(_ []tarEntry, r []byte) []byte { return append(append([]byte(nil), r...), 1) }, "duplicate": func(e []tarEntry, _ []byte) []byte { return tarBytes(t, append(e, e[0])) }, "order": func(e []tarEntry, _ []byte) []byte { e[0], e[1] = e[1], e[0]; return tarBytes(t, e) }} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(packageEntries(), raw)
			q := filepath.Join(t.TempDir(), "bad.tar")
			if err := os.WriteFile(q, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readImportPackage(q); err == nil {
				t.Fatal("bad archive accepted")
			}
		})
	}
}

func TestTUFJSONGateRejectsAliasesDuplicatesAndHugeArrays(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"signed":{},"Signed":{}}`), []byte(`{"signed":{},"signed":{}}`), []byte(`{"signed":{"Version":1}}`), []byte(`{"signatures":[` + string(bytes.Repeat([]byte("null,"), maxJSONMembers)) + `null]}`)} {
		if err := validateTUFJSON(raw); err == nil {
			t.Fatalf("accepted %s", raw[:min(len(raw), 80)])
		}
	}
	id := strings.Repeat("a", 64)
	sig := strings.Repeat("a", 128)
	valid := []byte(`{"signatures":[{"keyid":"` + id + `","sig":"` + sig + `"}],"signed":{"_type":"timestamp","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","meta":{"snapshot.json":{"version":1,"length":1,"hashes":{"sha256":"` + id + `"}}}}}`)
	if err := validateTUFJSON(valid); err != nil {
		t.Fatal(err)
	}
}

func TestTUFJSONGateRejectsWrongScalarTypesAtEveryRoleNode(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := id
	signature := strings.Repeat("a", 128)
	validTimestamp := `{"signatures":[{"keyid":"` + id + `","sig":"` + signature + `"}],"signed":{"_type":"timestamp","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","meta":{"snapshot.json":{"version":1,"length":1,"hashes":{"sha256":"` + hash + `"}}}}}`
	validRoot := `{"signatures":[{"keyid":"` + id + `","sig":"` + signature + `"}],"signed":{"_type":"root","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","consistent_snapshot":true,"keys":{"` + id + `":{"keytype":"ed25519","scheme":"ed25519","keyval":{"public":"` + id + `"}}},"roles":{"root":{"keyids":["` + id + `"],"threshold":1},"timestamp":{"keyids":["` + id + `"],"threshold":1},"snapshot":{"keyids":["` + id + `"],"threshold":1},"targets":{"keyids":["` + id + `"],"threshold":1}}}}`
	validTargets := `{"signatures":[{"keyid":"` + id + `","sig":"` + signature + `"}],"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{"` + TargetPath + `":{"length":1,"hashes":{"sha256":"` + hash + `"}}}}}`
	cases := map[string]string{
		"signature-keyid":  strings.Replace(validTimestamp, `"keyid":"`+id+`"`, `"keyid":null`, 1),
		"signature-sig":    strings.Replace(validTimestamp, `"sig":"`+signature+`"`, `"sig":null`, 1),
		"type":             strings.Replace(validTimestamp, `"_type":"timestamp"`, `"_type":null`, 1),
		"spec":             strings.Replace(validTimestamp, `"spec_version":"1.0.31"`, `"spec_version":null`, 1),
		"version-null":     strings.Replace(validTimestamp, `"version":1`, `"version":null`, 1),
		"version-zero":     strings.Replace(validTimestamp, `"version":1`, `"version":0`, 1),
		"version-overflow": strings.Replace(validTimestamp, `"version":1`, `"version":2147483648`, 1),
		"expiry":           strings.Replace(validTimestamp, `"expires":"2030-01-01T00:00:00Z"`, `"expires":null`, 1),
		"meta-version":     strings.Replace(validTimestamp, `"version":1,"length"`, `"version":null,"length"`, 1),
		"meta-length":      strings.Replace(validTimestamp, `"length":1`, `"length":null`, 1),
		"meta-hash":        strings.Replace(validTimestamp, `"sha256":"`+hash+`"`, `"sha256":null`, 1),
		"consistent":       strings.Replace(validRoot, `"consistent_snapshot":true`, `"consistent_snapshot":null`, 1),
		"keytype":          strings.Replace(validRoot, `"keytype":"ed25519"`, `"keytype":null`, 1),
		"scheme":           strings.Replace(validRoot, `"scheme":"ed25519"`, `"scheme":null`, 1),
		"public":           strings.Replace(validRoot, `"public":"`+id+`"`, `"public":null`, 1),
		"role-keyids":      strings.Replace(validRoot, `"keyids":["`+id+`"]`, `"keyids":null`, 1),
		"role-keyid-item":  strings.Replace(validRoot, `"keyids":["`+id+`"]`, `"keyids":[null]`, 1),
		"role-threshold":   strings.Replace(validRoot, `"threshold":1`, `"threshold":null`, 1),
		"target-length":    strings.Replace(validTargets, `"length":1`, `"length":null`, 1),
		"target-hash":      strings.Replace(validTargets, `"sha256":"`+hash+`"`, `"sha256":null`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateTUFJSON([]byte(raw)); err == nil {
				t.Fatal("wrong scalar type accepted")
			}
		})
	}
	for name, raw := range map[string]string{"timestamp": validTimestamp, "root": validRoot, "targets": validTargets} {
		t.Run("valid-"+name, func(t *testing.T) {
			if err := validateTUFJSON([]byte(raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTUFJSONGateRejectsRecognizedNullAndWrongContextFields(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sig := `[{"keyid":"` + id + `","sig":"aa"}]`
	bad := []string{
		`{"signatures":` + sig + `,"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{"` + TargetPath + `":{"length":2,"hashes":{"sha256":"aa"},"custom":null}}}}`,
		`{"signatures":` + sig + `,"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{"` + TargetPath + `":{"length":2,"hashes":{"sha256":"aa"}}},"delegations":null}}`,
		`{"signatures":[{"keyid":"` + id + `","sig":"aa","version":1}],"signed":{"_type":"timestamp","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","meta":{"snapshot.json":{"version":1,"length":1,"hashes":{"sha256":"aa"}}}}}`,
	}
	for _, raw := range bad {
		if err := validateTUFJSON([]byte(raw)); err == nil {
			t.Fatal("wrong-context field accepted")
		}
	}
}
