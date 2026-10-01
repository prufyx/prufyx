// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSPIFFEProfileMarkerIsIsolatedAndOldMarkersStable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := spiffeX509SVIDProfile()
	if err := checkProfileMarker(store, p, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(`{"apiVersion":"prufyx.io/knowledge-profile/v1","profile":"community-spiffe-x509-svid","targetPath":"knowledge/spiffe-x509-svid-profile.v1.json"}`), '\n')
	if !bytes.Equal(raw, want) {
		t.Fatalf("marker=%s", raw)
	}
	if err := checkProfileMarker(store, constraintsProfile(), false); err == nil {
		t.Fatal("CNCF profile accepted SPIFFE store")
	}
	cncf, err := markerBytes(constraintsProfile())
	if err != nil {
		t.Fatal(err)
	}
	if string(cncf) != "{\"apiVersion\":\"prufyx.io/knowledge-profile/v1\",\"profile\":\"community-constraints\",\"targetPath\":\"knowledge/constraints.v1.json\"}\n" {
		t.Fatalf("CNCF marker changed: %s", cncf)
	}
}
