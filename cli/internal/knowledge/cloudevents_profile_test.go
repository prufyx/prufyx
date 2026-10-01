// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCloudEventsProfileMarkerIsIsolatedAndOldMarkersStable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := ensureStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := cloudEventsStructuredJSONProfile()
	if err := checkProfileMarker(store, p, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(`{"apiVersion":"prufyx.io/knowledge-profile/v1","profile":"community-cloudevents-structured-json","targetPath":"knowledge/cloudevents-structured-json-profile.v1.json"}`), '\n')
	if !bytes.Equal(raw, want) {
		t.Fatalf("marker=%s", raw)
	}
	if err := checkProfileMarker(store, spiffeX509SVIDProfile(), false); err == nil {
		t.Fatal("SPIFFE profile accepted CloudEvents store")
	}
	spiffe, err := markerBytes(spiffeX509SVIDProfile())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spiffe, append([]byte(`{"apiVersion":"prufyx.io/knowledge-profile/v1","profile":"community-spiffe-x509-svid","targetPath":"knowledge/spiffe-x509-svid-profile.v1.json"}`), '\n')) {
		t.Fatalf("SPIFFE marker changed: %s", spiffe)
	}
}
