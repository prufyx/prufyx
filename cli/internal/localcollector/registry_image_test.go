// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/imageidentity"
)

var testNow = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

func TestRegistryImagesAreProjectedMinimallyAndFailClosed(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	digest := "@sha256:" + strings.Repeat("b", 64)
	root := workload("Deployment", []any{
		map[string]any{"image": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1", "args": []any{"--secret-flag=hunter2"}, "env": []any{map[string]any{"name": "TOKEN", "value": "hunter2"}}},
		map[string]any{"image": "docker.io/velero/velero:latest"},
		map[string]any{"image": "goharbor/harbor-core" + digest},
		map[string]any{"image": "docker.io/library/nats:2.15.0-alpine"},
		map[string]any{"image": "example-artifactregistry.gcr.io/gke-release/etcd:v9.9.9-gke.1"},
		map[string]any{"image": "private.invalid/team/private:secret"},
		map[string]any{"image": "docker.io/envoyproxy/envoy:distroless-v1.38.4"},
		map[string]any{"image": "quay.io/jetstack/cert-manager-controller:v1.17.2"}, // adapter registry, not the image registry
	}, nil)
	result, err := projectWorkload(root, adapter, "v3", testNow)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	for _, private := range []string{"hunter2", "private.invalid", "gke-release", "envoy", "TOKEN"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("%q escaped: %s", private, raw)
		}
	}
	images, _ := array(result["publicImages"])
	got := map[string][]any{}
	for _, row := range images {
		id := at(row, "componentId").(string)
		got[id] = append(got[id], row)
		// Only the existing row shape: nothing but these keys is ever written.
		m, _ := object(row)
		if len(m) != 6 {
			t.Fatalf("row has unexpected fields: %v", m)
		}
	}
	if len(images) != 5 {
		t.Fatalf("rows=%d: %s", len(images), raw)
	}
	wantVersion := map[string]any{
		"pkg:oci/cloudnative-pg/cloudnative-pg": "1.30.1",
		"pkg:oci/velero/velero":                 nil, // latest
		"pkg:oci/goharbor/harbor":               nil, // digest-only
		"pkg:oci/nats-io/nats-server":           "2.15.0",
		"pkg:oci/cert-manager/cert-manager":     "v1.17.2", // adapter path unchanged
	}
	for id, want := range wantVersion {
		rows := got[id]
		if len(rows) != 1 || at(rows[0], "observedVersion") != want {
			t.Fatalf("%s: %#v want version %v", id, rows, want)
		}
	}
	if scheme := at(got["pkg:oci/goharbor/harbor"][0], "versionScheme"); scheme != "digest" {
		t.Fatalf("digest-only scheme %v", scheme)
	}
	if scheme := at(got["pkg:oci/velero/velero"][0], "versionScheme"); scheme != "unknown" {
		t.Fatalf("latest scheme %v", scheme)
	}
}

func TestRegistryImagesIgnoreInitContainersOtherKindsAndLapsedRecords(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	image := map[string]any{"image": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1"}
	for name, root := range map[string]any{
		"init only":       workload("Deployment", []any{map[string]any{"image": "busybox:1"}}, []any{image}),
		"cronjob":         workload("CronJob", []any{image}, nil),
		"job":             workload("Job", []any{image}, nil),
		"replication ctl": workload("ReplicationController", []any{image}, nil),
	} {
		if kind := name; kind == "cronjob" {
			root = map[string]any{"items": []any{map[string]any{"kind": "CronJob", "spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{image}}}}}}}}}
		}
		result, err := projectWorkload(root, adapter, "v3", testNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if images, _ := array(result["publicImages"]); len(images) != 0 {
			t.Fatalf("%s projected %v", name, images)
		}
	}
	result, err := projectWorkload(workload("StatefulSet", []any{image}, nil), adapter, "v3", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if images, _ := array(result["publicImages"]); len(images) != 1 {
		t.Fatalf("statefulset: %v", images)
	}
	// A lapsed registry (record past validUntil) identifies nothing.
	result, err = projectWorkload(workload("Deployment", []any{image}, nil), adapter, "v3", time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if images, _ := array(result["publicImages"]); len(images) != 0 {
		t.Fatalf("expired registry projected %v", images)
	}
}

// The adapter registry stays authoritative for its own images: the image
// registry must not list a repository an adapter already identifies, and the
// cert-manager images stay covered by the adapter registry.
func TestImageRegistryDoesNotOverlapAdapterRegistry(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	table, err := imageidentity.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range table.Repos() {
		identity, _, _, _ := publicImage(repo + ":v1.2.3")
		if m := findAdapter(adapter.Contract, identity); m != nil {
			t.Fatalf("%s is owned by adapter %s", repo, m.ComponentID)
		}
	}
	for _, repo := range []string{"quay.io/jetstack/cert-manager-controller", "quay.io/jetstack/cert-manager-cainjector", "quay.io/jetstack/cert-manager-webhook"} {
		identity, _, _, _ := publicImage(repo + ":v1.17.2")
		if m := findAdapter(adapter.Contract, identity); m == nil || m.ComponentID != "pkg:oci/cert-manager/cert-manager" {
			t.Fatalf("cert-manager %s not covered by the adapter registry: %+v", repo, m)
		}
	}
}

// Records outside the catalog have no compatibility rule that consumes their
// rows, so their images produce no row at all.
func TestRegistryImagesOfNonCatalogRecordsAreNotCollected(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	table, err := imageidentity.Load()
	if err != nil {
		t.Fatal(err)
	}
	none := 0
	for _, r := range table.Records {
		for _, img := range r.Images {
			result, err := projectWorkload(workload("Deployment", []any{map[string]any{"image": img.Repo + ":v1.2.3"}}, nil), adapter, "v3", testNow)
			if err != nil {
				t.Fatal(err)
			}
			rows, _ := array(result["publicImages"])
			switch r.Catalog {
			case imageidentity.CatalogNone:
				none++
				if len(rows) != 0 {
					t.Fatalf("%s (catalog none) produced a row: %v", img.Repo, rows)
				}
			case imageidentity.CatalogMember:
				if len(rows) != 1 {
					t.Fatalf("%s (catalog member) produced %d rows", img.Repo, len(rows))
				}
			}
		}
	}
	if none == 0 {
		t.Fatal("no catalog none record exercised")
	}
}
