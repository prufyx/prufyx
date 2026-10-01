// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"encoding/json"
	"testing"
)

func TestValidateSnapshotMetadataAdmitsClosedGoCRDPolicy(t *testing.T) {
	policy := map[string]any{
		"version": "crd-pagination-policy-v2-go", "endpoint": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "profile": "raw-v1-continue",
		"pageLimit": 50, "maxPages": 64, "maxItems": 10000, "maxVersions": 100000, "maxProjectedBytes": 4 << 20, "overallTimeoutSeconds": 120,
		"localJsonStageDigest": testDigest('a'), "pageProjectionDigest": testDigest('b'), "finalMergeDigest": testDigest('c'),
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	metadata := metadataFile{CRDPaginationPolicy: raw}
	if err := validateSnapshotMetadata(metadata); err != nil {
		t.Fatalf("Go CRD policy rejected: %v", err)
	}
	policy["version"] = "crd-pagination-policy-v3-unknown"
	raw, _ = json.Marshal(policy)
	metadata.CRDPaginationPolicy = raw
	if err := validateSnapshotMetadata(metadata); err == nil {
		t.Fatal("unknown CRD policy version accepted")
	}
}

func testDigest(fill byte) string {
	value := make([]byte, 64)
	for i := range value {
		value[i] = fill
	}
	return "sha256:" + string(value)
}
