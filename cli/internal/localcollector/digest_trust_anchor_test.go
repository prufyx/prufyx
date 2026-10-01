// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/observation"
)

const (
	prometheusAdapterComponentID = "pkg:oci/prometheus/prometheus"
	prometheusAdapterAssetPath   = "internal/localcollector/assets/component-configuration-adapters-v3.json"
	approvedTableLocation        = "observation.approvedPrometheusImageDigestTable (internal/observation/import.go)"
)

// TestAdapterAssetPrometheusDigestsMatchApprovedTable is the drift guard for
// the Prometheus image-digest trust anchor.
//
// The digests live in two places by necessity: the collector matches an
// observed image against the adapter asset's platformDigests, and the two
// projections (observation and currentbundle) then re-check the digest against
// observation's approved Go table. Nothing in the type system keeps those two
// in agreement, so this test does, in both directions:
//
//   - every approved Go entry must be present in the asset, or the verifier
//     honors a digest capture will never produce; and
//   - every asset platformDigests entry must be approved by the Go table, or
//     the asset has silently grown a binding the verifier does not honor.
//
// Both sides are compared as sets. Nothing here assumes a version has exactly
// one platform digest, so the test survives capture recording more platforms.
func TestAdapterAssetPrometheusDigestsMatchApprovedTable(t *testing.T) {
	t.Parallel()

	registry, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatalf("load v3 adapter assets: %v", err)
	}

	assetDigests, found := prometheusAssetPlatformDigests(t, registry)
	if !found {
		t.Fatalf("%s declares no adapter for component %s, so none of the %d approved digests in %s can ever be reached",
			prometheusAdapterAssetPath, prometheusAdapterComponentID,
			len(observation.ApprovedPrometheusImageDigests()), approvedTableLocation)
	}

	approved := observation.ApprovedPrometheusImageDigests()
	if len(approved) == 0 {
		t.Fatalf("%s is empty; a trust anchor that approves nothing is a verification bypass, not a fix", approvedTableLocation)
	}

	// Direction 1: every approved Go digest must appear in the asset.
	for _, version := range sortedStringKeys(approved) {
		digest := approved[version]
		assetSet, ok := assetDigests[version]
		if !ok {
			t.Errorf("version %s: %s approves digest %s, but %s has no imageBindings entry for version %s. Add the asset binding or remove the approved entry.",
				version, approvedTableLocation, digest, prometheusAdapterAssetPath, version)
			continue
		}
		if !assetSet[digest] {
			t.Errorf("version %s: %s approves digest %s, but that digest is absent from platformDigests in %s, which lists %v. The verifier would honor a digest capture can never produce.",
				version, approvedTableLocation, digest, prometheusAdapterAssetPath, sortedDigestSet(assetSet))
		}
	}

	// Direction 2: every asset platformDigests entry must be approved.
	for _, version := range sortedDigestSetKeys(assetDigests) {
		approvedDigest, ok := approved[version]
		for _, digest := range sortedDigestSet(assetDigests[version]) {
			if !ok {
				t.Errorf("version %s: %s binds platform digest %s, but %s approves no digest for version %s at all. The asset would bind an image the verifier rejects.",
					version, prometheusAdapterAssetPath, digest, approvedTableLocation, version)
				continue
			}
			if approvedDigest != digest {
				t.Errorf("version %s: %s binds platform digest %s, but %s approves only %s. Widen the approved table in the same change, or drop the asset digest.",
					version, prometheusAdapterAssetPath, digest, approvedTableLocation, approvedDigest)
			}
		}
	}
}

// prometheusAssetPlatformDigests collects the Prometheus adapter's declared
// platform digests from the asset, keyed by version, as a set per version.
func prometheusAssetPlatformDigests(t *testing.T, registry adapterAssets) (map[string]map[string]bool, bool) {
	t.Helper()
	digests := make(map[string]map[string]bool)
	found := false
	for _, adapter := range registry.Contract.Adapters {
		if adapter.ComponentID != prometheusAdapterComponentID {
			continue
		}
		found = true
		if adapter.Entrypoint == nil {
			t.Fatalf("adapter %s in %s has no entrypointContract, so no image binding can be verified against %s",
				prometheusAdapterComponentID, prometheusAdapterAssetPath, approvedTableLocation)
		}
		for _, binding := range adapter.Entrypoint.ImageBindings {
			if digests[binding.Version] == nil {
				digests[binding.Version] = make(map[string]bool)
			}
			for _, digest := range binding.PlatformDigests {
				digests[binding.Version][digest] = true
			}
		}
	}
	return digests, found
}

func sortedStringKeys(in map[string]string) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedDigestSetKeys(in map[string]map[string]bool) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedDigestSet(in map[string]bool) []string {
	values := make([]string, 0, len(in))
	for value := range in {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
