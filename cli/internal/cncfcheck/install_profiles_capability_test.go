// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestInstallProfilesBindExternalCapability(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	current, err := externalCapabilityDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	// The previous capability document did not bind the profile parser and
	// target-byte join. It cannot authorize a profile-bearing target.
	legacy, err := json.Marshal(struct {
		Schema               string `json:"schema"`
		EngineContractDigest string `json:"engineContractDigest"`
		RegistryDigest       string `json:"registryDigest"`
		PolicyID             string `json:"policyId"`
		PolicyDigest         string `json:"policyDigest"`
		LandscapeRevision    string `json:"landscapeRevision"`
		LandscapeFileDigest  string `json:"landscapeFileDigest"`
	}{externalBundleSchema, constraintengine.EngineContractDigest(), base.registry.Digest(), base.pack.PolicyID, base.pack.PolicyDigest, base.landscape.Revision, base.landscape.LandscapeFileDigest})
	if err != nil {
		t.Fatal(err)
	}
	if current == digest(legacy) || lineattest.InstallProfileContract == "" {
		t.Fatal("profile semantics do not change the capability")
	}
	doc := externalCapabilityDocument{InstallProfileContract: lineattest.InstallProfileContract, Schema: externalBundleSchema, EngineContractDigest: constraintengine.EngineContractDigest(), RegistryDigest: base.registry.Digest(), PolicyID: base.pack.PolicyID, PolicyDigest: base.pack.PolicyDigest, LandscapeRevision: base.landscape.Revision, LandscapeFileDigest: base.landscape.LandscapeFileDigest}
	raw, err := json.Marshal(doc)
	if err != nil || digest(raw) != current {
		t.Fatal("compiled capability omits the profile contract")
	}
	if _, err := selectExternalProfile(base, digest(legacy)); err == nil {
		t.Fatal("legacy capability selected a profile-aware parser")
	}
	if _, err := admitIndexCapability(base, current, "sha256:legacy-base", current); err == nil {
		t.Fatal("foreign base capability admitted")
	}
}
