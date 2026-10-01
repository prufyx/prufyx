// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	SyntheticKnativeFrom = "91.0.0"
	SyntheticKnativeTo   = "92.0.0"
)

// GenerateKnativeConstraints returns an empty revision followed by one
// synthetic-test-only Knative rule under ephemeral keys. The fictional tuple
// exercises local knowledge selection without adding shipping coverage.
func GenerateKnativeConstraints(now time.Time) (Artifacts, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return Artifacts{}, errors.New("generation time is required")
	}
	keys, err := generateKeySet()
	if err != nil {
		return Artifacts{}, err
	}
	defer func() {
		for _, key := range keys {
			for index := range key.private {
				key.private[index] = 0
			}
		}
	}()
	root, err := signedRoot(1, now, keys, nil)
	if err != nil {
		return Artifacts{}, err
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		return Artifacts{}, err
	}
	empty, err := constraintsBundle("1", now, false)
	if err != nil {
		return Artifacts{}, err
	}
	active, err := syntheticKnativeConstraintsBundle("2", now)
	if err != nil {
		return Artifacts{}, err
	}
	continued, err := syntheticKnativeConstraintsBundle("3", now)
	if err != nil {
		return Artifacts{}, err
	}
	const targetName = "knowledge/constraints.v1.json"
	first, err := signedTargetPackage(1, now, targetName, empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	second, err := signedTargetPackage(2, now, targetName, active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	third, err := signedTargetPackage(3, now, targetName, continued, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	manifest := Manifest{
		APIVersion: "prufyx.io/synthetic-cncf-knowledge-fixture/v1", Purpose: "synthetic_test_only",
		PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339),
		BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)},
		Revisions: []Revision{
			{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(first), BundleDigest: digest(empty)},
			{Revision: "2", Coverage: "synthetic_knative_named_port", PackagePath: Revision2Name, PackageDigest: digest(second), BundleDigest: digest(active)},
			{Revision: "3", Coverage: "synthetic_knative_named_port_continuation", PackagePath: Revision3Name, PackageDigest: digest(third), BundleDigest: digest(continued)},
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Root: rootRaw, Revision1: first, Revision2: second, Revision3: third, Manifest: manifestRaw}, nil
}

func syntheticKnativeConstraintsBundle(revision string, now time.Time) ([]byte, error) {
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		return nil, err
	}
	catalogue, err := cncfcheck.Catalog(false, "knative")
	if err != nil || len(catalogue.Projects) != 1 || len(catalogue.Projects[0].Checks) != 1 {
		return nil, errors.New("synthetic Knative source is unavailable")
	}
	entry := catalogue.Projects[0].Checks[0]
	entry.Description = "Synthetic-test-only Knative named startup-probe port rule for a fictional version tuple."
	var rule map[string]json.RawMessage
	if json.Unmarshal(entry.Rule, &rule) != nil {
		return nil, errors.New("synthetic Knative rule is invalid")
	}
	var subject map[string]json.RawMessage
	if json.Unmarshal(rule["subject"], &subject) != nil {
		return nil, errors.New("synthetic Knative subject is invalid")
	}
	subject["from"], _ = json.Marshal(SyntheticKnativeFrom)
	subject["to"], _ = json.Marshal(SyntheticKnativeTo)
	rule["subject"], _ = json.Marshal(subject)
	rule["id"], _ = json.Marshal("synthetic.knative-serving-startup-port.91-to-92")
	var evidence map[string]json.RawMessage
	if json.Unmarshal(rule["evidence"], &evidence) != nil {
		return nil, errors.New("synthetic Knative evidence is invalid")
	}
	evidence["reviewedAt"], _ = json.Marshal(now.Add(-time.Hour).Format(time.RFC3339))
	evidence["validUntil"], _ = json.Marshal(now.Add(24 * time.Hour).Format(time.RFC3339))
	rule["evidence"], _ = json.Marshal(evidence)
	entry.Rule, err = json.Marshal(rule)
	if err != nil {
		return nil, err
	}
	pack := struct {
		Schema              string            `json:"schema"`
		Revision            string            `json:"revision"`
		PolicyID            string            `json:"policyId"`
		PolicyDigest        string            `json:"policyDigest"`
		LandscapeFileDigest string            `json:"landscapeFileDigest"`
		RegistryDigest      string            `json:"registryDigest"`
		Entries             []cncfcheck.Entry `json:"entries"`
	}{requirements.PackSchema, revision, requirements.PolicyID, requirements.PolicyDigest, requirements.LandscapeFileDigest, requirements.RegistryDigest, []cncfcheck.Entry{entry}}
	document := struct {
		Schema                 string `json:"schema"`
		Revision               string `json:"revision"`
		Purpose                string `json:"purpose"`
		EngineCapabilityDigest string `json:"engineCapabilityDigest"`
		Pack                   any    `json:"pack"`
	}{requirements.Schema, revision, "synthetic_test_only", requirements.EngineCapabilityDigest, pack}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if _, err := cncfcheck.ParseExternalBundle(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
