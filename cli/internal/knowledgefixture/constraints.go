// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// SemanticArtifacts is a private-test fixture with one valid empty revision
// and one TUF-signed target whose CNCF envelope fails fixed admission. Keys
// are generated and discarded inside GenerateConstraintsSemantic.
type SemanticArtifacts struct {
	Root                 []byte
	Revision1            []byte
	ValidRevision2       []byte
	Revision2            []byte
	Revision3            []byte
	Revision4            []byte
	RootDigest           string
	Revision1Digest      string
	ValidRevision2Digest string
	Revision2Digest      string
	Revision3Digest      string
	Revision4Digest      string
}

// GenerateConstraints returns two synthetic revisions under ephemeral keys.
// The first has complete empty coverage; the second contains one Kyverno rule.
// The source references come from the embedded example, but the fixture's
// generated evidence dates are synthetic and do not renew maintainer review.
// No private key is returned or persisted.
func GenerateConstraints(now time.Time) (Artifacts, error) {
	return generateConstraints(now, now.UTC().Add(24*time.Hour))
}

// GenerateConstraintsWithEvidenceExpiry is a test-only variant that keeps TUF
// metadata current while assigning the active rule an independently supplied
// source-evidence expiry. It never persists signing keys.
func GenerateConstraintsWithEvidenceExpiry(now, evidenceExpiry time.Time) (Artifacts, error) {
	return generateConstraints(now, evidenceExpiry)
}

func generateConstraints(now, evidenceExpiry time.Time) (Artifacts, error) {
	now = now.UTC().Truncate(time.Second)
	evidenceExpiry = evidenceExpiry.UTC().Truncate(time.Second)
	if now.IsZero() {
		return Artifacts{}, errors.New("generation time is required")
	}
	keys, err := generateKeySet()
	if err != nil {
		return Artifacts{}, err
	}
	root2Keys, err := generateKeySet()
	if err != nil {
		return Artifacts{}, err
	}
	defer func() {
		for _, keySet := range []map[string]*generatedKey{keys, root2Keys} {
			for _, key := range keySet {
				for index := range key.private {
					key.private[index] = 0
				}
			}
		}
	}()
	root, err := signedRoot(1, now, keys, nil)
	if err != nil {
		return Artifacts{}, err
	}
	root2, err := signedRoot(2, now, root2Keys, keys[metadata.ROOT].signer)
	if err != nil {
		return Artifacts{}, err
	}
	root2Raw, err := root2.ToBytes(false)
	if err != nil {
		return Artifacts{}, err
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		return Artifacts{}, err
	}
	continuation, err := constraintsBundle("3", now, true, evidenceExpiry)
	if err != nil {
		return Artifacts{}, err
	}
	rootFailure, err := signedTargetPackage(3, now, "knowledge/constraints.v1.json", continuation, root2Keys, keys[metadata.TIMESTAMP].signer, map[string][]byte{"metadata/2.root.json": root2Raw})
	if err != nil {
		return Artifacts{}, err
	}
	rootContinuation, err := signedTargetPackage(3, now, "knowledge/constraints.v1.json", continuation, root2Keys, root2Keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	empty, err := constraintsBundle("1", now, false)
	if err != nil {
		return Artifacts{}, err
	}
	active, err := constraintsBundle("2", now, true, evidenceExpiry)
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
	manifest := Manifest{
		APIVersion: "prufyx.io/synthetic-cncf-knowledge-fixture/v1", Purpose: "synthetic_test_only",
		PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339),
		BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)},
		Revisions: []Revision{
			{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(first), BundleDigest: digest(empty)},
			{Revision: "2", Coverage: "synthetic_kyverno_flag_presence", PackagePath: Revision2Name, PackageDigest: digest(second), BundleDigest: digest(active)},
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Root: rootRaw, Revision1: first, Revision2: second, Manifest: manifestRaw, RootV2RefreshFailure: rootFailure, RootV2Continuation: rootContinuation}, nil
}

// GenerateConstraintsSemantic supplies a same-root semantic rejection case.
// The malformed target is still correctly signed and hash-bound by TUF, so
// transport trust can advance before the fixed CNCF admission rejects it.
func GenerateConstraintsSemantic(now time.Time) (SemanticArtifacts, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return SemanticArtifacts{}, errors.New("generation time is required")
	}
	keys, err := generateKeySet()
	if err != nil {
		return SemanticArtifacts{}, err
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
		return SemanticArtifacts{}, err
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	empty, err := constraintsBundle("1", now, false)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	active, err := constraintsBundle("2", now, true)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		return SemanticArtifacts{}, err
	}
	badCapability := "sha256:" + strings.Repeat("0", 64)
	malformed := bytes.Replace(active, []byte(requirements.EngineCapabilityDigest), []byte(badCapability), 1)
	if bytes.Equal(malformed, active) {
		return SemanticArtifacts{}, errors.New("semantic fixture capability mutation missed")
	}
	first, err := signedTargetPackage(1, now, "knowledge/constraints.v1.json", empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	second, err := signedTargetPackage(2, now, "knowledge/constraints.v1.json", malformed, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	validSecond, err := signedTargetPackage(2, now, "knowledge/constraints.v1.json", active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	// These two targets are validly admitted CNCF envelopes, but carry an
	// older/equal semantic revision under fresher TUF metadata.  They prove
	// semantic rollback/conflict handling independently of TUF version checks.
	conflict := bytes.Replace(active,
		[]byte(`"nextAction":"For the declared official upstream bare reports-controller surface, remove reportsChunkSize from literal proposed arguments. Otherwise supply an explicit supported surface declaration or keep the result UNKNOWN; review reporting behavior separately."`),
		[]byte(`"nextAction":"Synthetic fixture alternative: remove reportsChunkSize from the proposed controller arguments."`), 1)
	if bytes.Equal(conflict, active) {
		return SemanticArtifacts{}, errors.New("semantic conflict rule mutation missed")
	}
	conflictPackage, err := signedTargetPackage(3, now, "knowledge/constraints.v1.json", conflict, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	rollbackPackage, err := signedTargetPackage(4, now, "knowledge/constraints.v1.json", empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return SemanticArtifacts{}, err
	}
	return SemanticArtifacts{
		Root: rootRaw, Revision1: first, ValidRevision2: validSecond, Revision2: second, Revision3: conflictPackage, Revision4: rollbackPackage,
		RootDigest: digest(rootRaw), Revision1Digest: digest(empty), ValidRevision2Digest: digest(active), Revision2Digest: digest(malformed),
		Revision3Digest: digest(conflict), Revision4Digest: digest(empty),
	}, nil
}

func constraintsBundle(revision string, now time.Time, active bool, expiry ...time.Time) ([]byte, error) {
	evidenceExpiry := now.Add(24 * time.Hour)
	if len(expiry) == 1 {
		evidenceExpiry = expiry[0]
	}
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		return nil, err
	}
	entries := []cncfcheck.Entry{}
	if active {
		catalogue, err := cncfcheck.Catalog(false, "kyverno")
		if err != nil || len(catalogue.Projects) != 1 {
			return nil, errors.New("synthetic Kyverno source is unavailable")
		}
		for _, entry := range catalogue.Projects[0].Checks {
			var shape struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(entry.Rule, &shape) == nil && shape.ID == "kyverno.reports-chunk-size-removed.1-13" {
				entries = append(entries, entry)
			}
		}
		if len(entries) != 1 {
			return nil, errors.New("synthetic Kyverno source is unavailable")
		}
		var rule map[string]json.RawMessage
		if json.Unmarshal(entries[0].Rule, &rule) != nil {
			return nil, errors.New("synthetic Kyverno rule is invalid")
		}
		var evidence map[string]json.RawMessage
		if json.Unmarshal(rule["evidence"], &evidence) != nil {
			return nil, errors.New("synthetic Kyverno evidence is invalid")
		}
		// These generated dates are test data, not a new maintainer review.
		evidence["reviewedAt"], _ = json.Marshal(now.Add(-time.Hour).Format(time.RFC3339))
		evidence["validUntil"], _ = json.Marshal(evidenceExpiry.Format(time.RFC3339))
		rule["evidence"], _ = json.Marshal(evidence)
		entries[0].Rule, err = json.Marshal(rule)
		if err != nil {
			return nil, err
		}
	}
	pack := struct {
		Schema              string            `json:"schema"`
		Revision            string            `json:"revision"`
		PolicyID            string            `json:"policyId"`
		PolicyDigest        string            `json:"policyDigest"`
		LandscapeFileDigest string            `json:"landscapeFileDigest"`
		RegistryDigest      string            `json:"registryDigest"`
		Entries             []cncfcheck.Entry `json:"entries"`
	}{requirements.PackSchema, revision, requirements.PolicyID, requirements.PolicyDigest, requirements.LandscapeFileDigest, requirements.RegistryDigest, entries}
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
