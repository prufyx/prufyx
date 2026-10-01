// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cloudeventsstructuredjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// GenerateCloudEventsStructuredJSON creates empty revision 1 and active revisions 2 and
// 3 under ephemeral test keys. It adds no shipping authority or coverage.
func GenerateCloudEventsStructuredJSON(now time.Time) (Artifacts, error) {
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
			for i := range key.private {
				key.private[i] = 0
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
	sources := []cloudeventsstructuredjson.NormativeSource{
		{Role: "spec", RepositoryURL: cloudeventsstructuredjson.NormativeRepository, Path: "spec.md", Commit: "d665aa6402a7ed5d0e506dc1c3cc408dba88d085", ContentDigest: "sha256:145d77472757044983f72ac98bda898ac0eadb0901121cb21794f655e8e1a4e5", Spans: []cloudeventsstructuredjson.SourceSpan{{StartLine: 171, EndLine: 215}, {StartLine: 237, EndLine: 255}, {StartLine: 256, EndLine: 289}, {StartLine: 290, EndLine: 300}, {StartLine: 301, EndLine: 315}}},
		{Role: "json-format", RepositoryURL: cloudeventsstructuredjson.NormativeRepository, Path: "json-format.md", Commit: "d665aa6402a7ed5d0e506dc1c3cc408dba88d085", ContentDigest: "sha256:51d66f45baeb151fea9a114c1a999ae90a39723f5a6f18d8bd3ba9bd97e1d7b4", Spans: []cloudeventsstructuredjson.SourceSpan{{StartLine: 42, EndLine: 45}, {StartLine: 49, EndLine: 70}, {StartLine: 106, EndLine: 115}, {StartLine: 131, EndLine: 142}}},
	}
	empty, err := cloudeventsstructuredjson.MakeProfile("1", "synthetic_test_only", sources, "")
	if err != nil {
		return Artifacts{}, err
	}
	active, err := cloudeventsstructuredjson.MakeProfile("2", "synthetic_test_only", sources, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	continued, err := cloudeventsstructuredjson.MakeProfile("3", "synthetic_test_only", sources, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	first, err := signedTargetPackage(1, now, cloudeventsstructuredjson.TargetPath, empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	second, err := signedTargetPackage(2, now, cloudeventsstructuredjson.TargetPath, active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	third, err := signedTargetPackage(3, now, cloudeventsstructuredjson.TargetPath, continued, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	manifest := Manifest{APIVersion: "prufyx.io/synthetic-cloudevents-structured-json-knowledge-fixture/v1", Purpose: "synthetic_test_only", PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339), BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)}, Revisions: []Revision{{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(first), BundleDigest: digest(empty)}, {Revision: "2", Coverage: "synthetic_structured_json_profile", PackagePath: Revision2Name, PackageDigest: digest(second), BundleDigest: digest(active)}, {Revision: "3", Coverage: "synthetic_structured_json_profile_continuation", PackagePath: Revision3Name, PackageDigest: digest(third), BundleDigest: digest(continued)}}}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Root: rootRaw, Revision1: first, Revision2: second, Revision3: third, Manifest: manifestRaw}, nil
}
