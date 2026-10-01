// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/spiffex509svid"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// GenerateSPIFFEX509SVID creates empty revision 1 and active revisions 2 and
// 3 under ephemeral test keys. It adds no shipping authority or coverage.
func GenerateSPIFFEX509SVID(now time.Time) (Artifacts, error) {
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
	source := spiffex509svid.NormativeSource{RepositoryURL: spiffex509svid.NormativeRepository, Path: spiffex509svid.NormativePath, Commit: "99470b9abc825f14aa364dfa2c3b53b02ba5db5b", ContentDigest: "sha256:a7dc93995458b750ad6622b3520e91aba21ff9712fa9ec3d16cefce234c9176e", Spans: []spiffex509svid.SourceSpan{{StartLine: 40, EndLine: 43}, {StartLine: 48, EndLine: 52}, {StartLine: 99, EndLine: 103}}}
	empty, err := spiffex509svid.MakeProfile("1", "synthetic_test_only", source, "")
	if err != nil {
		return Artifacts{}, err
	}
	active, err := spiffex509svid.MakeProfile("2", "synthetic_test_only", source, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	continued, err := spiffex509svid.MakeProfile("3", "synthetic_test_only", source, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	first, err := signedTargetPackage(1, now, spiffex509svid.TargetPath, empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	second, err := signedTargetPackage(2, now, spiffex509svid.TargetPath, active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	third, err := signedTargetPackage(3, now, spiffex509svid.TargetPath, continued, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	manifest := Manifest{APIVersion: "prufyx.io/synthetic-spiffe-x509-svid-knowledge-fixture/v1", Purpose: "synthetic_test_only", PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339), BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)}, Revisions: []Revision{{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(first), BundleDigest: digest(empty)}, {Revision: "2", Coverage: "synthetic_public_leaf_uri_san_profile", PackagePath: Revision2Name, PackageDigest: digest(second), BundleDigest: digest(active)}, {Revision: "3", Coverage: "synthetic_public_leaf_uri_san_profile_continuation", PackagePath: Revision3Name, PackageDigest: digest(third), BundleDigest: digest(continued)}}}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Root: rootRaw, Revision1: first, Revision2: second, Revision3: third, Manifest: manifestRaw}, nil
}
