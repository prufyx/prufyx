// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/tikvgcpv2"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// GenerateTiKVGCPV2WIFBackup creates empty revision 1 and active revisions 2 and
// 3 under ephemeral test keys. It adds no shipping authority or coverage.
func GenerateTiKVGCPV2WIFBackup(now time.Time) (Artifacts, error) {
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
	sources := []tikvgcpv2.NormativeSource{
		{Role: "target_setting_declaration", RepositoryURL: tikvgcpv2.TiKVRepository, Path: "src/config/mod.rs", Commit: "3f446cfa9eb1d5c653031d261e185911495d0359", ContentDigest: "sha256:aca62aff55a59927e5e6ff1f0d6aebda9aa00e559a110e6fc05f73b42aff2ca3", Spans: []tikvgcpv2.SourceSpan{{StartLine: 2859, EndLine: 2877}, {StartLine: 2910, EndLine: 2928}}},
		{Role: "target_full_backup_caller", RepositoryURL: tikvgcpv2.TiKVRepository, Path: "components/backup/src/endpoint.rs", Commit: "3f446cfa9eb1d5c653031d261e185911495d0359", ContentDigest: "sha256:c111331404f6e8af7fc9b80426d1f989473741c93009f2202488113897f3db46", Spans: []tikvgcpv2.SourceSpan{{StartLine: 63, EndLine: 71}}},
		{Role: "operator_action_guidance", RepositoryURL: tikvgcpv2.DocsRepository, Path: "tikv-configuration-file.md", Commit: "8d85871d64efa8bcad2d3c3c4c7edc2f4f3045be", ContentDigest: "sha256:9b3e8421658de1e93f6d2fa8833688c0bdbd3a02545262e221c9794ca0cca021", Spans: []tikvgcpv2.SourceSpan{{StartLine: 2430, EndLine: 2436}}},
	}
	empty, err := tikvgcpv2.MakeProfile("1", "synthetic_test_only", sources, "")
	if err != nil {
		return Artifacts{}, err
	}
	active, err := tikvgcpv2.MakeProfile("2", "synthetic_test_only", sources, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	continued, err := tikvgcpv2.MakeProfile("3", "synthetic_test_only", sources, now.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return Artifacts{}, err
	}
	first, err := signedTargetPackage(1, now, tikvgcpv2.TargetPath, empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	second, err := signedTargetPackage(2, now, tikvgcpv2.TargetPath, active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	third, err := signedTargetPackage(3, now, tikvgcpv2.TargetPath, continued, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		return Artifacts{}, err
	}
	manifest := Manifest{APIVersion: "prufyx.io/synthetic-tikv-gcp-v2-wif-backup-knowledge-fixture/v1", Purpose: "synthetic_test_only", PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339), BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)}, Revisions: []Revision{{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(first), BundleDigest: digest(empty)}, {Revision: "2", Coverage: "synthetic_tikv_gcp_v2_wif_backup_profile", PackagePath: Revision2Name, PackageDigest: digest(second), BundleDigest: digest(active)}, {Revision: "3", Coverage: "synthetic_tikv_gcp_v2_wif_backup_profile_continuation", PackagePath: Revision3Name, PackageDigest: digest(third), BundleDigest: digest(continued)}}}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Root: rootRaw, Revision1: first, Revision2: second, Revision3: third, Manifest: manifestRaw}, nil
}
