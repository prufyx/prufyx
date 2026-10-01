// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgefixture creates public, synthetic TUF packages for the
// offline knowledge database example. It never serializes or persists private
// signing keys and best-effort clears the directly held key slices.
package knowledgefixture

import (
	"archive/tar"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	RootName        = "synthetic-root.json"
	Revision1Name   = "synthetic-revision-1.tar"
	Revision2Name   = "synthetic-revision-2.tar"
	Revision3Name   = "synthetic-revision-3.tar"
	ManifestName    = "synthetic-manifest.json"
	syntheticCanary = "PUBLIC-SYNTHETIC-CANARY-7bd198"
	targetPath      = "knowledge/cert-manager.v1.json"
)

type Artifacts struct {
	Root                       []byte
	Revision1                  []byte
	Revision2                  []byte
	Revision3                  []byte
	Manifest                   []byte
	AdversarialTargetsRollback []byte
	RootV2RefreshFailure       []byte
	RootV2Continuation         []byte
}

type Manifest struct {
	APIVersion           string           `json:"apiVersion"`
	Purpose              string           `json:"purpose"`
	PrivateKeysPersisted bool             `json:"privateKeysPersisted"`
	GeneratedAt          string           `json:"generatedAt"`
	BootstrapRoot        ArtifactIdentity `json:"bootstrapRoot"`
	Revisions            []Revision       `json:"revisions"`
}

type ArtifactIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Revision struct {
	Revision      string `json:"revision"`
	Coverage      string `json:"coverage"`
	PackagePath   string `json:"packagePath"`
	PackageDigest string `json:"packageDigest"`
	BundleDigest  string `json:"bundleDigest"`
}

type bundleDocument struct {
	Schema               string               `json:"schema"`
	Revision             string               `json:"revision"`
	Purpose              string               `json:"purpose"`
	RequiredCapabilities []capabilityDocument `json:"requiredCapabilities"`
	Rules                []ruleDocument       `json:"rules"`
}

type capabilityDocument struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type ruleDocument struct {
	ID               string                   `json:"id"`
	Operator         string                   `json:"operator"`
	Component        string                   `json:"component"`
	Current          chartDocument            `json:"current"`
	Target           chartDocument            `json:"target"`
	RemovedPaths     []string                 `json:"removedPaths"`
	ReplacementFacts replacementFactsDocument `json:"replacementFacts"`
	Sources          []sourceDocument         `json:"sources"`
	Evidence         evidenceDocument         `json:"evidence"`
}

type chartDocument struct {
	Version             string `json:"version"`
	ChartManifestDigest string `json:"chartManifestDigest"`
}

type replacementFactsDocument struct {
	MetricsPath     string `json:"metricsPath"`
	MetricsPortName string `json:"metricsPortName"`
}

type sourceDocument struct {
	ID                   string   `json:"id"`
	URL                  string   `json:"url"`
	Revision             string   `json:"revision"`
	ContentDigest        string   `json:"contentDigest"`
	Spans                []string `json:"spans,omitempty"`
	LicensingDisposition string   `json:"licensingDisposition"`
}

type evidenceDocument struct {
	State            string `json:"state"`
	ReviewedAt       string `json:"reviewedAt"`
	ValidUntil       string `json:"validUntil"`
	TestVectorDigest string `json:"testVectorDigest"`
}

type generatedKey struct {
	private ed25519.PrivateKey
	signer  signature.Signer
}

// Generate creates two sequentially signed packages under one synthetic root.
// Revision 1 deliberately has complete but empty coverage. Revision 2 adds the
// existing reviewed cert-manager predicate. Nothing returned contains a
// private key.
func Generate(now time.Time) (Artifacts, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return Artifacts{}, fmt.Errorf("generation time is required")
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
				for i := range key.private {
					key.private[i] = 0
				}
			}
		}
	}()

	root, err := signedRoot(1, now, keys, nil)
	if err != nil {
		return Artifacts{}, err
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		return Artifacts{}, fmt.Errorf("encode root: %w", err)
	}
	root2, err := signedRoot(2, now, root2Keys, keys[metadata.ROOT].signer)
	if err != nil {
		return Artifacts{}, err
	}
	root2Raw, err := root2.ToBytes(false)
	if err != nil {
		return Artifacts{}, fmt.Errorf("encode rotated root: %w", err)
	}

	emptyBundle, err := encodeBundle("1", now, false)
	if err != nil {
		return Artifacts{}, err
	}
	activeBundle, err := encodeBundle("2", now, true)
	if err != nil {
		return Artifacts{}, err
	}
	continuationBundle, err := encodeBundle("3", now, true)
	if err != nil {
		return Artifacts{}, err
	}
	package1, err := signedPackage(1, now, emptyBundle, keys)
	if err != nil {
		return Artifacts{}, err
	}
	package2, err := signedPackage(2, now, activeBundle, keys)
	if err != nil {
		return Artifacts{}, err
	}
	rollback, err := signedTargetsRollbackPackage(now, activeBundle, keys)
	if err != nil {
		return Artifacts{}, err
	}
	rootFailure, err := signedPackageWithTimestampSigner(3, now, continuationBundle, root2Keys, keys[metadata.TIMESTAMP].signer, map[string][]byte{"metadata/2.root.json": root2Raw})
	if err != nil {
		return Artifacts{}, err
	}
	continuation, err := signedPackage(3, now, continuationBundle, root2Keys)
	if err != nil {
		return Artifacts{}, err
	}
	manifest := Manifest{
		APIVersion: "prufyx.io/synthetic-knowledge-fixture/v1", Purpose: "synthetic_test_only",
		PrivateKeysPersisted: false, GeneratedAt: now.Format(time.RFC3339),
		BootstrapRoot: ArtifactIdentity{Path: RootName, Digest: digest(rootRaw)},
		Revisions: []Revision{
			{Revision: "1", Coverage: "complete_empty", PackagePath: Revision1Name, PackageDigest: digest(package1), BundleDigest: digest(emptyBundle)},
			{Revision: "2", Coverage: "active_removed_monitor_values", PackagePath: Revision2Name, PackageDigest: digest(package2), BundleDigest: digest(activeBundle)},
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Artifacts{}, fmt.Errorf("encode manifest: %w", err)
	}
	return Artifacts{
		Root: rootRaw, Revision1: package1, Revision2: package2, Manifest: manifestRaw,
		AdversarialTargetsRollback: rollback, RootV2RefreshFailure: rootFailure,
		RootV2Continuation: continuation,
	}, nil
}

func generateKeySet() (map[string]*generatedKey, error) {
	keys := map[string]*generatedKey{}
	for _, role := range []string{metadata.ROOT, metadata.SNAPSHOT, metadata.TARGETS, metadata.TIMESTAMP} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate %s key: %w", role, err)
		}
		signer, err := signature.LoadSigner(private, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("load %s signer: %w", role, err)
		}
		keys[role] = &generatedKey{private: private, signer: signer}
	}
	return keys, nil
}

func signedRoot(version int64, now time.Time, keys map[string]*generatedKey, priorRootSigner signature.Signer) (*metadata.Metadata[metadata.RootType], error) {
	root := metadata.Root(now.Add(7 * 24 * time.Hour))
	root.Signed.Version = version
	for _, role := range []string{metadata.ROOT, metadata.SNAPSHOT, metadata.TARGETS, metadata.TIMESTAMP} {
		key, err := metadata.KeyFromPublicKey(keys[role].private.Public())
		if err != nil {
			return nil, fmt.Errorf("convert %s public key: %w", role, err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			return nil, fmt.Errorf("authorize %s key: %w", role, err)
		}
	}
	if priorRootSigner != nil {
		if _, err := root.Sign(priorRootSigner); err != nil {
			return nil, fmt.Errorf("sign rotated root with prior key: %w", err)
		}
	}
	if _, err := root.Sign(keys[metadata.ROOT].signer); err != nil {
		return nil, fmt.Errorf("sign root: %w", err)
	}
	return root, nil
}

func encodeBundle(revision string, now time.Time, active bool) ([]byte, error) {
	document := bundleDocument{
		Schema: certmanagervalues.ExternalBundleSchema, Revision: revision, Purpose: "synthetic_test_only",
		RequiredCapabilities: []capabilityDocument{{ID: certmanagervalues.ExternalEngineCapabilityID, Digest: certmanagervalues.ExternalEngineCapabilityDigest}},
		Rules:                []ruleDocument{},
	}
	if active {
		document.Rules = []ruleDocument{{
			ID: "cert-manager-1.20.3-to-1.21.1-removed-monitor-values", Operator: certmanagervalues.ExternalEngineCapabilityID,
			Component:        "pkg:helm/quay.io/jetstack/charts/cert-manager",
			Current:          chartDocument{Version: certmanagervalues.CurrentVersion, ChartManifestDigest: certmanagervalues.CurrentChartDigest},
			Target:           chartDocument{Version: certmanagervalues.TargetVersion, ChartManifestDigest: certmanagervalues.TargetChartDigest},
			RemovedPaths:     []string{"prometheus.servicemonitor.path", "prometheus.servicemonitor.targetPort", "prometheus.podmonitor.path"},
			ReplacementFacts: replacementFactsDocument{MetricsPath: "/metrics", MetricsPortName: "http-metrics"},
			Sources: []sourceDocument{
				{ID: "current-values-schema", URL: "https://raw.githubusercontent.com/cert-manager/cert-manager/1e1d16d1744e6d9c80e464e58e8d9ab1caed222b/deploy/charts/cert-manager/values.schema.json", Revision: "1e1d16d1744e6d9c80e464e58e8d9ab1caed222b", ContentDigest: "sha256:df61ae0ad0d368c5ae4a7d85ed89ff472e2e3d2d8392c01456ab3539399d2731", LicensingDisposition: "reference-only"},
				{ID: "target-values-schema", URL: "https://raw.githubusercontent.com/cert-manager/cert-manager/24e33194fb39488eff2bbf10c6dc640f407cad44/deploy/charts/cert-manager/values.schema.json", Revision: "24e33194fb39488eff2bbf10c6dc640f407cad44", ContentDigest: "sha256:47730ad9154f6cde7a081de7541f88e085ff92a5e5fd65a41a3d0223ff735bea", LicensingDisposition: "reference-only"},
				{ID: "release-notes", URL: "https://raw.githubusercontent.com/cert-manager/website/979f40477c362194b7bc794bfaa837f5f435b823/content/docs/releases/release-notes/release-notes-1.21.md", Revision: "979f40477c362194b7bc794bfaa837f5f435b823", ContentDigest: "sha256:a0574f2f71e08aed3bd6348db51aa718d9ec6d54b3d0da13ac14372cc365606a", Spans: []string{"28-32", "211-213"}, LicensingDisposition: "reference-only"},
				{ID: "upgrade-guide", URL: "https://raw.githubusercontent.com/cert-manager/website/5ed032b0ba04a4ecc66849088633c6ead901ec6e/content/docs/releases/upgrading/upgrading-1.20-1.21.md", Revision: "5ed032b0ba04a4ecc66849088633c6ead901ec6e", ContentDigest: "sha256:fd8b2fb1b228ca8c926bcde9e9d63dabc2614b29cc8c76ce49547ed5b248736b", Spans: []string{"44-56"}, LicensingDisposition: "reference-only"},
			},
			Evidence: evidenceDocument{State: "active", ReviewedAt: now.Add(-time.Hour).Format(time.RFC3339), ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339), TestVectorDigest: "sha256:b38cb213fbb68dc7bbff5490f96e1cf3d5de0a1604713ecdfa1502e6d985f80a"},
		}}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode revision %s bundle: %w", revision, err)
	}
	if _, err := certmanagervalues.ParseExternalBundle(raw); err != nil {
		return nil, fmt.Errorf("admit revision %s bundle: %w", revision, err)
	}
	return raw, nil
}

func signedPackage(version int64, now time.Time, target []byte, keys map[string]*generatedKey) ([]byte, error) {
	return signedPackageWithTimestampSigner(version, now, target, keys, keys[metadata.TIMESTAMP].signer, nil)
}

func signedPackageWithTimestampSigner(version int64, now time.Time, target []byte, keys map[string]*generatedKey, timestampSigner signature.Signer, extra map[string][]byte) ([]byte, error) {
	return signedTargetPackage(version, now, targetPath, target, keys, timestampSigner, extra)
}

// signedTargetPackage is shared only by the fixed in-process fixture profiles.
// It never returns or persists its ephemeral signing keys.
func signedTargetPackage(version int64, now time.Time, targetName string, target []byte, keys map[string]*generatedKey, timestampSigner signature.Signer, extra map[string][]byte) ([]byte, error) {
	targetInfo, err := metadata.TargetFile().FromBytes(targetName, target, "sha256")
	if err != nil {
		return nil, fmt.Errorf("target identity: %w", err)
	}
	targets := metadata.Targets(now.Add(72 * time.Hour))
	targets.Signed.Version = version
	targets.Signed.Targets[targetName] = targetInfo
	if _, err := targets.Sign(keys[metadata.TARGETS].signer); err != nil {
		return nil, fmt.Errorf("sign targets: %w", err)
	}
	targetsRaw, err := targets.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("encode targets: %w", err)
	}

	snapshot := metadata.Snapshot(now.Add(48 * time.Hour))
	snapshot.Signed.Version = version
	snapshot.Signed.Meta["targets.json"] = metaIdentity(version, targetsRaw)
	if _, err := snapshot.Sign(keys[metadata.SNAPSHOT].signer); err != nil {
		return nil, fmt.Errorf("sign snapshot: %w", err)
	}
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}

	timestamp := metadata.Timestamp(now.Add(24 * time.Hour))
	timestamp.Signed.Version = version
	timestamp.Signed.Meta["snapshot.json"] = metaIdentity(version, snapshotRaw)
	if _, err := timestamp.Sign(timestampSigner); err != nil {
		return nil, fmt.Errorf("sign timestamp: %w", err)
	}
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("encode timestamp: %w", err)
	}

	entries := map[string][]byte{
		fmt.Sprintf("metadata/%d.snapshot.json", version):                                snapshotRaw,
		fmt.Sprintf("metadata/%d.targets.json", version):                                 targetsRaw,
		"metadata/timestamp.json":                                                        timestampRaw,
		fmt.Sprintf("targets/knowledge/%s.%s", hexDigest(target), path.Base(targetName)): target,
	}
	for name, raw := range extra {
		entries[name] = raw
	}
	return canonicalTar(entries)
}

// signedTargetsRollbackPackage is available only through the in-process test
// fixture. Timestamp and snapshot advance to version 3, while snapshot declares
// targets version 1 after revision 2 established targets version 2. It proves
// partial trust progression cannot lower retained rollback floors.
func signedTargetsRollbackPackage(now time.Time, target []byte, keys map[string]*generatedKey) ([]byte, error) {
	targetInfo, err := metadata.TargetFile().FromBytes(targetPath, target, "sha256")
	if err != nil {
		return nil, err
	}
	targets := metadata.Targets(now.Add(72 * time.Hour))
	targets.Signed.Version = 1
	targets.Signed.Targets[targetPath] = targetInfo
	if _, err := targets.Sign(keys[metadata.TARGETS].signer); err != nil {
		return nil, err
	}
	targetsRaw, err := targets.ToBytes(false)
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(now.Add(48 * time.Hour))
	snapshot.Signed.Version = 3
	snapshot.Signed.Meta["targets.json"] = metaIdentity(1, targetsRaw)
	if _, err := snapshot.Sign(keys[metadata.SNAPSHOT].signer); err != nil {
		return nil, err
	}
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		return nil, err
	}
	timestamp := metadata.Timestamp(now.Add(24 * time.Hour))
	timestamp.Signed.Version = 3
	timestamp.Signed.Meta["snapshot.json"] = metaIdentity(3, snapshotRaw)
	if _, err := timestamp.Sign(keys[metadata.TIMESTAMP].signer); err != nil {
		return nil, err
	}
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		return nil, err
	}
	return canonicalTar(map[string][]byte{
		"metadata/1.targets.json":  targetsRaw,
		"metadata/3.snapshot.json": snapshotRaw,
		"metadata/timestamp.json":  timestampRaw,
		fmt.Sprintf("targets/knowledge/%s.cert-manager.v1.json", hexDigest(target)): target,
	})
}

func metaIdentity(version int64, raw []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(raw)
	return &metadata.MetaFiles{Version: version, Length: int64(len(raw)), Hashes: metadata.Hashes{"sha256": metadata.HexBytes(sum[:])}}
}

func canonicalTar(entries map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range names {
		data := entries[name]
		format := tar.FormatUSTAR
		if len(path.Base(name)) > 100 {
			format = tar.FormatGNU
		}
		header := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: format}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hexDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// SyntheticCanary returns the harmless canary used by the runnable example.
// It is deliberately unrelated to every curated path.
func SyntheticCanary() string { return syntheticCanary }
