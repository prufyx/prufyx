// SPDX-License-Identifier: AGPL-3.0-only

// Package stagingreceipt verifies the fixed, non-publishing Community staging
// bundle contract. All operations are local and fail closed.
package stagingreceipt

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	Repository                  = "prufyx/prufyx-cli"
	RepositoryID          int64 = 1360163747
	WorkflowPath                = ".github/workflows/community-release.yml"
	PublisherWorkflowPath       = ".github/workflows/community-publish.yml"
	PublisherRef                = "refs/heads/main"
	Event                       = "push"
	Ref                         = "refs/tags/v0.1.0-alpha.5"
	Version                     = "v0.1.0-alpha.5"
	ArtifactName                = "community-staging-bundle"
	ReceiptName                 = "STAGING-RECEIPT.json"
	ChecksumsName               = "SHA256SUMS"
	MaxMetadataBytes      int64 = 64 << 10
	MaxAssetBytes         int64 = 512 << 20
	MaxArchiveBytes       int64 = 640 << 20
)

type ReceiptError struct{ Message string }

func (e *ReceiptError) Error() string { return e.Message }
func reject(f string, a ...any) error { return &ReceiptError{fmt.Sprintf(f, a...)} }

type Identity struct{ BundleDir, Repository, WorkflowPath, WorkflowSHA, Event, RunID, RunAttempt, Ref, SourceSHA, Version string }
type Options struct {
	Identity
	OutputPath string
}
type ArtifactBindingOptions struct{ Metadata, Repository, RunID, ArtifactName string }
type StagingIdentityOptions struct {
	Identity
	RunMetadata, TagMetadata, ArtifactList, ArtifactMetadata string
	TagObjectMetadata                                        []string
	ArtifactID, ArtifactDigest, ArtifactSize, DownloadedSize string
}
type PublisherOptions struct {
	Identity
	PublisherWorkflowSHA, PublisherRunID, PublisherRunAttempt string
	ArtifactID, ArtifactDigest, ArtifactSize                  string
	OutputPath, HandoffPath                                   string
}

// PublisherHandoff returns the read-only handoff evidence for a separately
// authorized publisher. It does not contact a provider or grant write access.
func PublisherHandoff(o PublisherOptions) (map[string]any, error) {
	verified, err := verifiedBundle(o.Identity)
	if err != nil {
		return nil, err
	}
	if _, err := exactHex(o.PublisherWorkflowSHA, 40); err != nil {
		return nil, reject("publisher workflow SHA is invalid")
	}
	if !decimalPositive(o.PublisherRunID) || o.PublisherRunAttempt != "1" {
		return nil, reject("publisher run identity must be a positive first attempt")
	}
	if !decimalPositive(o.ArtifactID) || !decimalPositive(o.ArtifactSize) {
		return nil, reject("staging artifact identity must be positive")
	}
	digest, err := exactHex(o.ArtifactDigest, 64)
	if err != nil {
		return nil, err
	}
	runID, _ := parseInt(o.RunID)
	publisherRun, _ := parseInt(o.PublisherRunID)
	artifactID, _ := parseInt(o.ArtifactID)
	artifactSize, _ := parseInt(o.ArtifactSize)
	evidence := make([]map[string]any, 0, len(verified.assets))
	attestations := make([]map[string]any, 0, len(verified.assets))
	for _, asset := range verified.assets {
		name := asset["name"].(string)
		snapshot, ok := verified.snapshots[name]
		if !ok {
			return nil, reject("staged asset snapshot is incomplete")
		}
		evidence = append(evidence, map[string]any{"name": name, "sha256": "sha256:" + snapshot.digest, "size": snapshot.size})
		attestations = append(attestations, map[string]any{"name": name, "status": "VERIFIED", "repository": Repository, "signerWorkflow": Repository + "/" + WorkflowPath, "signerDigest": o.WorkflowSHA, "sourceRef": o.Ref, "sourceDigest": o.SourceSHA, "denySelfHostedRunners": true})
	}
	return map[string]any{"schemaVersion": "prufyx.io/community-publisher-handoff/v1", "status": "PUBLISHER_HANDOFF_VERIFIED", "repository": Repository, "repositoryId": RepositoryID, "stagingWorkflowPath": WorkflowPath, "stagingWorkflowSha": o.WorkflowSHA, "stagingEvent": Event, "stagingRunId": runID, "stagingRunAttempt": int64(1), "stagingRef": Ref, "sourceSha": o.SourceSHA, "version": Version, "stagingArtifactName": ArtifactName, "publisherWorkflowPath": PublisherWorkflowPath, "publisherWorkflowRef": PublisherRef, "publisherWorkflowSha": o.PublisherWorkflowSHA, "publisherRunId": publisherRun, "publisherRunAttempt": int64(1), "stagingArtifactId": artifactID, "stagingArtifactDigest": "sha256:" + digest, "stagingArtifactSize": artifactSize, "checksumSetDigest": verified.checksum, "stagingReceiptDigest": shaDigest(verified.receipt), "assets": evidence, "attestations": attestations}, nil
}
func CreatePublisherHandoff(o PublisherOptions) error {
	v, e := PublisherHandoff(o)
	if e != nil {
		return e
	}
	b, _ := canonical(v)
	f, e := createExclusive(o.OutputPath, 0600)
	if e != nil {
		return reject("cannot create publisher handoff")
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}
func VerifyPublisherHandoff(o PublisherOptions) error {
	v, e := PublisherHandoff(o)
	if e != nil {
		return e
	}
	raw, e := regularRead(o.HandoffPath, "publisher handoff", MaxMetadataBytes)
	if e != nil {
		return e
	}
	actual, e := decodeStrict(raw)
	if e != nil {
		return reject("publisher handoff is not strict JSON")
	}
	want, _ := canonical(v)
	can, _ := canonical(actual)
	if !bytes.Equal(raw, can) || !bytes.Equal(raw, want) {
		return reject("publisher handoff does not bind the exact verified bundle")
	}
	return nil
}

func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}

func createExclusive(path string, mode os.FileMode) (*os.File, error) {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return parent.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
}
func shaDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func decodeStrict(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, e
	}
	var x any
	if e = d.Decode(&x); e != io.EOF {
		if e == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, e
	}
	return v, nil
}
func decodeValue(d *json.Decoder, n int) (any, error) {
	if n > 128 {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	if x, ok := t.(json.Delim); ok {
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, errors.New("object key is not string")
				}
				if _, ok := m[key]; ok {
					return nil, fmt.Errorf("duplicate JSON key: %s", key)
				}
				v, e := decodeValue(d, n+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			_, e = d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				v, e := decodeValue(d, n+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
		}
	}
	switch x := t.(type) {
	case string, json.Number, bool, nil:
		return x, nil
	}
	return nil, errors.New("invalid JSON value")
}
func exactHex(s string, n int) (string, error) {
	if strings.HasPrefix(s, "sha256:") {
		s = s[7:]
	}
	if len(s) != n {
		return "", reject("digest must be exact lowercase hexadecimal")
	}
	for _, c := range s {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return "", reject("digest must be exact lowercase hexadecimal")
		}
	}
	return s, nil
}
func decimalPositive(s string) bool {
	if s == "" {
		return false
	}
	n := int64(0)
	for _, c := range s {
		if c < '0' || c > '9' || n > (1<<62)/10 {
			return false
		}
		n = n*10 + int64(c-'0')
	}
	return n > 0
}
func parseInt(s string) (int64, error) {
	if !decimalPositive(s) {
		return 0, reject("run ID is invalid")
	}
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
	}
	return n, nil
}
func links(i os.FileInfo) uint64 {
	if s, ok := i.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Nlink)
	}
	return 0
}
func regularRead(path, label string, max int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || links(i) != 1 || i.Size() > max {
		return nil, reject("%s must be a bounded regular single-link file", label)
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, reject("cannot safely read %s", label)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		return nil, reject("cannot safely read %s", label)
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || links(before) != 1 || before.Size() != i.Size() {
		return nil, reject("%s changed before being read", label)
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	after, statErr := f.Stat()
	if e != nil || statErr != nil || int64(len(b)) != before.Size() || int64(len(b)) > max || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return nil, reject("%s changed while being read or exceeds its bound", label)
	}
	return b, nil
}
func regularDigest(path, label string) (string, error) {
	return regularDigestLimit(path, label, MaxAssetBytes)
}
func regularDigestLimit(path, label string, max int64) (string, error) {
	digest, _, err := regularDigestSizeLimit(path, label, max)
	return digest, err
}
func regularDigestSizeLimit(path, label string, max int64) (string, int64, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || links(i) != 1 || i.Size() > max {
		return "", 0, reject("%s must be a bounded regular single-link file", label)
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return "", 0, reject("cannot safely read %s", label)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		return "", 0, reject("cannot safely read %s", label)
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || links(before) != 1 || before.Size() != i.Size() {
		return "", 0, reject("%s changed before being read", label)
	}
	h := sha256.New()
	n, e := io.CopyN(h, f, max+1)
	if e != nil && e != io.EOF {
		return "", 0, reject("cannot hash %s", label)
	}
	after, statErr := f.Stat()
	if statErr != nil || n != before.Size() || n > max || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return "", 0, reject("%s changed while being read", label)
	}
	return hex.EncodeToString(h.Sum(nil)), before.Size(), nil
}
func requiredAssets() []string {
	return []string{"Go-BSD-3-Clause.txt", "LICENSE", "NOTICE", "SBOM.spdx.json", "SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256", "THIRD-PARTY.md", "prufyx-cli_0.1.0-alpha.5_linux_amd64.tar.gz", "prufyx-cli_0.1.0-alpha.5_linux_arm64.tar.gz", "prufyx-cli_0.1.0-alpha.5_source.tar.gz"}
}
func RequiredAssets() []string { return append([]string(nil), requiredAssets()...) }
func identityCheck(i Identity) error {
	if i.Repository != Repository || i.WorkflowPath != WorkflowPath || i.Event != Event || i.Ref != Ref || i.Version != Version {
		return reject("staging identity is not the fixed alpha.5 contract")
	}
	if _, e := exactHex(i.WorkflowSHA, 40); e != nil {
		return reject("workflow SHA is invalid")
	}
	if _, e := exactHex(i.SourceSHA, 40); e != nil {
		return reject("source SHA is invalid")
	}
	if i.RunAttempt != "1" || !decimalPositive(i.RunID) {
		return reject("staging run identity must be a positive first attempt")
	}
	return nil
}
func exactDir(bundle string, receipt bool) error {
	st, e := os.Lstat(bundle)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return reject("bundle directory must be a real directory")
	}
	want := map[string]bool{ChecksumsName: true}
	for _, a := range requiredAssets() {
		want[a] = true
	}
	if receipt {
		want[ReceiptName] = true
	}
	es, e := os.ReadDir(bundle)
	if e != nil || len(es) != len(want) {
		return reject("staging bundle has missing or unexpected entries")
	}
	for _, x := range es {
		if !want[x.Name()] {
			return reject("staging bundle has missing or unexpected entries")
		}
	}
	var total int64
	for n := range want {
		limit := exactDirLimit(n)
		i, e := os.Lstat(filepath.Join(bundle, n))
		if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || links(i) != 1 || i.Size() > limit || i.Size() > MaxAssetBytes-total {
			return reject("staging bundle entry %s exceeds its bound", n)
		}
		total += i.Size()
	}
	var actualTotal int64
	for n := range want {
		limit := exactDirLimit(n)
		if remaining := MaxAssetBytes - actualTotal; limit > remaining {
			limit = remaining
		}
		_, size, e := regularDigestSizeLimit(filepath.Join(bundle, n), "staging bundle entry "+n, limit)
		if e != nil {
			return e
		}
		actualTotal += size
	}
	return nil
}
func exactDirLimit(name string) int64 {
	if name == ChecksumsName || name == ReceiptName {
		return MaxMetadataBytes
	}
	return MaxAssetBytes
}
func parseChecksums(bundle string) ([]map[string]any, string, error) {
	rows, _, digest, _, err := parseChecksumsSnapshot(bundle)
	return rows, digest, err
}

type assetSnapshot struct {
	digest string
	size   int64
}

func parseChecksumsSnapshot(bundle string) ([]map[string]any, map[string]assetSnapshot, string, []byte, error) {
	raw, e := regularRead(filepath.Join(bundle, ChecksumsName), ChecksumsName, MaxMetadataBytes)
	if e != nil {
		return nil, nil, "", nil, e
	}
	total := int64(len(raw))
	var receipt []byte
	if _, e := os.Lstat(filepath.Join(bundle, ReceiptName)); e == nil {
		receipt, e = regularRead(filepath.Join(bundle, ReceiptName), ReceiptName, MaxMetadataBytes)
		if e != nil || int64(len(receipt)) > MaxAssetBytes-total {
			return nil, nil, "", nil, reject("staging receipt exceeds its bound")
		}
		total += int64(len(receipt))
	} else if !os.IsNotExist(e) {
		return nil, nil, "", nil, reject("cannot safely stat staging receipt")
	}
	parts := bytes.SplitAfter(raw, []byte{'\n'})
	names := []string{}
	rows := []map[string]any{}
	for _, line := range parts {
		if len(line) == 0 {
			continue
		}
		if len(line) < 68 || line[64] != ' ' || line[65] != ' ' || line[len(line)-1] != '\n' {
			return nil, nil, "", nil, reject("SHA256SUMS has a non-canonical line")
		}
		d := string(line[:64])
		name := string(line[66 : len(line)-1])
		if _, e := exactHex(d, 64); e != nil || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "/\\\x00\r\n") {
			return nil, nil, "", nil, reject("SHA256SUMS has a non-canonical line")
		}
		for _, n := range names {
			if n == name {
				return nil, nil, "", nil, reject("SHA256SUMS contains a duplicate asset")
			}
		}
		names = append(names, name)
		rows = append(rows, map[string]any{"name": name, "sha256": "sha256:" + d})
	}
	want := requiredAssets()
	if len(names) != len(want) {
		return nil, nil, "", nil, reject("SHA256SUMS asset set is not the fixed staging set")
	}
	snapshots := make(map[string]assetSnapshot, len(names))
	for i, n := range names {
		if n != want[i] {
			return nil, nil, "", nil, reject("SHA256SUMS asset set is not the fixed staging set")
		}
		remaining := MaxAssetBytes - total
		got, size, e := regularDigestSizeLimit(filepath.Join(bundle, n), "staged asset "+n, remaining)
		if e != nil || got != rows[i]["sha256"].(string)[7:] {
			return nil, nil, "", nil, reject("staged asset digest mismatch for %s", n)
		}
		total += size
		snapshots[n] = assetSnapshot{digest: got, size: size}
	}
	return rows, snapshots, shaDigest(raw), receipt, nil
}
func expected(i Identity, bundle string) (map[string]any, error) {
	if e := identityCheck(i); e != nil {
		return nil, e
	}
	assets, checksum, e := parseChecksums(bundle)
	if e != nil {
		return nil, e
	}
	sourceRevision, e := regularRead(filepath.Join(bundle, "SOURCE-REVISION"), "SOURCE-REVISION", MaxMetadataBytes)
	if e != nil {
		return nil, e
	}
	return expectedFromAssets(i, assets, checksum, sourceRevision)
}
func expectedFromAssets(i Identity, assets []map[string]any, checksum string, sourceRevision []byte) (map[string]any, error) {
	if string(sourceRevision) != i.SourceSHA+"\n" {
		return nil, reject("SOURCE-REVISION does not match staged source SHA")
	}
	run, e := parseInt(i.RunID)
	if e != nil {
		return nil, e
	}
	return map[string]any{"schemaVersion": "prufyx.io/community-staging-receipt/v1", "status": "STAGED_BUILD_VERIFIED", "repository": i.Repository, "workflowPath": i.WorkflowPath, "workflowSha": i.WorkflowSHA, "event": i.Event, "runId": run, "runAttempt": int64(1), "ref": i.Ref, "sourceSha": i.SourceSHA, "version": i.Version, "artifactName": ArtifactName, "assets": assets, "checksumSetDigest": checksum, "receiptExcludedFromChecksumSet": true, "attestationSubjects": "assets_listed_in_SHA256SUMS"}, nil
}
func equal(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if !equal(v, y[k]) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case json.Number:
		y, ok := b.(json.Number)
		return ok && x.String() == y.String()
	default:
		return fmt.Sprintf("%T:%v", a, a) == fmt.Sprintf("%T:%v", b, b)
	}
}
func Generate(o Options) (map[string]any, error) {
	if e := exactDir(o.BundleDir, false); e != nil {
		return nil, e
	}
	v, e := expected(o.Identity, o.BundleDir)
	if e != nil {
		return nil, e
	}
	raw, _ := canonical(v)
	p := filepath.Join(o.BundleDir, ReceiptName)
	f, e := createExclusive(p, 0644)
	if e != nil {
		return nil, reject("cannot create in-bundle staging receipt")
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		_ = os.Remove(p)
		return nil, e
	}
	f.Close()
	if _, e = Verify(o); e != nil {
		return nil, e
	}
	return v, nil
}
func Verify(o Options) (map[string]any, error) {
	verified, e := verifiedBundle(o.Identity)
	if e != nil {
		return nil, e
	}
	return verified.receiptValue, nil
}

type bundleSnapshot struct {
	assets       []map[string]any
	snapshots    map[string]assetSnapshot
	checksum     string
	receipt      []byte
	receiptValue map[string]any
}

func verifiedBundle(i Identity) (bundleSnapshot, error) {
	if e := identityCheck(i); e != nil {
		return bundleSnapshot{}, e
	}
	if e := exactDir(i.BundleDir, true); e != nil {
		return bundleSnapshot{}, e
	}
	assets, snapshots, checksum, receipt, e := parseChecksumsSnapshot(i.BundleDir)
	if e != nil {
		return bundleSnapshot{}, e
	}
	sourceRevision, e := regularRead(filepath.Join(i.BundleDir, "SOURCE-REVISION"), "SOURCE-REVISION", MaxMetadataBytes)
	if e != nil {
		return bundleSnapshot{}, e
	}
	sourceSnapshot, ok := snapshots["SOURCE-REVISION"]
	if !ok || sourceSnapshot.digest != strings.TrimPrefix(shaDigest(sourceRevision), "sha256:") || sourceSnapshot.size != int64(len(sourceRevision)) {
		return bundleSnapshot{}, reject("SOURCE-REVISION changed after checksum verification")
	}
	want, e := expectedFromAssets(i, assets, checksum, sourceRevision)
	if e != nil {
		return bundleSnapshot{}, e
	}
	actual, e := decodeStrict(receipt)
	if e != nil {
		return bundleSnapshot{}, reject("staging receipt is not valid strict JSON")
	}
	can, _ := canonical(actual)
	wantRaw, _ := canonical(want)
	if !bytes.Equal(receipt, can) || !bytes.Equal(receipt, wantRaw) {
		return bundleSnapshot{}, reject("staging receipt does not bind the exact verified bundle")
	}
	return bundleSnapshot{assets: assets, snapshots: snapshots, checksum: checksum, receipt: receipt, receiptValue: want}, nil
}
func ArtifactBinding(o ArtifactBindingOptions) (map[string]any, error) {
	if o.Repository != Repository || o.ArtifactName != ArtifactName || !decimalPositive(o.RunID) {
		return nil, reject("artifact binding identity is invalid")
	}
	raw, e := regularRead(o.Metadata, "artifact metadata", MaxMetadataBytes)
	if e != nil {
		return nil, e
	}
	v, e := decodeStrict(raw)
	if e != nil {
		return nil, reject("artifact metadata is not valid strict JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, reject("artifact metadata has no artifact list")
	}
	a, ok := m["artifacts"].([]any)
	if !ok {
		return nil, reject("artifact metadata has no artifact list")
	}
	var found map[string]any
	for _, x := range a {
		q, ok := x.(map[string]any)
		if ok && q["name"] == ArtifactName {
			if found != nil {
				return nil, reject("artifact metadata must contain exactly one fixed staging artifact")
			}
			found = q
		}
	}
	if found == nil {
		return nil, reject("artifact metadata must contain exactly one fixed staging artifact")
	}
	id, ok := found["id"].(json.Number)
	if !ok {
		return nil, reject("artifact metadata has an invalid artifact ID")
	}
	n, e := id.Int64()
	if e != nil || n <= 0 {
		return nil, reject("artifact metadata has an invalid artifact ID")
	}
	dg, ok := found["digest"].(string)
	digest, e := exactHex(dg, 64)
	if !ok || e != nil || len(dg) != 71 || !strings.HasPrefix(dg, "sha256:") {
		return nil, reject("artifact metadata has an invalid artifact digest")
	}
	expired, ok := found["expired"].(bool)
	if !ok || expired {
		return nil, reject("artifact metadata does not bind current unexpired run")
	}
	wr, ok := found["workflow_run"].(map[string]any)
	if !ok {
		return nil, reject("artifact metadata does not bind current run")
	}
	rid, ok := wr["id"].(json.Number)
	if !ok {
		return nil, reject("artifact metadata does not bind current run")
	}
	rn, e := rid.Int64()
	if e != nil {
		return nil, e
	}
	run, e := parseInt(o.RunID)
	if e != nil || rn != run {
		return nil, reject("artifact metadata does not bind current run")
	}
	return map[string]any{"artifactDigest": "sha256:" + digest, "artifactId": n, "artifactName": ArtifactName, "runId": run}, nil
}

func strictObject(path, label string) (map[string]any, error) {
	raw, err := regularRead(path, label, MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	v, err := decodeStrict(raw)
	if err != nil {
		return nil, reject("%s is not strict JSON", label)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, reject("%s must be an object", label)
	}
	return m, nil
}
func num(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	x, e := n.Int64()
	return x, e == nil
}
func artifactProjection(v map[string]any) ([]any, error) {
	run, ok := v["workflow_run"].(map[string]any)
	if !ok {
		return nil, reject("artifact metadata is missing its workflow run projection")
	}
	id, ok := num(v["id"])
	name, nok := v["name"].(string)
	dg, dok := v["digest"].(string)
	size, sok := num(v["size_in_bytes"])
	exp, eok := v["expired"].(bool)
	rid, rok := num(run["id"])
	repo, pok := num(run["repository_id"])
	head, hrok := num(run["head_repository_id"])
	hs, hsok := run["head_sha"].(string)
	if !ok || id <= 0 || !nok || !dok || !sok || size <= 0 || !eok || !rok || rid <= 0 || !pok || !hrok || !hsok {
		return nil, reject("artifact metadata has a wrong-typed security projection")
	}
	if _, err := exactHex(dg, 64); err != nil || len(dg) != 71 || !strings.HasPrefix(dg, "sha256:") {
		return nil, reject("artifact metadata has an invalid digest")
	}
	if _, err := exactHex(hs, 40); err != nil {
		return nil, reject("artifact metadata has an invalid source SHA")
	}
	return []any{id, name, dg, size, exp, rid, repo, head, hs}, nil
}
func jsonEqual(a, b any) bool { x, _ := canonical(a); y, _ := canonical(b); return bytes.Equal(x, y) }

// ValidateStagingIdentity binds the provider metadata projections to the
// exact fixed first-attempt staging run. It only reads caller-supplied JSON.
func ValidateStagingIdentity(o StagingIdentityOptions) error {
	if err := identityCheck(o.Identity); err != nil {
		return err
	}
	if !decimalPositive(o.ArtifactID) || !decimalPositive(o.ArtifactSize) || o.DownloadedSize == "" {
		return reject("artifact identity has invalid numeric fields")
	}
	dg, err := exactHex(o.ArtifactDigest, 64)
	if err != nil {
		return err
	}
	run, err := strictObject(o.RunMetadata, "run metadata")
	if err != nil {
		return err
	}
	repo, ok := run["repository"].(map[string]any)
	head, ok2 := run["head_repository"].(map[string]any)
	rid, rok := num(run["id"])
	if !ok || !ok2 || repo["full_name"] != o.Repository || head["full_name"] != o.Repository || repo["id"] != json.Number(fmt.Sprint(RepositoryID)) || head["id"] != json.Number(fmt.Sprint(RepositoryID)) || !rok || rid <= 0 {
		return reject("run metadata has an unexpected repository identity")
	}
	wantRun, _ := parseInt(o.RunID)
	if rid != wantRun || run["path"] != o.WorkflowPath || run["event"] != o.Event || run["head_sha"] != o.SourceSHA || run["run_attempt"] != json.Number("1") || run["status"] != "completed" || run["conclusion"] != "success" || run["head_branch"] != strings.TrimPrefix(o.Ref, "refs/tags/") {
		return reject("run metadata does not bind the fixed staging identity")
	}
	tag, err := strictObject(o.TagMetadata, "tag ref metadata")
	if err != nil {
		return err
	}
	obj, ok := tag["object"].(map[string]any)
	if !ok {
		return reject("tag ref metadata has no object")
	}
	seen := map[string]bool{}
	for i := 0; obj["type"] == "tag"; i++ {
		if i >= 8 || i >= len(o.TagObjectMetadata) {
			return reject("annotated tag chain is incomplete or too deep")
		}
		sha, ok := obj["sha"].(string)
		if !ok || len(sha) != 40 || seen[sha] {
			return reject("annotated tag chain is invalid or cyclic")
		}
		seen[sha] = true
		tm, e := strictObject(o.TagObjectMetadata[i], "annotated tag metadata")
		if e != nil {
			return e
		}
		if tm["sha"] != sha {
			return reject("annotated tag metadata does not match requested object")
		}
		obj, ok = tm["object"].(map[string]any)
		if !ok {
			return reject("annotated tag metadata has no object")
		}
	}
	if obj["type"] != "commit" || obj["sha"] != o.SourceSHA || len(o.TagObjectMetadata) != len(seen) {
		return reject("tag does not resolve exactly to staged source SHA")
	}
	raw, e := regularRead(o.ArtifactList, "artifact list", MaxMetadataBytes)
	if e != nil {
		return e
	}
	listing, e := decodeStrict(raw)
	if e != nil {
		return reject("artifact list is not strict JSON")
	}
	pages := []any{listing}
	if p, ok := listing.([]any); ok {
		pages = p
	}
	var all []map[string]any
	var total int64 = -1
	ids := map[int64]bool{}
	for _, p := range pages {
		m, ok := p.(map[string]any)
		if !ok {
			return reject("artifact list has no complete page set")
		}
		tc, ok := num(m["total_count"])
		if !ok || (total >= 0 && tc != total) {
			return reject("artifact list pagination is incomplete")
		}
		total = tc
		items, ok := m["artifacts"].([]any)
		if !ok {
			return reject("artifact list has no complete page set")
		}
		for _, item := range items {
			im, ok := item.(map[string]any)
			if !ok {
				return reject("artifact list contains an invalid identity")
			}
			pr, e := artifactProjection(im)
			if e != nil {
				return e
			}
			id := pr[0].(int64)
			if ids[id] {
				return reject("artifact list contains a duplicate identity")
			}
			ids[id] = true
			all = append(all, im)
		}
	}
	if total != int64(len(all)) {
		return reject("artifact list pagination is incomplete")
	}
	direct, e := strictObject(o.ArtifactMetadata, "artifact metadata")
	if e != nil {
		return e
	}
	var match map[string]any
	for _, a := range all {
		if a["name"] == ArtifactName {
			if match != nil {
				return reject("artifact list must contain exactly one fixed staging artifact")
			}
			match = a
		}
	}
	if match == nil {
		return reject("artifact list must contain exactly one fixed staging artifact")
	}
	p1, e := artifactProjection(match)
	if e != nil {
		return e
	}
	p2, e := artifactProjection(direct)
	if e != nil || !jsonEqual(p1, p2) {
		return reject("artifact list and direct security projections do not agree")
	}
	workflowRun, ok := direct["workflow_run"].(map[string]any)
	if !ok {
		return reject("artifact metadata has no workflow run identity")
	}
	aid, _ := parseInt(o.ArtifactID)
	as, _ := parseInt(o.ArtifactSize)
	ds, _ := parseInt(o.DownloadedSize)
	did, _ := num(direct["id"])
	dsize, _ := num(direct["size_in_bytes"])
	workflowID, _ := num(workflowRun["id"])
	repositoryID, _ := num(workflowRun["repository_id"])
	headRepositoryID, _ := num(workflowRun["head_repository_id"])
	headSHA, _ := workflowRun["head_sha"].(string)
	runID, _ := parseInt(o.RunID)
	if did != aid || direct["name"] != ArtifactName || direct["digest"] != "sha256:"+dg || dsize != as || direct["expired"] != false || ds != as ||
		workflowID != runID || repositoryID != RepositoryID || headRepositoryID != RepositoryID || headSHA != o.SourceSHA {
		return reject("artifact does not bind the fixed unexpired staging container")
	}
	return nil
}

// ExtractPublisherZip performs bounded extraction of the exact publisher
// bundle entry set; it never executes an extracted file.
func ExtractPublisherZip(zipPath, expectedSHA, target string) error {
	want, e := exactHex(expectedSHA, 64)
	if e != nil {
		return e
	}
	got, e := regularDigestLimit(zipPath, "publisher artifact ZIP", MaxArchiveBytes)
	if e != nil || got != want {
		return reject("publisher artifact ZIP digest mismatch")
	}
	if _, e = os.Lstat(target); e == nil {
		return reject("publisher extraction target must be new")
	}
	parent := filepath.Dir(target)
	name := filepath.Base(target)
	if name == "." || name == string(filepath.Separator) || name == "" || filepath.Clean(target) != filepath.Join(parent, name) {
		return reject("publisher extraction target is invalid")
	}
	parentRoot, e := os.OpenRoot(parent)
	if e != nil {
		return reject("publisher extraction parent is unavailable")
	}
	defer parentRoot.Close()
	z, e := zip.OpenReader(zipPath)
	if e != nil {
		return reject("cannot safely extract publisher artifact ZIP")
	}
	defer z.Close()
	allowed := map[string]bool{ChecksumsName: true, ReceiptName: true}
	for _, a := range requiredAssets() {
		allowed[a] = true
	}
	if len(z.File) != len(allowed) {
		return reject("publisher artifact ZIP has an unexpected entry set")
	}
	seen := map[string]bool{}
	var total uint64
	if e = parentRoot.Mkdir(name, 0700); e != nil {
		return e
	}
	created, e := parentRoot.Lstat(name)
	if e != nil || !created.IsDir() || created.Mode()&os.ModeSymlink != 0 {
		_ = parentRoot.RemoveAll(name)
		return reject("cannot safely open publisher extraction target")
	}
	bundleRoot, e := parentRoot.OpenRoot(name)
	if e != nil {
		_ = parentRoot.RemoveAll(name)
		return reject("cannot safely open publisher extraction target")
	}
	defer bundleRoot.Close()
	opened, e := bundleRoot.Stat(".")
	if e != nil || !opened.IsDir() || !os.SameFile(created, opened) {
		_ = parentRoot.RemoveAll(name)
		return reject("publisher extraction target changed before opening")
	}
	complete := false
	defer func() {
		if !complete {
			_ = parentRoot.RemoveAll(name)
		}
	}()
	for _, f := range z.File {
		if seen[f.Name] || !allowed[f.Name] || f.Name != filepath.Base(f.Name) || f.FileInfo().Mode().IsDir() || f.FileInfo().Mode()&os.ModeSymlink != 0 || f.Flags&1 != 0 || f.Method != zip.Store && f.Method != zip.Deflate || f.UncompressedSize64 > uint64(MaxAssetBytes) {
			return reject("publisher artifact ZIP contains an unsafe entry")
		}
		seen[f.Name] = true
		total += f.UncompressedSize64
		if total > uint64(MaxAssetBytes) {
			return reject("publisher artifact ZIP exceeds its aggregate bound")
		}
		in, e := f.Open()
		if e != nil {
			return e
		}
		out, e := bundleRoot.OpenFile(f.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			in.Close()
			return e
		}
		written, copyErr := io.CopyN(out, in, int64(f.UncompressedSize64)+1)
		inErr := in.Close()
		outErr := out.Close()
		if copyErr != nil && copyErr != io.EOF {
			return copyErr
		}
		if written != int64(f.UncompressedSize64) {
			return reject("publisher artifact ZIP entry size mismatch")
		}
		if inErr != nil || outErr != nil {
			return reject("cannot safely finalize publisher artifact ZIP entry")
		}
	}
	if len(seen) != len(allowed) {
		return reject("publisher artifact ZIP has an unexpected entry set")
	}
	complete = true
	return nil
}

func parseFlags(args []string, allowed, required map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return nil, reject("invalid staging receipt arguments")
		}
		k := strings.TrimPrefix(args[i], "--")
		takes, ok := allowed[k]
		if !ok || seen[k] {
			return nil, reject("invalid staging receipt arguments")
		}
		if takes {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return nil, reject("invalid staging receipt arguments")
			}
			out[k] = args[i+1]
			i++
		} else {
			out[k] = "true"
		}
		seen[k] = true
	}
	for k := range required {
		if out[k] == "" {
			return nil, reject("invalid staging receipt arguments")
		}
	}
	return out, nil
}
func parseFlagsRepeat(args []string, allowed, required map[string]bool, repeated string) (map[string]string, []string, error) {
	out := map[string]string{}
	seen := map[string]bool{}
	values := []string{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return nil, nil, reject("invalid staging receipt arguments")
		}
		key := strings.TrimPrefix(args[i], "--")
		takes, ok := allowed[key]
		if !ok || (key != repeated && seen[key]) {
			return nil, nil, reject("invalid staging receipt arguments")
		}
		if takes {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return nil, nil, reject("invalid staging receipt arguments")
			}
			if key == repeated {
				values = append(values, args[i+1])
				if len(values) > 8 {
					return nil, nil, reject("annotated tag chain is too deep")
				}
			} else {
				out[key] = args[i+1]
			}
			i++
		} else {
			out[key] = "true"
		}
		seen[key] = true
	}
	for key := range required {
		if !seen[key] || out[key] == "" {
			return nil, nil, reject("invalid staging receipt arguments")
		}
	}
	return out, values, nil
}
func identityFromFlags(f map[string]string) Identity {
	return Identity{BundleDir: f["bundle-dir"], Repository: f["repository"], WorkflowPath: f["workflow-path"], WorkflowSHA: f["workflow-sha"], Event: f["event"], RunID: f["run-id"], RunAttempt: f["run-attempt"], Ref: f["ref"], SourceSHA: f["source-sha"], Version: f["version"]}
}

// Run exposes every legacy staging operation through a provider-independent
// local dispatcher. stdin is accepted for embedding symmetry; no operation
// reads it or contacts a remote service.
func Run(args []string, _ io.Reader, stdout, _ io.Writer) error {
	if len(args) == 0 {
		return reject("missing staging receipt command")
	}
	base := map[string]bool{"bundle-dir": true, "repository": true, "workflow-path": true, "workflow-sha": true, "event": true, "run-id": true, "run-attempt": true, "ref": true, "source-sha": true, "version": true}
	required := map[string]bool{}
	for k := range base {
		required[k] = true
	}
	switch args[0] {
	case "create", "verify":
		f, e := parseFlags(args[1:], base, required)
		if e != nil {
			return e
		}
		o := Options{Identity: identityFromFlags(f)}
		if args[0] == "create" {
			_, e = Generate(o)
		} else {
			_, e = Verify(o)
		}
		return e
	case "artifact-binding":
		f, e := parseFlags(args[1:], map[string]bool{"metadata": true, "repository": true, "run-id": true, "artifact-name": true}, map[string]bool{"metadata": true, "repository": true, "run-id": true, "artifact-name": true})
		if e != nil {
			return e
		}
		v, e := ArtifactBinding(ArtifactBindingOptions{Metadata: f["metadata"], Repository: f["repository"], RunID: f["run-id"], ArtifactName: f["artifact-name"]})
		if e == nil {
			b, _ := canonical(v)
			_, e = stdout.Write(b)
		}
		return e
	case "extract-publisher-zip":
		f, e := parseFlags(args[1:], map[string]bool{"zip-path": true, "zip-sha256": true, "bundle-dir": true}, map[string]bool{"zip-path": true, "zip-sha256": true, "bundle-dir": true})
		if e != nil {
			return e
		}
		return ExtractPublisherZip(f["zip-path"], f["zip-sha256"], f["bundle-dir"])
	case "validate-staging-identity":
		allowed := map[string]bool{"bundle-dir": true, "repository": true, "workflow-path": true, "workflow-sha": true, "event": true, "run-id": true, "run-attempt": true, "ref": true, "source-sha": true, "version": true, "run-metadata": true, "tag-metadata": true, "artifact-list": true, "artifact-metadata": true, "artifact-id": true, "artifact-digest": true, "artifact-size": true, "downloaded-size": true, "tag-object-metadata": true}
		required := map[string]bool{"bundle-dir": true, "repository": true, "workflow-path": true, "workflow-sha": true, "event": true, "run-id": true, "run-attempt": true, "ref": true, "source-sha": true, "version": true, "run-metadata": true, "tag-metadata": true, "artifact-list": true, "artifact-metadata": true, "artifact-id": true, "artifact-digest": true, "artifact-size": true, "downloaded-size": true}
		f, repeated, e := parseFlagsRepeat(args[1:], allowed, required, "tag-object-metadata")
		if e != nil {
			return e
		}
		return ValidateStagingIdentity(StagingIdentityOptions{Identity: identityFromFlags(f), RunMetadata: f["run-metadata"], TagMetadata: f["tag-metadata"], ArtifactList: f["artifact-list"], ArtifactMetadata: f["artifact-metadata"], TagObjectMetadata: repeated, ArtifactID: f["artifact-id"], ArtifactDigest: f["artifact-digest"], ArtifactSize: f["artifact-size"], DownloadedSize: f["downloaded-size"]})
	case "publisher-handoff", "verify-publisher-handoff":
		allowed := map[string]bool{"bundle-dir": true, "repository": true, "workflow-path": true, "workflow-sha": true, "event": true, "run-id": true, "run-attempt": true, "ref": true, "source-sha": true, "version": true, "publisher-workflow-sha": true, "publisher-run-id": true, "publisher-run-attempt": true, "artifact-id": true, "artifact-digest": true, "artifact-size": true, "output": true, "handoff": true}
		req := map[string]bool{}
		for k := range allowed {
			req[k] = true
		}
		delete(req, "output")
		delete(req, "handoff")
		if args[0] == "publisher-handoff" {
			req["output"] = true
		} else {
			req["handoff"] = true
		}
		f, e := parseFlags(args[1:], allowed, req)
		if e != nil {
			return e
		}
		o := PublisherOptions{Identity: identityFromFlags(f), PublisherWorkflowSHA: f["publisher-workflow-sha"], PublisherRunID: f["publisher-run-id"], PublisherRunAttempt: f["publisher-run-attempt"], ArtifactID: f["artifact-id"], ArtifactDigest: f["artifact-digest"], ArtifactSize: f["artifact-size"], OutputPath: f["output"], HandoffPath: f["handoff"]}
		if args[0] == "publisher-handoff" {
			return CreatePublisherHandoff(o)
		}
		return VerifyPublisherHandoff(o)
	default:
		return reject("unknown staging receipt command")
	}
}
