// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgerelease builds one complete signed knowledge-database
// release from the reviewed knowledge embedded in this source tree. It is the
// offline, deterministic one-shot composition of the existing export, prepare,
// sign and finalize steps. It never generates keys, reads a clock for metadata,
// uses the network, or publishes anything.
package knowledgerelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// ErrRejected is returned for any unusable input; it never carries key material.
var ErrRejected = errors.New("knowledge release rejected")

// ErrGuard marks a refusal by a pre-signing guard (expectation, replay, expiry
// or state check). No key file has been read when it is returned.
var ErrGuard = errors.New("knowledge release guard")

func guard(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), errors.Join(ErrRejected, ErrGuard))
}

// Role lifetimes. Targets and snapshot live longer than the timestamp so that a
// timestamp-only refresh can keep a package fresh without the other two keys.
const (
	ContentLifetime   = 21 * 24 * time.Hour // targets and snapshot
	TimestampLifetime = 14 * 24 * time.Hour
	minRefreshMargin  = 24 * time.Hour
)

const maxPassphraseBytes = 1024

// Profiles a release can publish. The empty profile means ProfileCNCF.
const (
	ProfileCNCF         = "cncf"
	ProfileCNCFProjects = "cncf-projects"
)

// Options are all inputs of one release. Paths are absolute.
type Options struct {
	// Profile selects the layout: ProfileCNCF (the default) publishes the
	// single external bundle; ProfileCNCFProjects publishes the index plus
	// one target per project, all signed by the same targets role key.
	Profile string
	// PreviousIndex is, for ProfileCNCFProjects, the last published index
	// (a committed, generated file). Projects whose target bytes did not
	// change keep their previous revision, and Revision must be greater than
	// the previous index revision. FirstRelease stands in for it when no
	// index was ever published; exactly one of the two is required.
	PreviousIndex string
	FirstRelease  bool
	// Revision is the positive knowledge revision; Version is the positive
	// TUF version used for the targets, snapshot and timestamp roles. With a
	// previous package it must exceed that package's timestamp version.
	Revision string
	Version  int64
	// Root is the signed public TUF root and RootDigest its independently
	// verified SHA-256 ("sha256:<hex>").
	Root       string
	RootDigest string
	// Role key files are encrypted role keys made by knowledge-sign init.
	TargetsKey, SnapshotKey, TimestampKey string
	// PassphraseFile holds the key passphrase (one line, mode 0600 or tighter).
	PassphraseFile string
	// PackageURL is the exact HTTPS URL the package will be served from. It is
	// only written into the release plan, which ProfileCNCFProjects has none of.
	PackageURL string
	// OutputDir is a new directory; the release is written inside it.
	OutputDir string
	// Expires optionally sets the targets and snapshot expiry (exact UTC
	// RFC3339); it may not exceed the earliest reviewed-evidence expiry or
	// Now+ContentLifetime, which is also the default. Required in CI mode.
	Expires string
	// TimestampExpires optionally sets an earlier timestamp expiry; the default
	// and maximum is min(targets expiry, Now+TimestampLifetime).
	TimestampExpires string
	// Now is the instant used to reject an already expired release and to
	// derive the default expiries.
	Now time.Time

	// CI marks an unattended run: Expires, the content and index expectations
	// and (unless FirstRelease) the previous package expectation are required,
	// and the run attempt must be exactly "1".
	CI bool
	// RunAttempt is the CI run attempt counter (GITHUB_RUN_ATTEMPT). A value
	// other than "1" is always refused; an empty value only outside CI mode.
	RunAttempt string
	// ExpectContentDigest and ExpectIndexDigest bind the signature to the
	// reviewed packet: they are compared with the digests of the exported
	// targets before any key is read.
	ExpectContentDigest string
	ExpectIndexDigest   string
	// PreviousPackage is the live package; it must verify against Root and its
	// digest must equal ExpectPreviousPackageDigest.
	PreviousPackage             string
	ExpectPreviousPackageDigest string
}

// Result describes the written release.
type Result struct {
	// Expires is the targets and snapshot expiry.
	Expires          string                               `json:"expires"`
	TimestampExpires string                               `json:"timestampExpires"`
	Receipt          knowledgepublish.FinalizationReceipt `json:"receipt"`
	Files            []string                             `json:"files"`
	Revision         string                               `json:"revision"`
	ContentDigest    string                               `json:"contentDigest"`
	IndexDigest      string                               `json:"indexDigest"`
	// EvidenceExpiresAt is the evidence expiry bound into the signed package.
	EvidenceExpiresAt string `json:"evidenceExpiresAt"`
	PackageDigest     string `json:"packageDigest"`
	TimestampVersion  int64  `json:"timestampVersion"`
	// PreviousPackageDigest is the verified live package this release replaces.
	PreviousPackageDigest string `json:"previousPackageDigest,omitempty"`
}

// Digests are the keyless identities of the exported targets.
type Digests struct {
	// ContentDigest is the sha256 of the sorted lines "<target path> <sha256 hex>\n"
	// of every exported target (index or bundle, plus project targets).
	ContentDigest string `json:"contentDigest"`
	// IndexDigest is the index digest (per-project) or bundle digest (single).
	IndexDigest string `json:"indexDigest"`
	// EvidenceExpiresAt is the canonical UTC RFC3339 expiry of the evidence
	// bundle behind the targets; a planned expiry is min(now+21d, this value).
	// It is never guessed: a target set whose evidence expiry is absent or not
	// canonical is refused (ErrEvidenceExpiryUnknown).
	EvidenceExpiresAt string `json:"evidenceExpiresAt"`
}

// ErrEvidenceExpiryUnknown is returned when the evidence expiry of the
// exported targets is absent or not canonical UTC RFC3339.
var ErrEvidenceExpiryUnknown = errors.Join(ErrRejected, errors.New("evidence expiry unknown"))

// evidenceExpiry returns value only when it is canonical UTC RFC3339.
func evidenceExpiry(value string) (string, error) {
	if _, err := parseUTC(value); err != nil {
		return "", ErrEvidenceExpiryUnknown
	}
	return value, nil
}

// built is the exported target set of one release.
type built struct {
	target    []byte // the bundle, or the index
	targetRel string // TUF path of target
	projects  []knowledgepublish.Target
	all       []knowledgepublish.Target // every target, index/bundle first
	admission cncfcheck.ExternalAdmission
	digests   Digests
}

// ComputeDigests exports the targets without any key and returns their
// digests. It is what a pre-approval plan derives and what Run then enforces.
func ComputeDigests(o Options) (Digests, error) {
	if err := o.validateBuild(); err != nil {
		return Digests{}, err
	}
	b, err := buildTargets(o)
	if err != nil {
		return Digests{}, err
	}
	return b.digests, nil
}

// ContentDigest hashes a target set independent of order.
func ContentDigest(targets []knowledgepublish.Target) string {
	lines := make([]string, 0, len(targets))
	for _, t := range targets {
		sum := sha256.Sum256(t.Raw)
		lines = append(lines, t.Path+" "+hex.EncodeToString(sum[:])+"\n")
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func buildTargets(o Options) (built, error) {
	if o.Profile == ProfileCNCFProjects {
		return buildProjectTargets(o)
	}
	target, err := cncfcheck.ExportEmbeddedExternalBundle(o.Revision)
	if err != nil {
		return built{}, ErrRejected
	}
	bundle, err := cncfcheck.ParseExternalBundle(target)
	if err != nil {
		return built{}, ErrRejected
	}
	admission, err := bundle.Admission()
	if err != nil {
		return built{}, ErrRejected
	}
	evidence, err := evidenceExpiry(admission.EvidenceExpiresAt)
	if err != nil {
		return built{}, err
	}
	all := []knowledgepublish.Target{{Path: knowledge.ConstraintsTargetPath, Raw: target}}
	return built{target: target, targetRel: knowledge.ConstraintsTargetPath, all: all, admission: admission,
		digests: Digests{ContentDigest: ContentDigest(all), IndexDigest: bundle.BundleDigest(), EvidenceExpiresAt: evidence}}, nil
}

func buildProjectTargets(o Options) (built, error) {
	var index cncfcheck.ExternalTarget
	var projects []cncfcheck.ExternalTarget
	var err error
	if o.FirstRelease {
		index, projects, err = buildFirst(o.Revision, nil)
	} else {
		var previous []byte
		if previous, err = read(o.PreviousIndex, cncfcheck.MaxExternalTargetBytes); err != nil {
			return built{}, ErrRejected
		}
		// Refuses a revision that does not advance the previous index.
		index, projects, err = buildFrom(o.Revision, previous)
	}
	if err != nil {
		// Includes cncfcheck.ErrDistributionsNotPublishable: distribution
		// records have no project target yet, so the pack cannot be
		// published in this layout.
		return built{}, fmt.Errorf("build per-project targets: %w", errors.Join(ErrRejected, err))
	}
	parsed, err := cncfcheck.ParseExternalIndex(index.Bytes)
	if err != nil {
		return built{}, ErrRejected
	}
	admission, err := parsed.Admission()
	if err != nil {
		return built{}, ErrRejected
	}
	evidence, err := evidenceExpiry(admission.EvidenceExpiresAt)
	if err != nil {
		return built{}, err
	}
	set := make([]knowledgepublish.Target, 0, len(projects))
	for _, project := range projects {
		set = append(set, knowledgepublish.Target{Path: project.Path, Raw: project.Bytes})
	}
	all := append([]knowledgepublish.Target{{Path: index.Path, Raw: index.Bytes}}, set...)
	sum := sha256.Sum256(index.Bytes)
	return built{target: index.Bytes, targetRel: index.Path, projects: set, all: all, admission: admission,
		digests: Digests{ContentDigest: ContentDigest(all), IndexDigest: "sha256:" + hex.EncodeToString(sum[:]), EvidenceExpiresAt: evidence}}, nil
}

// Run builds, signs, verifies and writes one release. Every guard runs before
// the first key file is read.
func Run(o Options) (Result, error) {
	if err := o.validate(); err != nil {
		return Result{}, err
	}
	rootRaw, err := read(o.Root, knowledgepublish.MaxRootBytes)
	if err != nil {
		return Result{}, ErrRejected
	}
	b, err := buildTargets(o)
	if err != nil {
		return Result{}, err
	}
	previous, err := o.preflight(b)
	if err != nil {
		return Result{}, err
	}
	targetsExp, timestampExp, err := o.expiries(b.admission.EvidenceExpiresAt)
	if err != nil {
		return Result{}, err
	}

	targetsRaw, err := signRole(o, rootRaw, metadata.TARGETS, o.TargetsKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: b.target, Projects: b.projects, RootDigest: o.RootDigest, Version: o.Version, Expires: targetsExp})
	})
	if err != nil {
		return Result{}, err
	}
	snapshotRaw, err := signRole(o, rootRaw, metadata.SNAPSHOT, o.SnapshotKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: rootRaw, Target: b.target, Projects: b.projects, Targets: targetsRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: targetsExp})
	})
	if err != nil {
		return Result{}, err
	}
	timestampRaw, err := signRole(o, rootRaw, metadata.TIMESTAMP, o.TimestampKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: rootRaw, Target: b.target, Projects: b.projects, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: timestampExp})
	})
	if err != nil {
		return Result{}, err
	}
	finalize := knowledgepublish.FinalizePackageOptions{
		Root: rootRaw, Target: b.target, Projects: b.projects, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw, RootDigest: o.RootDigest,
	}
	var packageRaw, planRaw []byte
	var receipt knowledgepublish.FinalizationReceipt
	if o.Profile == ProfileCNCFProjects {
		packageRaw, receipt, err = knowledgepublish.FinalizePackage(finalize)
	} else {
		packageRaw, planRaw, receipt, err = knowledgepublish.FinalizePackageWithReleasePlan(finalize, o.PackageURL)
	}
	if err != nil {
		return Result{}, ErrRejected
	}
	// The verified target digest is what status.json will publish: it must be
	// the one the reviewed packet announced.
	if receipt.TargetDigest != b.digests.IndexDigest || (o.ExpectIndexDigest != "" && receipt.TargetDigest != o.ExpectIndexDigest) {
		return Result{}, guard("verified target digest differs from the expected index digest")
	}

	version := strconv.FormatInt(o.Version, 10)
	var files []outFile
	if o.Profile == ProfileCNCFProjects {
		files = []outFile{
			{"root.json", rootRaw},
			{version + ".targets.json", targetsRaw},
			{version + ".snapshot.json", snapshotRaw},
			{"timestamp.json", timestampRaw},
			{ProfileCNCFProjects + "-" + o.Revision + ".tar", packageRaw},
			// The targets keep their TUF paths, so the directory can be fed back
			// to the publisher. The index is the next previous index to commit.
			{b.targetRel, b.target},
		}
		for _, p := range b.projects {
			files = append(files, outFile{p.Path, p.Raw})
		}
	} else {
		files = []outFile{
			{"root.json", rootRaw},
			{"constraints.v1.json", b.target},
			{version + ".targets.json", targetsRaw},
			{version + ".snapshot.json", snapshotRaw},
			{"timestamp.json", timestampRaw},
			{"cncf-" + o.Revision + ".tar", packageRaw},
			{"cncf-" + o.Revision + ".release-plan.json", planRaw},
		}
	}
	result := Result{
		Expires: targetsExp, TimestampExpires: timestampExp, Receipt: receipt, Revision: o.Revision,
		ContentDigest: b.digests.ContentDigest, IndexDigest: b.digests.IndexDigest, EvidenceExpiresAt: b.digests.EvidenceExpiresAt, PackageDigest: receipt.PackageDigest,
		TimestampVersion: o.Version,
	}
	if previous != nil {
		result.PreviousPackageDigest = previous.PackageDigest
	}
	if err := writeAll(o.OutputDir, files, &result); err != nil {
		return Result{}, err
	}
	return result, nil
}

type outFile struct {
	name string
	raw  []byte
}

func writeAll(dir string, files []outFile, result *Result) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return ErrRejected
	}
	for _, f := range files {
		full := filepath.Join(dir, filepath.FromSlash(f.name))
		if d := path.Dir(f.name); d != "." {
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o700); err != nil {
				return ErrRejected
			}
		}
		if err := knowledgepublish.WriteExclusive(full, f.raw); err != nil {
			return ErrRejected
		}
		result.Files = append(result.Files, f.name)
	}
	return nil
}

// preflight runs every guard that must pass before a key is read. It returns
// the verified previous package, if one was given.
func (o Options) preflight(b built) (*LiveState, error) {
	if o.RunAttempt != "" && o.RunAttempt != "1" {
		return nil, guard("run attempt %q is not 1: an approved run is never replayed", o.RunAttempt)
	}
	if o.CI {
		if o.RunAttempt != "1" {
			return nil, guard("CI mode needs run attempt 1")
		}
		if o.Expires == "" {
			return nil, guard("CI mode needs an explicit expires")
		}
		if o.ExpectContentDigest == "" || o.ExpectIndexDigest == "" {
			return nil, guard("CI mode needs the expected content and index digests")
		}
		if !o.FirstRelease && (o.ExpectPreviousPackageDigest == "" || o.PreviousPackage == "") {
			return nil, guard("CI mode needs the previous package and its expected digest")
		}
	}
	if o.FirstRelease && (o.ExpectPreviousPackageDigest != "" || o.PreviousPackage != "") {
		return nil, guard("a first release has no previous package")
	}
	if o.ExpectContentDigest != "" && o.ExpectContentDigest != b.digests.ContentDigest {
		return nil, guard("content digest differs from the expected one")
	}
	if o.ExpectIndexDigest != "" && o.ExpectIndexDigest != b.digests.IndexDigest {
		return nil, guard("index digest differs from the expected one")
	}
	if o.ExpectPreviousPackageDigest != "" && o.PreviousPackage == "" {
		return nil, guard("a previous package digest cannot be checked without the package")
	}
	if o.PreviousPackage == "" {
		return nil, nil
	}
	if !filepath.IsAbs(o.PreviousPackage) {
		return nil, guard("previous package path is not absolute")
	}
	live, err := InspectLive(o.PreviousPackage, o.Root, o.RootDigest, o.Profile, o.ExpectPreviousPackageDigest)
	if err != nil {
		return nil, guard("previous package does not verify against the pinned root: %v", err)
	}
	if o.ExpectPreviousPackageDigest != "" && live.PackageDigest != o.ExpectPreviousPackageDigest {
		return nil, guard("previous package digest differs from the expected one")
	}
	if o.Version <= live.TimestampVersion {
		return nil, guard("version %d does not exceed the live timestamp version %d", o.Version, live.TimestampVersion)
	}
	revision, err := strconv.ParseUint(o.Revision, 10, 63)
	liveRevision, liveErr := strconv.ParseUint(live.Revision, 10, 63)
	if err != nil || liveErr != nil || revision <= liveRevision {
		return nil, guard("revision %s does not exceed the live revision %s", o.Revision, live.Revision)
	}
	return &live, nil
}

// expiries derives the targets/snapshot expiry and the timestamp expiry.
func (o Options) expiries(evidence string) (targets, timestamp string, err error) {
	evidenceEnd, err := parseUTC(evidence)
	if err != nil {
		return "", "", ErrRejected
	}
	end := minTime(evidenceEnd, o.Now.UTC().Add(ContentLifetime))
	if o.Expires != "" {
		requested, perr := parseUTC(o.Expires)
		if perr != nil || requested.After(end) {
			return "", "", guard("expires is not canonical UTC or exceeds min(evidence expiry, now+21d)")
		}
		end = requested
	}
	if !end.After(o.Now) {
		return "", "", guard("targets and snapshot would already be expired")
	}
	tsEnd := minTime(end, o.Now.UTC().Add(TimestampLifetime))
	if o.TimestampExpires != "" {
		requested, perr := parseUTC(o.TimestampExpires)
		if perr != nil || requested.After(tsEnd) {
			return "", "", guard("timestamp expires is not canonical UTC or exceeds min(targets expiry, now+14d)")
		}
		tsEnd = requested
	}
	if !tsEnd.After(o.Now) {
		return "", "", guard("timestamp would already be expired")
	}
	return end.Format(time.RFC3339), tsEnd.Format(time.RFC3339), nil
}

func parseUTC(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339) != value {
		return time.Time{}, ErrRejected
	}
	return t, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b.UTC().Truncate(time.Second)
	}
	return a.UTC().Truncate(time.Second)
}

func (o Options) validateBuild() error {
	if o.Revision == "" {
		return ErrRejected
	}
	if _, err := strconv.ParseUint(o.Revision, 10, 63); err != nil {
		return ErrRejected
	}
	switch o.Profile {
	case "", ProfileCNCF:
		if o.PreviousIndex != "" || o.FirstRelease {
			return fmt.Errorf("previous index and first release apply to the %s profile only: %w", ProfileCNCFProjects, ErrRejected)
		}
	case ProfileCNCFProjects:
		// Fail closed: an omitted previous index would bump every project.
		// The first comparison is an XOR: both set or both unset is refused.
		if (o.PreviousIndex == "") == !o.FirstRelease || o.PreviousIndex != "" && !filepath.IsAbs(o.PreviousIndex) {
			return fmt.Errorf("the %s profile needs exactly one of a previous index and a first release: %w", ProfileCNCFProjects, ErrRejected)
		}
	default:
		return ErrRejected
	}
	return nil
}

func (o Options) validate() error {
	for _, p := range []string{o.Root, o.TargetsKey, o.SnapshotKey, o.TimestampKey, o.PassphraseFile, o.OutputDir} {
		if !filepath.IsAbs(p) {
			return ErrRejected
		}
	}
	// A per-project release has no release plan, hence no package URL.
	if o.Version <= 0 || o.RootDigest == "" || (o.PackageURL == "" && o.Profile != ProfileCNCFProjects) || o.Now.IsZero() {
		return ErrRejected
	}
	return o.validateBuild()
}

func signRole(o Options, rootRaw []byte, role, keyPath string, prepare func() (knowledgepublish.Preparation, error)) ([]byte, error) {
	prep, err := prepare()
	if err != nil {
		return nil, ErrRejected
	}
	key, err := read(keyPath, knowledgesign.MaxKeyBytes)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(key)
	passphrase, err := readPassphrase(o.PassphraseFile)
	if err != nil {
		return nil, ErrRejected
	}
	envelope, err := knowledgesign.SignRole(knowledgesign.SignOptions{
		Root: rootRaw, RootDigest: o.RootDigest, Role: role,
		Unsigned: prep.UnsignedMetadata, ExpectedPayloadDigest: payloadDigest(prep.Payload),
		EncryptedKey: key, Passphrase: passphrase,
	})
	if err != nil {
		return nil, ErrRejected
	}
	raw, err := knowledgepublish.FinalizeRole(rootRaw, o.RootDigest, role, prep.UnsignedMetadata, envelope)
	if err != nil {
		return nil, ErrRejected
	}
	return raw, nil
}

func read(path string, limit int) ([]byte, error) { return currentbundle.ReadBoundedFile(path, limit) }

func readPassphrase(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrRejected
	}
	raw, err := read(path, maxPassphraseBytes)
	if err != nil {
		return nil, ErrRejected
	}
	raw = bytes.TrimRight(raw, "\r\n")
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w", ErrRejected)
	}
	return raw, nil
}

func payloadDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Test seams for the per-project builders.
var (
	buildFirst = cncfcheck.BuildEmbeddedExternalTargets
	buildFrom  = cncfcheck.BuildEmbeddedExternalTargetsFrom
)
