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
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// ErrRejected is returned for any unusable input; it never carries key material.
var ErrRejected = errors.New("knowledge release rejected")

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
	// TUF version used for the targets, snapshot and timestamp roles.
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
	// Expires optionally caps all role expiries (exact UTC RFC3339). The
	// default and maximum is the earliest reviewed-evidence expiry of the
	// exported knowledge.
	Expires string
	// Now is the instant used to reject an already expired release.
	Now time.Time
}

// Result describes the written release.
type Result struct {
	Expires  string                               `json:"expires"`
	Receipt  knowledgepublish.FinalizationReceipt `json:"receipt"`
	Files    []string                             `json:"files"`
	Revision string                               `json:"revision"`
}

// Run builds, signs, verifies and writes one release.
func Run(o Options) (Result, error) {
	if err := o.validate(); err != nil {
		return Result{}, err
	}
	rootRaw, err := read(o.Root, knowledgepublish.MaxRootBytes)
	if err != nil {
		return Result{}, ErrRejected
	}
	if o.Profile == ProfileCNCFProjects {
		return runProjects(o, rootRaw)
	}
	target, err := cncfcheck.ExportEmbeddedExternalBundle(o.Revision)
	if err != nil {
		return Result{}, ErrRejected
	}
	bundle, err := cncfcheck.ParseExternalBundle(target)
	if err != nil {
		return Result{}, ErrRejected
	}
	admission, err := bundle.Admission()
	if err != nil || admission.EvidenceExpiresAt == "" {
		return Result{}, ErrRejected
	}
	expires := admission.EvidenceExpiresAt
	if o.Expires != "" {
		if o.Expires > expires { // canonical UTC RFC3339 compares lexically
			return Result{}, ErrRejected
		}
		expires = o.Expires
	}
	end, err := time.Parse(time.RFC3339, expires)
	if err != nil || end.Format(time.RFC3339) != expires || !end.After(o.Now) {
		return Result{}, ErrRejected
	}

	targetsRaw, err := signRole(o, rootRaw, metadata.TARGETS, o.TargetsKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	snapshotRaw, err := signRole(o, rootRaw, metadata.SNAPSHOT, o.SnapshotKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: rootRaw, Target: target, Targets: targetsRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	timestampRaw, err := signRole(o, rootRaw, metadata.TIMESTAMP, o.TimestampKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: rootRaw, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	packageRaw, planRaw, receipt, err := knowledgepublish.FinalizePackageWithReleasePlan(knowledgepublish.FinalizePackageOptions{
		Root: rootRaw, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw, RootDigest: o.RootDigest,
	}, o.PackageURL)
	if err != nil {
		return Result{}, ErrRejected
	}

	version := strconv.FormatInt(o.Version, 10)
	files := []struct {
		name string
		raw  []byte
	}{
		{"root.json", rootRaw},
		{"constraints.v1.json", target},
		{version + ".targets.json", targetsRaw},
		{version + ".snapshot.json", snapshotRaw},
		{"timestamp.json", timestampRaw},
		{"cncf-" + o.Revision + ".tar", packageRaw},
		{"cncf-" + o.Revision + ".release-plan.json", planRaw},
	}
	if err := os.Mkdir(o.OutputDir, 0o700); err != nil {
		return Result{}, ErrRejected
	}
	result := Result{Expires: expires, Receipt: receipt, Revision: o.Revision}
	for _, f := range files {
		if err := knowledgepublish.WriteExclusive(filepath.Join(o.OutputDir, f.name), f.raw); err != nil {
			return Result{}, ErrRejected
		}
		result.Files = append(result.Files, f.name)
	}
	return result, nil
}

func (o Options) validate() error {
	for _, p := range []string{o.Root, o.TargetsKey, o.SnapshotKey, o.TimestampKey, o.PassphraseFile, o.OutputDir} {
		if !filepath.IsAbs(p) {
			return ErrRejected
		}
	}
	// A per-project release has no release plan, hence no package URL.
	if o.Revision == "" || o.Version <= 0 || o.RootDigest == "" || (o.PackageURL == "" && o.Profile != ProfileCNCFProjects) || o.Now.IsZero() {
		return ErrRejected
	}
	switch o.Profile {
	case "", ProfileCNCF:
		if o.PreviousIndex != "" || o.FirstRelease {
			return fmt.Errorf("previous index and first release apply to the %s profile only: %w", ProfileCNCFProjects, ErrRejected)
		}
	case ProfileCNCFProjects:
		// Fail closed: an omitted previous index would bump every project.
		if (o.PreviousIndex == "") == !o.FirstRelease || o.PreviousIndex != "" && !filepath.IsAbs(o.PreviousIndex) {
			return fmt.Errorf("the %s profile needs exactly one of a previous index and a first release: %w", ProfileCNCFProjects, ErrRejected)
		}
	default:
		return ErrRejected
	}
	if _, err := strconv.ParseUint(o.Revision, 10, 63); err != nil {
		return ErrRejected
	}
	return nil
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

// runProjects builds, signs, verifies and writes one per-project release. It
// publishes no release plan: the plan format describes the single target
// only. The written index is the next previous index to commit.
func runProjects(o Options, rootRaw []byte) (Result, error) {
	var index cncfcheck.ExternalTarget
	var projects []cncfcheck.ExternalTarget
	var err error
	if o.FirstRelease {
		index, projects, err = cncfcheck.BuildEmbeddedExternalTargets(o.Revision, nil)
	} else {
		var previous []byte
		if previous, err = read(o.PreviousIndex, cncfcheck.MaxExternalTargetBytes); err != nil {
			return Result{}, ErrRejected
		}
		// Refuses a revision that does not advance the previous index.
		index, projects, err = cncfcheck.BuildEmbeddedExternalTargetsFrom(o.Revision, previous)
	}
	if err != nil {
		// Includes cncfcheck.ErrDistributionsNotPublishable: distribution
		// records have no project target yet, so the pack cannot be
		// published in this layout.
		return Result{}, fmt.Errorf("build per-project targets: %w", errors.Join(ErrRejected, err))
	}
	parsed, err := cncfcheck.ParseExternalIndex(index.Bytes)
	if err != nil {
		return Result{}, ErrRejected
	}
	admission, err := parsed.Admission()
	if err != nil || admission.EvidenceExpiresAt == "" {
		return Result{}, ErrRejected
	}
	expires := admission.EvidenceExpiresAt
	if o.Expires != "" {
		if o.Expires > expires {
			return Result{}, ErrRejected
		}
		expires = o.Expires
	}
	end, err := time.Parse(time.RFC3339, expires)
	if err != nil || end.Format(time.RFC3339) != expires || !end.After(o.Now) {
		return Result{}, ErrRejected
	}
	set := make([]knowledgepublish.Target, 0, len(projects))
	for _, project := range projects {
		set = append(set, knowledgepublish.Target{Path: project.Path, Raw: project.Bytes})
	}

	targetsRaw, err := signRole(o, rootRaw, metadata.TARGETS, o.TargetsKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: index.Bytes, Projects: set, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	snapshotRaw, err := signRole(o, rootRaw, metadata.SNAPSHOT, o.SnapshotKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: rootRaw, Target: index.Bytes, Projects: set, Targets: targetsRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	timestampRaw, err := signRole(o, rootRaw, metadata.TIMESTAMP, o.TimestampKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: rootRaw, Target: index.Bytes, Projects: set, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: o.RootDigest, Version: o.Version, Expires: expires})
	})
	if err != nil {
		return Result{}, err
	}
	packageRaw, receipt, err := knowledgepublish.FinalizePackage(knowledgepublish.FinalizePackageOptions{
		Root: rootRaw, Target: index.Bytes, Projects: set, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw, RootDigest: o.RootDigest,
	})
	if err != nil {
		return Result{}, ErrRejected
	}

	version := strconv.FormatInt(o.Version, 10)
	files := []struct {
		name string
		raw  []byte
	}{
		{"root.json", rootRaw},
		{version + ".targets.json", targetsRaw},
		{version + ".snapshot.json", snapshotRaw},
		{"timestamp.json", timestampRaw},
		{ProfileCNCFProjects + "-" + o.Revision + ".tar", packageRaw},
		// The targets keep their TUF paths, so the directory can be fed back
		// to the publisher. The index is the next previous index to commit.
		{index.Path, index.Bytes},
	}
	for _, project := range projects {
		files = append(files, struct {
			name string
			raw  []byte
		}{project.Path, project.Bytes})
	}
	if err := os.Mkdir(o.OutputDir, 0o700); err != nil {
		return Result{}, ErrRejected
	}
	result := Result{Expires: expires, Receipt: receipt, Revision: o.Revision}
	for _, f := range files {
		full := filepath.Join(o.OutputDir, filepath.FromSlash(f.name))
		if dir := path.Dir(f.name); dir != "." {
			if err := os.MkdirAll(filepath.Join(o.OutputDir, filepath.FromSlash(dir)), 0o700); err != nil {
				return Result{}, ErrRejected
			}
		}
		if err := knowledgepublish.WriteExclusive(full, f.raw); err != nil {
			return Result{}, ErrRejected
		}
		result.Files = append(result.Files, f.name)
	}
	return result, nil
}
