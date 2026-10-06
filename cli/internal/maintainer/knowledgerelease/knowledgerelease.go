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

// Options are all inputs of one release. Paths are absolute.
type Options struct {
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
	// PackageURL is the exact HTTPS URL the package will be served from.
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
	if o.Revision == "" || o.Version <= 0 || o.RootDigest == "" || o.PackageURL == "" || o.Now.IsZero() {
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
