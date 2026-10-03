// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"fmt"
	"path"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// ProjectsRepository signs per-project CNCF packages with ephemeral test keys
// held only in memory. It exists for tests; it never serializes a private key.
type ProjectsRepository struct {
	keys       map[string]*generatedKey
	Root       []byte
	RootDigest string
	now        time.Time
}

// ProjectsPackage describes one signed package. Targets are signed into the
// targets role by TUF path. Replace places different bytes under a signed
// target's package member; Omit drops a signed target's member; Extra adds
// unsigned package members verbatim.
type ProjectsPackage struct {
	Version int64
	Targets map[string][]byte
	Replace map[string][]byte
	Omit    []string
	Extra   map[string][]byte
}

// NewProjectsRepository creates a version 1 root with fresh test keys.
func NewProjectsRepository(now time.Time) (*ProjectsRepository, error) {
	keys, err := generateKeySet()
	if err != nil {
		return nil, err
	}
	root, err := signedRoot(1, now, keys, nil)
	if err != nil {
		return nil, err
	}
	raw, err := root.ToBytes(false)
	if err != nil {
		return nil, err
	}
	return &ProjectsRepository{keys: keys, Root: raw, RootDigest: digest(raw), now: now}, nil
}

// Package signs targets, snapshot and timestamp at p.Version and returns the
// canonical package bytes.
func (r *ProjectsRepository) Package(p ProjectsPackage) ([]byte, error) {
	targets := metadata.Targets(r.now.Add(72 * time.Hour))
	targets.Signed.Version = p.Version
	for name, raw := range p.Targets {
		info, err := metadata.TargetFile().FromBytes(name, raw, "sha256")
		if err != nil {
			return nil, fmt.Errorf("target identity %s: %w", name, err)
		}
		targets.Signed.Targets[name] = info
	}
	if _, err := targets.Sign(r.keys[metadata.TARGETS].signer); err != nil {
		return nil, err
	}
	targetsRaw, err := targets.ToBytes(false)
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(r.now.Add(48 * time.Hour))
	snapshot.Signed.Version = p.Version
	snapshot.Signed.Meta["targets.json"] = metaIdentity(p.Version, targetsRaw)
	if _, err := snapshot.Sign(r.keys[metadata.SNAPSHOT].signer); err != nil {
		return nil, err
	}
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		return nil, err
	}
	timestamp := metadata.Timestamp(r.now.Add(24 * time.Hour))
	timestamp.Signed.Version = p.Version
	timestamp.Signed.Meta["snapshot.json"] = metaIdentity(p.Version, snapshotRaw)
	if _, err := timestamp.Sign(r.keys[metadata.TIMESTAMP].signer); err != nil {
		return nil, err
	}
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		return nil, err
	}
	entries := map[string][]byte{
		fmt.Sprintf("metadata/%d.snapshot.json", p.Version): snapshotRaw,
		fmt.Sprintf("metadata/%d.targets.json", p.Version):  targetsRaw,
		"metadata/timestamp.json":                           timestampRaw,
	}
	omitted := map[string]bool{}
	for _, name := range p.Omit {
		omitted[name] = true
	}
	for name, raw := range p.Targets {
		if omitted[name] {
			continue
		}
		member := ProjectsPackageMember(name, raw)
		if replacement, ok := p.Replace[name]; ok {
			raw = replacement
		}
		entries[member] = raw
	}
	for name, raw := range p.Extra {
		entries[name] = raw
	}
	return canonicalTar(entries)
}

// ProjectsPackageMember is the hash-prefixed package member of one target.
func ProjectsPackageMember(targetPath string, raw []byte) string {
	return "targets/" + path.Dir(targetPath) + "/" + hexDigest(raw) + "." + path.Base(targetPath)
}

// Close clears the in-memory private keys.
func (r *ProjectsRepository) Close() {
	for _, key := range r.keys {
		for i := range key.private {
			key.private[i] = 0
		}
	}
}
