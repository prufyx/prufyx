// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// StoreInfo describes a verified knowledge database a scan reads.
type StoreInfo struct {
	// Provenance identifies the database, the selected target and the
	// opened project targets in the report.
	Provenance scanreport.KnowledgeStore
	// EvaluatedAt is the verifier's clock: the only instant the selection
	// may be evaluated at.
	EvaluatedAt time.Time
	// Absent lists the opened projects the selected index has no target
	// for; nothing about them can be checked.
	Absent map[string]bool
}

// Store is knowledge selected from a verified local knowledge database.
// Every rule, line review and path policy comes from the database; nothing
// comes from the embedded knowledge.
type Store struct {
	snapshot *cncfcheck.ScanKnowledge
	// digests holds, per opened project, the digest of the envelope that
	// holds its rules.
	digests  map[string]string
	revision string
	digest   string
	info     StoreInfo
}

// StoreError is a knowledge database that could not be opened or verified.
// Reason is catalog text naming the class of failure; it never names the
// path.
type StoreError struct{ Reason string }

func (e *StoreError) Error() string {
	return scanreport.Text(scanreport.UsageKnowledgeDBFailed, e.Reason)
}

// Unwrap makes a StoreError an integrity failure.
func (e *StoreError) Unwrap() error { return ErrIntegrity }

// OpenStore opens and verifies the current selection of the knowledge
// database at path for the named catalog projects, with the verification
// every check with --knowledge-db uses. Any failure is a *StoreError.
func OpenStore(path string, projects []string) (*Store, error) {
	if reason := precheckStore(path); reason != "" {
		return nil, &StoreError{Reason: reason}
	}
	selection, err := cncfknowledge.OpenScan(path, projects)
	if err != nil {
		return nil, &StoreError{Reason: storeFailure(err)}
	}
	bundles := map[string]cncfcheck.ExternalBundle{}
	digests := map[string]string{}
	info := StoreInfo{
		EvaluatedAt: selection.EvaluatedAt, Absent: map[string]bool{},
		Provenance: scanreport.KnowledgeStore{
			Path: filepath.Clean(path), Layout: selection.Layout, TargetPath: selection.TargetPath,
			TrustReceiptDigest: selection.TrustReceiptDigest, Purpose: selection.Purpose, ImportedVerifiedAt: selection.ImportedVerifiedAt,
		},
	}
	for _, project := range selection.Projects {
		bundles[project.Project] = project.Bundle
		digests[project.Project] = project.Bundle.BundleDigest()
		if project.Target == nil {
			continue
		}
		target := *project.Target
		info.Provenance.Projects = append(info.Provenance.Projects, scanreport.KnowledgeStoreProject{
			Project: target.Project, Status: target.Status, TargetPath: target.TargetPath, Revision: target.Revision, Digest: target.Digest,
		})
		if target.Status != "present" {
			info.Absent[project.Project] = true
		}
	}
	snapshot, err := cncfcheck.NewStoreScanKnowledge(bundles)
	if err != nil {
		return nil, &StoreError{Reason: scanreport.KnowledgeDBIntegrity}
	}
	return &Store{snapshot: snapshot, digests: digests, revision: selection.Revision, digest: selection.BundleDigest, info: info}, nil
}

// storeMarkers are the files of which an existing knowledge database holds
// at least one: the profile marker, the selection, or a pending import that
// needs recovery.
var storeMarkers = []string{"profile.json", "selection.json", "import-pending.json"}

// precheckStore refuses, without writing anything, a path that is not an
// existing knowledge database: scan is read-only, and the database opener
// takes a lock (creating its lock file) and creates a missing directory. The
// path must be a directory, not a symbolic link, private to its owner (mode
// 0700, as the database requires), holding a profile, selection or pending
// import file. It returns the failure class, or "" when the opener may run;
// the opener still verifies everything, without following symbolic links.
func precheckStore(path string) string {
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		return scanreport.KnowledgeDBMissing
	case info.Mode()&os.ModeSymlink != 0:
		return scanreport.KnowledgeDBNotPrivate
	case !info.IsDir():
		return scanreport.KnowledgeDBMissing
	case info.Mode().Perm() != 0o700:
		return scanreport.KnowledgeDBNotPrivate
	}
	for _, name := range storeMarkers {
		if marker, err := os.Lstat(filepath.Join(path, name)); err == nil && marker.Mode().IsRegular() {
			return ""
		}
	}
	return scanreport.KnowledgeDBNotAStore
}

// storeFailure names the class of a database failure.
func storeFailure(err error) string {
	switch {
	case errors.Is(err, knowledge.ErrNoSelection):
		return scanreport.KnowledgeDBNoSelection
	case errors.Is(err, knowledge.ErrLayout):
		return scanreport.KnowledgeDBLayout
	case errors.Is(err, knowledge.ErrRollback):
		return scanreport.KnowledgeDBRollback
	case errors.Is(err, knowledge.ErrExpired):
		return scanreport.KnowledgeDBExpired
	case errors.Is(err, knowledge.ErrTrustAdvanced):
		return scanreport.KnowledgeDBTrustAdvanced
	case errors.Is(err, knowledge.ErrRecoveryRequired):
		return scanreport.KnowledgeDBRecovery
	case errors.Is(err, knowledge.ErrIntegrity), errors.Is(err, cncfknowledge.ErrIntegrity), errors.Is(err, cncfcheck.ErrIntegrity):
		return scanreport.KnowledgeDBIntegrity
	case errors.Is(err, knowledge.ErrInvalid), errors.Is(err, cncfknowledge.ErrInvalid), errors.Is(err, cncfcheck.ErrInvalid):
		return scanreport.KnowledgeDBInvalid
	}
	return scanreport.KnowledgeDBIntegrity
}

// Origin is "external_signed_local".
func (k *Store) Origin() string { return k.snapshot.Origin() }

// Revision is the selected revision (the index revision of a per-project
// database).
func (k *Store) Revision() string { return k.revision }

// PackDigest is the digest of the selected target (the index of a
// per-project database).
func (k *Store) PackDigest() string { return k.digest }

// Projects lists every catalog project slug in order.
func (k *Store) Projects() []string { return k.snapshot.Projects() }

// Component returns the subject component of a catalog project.
func (k *Store) Component(slug string) (string, bool) { return k.snapshot.Component(slug) }

// Rules lists the project's rules from the database in rule-id order.
func (k *Store) Rules(project string) []cncfcheck.ScanRule { return k.snapshot.Rules(project) }

// Evaluate evaluates over the project's envelope from the database only.
func (k *Store) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	digest, ok := k.digests[project]
	if !ok {
		return Evaluation{}, ErrIntegrity
	}
	return evaluateSnapshot(k.snapshot, "external_declared", digest, policy, project, facts, inputRaw, now)
}

// AttestationsFor returns the database's line reviews.
func (k *Store) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.snapshot.AttestationsFor(component, line, family, now)
}

// PathPolicyFor returns the database's upgrade-path policy record.
func (k *Store) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	return k.snapshot.PathPolicyFor(component, now)
}

// ServedAPIs: the knowledge database format carries no served lists yet,
// so every Kubernetes API group document is a named gap, as with the
// embedded knowledge.
func (k *Store) ServedAPIs(component, line string, now time.Time) ServedStatus {
	return ServedStatus{}
}

// KnowledgeAge is the end dates of the active rules of the opened targets.
func (k *Store) KnowledgeAge() []knowledgeage.Source { return k.snapshot.KnowledgeAge() }

// Store describes the database.
func (k *Store) Store() *StoreInfo {
	info := k.info
	return &info
}
