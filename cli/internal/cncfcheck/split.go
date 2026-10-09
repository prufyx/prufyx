// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

// Per-project layout. The CNCF knowledge database is published as one TUF
// target per project plus one small index target. Every project target is a
// complete operator-cncf-knowledge envelope holding only that project's
// entries, so the 1 MiB external bundle cap applies to each target separately.
const (
	ExternalIndexSchema = "prufyx.io/cncf-knowledge-index/v1"
	// ExternalIndexSchemaRecords is the index of a layout in which at least
	// one project target is a records envelope. Its entries say which
	// (records: true). A binary that predates it refuses the index, and
	// with it the whole package.
	ExternalIndexSchemaRecords  = "prufyx.io/cncf-knowledge-index/v2"
	ExternalIndexTargetPath     = "knowledge/cncf/index.v1.json"
	ExternalProjectTargetPrefix = "knowledge/cncf/projects/"
	ExternalProjectTargetSuffix = ".v1.json"
	// MaxExternalTargetBytes is the per-target cap for the index and for
	// every project target. It equals the single-envelope parser cap.
	MaxExternalTargetBytes = maxExternalBundleBytes
	// MaxExternalIndexProjects bounds the project targets one index may list.
	MaxExternalIndexProjects = 256
	// TargetSizeAlarmPercent is the share of MaxExternalTargetBytes at which
	// the maintainer size check fails.
	TargetSizeAlarmPercent = 80
)

var externalProjectTargetRE = regexp.MustCompile(`^knowledge/cncf/projects/([a-z0-9]+(?:-[a-z0-9]+)*)\.v1\.json$`)

// ExternalIndexEntry binds one project target. Length and Digest must equal
// the TUF target identity; the remaining fields must equal the semantic
// admission of the project envelope.
type ExternalIndexEntry struct {
	Project           string `json:"project"`
	TargetPath        string `json:"targetPath"`
	Revision          string `json:"revision"`
	Length            int64  `json:"length"`
	Digest            string `json:"digest"`
	RuleDigest        string `json:"ruleDigest"`
	EvidenceExpiresAt string `json:"evidenceExpiresAt"`
	// Records is true when the project target is a records envelope. It is
	// absent from every entry of a v1 index.
	Records bool `json:"records,omitempty"`
}

type externalIndexDocument struct {
	Schema                 string               `json:"schema"`
	Revision               string               `json:"revision"`
	Purpose                string               `json:"purpose"`
	EngineCapabilityDigest string               `json:"engineCapabilityDigest"`
	Projects               []ExternalIndexEntry `json:"projects"`
}

// ExternalIndex is a parser-issued, sealed view of an index target.
type ExternalIndex struct {
	raw       []byte
	document  externalIndexDocument
	admission ExternalAdmission
	base      *bundle
	seal      *externalBundleSeal
}

// ExternalTarget is one built target: its TUF path and exact bytes.
type ExternalTarget struct {
	Path  string
	Bytes []byte
}

// ProjectTargetPath returns the TUF target path of one project target.
func ProjectTargetPath(project string) string {
	return ExternalProjectTargetPrefix + project + ExternalProjectTargetSuffix
}

// ProjectFromTargetPath returns the project slug of a project target path.
func ProjectFromTargetPath(targetPath string) (string, bool) {
	match := externalProjectTargetRE.FindStringSubmatch(targetPath)
	if match == nil || len(match[1]) > 64 {
		return "", false
	}
	return match[1], true
}

// ParseExternalIndex strictly admits an index target: canonical compact JSON,
// the compiled engine capability, sorted unique known projects, and bounded
// per-project identities. It performs no TUF or network operation.
func ParseExternalIndex(raw []byte) (ExternalIndex, error) {
	return parseExternalIndex(raw, nil)
}

func parseExternalIndex(raw []byte, base *bundle) (ExternalIndex, error) {
	if len(raw) == 0 || len(raw) > MaxExternalTargetBytes || scanExternalJSON(raw) != nil {
		return ExternalIndex{}, ErrInvalid
	}
	var document externalIndexDocument
	if strictJSON(raw, &document) != nil {
		return ExternalIndex{}, ErrInvalid
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ExternalIndex{}, ErrInvalid
	}
	if (document.Schema != ExternalIndexSchema && document.Schema != ExternalIndexSchemaRecords) || !validExternalRevision(document.Revision) || (document.Purpose != "operator_provided" && document.Purpose != "synthetic_test_only") || len(document.Projects) == 0 || len(document.Projects) > MaxExternalIndexProjects {
		return ExternalIndex{}, ErrInvalid
	}
	if base == nil {
		loaded, err := load()
		if err != nil {
			return ExternalIndex{}, err
		}
		base = &loaded
	}
	capability, err := externalCapabilityDigest(*base)
	if err != nil || document.EngineCapabilityDigest != capability {
		return ExternalIndex{}, ErrIntegrity
	}
	var earliest time.Time
	withRecords := 0
	for i, entry := range document.Projects {
		if entry.Records {
			withRecords++
		}
		if i > 0 && document.Projects[i-1].Project >= entry.Project {
			return ExternalIndex{}, ErrInvalid
		}
		if !base.hasProject(entry.Project) || entry.TargetPath != ProjectTargetPath(entry.Project) || !validExternalRevision(entry.Revision) || entry.Length < 1 || entry.Length > MaxExternalTargetBytes || !digestPattern.MatchString(entry.Digest) || !digestPattern.MatchString(entry.RuleDigest) {
			return ExternalIndex{}, ErrInvalid
		}
		if _, ok := ProjectFromTargetPath(entry.TargetPath); !ok {
			return ExternalIndex{}, ErrInvalid
		}
		expires, err := time.Parse(time.RFC3339, entry.EvidenceExpiresAt)
		if err != nil || expires.Location() != time.UTC || expires.Format(time.RFC3339) != entry.EvidenceExpiresAt {
			return ExternalIndex{}, ErrInvalid
		}
		if earliest.IsZero() || expires.Before(earliest) {
			earliest = expires
		}
	}
	// The schema is exactly the level the entries need: a v1 index lists
	// no records target, a v2 index at least one.
	if (document.Schema == ExternalIndexSchemaRecords) != (withRecords > 0) {
		return ExternalIndex{}, ErrInvalid
	}
	type ruleBinding struct {
		Project    string `json:"project"`
		Revision   string `json:"revision"`
		RuleDigest string `json:"ruleDigest"`
		Records    bool   `json:"records,omitempty"`
	}
	bindings := make([]ruleBinding, 0, len(document.Projects))
	for _, entry := range document.Projects {
		bindings = append(bindings, ruleBinding{Project: entry.Project, Revision: entry.Revision, RuleDigest: entry.RuleDigest, Records: entry.Records})
	}
	admission := ExternalAdmission{Revision: document.Revision, Purpose: document.Purpose, EngineCapabilityDigest: document.EngineCapabilityDigest, HasRule: true, RuleDigest: externalDigestJSON(bindings), EvidenceExpiresAt: earliest.Format(time.RFC3339)}
	return ExternalIndex{raw: append([]byte(nil), raw...), document: document, admission: admission, base: base, seal: &externalBundleSeal{}}, nil
}

// Admission returns the aggregate semantic identity of the index. RuleDigest
// binds every project's revision and rule digest; EvidenceExpiresAt is the
// earliest expiry over all project targets.
func (x ExternalIndex) Admission() (ExternalAdmission, error) {
	if x.seal == nil {
		return ExternalAdmission{}, ErrIntegrity
	}
	return x.admission, nil
}

// Entries returns a copy of the index entries in project order.
func (x ExternalIndex) Entries() []ExternalIndexEntry {
	if x.seal == nil {
		return nil
	}
	return append([]ExternalIndexEntry(nil), x.document.Projects...)
}

// Entry returns the entry for one project.
func (x ExternalIndex) Entry(project string) (ExternalIndexEntry, bool) {
	if x.seal == nil {
		return ExternalIndexEntry{}, false
	}
	for _, entry := range x.document.Projects {
		if entry.Project == project {
			return entry, true
		}
	}
	return ExternalIndexEntry{}, false
}

// AdmitExternalProjectTarget admits one project target against its index
// entry: exact length and digest, envelope revision and purpose, every rule
// entry and every record owned by the project, whether the target is a
// records envelope, and the semantic content digest and expiry. Any mismatch
// is an integrity failure.
func AdmitExternalProjectTarget(index ExternalIndex, project string, raw []byte) (ExternalBundle, error) {
	entry, ok := index.Entry(project)
	if !ok || int64(len(raw)) != entry.Length || digest(raw) != entry.Digest {
		return ExternalBundle{}, ErrIntegrity
	}
	bundle, err := parseExternalBundle(raw, index.base)
	if err != nil {
		return ExternalBundle{}, ErrIntegrity
	}
	admission, err := bundle.Admission()
	if err != nil || admission.Revision != entry.Revision || admission.Purpose != index.document.Purpose || admission.EngineCapabilityDigest != index.document.EngineCapabilityDigest || !(admission.HasRule || admission.HasRecords) || admission.HasRecords != entry.Records || admission.RuleDigest != entry.RuleDigest || admission.EvidenceExpiresAt != entry.EvidenceExpiresAt {
		return ExternalBundle{}, ErrIntegrity
	}
	for _, item := range bundle.pack.Entries {
		if item.Project != project {
			return ExternalBundle{}, ErrIntegrity
		}
	}
	// A record of another project's scope never rides in this target: the
	// scan would read it as this project's knowledge.
	if !recordsOwnedBy(bundle.pack, project, index.base.landscape.Projects) {
		return ExternalBundle{}, ErrIntegrity
	}
	return bundle, nil
}

// EmptyExternalBundle returns a parsed envelope without rules. It represents
// a project that has no target in the selected index, so evaluation reports
// UNKNOWN. It is never published and grants no authority.
func EmptyExternalBundle(revision, purpose string) (ExternalBundle, error) {
	if !validExternalRevision(revision) || (purpose != "operator_provided" && purpose != "synthetic_test_only") {
		return ExternalBundle{}, ErrInvalid
	}
	base, err := load()
	if err != nil {
		return ExternalBundle{}, err
	}
	raw, err := encodeExternalEnvelope(base, revision, purpose, nil)
	if err != nil {
		return ExternalBundle{}, err
	}
	return ParseExternalBundle(raw)
}

// BuildEmbeddedExternalTargets splits the embedded CNCF pack into one target
// per project plus the index, deterministically. Every project target gets
// revision unless projectRevisions names another revision for it.
func BuildEmbeddedExternalTargets(revision string, projectRevisions map[string]string) (ExternalTarget, []ExternalTarget, error) {
	return buildEmbeddedExternalTargets(revision, "operator_provided", func(project string, _ func(string) ([]byte, error)) (string, error) {
		if value, ok := projectRevisions[project]; ok {
			return value, nil
		}
		return revision, nil
	})
}

// BuildEmbeddedExternalTargetsFrom builds the per-project layout at revision
// while keeping the previous revision of every project whose target bytes
// would be unchanged. The previous index must be admitted by this binary.
func BuildEmbeddedExternalTargetsFrom(revision string, previousIndex []byte) (ExternalTarget, []ExternalTarget, error) {
	previous, err := ParseExternalIndex(previousIndex)
	if err != nil {
		return ExternalTarget{}, nil, err
	}
	prior, err := strconvRevision(previous.document.Revision)
	if err != nil {
		return ExternalTarget{}, nil, err
	}
	next, err := strconvRevision(revision)
	if err != nil || next <= prior {
		return ExternalTarget{}, nil, ErrInvalid
	}
	return buildEmbeddedExternalTargets(revision, previous.document.Purpose, func(project string, encode func(string) ([]byte, error)) (string, error) {
		entry, ok := previous.Entry(project)
		if !ok {
			return revision, nil
		}
		raw, err := encode(entry.Revision)
		if err != nil {
			return "", err
		}
		if digest(raw) == entry.Digest {
			return entry.Revision, nil
		}
		return revision, nil
	})
}

func buildEmbeddedExternalTargets(revision, purpose string, revisionFor func(string, func(string) ([]byte, error)) (string, error)) (ExternalTarget, []ExternalTarget, error) {
	if !validExternalRevision(revision) {
		return ExternalTarget{}, nil, ErrInvalid
	}
	base, err := load()
	if err != nil {
		return ExternalTarget{}, nil, err
	}
	return buildExternalTargets(base, revision, purpose, revisionFor)
}

// ErrDistributionsNotPublishable is joined with ErrIntegrity when a source
// pack holds distribution records: they are not scoped to one project, no
// target carries them yet, and the pack is refused rather than published
// without them.
var ErrDistributionsNotPublishable = errors.New("distribution records have no knowledge target yet")

// ErrRecordWithoutOwner is joined with ErrIntegrity when a record names a
// component that is not the subject of exactly one catalog project.
var ErrRecordWithoutOwner = errors.New("a record names no single catalog project")

// buildExternalTargets splits base's pack into project targets. Every rule
// entry goes to its project's target, every record (line attestation,
// upgrade-path policy, served-API list) to the target of the project whose
// subject component it names; a project with records and no rules still
// gets a target. A target with records is a records envelope and the index
// is then a v2 index. A source pack holding distribution records is refused
// rather than published without them.
func buildExternalTargets(base bundle, revision, purpose string, revisionFor func(string, func(string) ([]byte, error)) (string, error)) (ExternalTarget, []ExternalTarget, error) {
	if len(base.pack.Distributions) > 0 {
		return ExternalTarget{}, nil, errors.Join(ErrIntegrity, ErrDistributionsNotPublishable)
	}
	capability, err := externalCapabilityDigest(base)
	if err != nil {
		return ExternalTarget{}, nil, ErrIntegrity
	}
	byProject := map[string][]Entry{}
	for _, entry := range base.pack.Entries {
		byProject[entry.Project] = append(byProject[entry.Project], entry)
	}
	records, err := splitRecords(base.pack, base.landscape.Projects)
	if err != nil {
		return ExternalTarget{}, nil, errors.Join(ErrIntegrity, ErrRecordWithoutOwner)
	}
	for project := range records {
		if _, ok := byProject[project]; !ok {
			byProject[project] = nil
		}
	}
	projects := make([]string, 0, len(byProject))
	for project := range byProject {
		projects = append(projects, project)
	}
	sort.Strings(projects)
	if len(projects) == 0 || len(projects) > MaxExternalIndexProjects {
		return ExternalTarget{}, nil, ErrIntegrity
	}
	index := externalIndexDocument{Schema: ExternalIndexSchema, Revision: revision, Purpose: purpose, EngineCapabilityDigest: capability}
	if len(records) > 0 {
		index.Schema = ExternalIndexSchemaRecords
	}
	targets := make([]ExternalTarget, 0, len(projects))
	for _, project := range projects {
		entries := byProject[project]
		sections := records[project]
		encode := func(projectRevision string) ([]byte, error) {
			return encodeExternalEnvelopeWithRecords(base, projectRevision, purpose, entries, sections)
		}
		projectRevision, err := revisionFor(project, encode)
		if err != nil {
			return ExternalTarget{}, nil, err
		}
		if !validExternalRevision(projectRevision) {
			return ExternalTarget{}, nil, ErrInvalid
		}
		raw, err := encode(projectRevision)
		if err != nil {
			return ExternalTarget{}, nil, err
		}
		bundle, err := parseExternalBundle(raw, &base)
		if err != nil {
			return ExternalTarget{}, nil, err
		}
		admission, err := bundle.Admission()
		if err != nil {
			return ExternalTarget{}, nil, ErrIntegrity
		}
		index.Projects = append(index.Projects, ExternalIndexEntry{Project: project, TargetPath: ProjectTargetPath(project), Revision: projectRevision, Length: int64(len(raw)), Digest: digest(raw), RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt, Records: admission.HasRecords})
		targets = append(targets, ExternalTarget{Path: ProjectTargetPath(project), Bytes: raw})
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		return ExternalTarget{}, nil, ErrIntegrity
	}
	parsed, err := parseExternalIndex(indexRaw, &base)
	if err != nil {
		return ExternalTarget{}, nil, err
	}
	for _, target := range targets {
		project, _ := ProjectFromTargetPath(target.Path)
		if _, err := AdmitExternalProjectTarget(parsed, project, target.Bytes); err != nil {
			return ExternalTarget{}, nil, err
		}
	}
	return ExternalTarget{Path: ExternalIndexTargetPath, Bytes: indexRaw}, targets, nil
}

// encodeExternalEnvelope writes one compact envelope over entries. The pack
// schema follows the entries exactly as validPackSchema requires.
func encodeExternalEnvelope(base bundle, revision, purpose string, entries []Entry) ([]byte, error) {
	return encodeExternalEnvelopeWithRecords(base, revision, purpose, entries, recordSections{})
}

// encodeExternalEnvelopeWithRecords is encodeExternalEnvelope with record
// sections: the envelope is a records envelope exactly when it carries one.
func encodeExternalEnvelopeWithRecords(base bundle, revision, purpose string, entries []Entry, records recordSections) ([]byte, error) {
	capability, err := externalCapabilityDigest(base)
	if err != nil {
		return nil, ErrIntegrity
	}
	if entries == nil {
		entries = []Entry{}
	}
	pack := rulePack{Revision: revision, PolicyID: base.pack.PolicyID, PolicyDigest: base.pack.PolicyDigest, LandscapeFileDigest: base.pack.LandscapeFileDigest, RegistryDigest: base.pack.RegistryDigest, Entries: entries,
		LineAttestations: records.LineAttestations, PathPolicies: records.PathPolicies, ServedAPIs: records.ServedAPIs}
	pack.Schema, err = requiredPackSchema(pack)
	if err != nil {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(struct {
		Schema                 string   `json:"schema"`
		Revision               string   `json:"revision"`
		Purpose                string   `json:"purpose"`
		EngineCapabilityDigest string   `json:"engineCapabilityDigest"`
		Pack                   rulePack `json:"pack"`
	}{envelopeSchemaFor(pack), revision, purpose, capability, pack})
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func strconvRevision(value string) (uint64, error) {
	if !validExternalRevision(value) {
		return 0, ErrInvalid
	}
	var n uint64
	for _, c := range value {
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

// TargetSizeAlarmBytes is the smallest target size that fails the size check.
func TargetSizeAlarmBytes() int64 {
	limit := int64(MaxExternalTargetBytes) * TargetSizeAlarmPercent
	return (limit + 99) / 100
}
