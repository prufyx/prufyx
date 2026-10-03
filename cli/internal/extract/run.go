// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// ManifestSchema identifies manifest.json.
const ManifestSchema = "prufyx.io/extractor-run-manifest/v1"

// DefaultLease is the validity window given to every derived rule.
const DefaultLease = 90 * 24 * time.Hour

// Options configures a run.
type Options struct {
	// Repo is the repository to derive from.
	Repo RepoRef
	// DerivedAt stamps every rule (and is its reviewedAt). It must be a
	// whole second in UTC; Verify reuses the recorded value.
	DerivedAt time.Time
	// Lease is the validity window; zero means DefaultLease.
	Lease time.Duration
	// ExistingRules are published pack files whose rule ids a candidate
	// must not reuse.
	ExistingRules []string
}

// Manifest is manifest.json.
type Manifest struct {
	Schema     string                     `json:"schema"`
	Extractor  constraintengine.Extractor `json:"extractor"`
	CodeFiles  []CodeFile                 `json:"codeFiles"`
	Repo       string                     `json:"repo"`
	DerivedAt  string                     `json:"derivedAt"`
	ValidUntil string                     `json:"validUntil"`
	Pairs      []PairRecord               `json:"pairs"`
	Commits    []CommitRecord             `json:"commits"`
	Outputs    map[string]string          `json:"outputs"`
	Totals     Totals                     `json:"totals"`
}

// PairRecord is the outcome for one pair.
type PairRecord struct {
	From       string   `json:"from"`
	FromTag    string   `json:"fromTag"`
	FromCommit string   `json:"fromCommit"`
	To         string   `json:"to"`
	ToTag      string   `json:"toTag"`
	ToCommit   string   `json:"toCommit"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason,omitempty"`
	Rules      []string `json:"rules"`
	Proof      any      `json:"proof"`
	// Attestation is recorded for every pair of an extractor that attests
	// lines, and omitted for any other extractor.
	Attestation *PairAttestation `json:"attestation,omitempty"`
}

// PairAttestation records whether a pair's target line was attested.
type PairAttestation struct {
	Status   string   `json:"status"`
	Line     string   `json:"line"`
	Families []string `json:"families"`
	Reason   string   `json:"reason,omitempty"`
}

// Pair attestation statuses.
const (
	PairAttested    = "attested"
	PairNotAttested = "not-attested"
)

// Pair statuses.
const (
	PairDerived  = "derived"
	PairWithheld = "withheld"
)

// CommitRecord summarises what was read at one commit; reads/<commit>.tsv
// lists every file.
type CommitRecord struct {
	Commit      string `json:"commit"`
	Reads       int    `json:"reads"`
	Listings    int    `json:"listings"`
	ReadsDigest string `json:"readsDigest"`
}

// Totals counts the run's output.
type Totals struct {
	Pairs     int `json:"pairs"`
	Derived   int `json:"derived"`
	Withheld  int `json:"withheld"`
	Rules     int `json:"rules"`
	Vectors   int `json:"vectors"`
	CommitsRd int `json:"commitsRead"`
	// Attestations counts line attestations; omitted when zero.
	Attestations int `json:"attestations,omitempty"`
}

// Output is a complete run result, rendered to files by Files.
type Output struct {
	Entries  []Entry
	Vectors  []Vector
	Manifest Manifest
	// Attestations are the stamped line attestations, in canonical order.
	// They are written to attestations.json when the extractor attests
	// lines and there is at least one.
	Attestations []lineattest.LineAttestation
	attests      bool
	reads        map[string][]ReadRecord
}

var timeRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// Run derives every pair the extractor names and checks the result.
func Run(ctx context.Context, ex Extractor, tags TagSource, reader PinnedReader, opts Options) (*Output, error) {
	src, ok := ex.(CodeSource)
	if !ok {
		return nil, fmt.Errorf("extractor %s does not expose its source for the code digest", ex.ID())
	}
	dir, own := src.SourceFiles()
	files, err := CodeFiles(FrameworkSource(), SourceSet{Dir: dir, Files: own})
	if err != nil {
		return nil, err
	}
	identity := constraintengine.Extractor{ID: ex.ID(), Version: ex.Version(), CodeDigest: CodeDigest(files)}
	if err := constraintengine.ValidateBasis(constraintengine.BasisMechanical, &identity, "2000-01-01T00:00:00Z"); err != nil {
		return nil, fmt.Errorf("extractor identity: %w", err)
	}
	if opts.Repo.Key == "" || !ex.Applies(opts.Repo) {
		return nil, fmt.Errorf("extractor %s does not read repository %q", ex.ID(), opts.Repo.Key)
	}
	derived := opts.DerivedAt.UTC()
	if derived.IsZero() || !derived.Equal(derived.Truncate(time.Second)) {
		return nil, fmt.Errorf("derivedAt must be a whole second")
	}
	lease := opts.Lease
	if lease == 0 {
		lease = DefaultLease
	}
	derivedAt, validUntil := derived.Format(time.RFC3339), derived.Add(lease).Format(time.RFC3339)
	if !timeRE.MatchString(derivedAt) || !timeRE.MatchString(validUntil) {
		return nil, fmt.Errorf("derivedAt out of range")
	}

	tagList, err := tags.Tags(opts.Repo)
	if err != nil {
		return nil, fmt.Errorf("tags of %s: %w", opts.Repo.Key, err)
	}
	pairs := ex.Pairs(ReleaseIndex{Repo: opts.Repo, Tags: tagList})
	for _, p := range pairs {
		if p.Repo != opts.Repo || !IsCommitSHA(p.FromCommit) || !IsCommitSHA(p.ToCommit) {
			return nil, fmt.Errorf("extractor returned an unpinned pair %s", p.Key())
		}
	}

	rec := NewRecorder(reader)
	out := &Output{reads: map[string][]ReadRecord{}}
	m := &out.Manifest
	*m = Manifest{Schema: ManifestSchema, Extractor: identity, CodeFiles: files, Repo: opts.Repo.Key, DerivedAt: derivedAt, ValidUntil: validUntil, Pairs: []PairRecord{}, Outputs: map[string]string{}}
	passByRule := map[string][]string{}
	attester, attests := ex.(LineAttester)
	families := map[string]bool{}
	if attests {
		out.attests = true
		for _, f := range attester.AttestedFamilies() {
			if _, ok := lineattest.LookupFamily(f); !ok {
				return nil, fmt.Errorf("extractor %s attests unknown fact family %q", ex.ID(), f)
			}
			families[f] = true
		}
	}
	for _, pair := range pairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pr := PairRecord{From: pair.From, FromTag: pair.FromTag, FromCommit: pair.FromCommit, To: pair.To, ToTag: pair.ToTag, ToCommit: pair.ToCommit, Rules: []string{}}
		res, err := ex.Extract(ctx, rec, pair)
		line, lineOK := lineattest.LineOf(pair.To)
		if w, withheld := IsWithheld(err); withheld {
			pr.Status, pr.Reason, pr.Proof = PairWithheld, w.Reason, w.Proof
			if attests {
				pr.Attestation = &PairAttestation{Status: PairNotAttested, Line: line, Families: []string{}, Reason: "the pair is withheld"}
			}
			m.Pairs = append(m.Pairs, pr)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pair %s: %w", pair.Key(), err)
		}
		pr.Status, pr.Proof = PairDerived, res.Proof
		for _, c := range res.Candidates {
			entry, err := stamp(c, rec, identity, derivedAt, validUntil)
			if err != nil {
				return nil, fmt.Errorf("pair %s: %w", pair.Key(), err)
			}
			if !(constraintengine.RuleTransition{Component: entry.Rule.Subject.Component, From: entry.Rule.Subject.From, To: entry.Rule.Subject.To}).IsAnchor(pair.From, pair.To) {
				return nil, fmt.Errorf("pair %s: rule %s has subject %s -> %s", pair.Key(), entry.Rule.ID, entry.Rule.Subject.From, entry.Rule.Subject.To)
			}
			out.Entries = append(out.Entries, entry)
			passByRule[entry.Rule.ID] = c.PassMembers
			pr.Rules = append(pr.Rules, entry.Rule.ID)
		}
		sort.Strings(pr.Rules)
		if !attests && (len(res.Attestations) > 0 || res.NotAttested != "") {
			return nil, fmt.Errorf("pair %s: extractor %s returned attestations but does not attest lines", pair.Key(), ex.ID())
		}
		if attests {
			pa := &PairAttestation{Status: PairNotAttested, Line: line, Families: []string{}}
			for _, c := range res.Attestations {
				if !families[c.FactFamily] || !lineOK || c.Line != line {
					return nil, fmt.Errorf("pair %s: attestation for line %q family %q is outside the pair's target line %s or the extractor's families", pair.Key(), c.Line, c.FactFamily, line)
				}
				a, err := stampAttestation(c, rec, identity, derivedAt, validUntil)
				if err != nil {
					return nil, fmt.Errorf("pair %s: %w", pair.Key(), err)
				}
				out.Attestations = append(out.Attestations, a)
				pa.Families = append(pa.Families, c.FactFamily)
			}
			sort.Strings(pa.Families)
			switch {
			case len(pa.Families) > 0 && res.NotAttested != "":
				return nil, fmt.Errorf("pair %s: both attested and not attested", pair.Key())
			case len(pa.Families) > 0:
				pa.Status = PairAttested
			case res.NotAttested != "":
				pa.Reason = res.NotAttested
			default:
				pa.Reason = "the extractor stated no attestation"
			}
			pr.Attestation = pa
		}
		m.Pairs = append(m.Pairs, pr)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Rule.ID < out.Entries[j].Rule.ID })
	for i := 1; i < len(out.Entries); i++ {
		if out.Entries[i-1].Rule.ID == out.Entries[i].Rule.ID {
			return nil, fmt.Errorf("duplicate rule id %s", out.Entries[i].Rule.ID)
		}
	}
	for _, e := range out.Entries {
		vs, err := GenerateVectors(e, passByRule[e.Rule.ID])
		if err != nil {
			return nil, err
		}
		out.Vectors = append(out.Vectors, vs...)
	}
	if err := checkCandidates(out.Entries, opts.ExistingRules); err != nil {
		return nil, err
	}
	if err := CheckVectors(out.Entries, out.Vectors, derived); err != nil {
		return nil, err
	}
	if err := checkAttestations(out); err != nil {
		return nil, err
	}
	for _, c := range rec.Commits(opts.Repo) {
		reads := rec.CommitReads(opts.Repo, c)
		out.reads[c] = reads
		m.Commits = append(m.Commits, CommitRecord{Commit: c, Reads: len(reads), Listings: rec.Listings(opts.Repo, c), ReadsDigest: digest(readsTSV(reads))})
	}
	m.Totals = Totals{Pairs: len(m.Pairs), Rules: len(out.Entries), Vectors: len(out.Vectors), CommitsRd: len(m.Commits), Attestations: len(out.Attestations)}
	for _, p := range m.Pairs {
		if p.Status == PairDerived {
			m.Totals.Derived++
		} else {
			m.Totals.Withheld++
		}
	}
	return out, nil
}

// stamp turns an extractor candidate into a pack entry with mechanical
// provenance. Source digests and line counts come from the recorder, so a
// candidate can only cite bytes the extractor actually read.
func stamp(c Candidate, rec *Recorder, id constraintengine.Extractor, derivedAt, validUntil string) (Entry, error) {
	if c.Rule.SetCondition != nil {
		cond := *c.Rule.SetCondition
		cond.Members = append([]string(nil), cond.Members...)
		c.Rule.SetCondition = &cond
	}
	e := Entry{Project: c.Project, Description: c.Description, RequiredFacts: append([]Fact(nil), c.RequiredFacts...), Rule: RuleJSON{
		ID: c.Rule.ID, Operator: c.Rule.Operator, Subject: c.Rule.Subject, SetCondition: c.Rule.SetCondition, Range: c.Rule.Range, Condition: c.Rule.Condition,
		ReasonCode: c.Rule.ReasonCode, NextAction: c.Rule.NextAction,
		Evidence: Evidence{State: "active", Basis: constraintengine.BasisMechanical, Extractor: id, DerivedAt: derivedAt, ReviewedAt: derivedAt, ValidUntil: validUntil},
	}}
	sources, err := stampSources("rule "+c.Rule.ID, c.Sources, rec)
	if err != nil {
		return Entry{}, err
	}
	e.Rule.Evidence.Sources = sources
	return e, nil
}

// stampSources resolves cited files to pinned evidence. Digests and line
// counts come from the recorder, so a record can only cite bytes the
// extractor actually read.
func stampSources(what string, refs []SourceRef, rec *Recorder) ([]constraintengine.SourceEvidence, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("%s cites no source", what)
	}
	var out []constraintengine.SourceEvidence
	for _, s := range refs {
		read, ok := rec.Lookup(s.Repo, s.Commit, s.Path)
		if !ok {
			return nil, fmt.Errorf("%s cites %s@%s:%s, which the extractor did not read", what, s.Repo.Key, s.Commit, s.Path)
		}
		start, end := s.StartLine, s.EndLine
		if end == 0 {
			start, end = 1, read.Lines
		}
		if start < 1 || end < start || end > read.Lines {
			return nil, fmt.Errorf("%s cites lines %d-%d of %s, which has %d lines", what, start, end, s.Path, read.Lines)
		}
		out = append(out, constraintengine.SourceEvidence{ID: s.ID, URL: s.Repo.BlobURL(s.Commit, s.Path), Revision: s.Commit, ContentDigest: "sha256:" + read.SHA256, StartLine: start, EndLine: end})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// stampAttestation turns an attestation candidate into a line attestation
// with mechanical provenance: reviewedAt is derivedAt, the lease is the
// rules' lease.
func stampAttestation(c AttestationCandidate, rec *Recorder, id constraintengine.Extractor, derivedAt, validUntil string) (lineattest.LineAttestation, error) {
	extractor := id
	ids := append([]string{}, c.RuleIDs...)
	sort.Strings(ids)
	a := lineattest.LineAttestation{Component: c.Component, Line: c.Line, FactFamily: c.FactFamily, Completeness: lineattest.Completeness, RuleIDs: ids,
		Evidence: lineattest.Evidence{Basis: constraintengine.BasisMechanical, Extractor: &extractor, DerivedAt: derivedAt, ReviewedAt: derivedAt, ValidUntil: validUntil}}
	sources, err := stampSources("attestation "+a.Key().String(), c.Sources, rec)
	if err != nil {
		return lineattest.LineAttestation{}, err
	}
	a.Evidence.Sources = sources
	if err := a.Validate(); err != nil {
		return lineattest.LineAttestation{}, fmt.Errorf("attestation %s: %w", a.Key(), err)
	}
	return a, nil
}

// checkAttestations puts the attestations in canonical order and requires
// each to list exactly the run's own rules for its line and family, through
// the same check a pack's attestations pass.
func checkAttestations(out *Output) error {
	if len(out.Attestations) == 0 {
		return nil
	}
	lineattest.Sort(out.Attestations)
	raw, err := lineattest.Marshal(out.Attestations)
	if err != nil {
		return fmt.Errorf("attestations: %w", err)
	}
	rules := make([]json.RawMessage, 0, len(out.Entries))
	for _, e := range out.Entries {
		r, err := json.Marshal(e.Rule)
		if err != nil {
			return err
		}
		rules = append(rules, r)
	}
	result := rulecheck.ValidateLineAttestations(raw, rules, rulecheck.AttestationOptions{})
	if !result.Valid {
		var lines []string
		for _, f := range result.Findings {
			lines = append(lines, fmt.Sprintf("%s: %s: %s", f.RuleID, f.Check, f.Message))
		}
		return fmt.Errorf("rulecheck rejected attestations:\n%s", strings.Join(lines, "\n"))
	}
	return nil
}

func checkCandidates(entries []Entry, existing []string) error {
	if len(entries) == 0 {
		return nil
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	result, err := rulecheck.Validate(raw, rulecheck.Options{AllowRange: true, ExistingRulesPaths: existing})
	if err != nil {
		return fmt.Errorf("rulecheck: %w", err)
	}
	if !result.Valid {
		var lines []string
		for _, f := range result.Findings {
			lines = append(lines, fmt.Sprintf("%s: %s: %s", f.RuleID, f.Check, f.Message))
		}
		return fmt.Errorf("rulecheck rejected candidates:\n%s", strings.Join(lines, "\n"))
	}
	return nil
}

func readsTSV(reads []ReadRecord) []byte {
	var buf bytes.Buffer
	for _, r := range reads {
		buf.WriteString(r.Path + "\t" + r.SHA256 + "\t" + strconv.Itoa(r.Size) + "\n")
	}
	return buf.Bytes()
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Output file names.
const (
	FileCandidates = "candidates.json"
	FileVectors    = "vectors.json"
	FileManifest   = "manifest.json"
	// FileAttestations is written only by an extractor that attests lines,
	// and only when the run attests at least one line: an attestation
	// document is never empty, so a run without attestations has no file
	// (and extract verify reports a stray one as not re-derived).
	FileAttestations = "attestations.json"
	DirReads         = "reads"
)

// Files renders the output as relative path -> bytes.
func (o *Output) Files() (map[string][]byte, error) {
	files := map[string][]byte{}
	entries := o.Entries
	if entries == nil {
		entries = []Entry{}
	}
	vectors := o.Vectors
	if vectors == nil {
		vectors = []Vector{}
	}
	var err error
	if files[FileCandidates], err = Canonical(entries); err != nil {
		return nil, err
	}
	if files[FileVectors], err = Canonical(vectors); err != nil {
		return nil, err
	}
	m := o.Manifest
	m.Outputs = map[string]string{FileCandidates: digest(files[FileCandidates]), FileVectors: digest(files[FileVectors])}
	if o.attests && len(o.Attestations) > 0 {
		if files[FileAttestations], err = Canonical(o.Attestations); err != nil {
			return nil, err
		}
		m.Outputs[FileAttestations] = digest(files[FileAttestations])
	}
	for c, reads := range o.reads {
		name := DirReads + "/" + c + ".tsv"
		files[name] = readsTSV(reads)
		m.Outputs[name] = digest(files[name])
	}
	if files[FileManifest], err = Canonical(m); err != nil {
		return nil, err
	}
	return files, nil
}

// Write writes the output into dir, which must not exist or be empty.
func (o *Output) Write(dir string) error {
	files, err := o.Files()
	if err != nil {
		return err
	}
	if items, err := os.ReadDir(dir); err == nil && len(items) > 0 {
		return fmt.Errorf("output directory %s is not empty", dir)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ReadManifest loads dir/manifest.json.
func ReadManifest(dir string) (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, FileManifest))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("manifest schema %q", m.Schema)
	}
	return m, nil
}

// Verify re-derives the run recorded in dir from the pinned bytes and
// reports every file that is not byte-identical, missing or extra. The
// recorded derivedAt, lease and repository are reused; the extractor
// identity (including the code digest of this binary) must match the
// recorded one.
func Verify(ctx context.Context, ex Extractor, tags TagSource, reader PinnedReader, dir string, existing []string) ([]string, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return nil, err
	}
	derived, err := time.Parse(time.RFC3339, m.DerivedAt)
	if err != nil {
		return nil, fmt.Errorf("manifest derivedAt: %w", err)
	}
	until, err := time.Parse(time.RFC3339, m.ValidUntil)
	if err != nil {
		return nil, fmt.Errorf("manifest validUntil: %w", err)
	}
	repo, err := ParseRepo(m.Repo)
	if err != nil {
		return nil, err
	}
	out, err := Run(ctx, ex, tags, reader, Options{Repo: repo, DerivedAt: derived, Lease: until.Sub(derived), ExistingRules: existing})
	if err != nil {
		return nil, fmt.Errorf("re-derivation failed: %w", err)
	}
	var problems []string
	if out.Manifest.Extractor != m.Extractor {
		problems = append(problems, fmt.Sprintf("extractor identity differs: recorded %s %s %s, this binary %s %s %s", m.Extractor.ID, m.Extractor.Version, m.Extractor.CodeDigest, out.Manifest.Extractor.ID, out.Manifest.Extractor.Version, out.Manifest.Extractor.CodeDigest))
	}
	want, err := out.Files()
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		have[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			problems = append(problems, name+": missing")
			continue
		}
		if !bytes.Equal(got, want[name]) {
			problems = append(problems, name+": differs from the re-derivation")
		}
	}
	extra := []string{}
	for name := range have {
		if _, ok := want[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, name+": not produced by the re-derivation")
	}
	return problems, nil
}
