// SPDX-License-Identifier: AGPL-3.0-only

package chartrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
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

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// source is this package's own Go source, embedded at build time. The
// pattern includes test files; extract.CodeFiles skips them.
//
//go:embed *.go
var source embed.FS

// SourceDir is this package's directory as it appears in code digest lines.
const SourceDir = "extract/chartrun"

// Source returns this package's source set.
func Source() extract.SourceSet { return extract.SourceSet{Dir: SourceDir, Files: source} }

// CodeFiles lists the files a chart extractor's code digest covers: the
// framework's, this package's and the extractor's own package's.
func CodeFiles(ex Extractor) ([]extract.CodeFile, error) {
	dir, own := ex.SourceFiles()
	return extract.CodeFiles(extract.FrameworkSource(), Source(), extract.SourceSet{Dir: dir, Files: own})
}

// Output is a complete run result, rendered to files by Files.
type Output struct {
	Entries  []Entry
	Vectors  []Vector
	Manifest extract.Manifest
	reads    map[string][]extract.ReadRecord
}

var timeRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// Run derives every pair the chart extractor names and checks the result,
// as extract.Run does.
func Run(ctx context.Context, ex Extractor, tags extract.TagSource, reader extract.PinnedReader, opts extract.Options) (*Output, error) {
	files, err := CodeFiles(ex)
	if err != nil {
		return nil, err
	}
	identity := constraintengine.Extractor{ID: ex.ID(), Version: ex.Version(), CodeDigest: extract.CodeDigest(files)}
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
		lease = extract.DefaultLease
	}
	derivedAt, validUntil := derived.Format(time.RFC3339), derived.Add(lease).Format(time.RFC3339)
	if !timeRE.MatchString(derivedAt) || !timeRE.MatchString(validUntil) {
		return nil, fmt.Errorf("derivedAt out of range")
	}

	tagList, err := tags.Tags(opts.Repo)
	if err != nil {
		return nil, fmt.Errorf("tags of %s: %w", opts.Repo.Key, err)
	}
	pairs := ex.Pairs(extract.ReleaseIndex{Repo: opts.Repo, Tags: tagList})
	for _, p := range pairs {
		if p.Repo != opts.Repo || !extract.IsCommitSHA(p.FromCommit) || !extract.IsCommitSHA(p.ToCommit) {
			return nil, fmt.Errorf("extractor returned an unpinned pair %s", p.Key())
		}
	}

	rec := extract.NewRecorder(reader)
	out := &Output{reads: map[string][]extract.ReadRecord{}}
	m := &out.Manifest
	*m = extract.Manifest{Schema: extract.ManifestSchema, Extractor: identity, CodeFiles: files, Repo: opts.Repo.Key, DerivedAt: derivedAt, ValidUntil: validUntil, Pairs: []extract.PairRecord{}, Outputs: map[string]string{}}
	passByRule := map[string][]string{}
	for _, pair := range pairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pr := extract.PairRecord{From: pair.From, FromTag: pair.FromTag, FromCommit: pair.FromCommit, To: pair.To, ToTag: pair.ToTag, ToCommit: pair.ToCommit, Rules: []string{}}
		res, err := ex.Extract(ctx, rec, pair)
		if w, withheld := extract.IsWithheld(err); withheld {
			pr.Status, pr.Reason, pr.Proof = extract.PairWithheld, w.Reason, w.Proof
			m.Pairs = append(m.Pairs, pr)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pair %s: %w", pair.Key(), err)
		}
		pr.Status, pr.Proof = extract.PairDerived, res.Proof
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
	for _, c := range rec.Commits(opts.Repo) {
		reads := rec.CommitReads(opts.Repo, c)
		out.reads[c] = reads
		m.Commits = append(m.Commits, extract.CommitRecord{Commit: c, Reads: len(reads), Listings: rec.Listings(opts.Repo, c), ReadsDigest: digest(readsTSV(reads))})
	}
	m.Totals = extract.Totals{Pairs: len(m.Pairs), Rules: len(out.Entries), Vectors: len(out.Vectors), CommitsRd: len(m.Commits)}
	for _, p := range m.Pairs {
		if p.Status == extract.PairDerived {
			m.Totals.Derived++
		} else {
			m.Totals.Withheld++
		}
	}
	return out, nil
}

// stamp turns a candidate into a pack entry with mechanical provenance.
// Source digests and line counts come from the recorder, so a candidate can
// only cite bytes the extractor actually read.
func stamp(c Candidate, rec *extract.Recorder, id constraintengine.Extractor, derivedAt, validUntil string) (Entry, error) {
	if c.Rule.SetCondition != nil {
		cond := *c.Rule.SetCondition
		cond.Members = append([]string(nil), cond.Members...)
		c.Rule.SetCondition = &cond
	}
	if c.Rule.Subject.Chart != nil {
		chart := *c.Rule.Subject.Chart
		c.Rule.Subject.Chart = &chart
	}
	if c.Rule.Dependency != nil {
		dep := *c.Rule.Dependency
		c.Rule.Dependency = &dep
	}
	e := Entry{Project: c.Project, Description: c.Description, RequiredFacts: append([]extract.Fact(nil), c.RequiredFacts...), Rule: RuleJSON{
		ID: c.Rule.ID, Operator: c.Rule.Operator, Subject: c.Rule.Subject, SetCondition: c.Rule.SetCondition, Dependency: c.Rule.Dependency,
		ReasonCode: c.Rule.ReasonCode, NextAction: c.Rule.NextAction,
		Evidence: extract.Evidence{State: "active", Basis: constraintengine.BasisMechanical, Extractor: id, DerivedAt: derivedAt, ReviewedAt: derivedAt, ValidUntil: validUntil},
	}}
	sources, err := stampSources("rule "+c.Rule.ID, c.Sources, rec)
	if err != nil {
		return Entry{}, err
	}
	e.Rule.Evidence.Sources = sources
	return e, nil
}

// stampSources resolves cited files to pinned evidence, as extract does.
func stampSources(what string, refs []extract.SourceRef, rec *extract.Recorder) ([]constraintengine.SourceEvidence, error) {
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

// chartSources is the chart-source table rulecheck checks a chart rule
// against; nil is the embedded table. Only this package's tests set it.
var chartSources *chartidentity.SourceTable

func checkCandidates(entries []Entry, existing []string) error {
	if len(entries) == 0 {
		return nil
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	result, err := rulecheck.Validate(raw, rulecheck.Options{AllowRange: true, ExistingRulesPaths: existing, ChartSources: chartSources})
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

func readsTSV(reads []extract.ReadRecord) []byte {
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

// Files renders the output as relative path -> bytes, under extract's file
// names.
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
	if files[extract.FileCandidates], err = extract.Canonical(entries); err != nil {
		return nil, err
	}
	if files[extract.FileVectors], err = extract.Canonical(vectors); err != nil {
		return nil, err
	}
	m := o.Manifest
	m.Outputs = map[string]string{extract.FileCandidates: digest(files[extract.FileCandidates]), extract.FileVectors: digest(files[extract.FileVectors])}
	for c, reads := range o.reads {
		name := extract.DirReads + "/" + c + ".tsv"
		files[name] = readsTSV(reads)
		m.Outputs[name] = digest(files[name])
	}
	if files[extract.FileManifest], err = extract.Canonical(m); err != nil {
		return nil, err
	}
	return files, nil
}

// Verify re-derives the run recorded in dir from the pinned bytes and
// reports every file that is not byte-identical, missing or extra, as
// extract.Verify does.
func Verify(ctx context.Context, ex Extractor, tags extract.TagSource, reader extract.PinnedReader, dir string, existing []string) ([]string, error) {
	m, err := extract.ReadManifest(dir)
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
	repo, err := extract.ParseRepo(m.Repo)
	if err != nil {
		return nil, err
	}
	out, err := Run(ctx, ex, tags, reader, extract.Options{Repo: repo, DerivedAt: derived, Lease: until.Sub(derived), ExistingRules: existing})
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
