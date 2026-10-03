// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

func attestationFor(t *testing.T, out *extract.Output, line string) (lineattest.LineAttestation, bool) {
	t.Helper()
	for _, a := range out.Attestations {
		if a.Line == line {
			return a, true
		}
	}
	return lineattest.LineAttestation{}, false
}

// Every derived line is attested, a quiet line with an empty rule list, and
// each attestation lists exactly the run's rules for its line.
func TestEveryDerivedLineIsAttested(t *testing.T) {
	out := fixtureOutput(t)
	if len(out.Attestations) != len(out.Manifest.Pairs) || out.Manifest.Totals.Attestations != 4 {
		t.Fatalf("%d attestations for %d pairs", len(out.Attestations), len(out.Manifest.Pairs))
	}
	for _, p := range out.Manifest.Pairs {
		line := strings.TrimSuffix(p.To, ".0")
		a, ok := attestationFor(t, out, line)
		if !ok || p.Attestation == nil || p.Attestation.Status != extract.PairAttested || p.Attestation.Line != line {
			t.Fatalf("line %s: attestation %v, pair record %+v", line, ok, p.Attestation)
		}
		if !slices.Equal(a.RuleIDs, p.Rules) {
			t.Fatalf("line %s lists %v, the pair derived %v", line, a.RuleIDs, p.Rules)
		}
		ev := a.Evidence
		if a.Component != purl || a.FactFamily != lineattest.FamilyKubernetesRemovedServedGVK || a.Completeness != lineattest.Completeness ||
			ev.Basis != "mechanical" || ev.Extractor == nil || ev.Extractor.ID != ID || ev.Extractor.Version != Version || ev.DerivedAt != "2026-10-03T00:00:00Z" ||
			ev.ReviewedAt != ev.DerivedAt || ev.ValidUntil != "2027-01-01T00:00:00Z" || len(ev.Sources) != 2 {
			t.Fatalf("line %s: %+v", line, a)
		}
		for i, s := range ev.Sources {
			commit := p.FromCommit
			if i == 1 {
				commit = p.ToCommit
			}
			data := mustRead(t, filepath.Join(fixtureRoot, Repo, "commits", commit, spec))
			if s.Revision != commit || s.ContentDigest != "sha256:"+sha(data) || s.StartLine != 1 || s.EndLine != strings.Count(string(data), "\n") {
				t.Fatalf("line %s source %d: %+v", line, i, s)
			}
		}
	}
	quiet, _ := attestationFor(t, out, "1.31")
	if quiet.RuleIDs == nil || len(quiet.RuleIDs) != 0 {
		t.Fatalf("quiet line: %+v", quiet.RuleIDs)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files[extract.FileAttestations]), `"ruleIds": []`) {
		t.Fatal("a quiet line must be written with an empty rule list, not null")
	}
	parsed, err := lineattest.Parse(files[extract.FileAttestations])
	if err != nil || len(parsed) != 4 {
		t.Fatalf("attestations.json does not parse strictly: %v", err)
	}
	cands := files[extract.FileCandidates]
	var rules = rulesOf(t, cands)
	if r := rulecheck.ValidateLineAttestations(files[extract.FileAttestations], rules, rulecheck.AttestationOptions{}); !r.Valid {
		t.Fatalf("rulecheck: %+v", r.Findings)
	}
}

// A removal with no adapter fact has no rule, so the line is not attested.
func TestRemovalWithoutAdapterFactIsNotAttested(t *testing.T) {
	saved := adapterFacts
	defer func() { adapterFacts = saved }()
	adapterFacts = slices.DeleteFunc(slices.Clone(saved), func(f adapterFact) bool { return f.Line == 33 })
	out := fixtureOutput(t)
	p := pairTo(t, out, "v1.33.0")
	if p.Status != extract.PairDerived || len(p.Rules) != 0 || p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested ||
		!strings.Contains(p.Attestation.Reason, "authentication.k8s.io/v1beta1/SelfSubjectReview") {
		t.Fatalf("1.33: %+v %+v", p, p.Attestation)
	}
	if _, ok := attestationFor(t, out, "1.33"); ok {
		t.Fatal("a line with an unruled removal is attested")
	}
	if _, ok := attestationFor(t, out, "1.32"); !ok {
		t.Fatal("other lines stay attested")
	}
}

func TestWithheldPairIsNotAttested(t *testing.T) {
	root := copyFixture(t)
	if err := os.Remove(filepath.Join(commitDir(root, 24), spec)); err != nil {
		t.Fatal(err)
	}
	out := runOn(t, extract.FixtureReader{Root: root})
	p := pairTo(t, out, "v1.25.0")
	if p.Status != extract.PairWithheld || p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || p.Attestation.Reason != "the pair is withheld" {
		t.Fatalf("%+v", p.Attestation)
	}
	if _, ok := attestationFor(t, out, "1.25"); ok {
		t.Fatal("a withheld line is attested")
	}
}

// Re-derivation reproduces the attestations byte for byte, and verify
// reports any edit to them.
func TestAttestationsAreReproducibleAndVerified(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := fixtureOutput(t).Write(dir); err != nil {
		t.Fatal(err)
	}
	r := extract.FixtureReader{Root: fixtureRoot}
	verify := func() []string {
		problems, err := extract.Verify(context.Background(), New(0), r, r, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		return problems
	}
	if p := verify(); len(p) != 0 {
		t.Fatalf("clean run: %v", p)
	}
	path := filepath.Join(dir, extract.FileAttestations)
	orig := mustRead(t, path)
	for name, edit := range map[string]func(string) string{
		"rule dropped": func(s string) string {
			return strings.Replace(s, "      \"kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0\",\n", "", 1)
		},
		"lease extended": func(s string) string {
			return strings.Replace(s, `"validUntil": "2027-01-01T00:00:00Z"`, `"validUntil": "2027-02-01T00:00:00Z"`, 1)
		},
		"quiet line made": func(s string) string { return strings.Replace(s, `"line": "1.32"`, `"line": "1.34"`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			edited := edit(string(orig))
			if edited == string(orig) {
				t.Fatal("edit did not apply")
			}
			if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(path, orig, 0o644)
			if p := verify(); !slices.Contains(p, extract.FileAttestations+": differs from the re-derivation") {
				t.Fatalf("verify: %v", p)
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if p := verify(); !slices.Contains(p, extract.FileAttestations+": missing") {
		t.Fatalf("verify without attestations.json: %v", p)
	}
}

// tamper wraps the extractor and edits each extraction, to show the
// framework refuses attestations that do not match the run.
type tamper struct {
	*Extractor
	edit func(*extract.Extraction, extract.VersionPair)
}

func (x tamper) Extract(ctx context.Context, r extract.PinnedReader, p extract.VersionPair) (extract.Extraction, error) {
	res, err := x.Extractor.Extract(ctx, r, p)
	if err == nil {
		x.edit(&res, p)
	}
	return res, err
}

// notAttester has the extractor's methods but not AttestedFamilies.
type notAttester struct{ x tamper }

func (n notAttester) ID() string                                          { return n.x.ID() }
func (n notAttester) Version() string                                     { return n.x.Version() }
func (n notAttester) Applies(r extract.RepoRef) bool                      { return n.x.Applies(r) }
func (n notAttester) SourceFiles() (string, fs.FS)                        { return n.x.SourceFiles() }
func (n notAttester) Pairs(ix extract.ReleaseIndex) []extract.VersionPair { return n.x.Pairs(ix) }
func (n notAttester) Extract(ctx context.Context, r extract.PinnedReader, p extract.VersionPair) (extract.Extraction, error) {
	return n.x.Extract(ctx, r, p)
}

func TestFrameworkRefusesMismatchedAttestations(t *testing.T) {
	at := func(line string, f func(a *extract.AttestationCandidate)) func(*extract.Extraction, extract.VersionPair) {
		return func(res *extract.Extraction, p extract.VersionPair) {
			if strings.TrimSuffix(p.To, ".0") == line && len(res.Attestations) == 1 {
				f(&res.Attestations[0])
			}
		}
	}
	r := extract.FixtureReader{Root: fixtureRoot}
	for name, edit := range map[string]func(*extract.Extraction, extract.VersionPair){
		"rule left out": at("1.25", func(a *extract.AttestationCandidate) { a.RuleIDs = a.RuleIDs[1:] }),
		"rule added": at("1.31", func(a *extract.AttestationCandidate) {
			a.RuleIDs = []string{"kubernetes.served-api-removal.zz.1-30-0-to-1-31-0"}
		}),
		"rule of another line": at("1.31", func(a *extract.AttestationCandidate) {
			a.RuleIDs = []string{"kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0"}
		}),
		"another line":     at("1.31", func(a *extract.AttestationCandidate) { a.Line = "1.30" }),
		"unknown family":   at("1.31", func(a *extract.AttestationCandidate) { a.FactFamily = "kubernetes.other" }),
		"source not read":  at("1.31", func(a *extract.AttestationCandidate) { a.Sources[0].Path = "README.md" }),
		"no sources":       at("1.31", func(a *extract.AttestationCandidate) { a.Sources = nil }),
		"attested and not": func(res *extract.Extraction, _ extract.VersionPair) { res.NotAttested = "both" },
		"two for one line": func(res *extract.Extraction, _ extract.VersionPair) {
			res.Attestations = append(res.Attestations, res.Attestations...)
		},
		"another component": at("1.31", func(a *extract.AttestationCandidate) { a.Component = "pkg:github/x/y" }),
	} {
		t.Run(name, func(t *testing.T) {
			x := tamper{New(0), edit}
			if _, err := extract.Run(context.Background(), x, r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt}); err == nil {
				t.Fatal("run succeeded")
			}
		})
	}
	n := notAttester{tamper{New(0), func(*extract.Extraction, extract.VersionPair) {}}}
	if _, err := extract.Run(context.Background(), n, r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt}); err == nil || !strings.Contains(err.Error(), "does not attest lines") {
		t.Fatalf("an extractor that does not attest lines returned attestations: %v", err)
	}
}

func rulesOf(t *testing.T, candidates []byte) []json.RawMessage {
	t.Helper()
	var entries []struct {
		Rule json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(candidates, &entries); err != nil {
		t.Fatal(err)
	}
	var rules []json.RawMessage
	for _, e := range entries {
		rules = append(rules, e.Rule)
	}
	return rules
}

// A run that attests no line writes no attestations.json (a document is
// never empty), the manifest does not list it, and verify agrees: the
// re-derivation has no such file, so a stray one is reported.
func TestRunWithoutAttestationsWritesNoAttestationFile(t *testing.T) {
	// A fresh extractor per run: an extractor instance caches what it read.
	fresh := func() tamper {
		return tamper{New(0), func(res *extract.Extraction, _ extract.VersionPair) {
			res.Attestations, res.NotAttested = nil, "not attested in this test"
		}}
	}
	r := extract.FixtureReader{Root: fixtureRoot}
	out, err := extract.Run(context.Background(), fresh(), r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[extract.FileAttestations]; ok || len(out.Attestations) != 0 {
		t.Fatalf("attestations.json written for a run without attestations")
	}
	if _, ok := out.Manifest.Outputs[extract.FileAttestations]; ok {
		t.Fatal("manifest lists attestations.json")
	}
	for _, p := range out.Manifest.Pairs {
		if p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested {
			t.Fatalf("pair %s: %+v", p.To, p.Attestation)
		}
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	verify := func() []string {
		problems, err := extract.Verify(context.Background(), fresh(), r, r, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		return problems
	}
	if p := verify(); len(p) != 0 {
		t.Fatalf("clean run: %v", p)
	}
	if err := os.WriteFile(filepath.Join(dir, extract.FileAttestations), []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := verify(); !slices.Contains(p, extract.FileAttestations+": not produced by the re-derivation") {
		t.Fatalf("verify with a stray empty attestations.json: %v", p)
	}
}

// The extractor's own rules carry a range over the whole previous and
// target minor line, so every attestation it emits passes the line-wide
// check; a rule narrowed to its anchor pair makes the run fail.
func TestEmittedRulesAreLineWide(t *testing.T) {
	out := fixtureOutput(t)
	family, _ := lineattest.LookupFamily(lineattest.FamilyKubernetesRemovedServedGVK)
	n := 0
	for _, a := range out.Attestations {
		for _, e := range out.Entries {
			if !slices.Contains(a.RuleIDs, e.Rule.ID) {
				continue
			}
			n++
			tr := constraintengine.RuleTransition{Component: e.Rule.Subject.Component, From: e.Rule.Subject.From, To: e.Rule.Subject.To, Range: e.Rule.Range}
			if !family.CoversLine(tr, a.Line) {
				t.Fatalf("rule %s is not line-wide for %s", e.Rule.ID, a.Line)
			}
		}
	}
	if n == 0 {
		t.Fatal("no attested rule checked")
	}
	x := tamper{New(0), func(res *extract.Extraction, p extract.VersionPair) {
		if p.To == "v1.25.0" || p.To == "1.25.0" {
			for i := range res.Candidates {
				res.Candidates[i].Rule.Range = nil
			}
		}
	}}
	r := extract.FixtureReader{Root: fixtureRoot}
	if _, err := extract.Run(context.Background(), x, r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt}); err == nil || !strings.Contains(err.Error(), "rule-not-line-wide") {
		t.Fatalf("anchor-only rules attested: %v", err)
	}
}

// noFamilies attests lines but declares no fact family.
type noFamilies struct{ tamper }

func (noFamilies) AttestedFamilies() []string { return nil }

func TestFrameworkRefusesAttestationOfUndeclaredFamily(t *testing.T) {
	x := noFamilies{tamper{New(0), func(*extract.Extraction, extract.VersionPair) {}}}
	r := extract.FixtureReader{Root: fixtureRoot}
	if _, err := extract.Run(context.Background(), x, r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt}); err == nil {
		t.Fatal("an attestation of a family the extractor does not declare was accepted")
	}
}
