// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Extractor identity.
const (
	// IDPrefix is followed by the project slug: one extractor id per project.
	IDPrefix = "cli.flag-removal."
	// Version is bumped on any output change.
	Version = "1.0.0"

	// ReasonCode of the rules the extractor proposes.
	ReasonCode = "CLI_FLAG_REMOVED"

	maxIDBytes = 128
)

// attestedFamily is the fact family the extractor attests lines of. No
// cli-flags family exists in the line attestation vocabulary, so it is empty:
// every pair is recorded as not attested and no attestation is ever stated.
// The extractor yields candidates and a ledger only.
const attestedFamily = ""

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Extractor wires ComparePair into the extract framework. A pair is the first
// release of one minor line and the first release of the next minor line of
// the same major. The Proof of a pair is its PairResult; the ledger of the
// PairResult is the pair's Extraction.Ledger. A pair is never attested.
type Extractor struct {
	slug      string
	component string
	target    Target
	family    string
	// registry is the fact registry the candidates are checked against; nil
	// means this build's compiled registry. Only tests set it.
	registry func() []constraintengine.FactDefinition
}

// New returns the extractor of one project. component is the catalog
// component (a pkg:github/... identifier) of the cli_flags_set fact.
func New(slug, component string, t Target) (*Extractor, error) {
	if !slugRE.MatchString(slug) {
		return nil, fmt.Errorf("cliflags: project slug %q", slug)
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	if t.Repo.Key == "" {
		return nil, fmt.Errorf("cliflags: target without repository")
	}
	return &Extractor{slug: slug, component: component, target: t, family: attestedFamily}, nil
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return IDPrefix + x.slug }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(r extract.RepoRef) bool { return r == x.target.Repo }

// SourceFiles implements extract.CodeSource: this package and the shared
// member encoder it calls.
func (x *Extractor) SourceFiles() (string, fs.FS) {
	s := SourceSet()
	return s.Dir, s.Files
}

// AttestedFamilies implements extract.LineAttester. It is empty.
func (x *Extractor) AttestedFamilies() []string {
	if x.family == "" {
		return []string{}
	}
	return []string{x.family}
}

// AttestedComponent implements extract.ComponentAttester.
func (x *Extractor) AttestedComponent() string { return x.component }

// FactID is the set fact the extractor's rules read.
func (x *Extractor) FactID() string {
	return "component." + strings.ReplaceAll(x.slug, "-", "_") + ".cli_flags_set"
}

// factRegistered reports whether the registry holds the extractor's fact as
// a set fact of its component, and the digest of the matched definition.
func (x *Extractor) factRegistered() (bool, string) {
	defs := cncfcheck.CompiledFactDefinitions
	if x.registry != nil {
		defs = x.registry
	}
	for _, d := range defs() {
		if d.ID == x.FactID() && d.Component == x.component && d.Type == constraintengine.FactSet {
			h := sha256.New()
			for _, f := range []string{d.ID, d.Component, string(d.Type), strings.Join(d.EnumTokens, ","), FactShape} {
				fmt.Fprintf(h, "%d:%s\n", len(f), f)
			}
			return true, "sha256:" + hex.EncodeToString(h.Sum(nil))
		}
	}
	return false, ""
}

var (
	canonTagRE = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
)

type line struct {
	major, minor int
	patch        int
	tag          extract.Tag
	version      string
}

// Pairs implements extract.Extractor. Release tags are final releases with
// canonical numbers (v1.2.3 or 1.2.3). A release tagged twice at different
// commits is dropped with its whole line: no pair names it. Pairs are only
// between a line and the next minor line of the same major, each named by its
// first (lowest patch) release.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	type rel struct {
		line
		bad bool
	}
	byVersion := map[string]*rel{}
	badLine := map[[2]int]bool{}
	for _, t := range index.Tags {
		m := canonTagRE.FindStringSubmatch(t.Name)
		if m == nil || !extract.IsCommitSHA(t.Commit) {
			continue
		}
		maj, _ := strconv.Atoi(m[1])
		mnr, _ := strconv.Atoi(m[2])
		pat, _ := strconv.Atoi(m[3])
		v := fmt.Sprintf("%d.%d.%d", maj, mnr, pat)
		if prev, dup := byVersion[v]; dup {
			if prev.tag.Commit != t.Commit {
				badLine[[2]int{maj, mnr}] = true
			}
			if prev.tag.Name <= t.Name {
				continue
			}
		}
		byVersion[v] = &rel{line: line{maj, mnr, pat, t, v}}
	}
	firsts := map[[2]int]line{}
	for _, r := range byVersion {
		k := [2]int{r.major, r.minor}
		if badLine[k] {
			continue
		}
		if cur, ok := firsts[k]; !ok || r.patch < cur.patch {
			firsts[k] = r.line
		}
	}
	keys := make([][2]int, 0, len(firsts))
	for k := range firsts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var out []extract.VersionPair
	for i := 1; i < len(keys); i++ {
		a, b := keys[i-1], keys[i]
		if a[0] != b[0] || a[1]+1 != b[1] {
			continue
		}
		fa, fb := firsts[a], firsts[b]
		out = append(out, extract.VersionPair{Repo: index.Repo,
			From: fa.version, FromTag: fa.tag.Name, FromCommit: fa.tag.Commit,
			To: fb.version, ToTag: fb.tag.Name, ToCommit: fb.tag.Commit})
	}
	return out
}

// Extract implements extract.Extractor. A read failure aborts the run (fail
// closed): it is never a quiet pair.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, p extract.VersionPair) (extract.Extraction, error) {
	ok, digest := x.factRegistered()
	fact := FactRef{ID: x.FactID(), Component: x.component, Registered: ok, Digest: digest}
	res, err := ComparePair(ctx, r, x.target, p.FromCommit, p.ToCommit, fact)
	if err != nil {
		return extract.Extraction{}, err
	}
	e := extract.Extraction{Proof: res, Ledger: frameworkLedger(res.Ledger)}
	// The comparison is never attestable, and no family is registered: the
	// pair is not attested whatever else holds (design 11.1 item 1).
	switch {
	case len(res.Ledger) > 0 || !res.Attestable():
		e.NotAttested = "the pair withheld items or states candidates only"
	case x.family == "":
		e.NotAttested = "no cli flags fact family is registered for attestation"
	default:
		e.NotAttested = "the extractor states no attestation"
	}
	if len(res.Removed) > 0 {
		c, err := x.candidate(p, res)
		if err != nil {
			return extract.Extraction{}, err
		}
		e.Candidates = []extract.Candidate{c}
	}
	return e, nil
}

func frameworkLedger(l []LedgerEntry) []extract.LedgerEntry {
	if len(l) == 0 {
		return nil
	}
	out := make([]extract.LedgerEntry, len(l))
	for i, e := range l {
		out[i] = extract.LedgerEntry{Code: e.Code, Item: e.Item}
	}
	return out
}

func slugOf(s string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(s))
}

// candidate is the one rule of a pair: the flags removed between the two
// pinned trees are forbidden members of the component's cli_flags_set.
func (x *Extractor) candidate(p extract.VersionPair, res *PairResult) (extract.Candidate, error) {
	id := fmt.Sprintf("%s.cli-flag-removal.%s-to-%s", x.slug, slugOf(p.From), slugOf(p.To))
	if len(id) > maxIDBytes {
		return extract.Candidate{}, fmt.Errorf("cliflags: rule id %s over %d bytes", id, maxIDBytes)
	}
	var pass []string
	for i := range res.To.Binaries {
		for _, m := range res.To.Binaries[i].Set.Members {
			pass = append(pass, m)
			break
		}
		if len(pass) > 0 {
			break
		}
	}
	return extract.Candidate{
		Project: x.slug,
		Description: fmt.Sprintf("%s %s registers none of the %d command line flag(s) listed, which %s registered: the binaries of the pinned tree at each tag were read from source and no registration, string literal or alias of the name was found at %s. A flag that was renamed is reported as the removal of the old spelling only: the replacement spelling, if any, is not named, and a human must confirm what replaces it. A flag name built at run time (concatenation or Sprintf) is not seen, and the literal sweep matches whole string literals only, so a name inside a longer literal is not a hit. Shorthand spellings, environment variable forms and flags registered inside libraries the module does not vendor are not checked.",
			x.slug, p.To, len(res.Removed), p.From, p.To),
		RequiredFacts: []extract.Fact{{
			Side: "proposed", ID: x.FactID(), Component: x.component, Type: string(constraintengine.FactSet),
			Description: fmt.Sprintf("Long command line flag names (without leading dashes) that the %s workloads of the proposed bundle pass.", x.slug),
		}},
		Rule: extract.Rule{
			ID:       id,
			Operator: constraintengine.OperatorForbidSetMember,
			Subject:  extract.Subject{Component: x.component, From: p.From, To: p.To},
			SetCondition: &extract.SetCondition{Side: "proposed", Component: x.component, FactID: x.FactID(),
				Members: append([]string(nil), res.Removed...)},
			ReasonCode: ReasonCode,
			NextAction: fmt.Sprintf("remove each listed %s flag before upgrading to %s; a rename shows as removal of the old name only, the new name is not given: a human must confirm it", x.slug, p.To),
		},
		Sources: []extract.SourceRef{
			{ID: "from-go-mod", Repo: p.Repo, Commit: p.FromCommit, Path: "go.mod"},
			{ID: "to-go-mod", Repo: p.Repo, Commit: p.ToCommit, Path: "go.mod"},
		},
		PassMembers: pass,
	}, nil
}
