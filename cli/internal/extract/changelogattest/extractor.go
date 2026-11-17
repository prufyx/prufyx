// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Extractor identity.
const (
	// IDPrefix is followed by the project slug: one extractor per component.
	IDPrefix = "changelog.entries."
	// Version is bumped on any output change.
	Version = "1.0.0"
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Extractor attests, for one component, the lines of the changelog-attested
// family: it implements extract.LineAttester and extract.ComponentAttester.
// It emits no rule and no draft. The family's member table is empty, so
// until a reviewed change admits the component the framework refuses every
// attestation it states.
type Extractor struct {
	slug string
	cfg  Config

	mu   sync.Mutex
	tags []extract.Tag
}

// New returns the extractor of one component.
func New(slug string, cfg Config) (*Extractor, error) {
	if !slugRE.MatchString(slug) {
		return nil, fmt.Errorf("changelogattest: project slug %q", slug)
	}
	if cfg.Target.Component == "" || cfg.Target.Repo.Key == "" {
		return nil, fmt.Errorf("changelogattest: target without component or repository")
	}
	if cfg.Dispositions == nil || cfg.Dispositions.Component != cfg.Target.Component {
		return nil, fmt.Errorf("changelogattest: dispositions are not those of %s", cfg.Target.Component)
	}
	if _, err := parsePackRules(cfg.PackRules); err != nil {
		return nil, fmt.Errorf("changelogattest: %w", err)
	}
	return &Extractor{slug: slug, cfg: cfg}, nil
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return IDPrefix + x.slug }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(r extract.RepoRef) bool { return r == x.cfg.Target.Repo }

// AttestedFamilies implements extract.LineAttester.
func (x *Extractor) AttestedFamilies() []string {
	return []string{lineattest.FamilyChangelogAttestedEntries}
}

// AttestedComponent implements extract.ComponentAttester.
func (x *Extractor) AttestedComponent() string { return x.cfg.Target.Component }

// SourceFiles implements extract.CodeSource: this package and the entry
// reader it calls.
func (x *Extractor) SourceFiles() (string, fs.FS) {
	s := SourceSet()
	return s.Dir, s.Files
}

// Pairs implements extract.Extractor: every two lines that follow each other
// as minor lines of one major, each named by its first final release.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	x.mu.Lock()
	x.tags = append([]extract.Tag(nil), index.Tags...)
	x.mu.Unlock()
	first := map[[2]int]rel{}
	bad := map[[2]int]bool{}
	seen := map[string]string{}
	for _, t := range index.Tags {
		r, ok := parseRel(t)
		if !ok {
			continue
		}
		if c, dup := seen[r.version]; dup && c != t.Commit {
			bad[[2]int{r.maj, r.min}] = true
		}
		seen[r.version] = t.Commit
		k := [2]int{r.maj, r.min}
		if cur, ok := first[k]; !ok || r.pat < cur.pat || (r.pat == cur.pat && t.Name < cur.tag.Name) {
			first[k] = r
		}
	}
	keys := make([][2]int, 0, len(first))
	for k := range first {
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
		if a[0] != b[0] || a[1]+1 != b[1] || bad[a] || bad[b] {
			continue
		}
		fa, fb := first[a], first[b]
		out = append(out, extract.VersionPair{Repo: index.Repo,
			From: fa.version, FromTag: fa.tag.Name, FromCommit: fa.tag.Commit,
			To: fb.version, ToTag: fb.tag.Name, ToCommit: fb.tag.Commit})
	}
	return out
}

// Extract implements extract.Extractor. A pair the attestation cannot be
// established for is withheld with its typed reason; nothing is attested.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	x.mu.Lock()
	tags := append([]extract.Tag(nil), x.tags...)
	x.mu.Unlock()
	if len(tags) == 0 {
		return extract.Extraction{}, fmt.Errorf("changelogattest: Extract before Pairs")
	}
	res, err := Attest(r, x.cfg, tags, pair)
	if err != nil {
		if code, ok := ce.CodeOf(err); ok {
			return extract.Extraction{}, &extract.Withheld{Reason: err.Error(), Proof: map[string]string{"code": string(code)}}
		}
		return extract.Extraction{}, err
	}
	return extract.Extraction{Proof: res.Proof, Attestations: []extract.AttestationCandidate{res.Candidate}}, nil
}
