// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// RepoRef names an upstream repository as host/owner/name, for example
// "github.com/kubernetes/kubernetes".
type RepoRef struct {
	Key string
}

var repoKeyRE = regexp.MustCompile(`^github\.com/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ParseRepo validates a repository key. Only GitHub repositories are
// accepted: cited sources must be immutable GitHub blob URLs.
func ParseRepo(key string) (RepoRef, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	if !repoKeyRE.MatchString(key) {
		return RepoRef{}, fmt.Errorf("repository %q: want github.com/<owner>/<name>", key)
	}
	return RepoRef{Key: key}, nil
}

// OwnerName returns the owner and name parts of the key.
func (r RepoRef) OwnerName() (string, string) {
	parts := strings.Split(r.Key, "/")
	if len(parts) != 3 {
		return "", ""
	}
	return parts[1], parts[2]
}

// BlobURL is the immutable GitHub URL of path at commit.
func (r RepoRef) BlobURL(commit, path string) string {
	return "https://" + r.Key + "/blob/" + commit + "/" + path
}

// Tag is one recorded tag and the commit it points at.
type Tag struct {
	Name   string
	Commit string
}

// ReleaseIndex is the repository's tag record as the mirror saw it, sorted
// by tag name. Extractors derive their version pairs from it.
type ReleaseIndex struct {
	Repo RepoRef
	Tags []Tag
}

// VersionPair is one upgrade the extractor evaluates: from one release tag
// to another, each pinned to the exact commit the tag pointed at.
type VersionPair struct {
	Repo       RepoRef
	From       string // release version, e.g. "1.36.0"
	FromTag    string // e.g. "v1.36.0"
	FromCommit string
	To         string
	ToTag      string
	ToCommit   string
}

// Key is a stable, human-readable pair name.
func (p VersionPair) Key() string { return p.From + "->" + p.To }

// Extractor derives rule candidates from pinned upstream bytes. It must be
// deterministic: the same version given the same bytes returns the same
// candidates in the same order.
type Extractor interface {
	// ID is the public extractor id, e.g. "k8s.feature-gate-removal".
	ID() string
	// Version is a strict major.minor.patch, bumped on any output change.
	Version() string
	// Applies reports whether the extractor reads this repository.
	Applies(repo RepoRef) bool
	// Pairs returns the version pairs to evaluate.
	Pairs(index ReleaseIndex) []VersionPair
	// Extract reads pinned bytes through r and derives the candidates for
	// one pair. It returns a *Withheld error when the pair cannot be
	// established completely; any other error aborts the run.
	Extract(ctx context.Context, r PinnedReader, pair VersionPair) (Extraction, error)
}

// CodeSource is implemented by every extractor: the embedded Go source of
// its own package (non-test files only are hashed), named by package
// directory relative to the module's internal/ tree.
type CodeSource interface {
	SourceFiles() (dir string, files fs.FS)
}

// Extraction is the result for one pair.
type Extraction struct {
	Candidates []Candidate
	// Proof is the extractor's own account of the derivation (what it
	// parsed and why each claim holds). It is recorded in the manifest and
	// must marshal deterministically.
	Proof any
}

// Withheld means the pair could not be established completely, so no rule
// may be derived from it. It is not a run failure.
type Withheld struct {
	Reason string
	Proof  any
}

func (w *Withheld) Error() string { return "withheld: " + w.Reason }

// IsWithheld reports whether err withholds a pair.
func IsWithheld(err error) (*Withheld, bool) {
	var w *Withheld
	if errors.As(err, &w) {
		return w, true
	}
	return nil, false
}

// Candidate is one rule an extractor proposes. The framework adds the
// evidence state, basis, extractor identity, times and source digests.
type Candidate struct {
	Project       string
	Description   string
	RequiredFacts []Fact
	Rule          Rule
	Sources       []SourceRef
	// PassMembers is an example complete set that holds no forbidden
	// member, used for the pass vector of a forbid_set_member rule. It may
	// be empty.
	PassMembers []string
}

// Fact is one requiredFacts declaration of a pack entry.
type Fact struct {
	Side        string   `json:"side"`
	ID          string   `json:"id"`
	Component   string   `json:"component"`
	Type        string   `json:"type"`
	EnumTokens  []string `json:"enumTokens"`
	Description string   `json:"description"`
}

// Rule is the part of a rule an extractor decides.
type Rule struct {
	ID           string
	Operator     string
	Subject      Subject
	SetCondition *SetCondition
	ReasonCode   string
	NextAction   string
}

// Subject is the reviewed anchor transition.
type Subject struct {
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// SetCondition is a forbid_set_member condition.
type SetCondition struct {
	Side      string   `json:"side"`
	Component string   `json:"component"`
	FactID    string   `json:"factId"`
	Members   []string `json:"members"`
}

// SourceRef cites lines of a file the extractor read. EndLine 0 cites the
// whole file (1 to its last line).
type SourceRef struct {
	ID        string
	Repo      RepoRef
	Commit    string
	Path      string
	StartLine int
	EndLine   int
}
