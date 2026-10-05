// SPDX-License-Identifier: AGPL-3.0-only

// Package repinbaselines reads the owner's per-repository baseline choices
// for "evidence repin".
//
// The shared latest rule (package latestrelease) refuses to pick a latest
// release for a repository whose tags mix schemes; such a repository stays
// PENDING_AMBIGUOUS_LATEST and every rule citing it cannot be renewed. The
// owner may decide, for one repository, which tag is the baseline its
// citations are compared with. The decision is a reviewed file in the
// repository (cli/knowledge/repin-baselines.json). Each entry names the
// repository, the chosen tag, the exact commit that tag must resolve to, a
// reason, the decision time and a reference to the owner approval that
// admitted the entry. A change to the file is admitted by the knowledge gate
// only with an owner approval (subject repinBaseline), and repin uses an
// entry only while the tag still resolves to exactly the recorded commit.
package repinbaselines

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	// Schema identifies the baselines file.
	Schema = "prufyx.io/repin-baselines/v1"
	// DefaultPath is where the file lives in the repository.
	DefaultPath = "cli/knowledge/repin-baselines.json"
	// ApprovalPack is the pack name an approval for an entry carries, and
	// the directory under the approvals directory that holds the files.
	ApprovalPack = "repin-baselines"
	// MaxBytes bounds the file.
	MaxBytes = 1 << 20
	// MaxEntries bounds the number of entries.
	MaxEntries = 512
	maxReason  = 500
)

// Entry is one repository's baseline choice. Field order is the order of
// the sorted keys of its canonical form.
type Entry struct {
	// Approval is the candidate id of the owner approval that admitted the
	// entry (for example "pr-15").
	Approval string `json:"approval"`
	// Commit is the exact commit SHA the tag must resolve to.
	Commit    string `json:"commit"`
	DecidedAt string `json:"decidedAt"`
	Reason    string `json:"reason"`
	// Repository is owner/repo.
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

// File is the baselines file.
type File struct {
	Entries []Entry `json:"entries"`
	Schema  string  `json:"schema"`
}

var (
	ownerRE    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)
	repoRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	tagRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	commitRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	timeRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	approvalRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// SplitRepository splits owner/repo and checks both parts.
func SplitRepository(repository string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok || !ownerRE.MatchString(owner) || !repoRE.MatchString(repo) || repo == "." || repo == ".." || strings.HasSuffix(repo, ".git") {
		return "", "", fmt.Errorf("repository %q is not owner/repo", clip(repository))
	}
	return owner, repo, nil
}

// Key is the case-folded owner/repo a repository is looked up by. GitHub
// names are case-insensitive, so two spellings are one repository.
func Key(repository string) string { return strings.ToLower(repository) }

// ApprovalID is the rule id an approval for the repository carries and the
// base name of its file: owner--repo. An owner login cannot hold two
// consecutive hyphens, so the first "--" splits it back unambiguously.
func ApprovalID(repository string) (string, error) {
	owner, repo, err := SplitRepository(repository)
	if err != nil {
		return "", err
	}
	return strings.ToLower(owner) + "--" + strings.ToLower(repo), nil
}

func clip(s string) string {
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// Validate checks one entry.
func (e Entry) Validate() error {
	if _, _, err := SplitRepository(e.Repository); err != nil {
		return err
	}
	switch {
	case !tagRE.MatchString(e.Tag) || strings.Contains(e.Tag, ".."):
		return fmt.Errorf("%s: tag %q is not a plain tag name", clip(e.Repository), clip(e.Tag))
	case !commitRE.MatchString(e.Commit):
		return fmt.Errorf("%s: commit is not 40 lowercase hex digits", clip(e.Repository))
	case !timeRE.MatchString(e.DecidedAt):
		return fmt.Errorf("%s: decidedAt is not an RFC 3339 UTC time", clip(e.Repository))
	case !approvalRE.MatchString(e.Approval):
		return fmt.Errorf("%s: approval reference is out of range", clip(e.Repository))
	case strings.TrimSpace(e.Reason) == "" || len(e.Reason) > maxReason || !utf8.ValidString(e.Reason) || e.Reason != strings.TrimSpace(e.Reason):
		return fmt.Errorf("%s: reason must be 1..%d characters without surrounding space", clip(e.Repository), maxReason)
	}
	for _, r := range e.Reason {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: reason holds a control character", clip(e.Repository))
		}
	}
	return nil
}

// Canonical is the entry's canonical JSON: keys sorted, two-space indent,
// one final newline. This is what an owner approval binds.
func (e Entry) Canonical() []byte {
	raw, err := json.MarshalIndent(map[string]string{
		"approval": e.Approval, "commit": e.Commit, "decidedAt": e.DecidedAt,
		"reason": e.Reason, "repository": e.Repository, "tag": e.Tag,
	}, "", "  ")
	if err != nil {
		return nil
	}
	return append(raw, '\n')
}

// Digest is "sha256:" and the hex sha256 of the canonical form. Repin
// records it on every citation compared with the entry's tag.
func (e Entry) Digest() string {
	sum := sha256.Sum256(e.Canonical())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Parse reads and checks a baselines file strictly: no unknown or repeated
// member, the right schema, valid entries sorted by repository, no
// repository twice (case-insensitively).
func Parse(raw []byte) (File, error) {
	if len(raw) > MaxBytes {
		return File{}, errors.New("repin baselines: file too large")
	}
	raw = []byte(strings.TrimSuffix(string(raw), "\n"))
	if err := strictjson.Check(raw); err != nil {
		return File{}, fmt.Errorf("repin baselines: %w", err)
	}
	var f File
	if err := strictjson.Decode(raw, &f); err != nil {
		return File{}, fmt.Errorf("repin baselines: %w", err)
	}
	if f.Schema != Schema {
		return File{}, errors.New("repin baselines: wrong schema")
	}
	if len(f.Entries) > MaxEntries {
		return File{}, errors.New("repin baselines: too many entries")
	}
	seen := map[string]bool{}
	for i, e := range f.Entries {
		if err := e.Validate(); err != nil {
			return File{}, fmt.Errorf("repin baselines: %w", err)
		}
		k := Key(e.Repository)
		if seen[k] {
			return File{}, fmt.Errorf("repin baselines: repository %s twice", clip(e.Repository))
		}
		seen[k] = true
		if i > 0 && Key(f.Entries[i-1].Repository) > k {
			return File{}, errors.New("repin baselines: entries are not sorted by repository")
		}
	}
	return f, nil
}

// ParseOptional is Parse for a file that may be absent: nil raw is an empty
// file.
func ParseOptional(raw []byte) (File, error) {
	if raw == nil {
		return File{Schema: Schema, Entries: []Entry{}}, nil
	}
	return Parse(raw)
}

// Lookup returns the entry for a repository (owner/repo, any case).
func (f File) Lookup(repository string) (Entry, bool) {
	k := Key(repository)
	i := sort.Search(len(f.Entries), func(i int) bool { return Key(f.Entries[i].Repository) >= k })
	if i < len(f.Entries) && Key(f.Entries[i].Repository) == k {
		return f.Entries[i], true
	}
	return Entry{}, false
}

// Marshal renders the file the way it is committed (indented, final
// newline).
func (f File) Marshal() ([]byte, error) {
	if f.Entries == nil {
		f.Entries = []Entry{}
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
