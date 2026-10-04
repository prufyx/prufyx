// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Schemas.
const (
	BundleSchema = "prufyx.io/consensus-claims/v1"
	ReportSchema = "prufyx.io/consensus-report/v1"
)

// Bundle bounds.
const (
	MaxBundleBytes    = 1 << 20
	MaxClaims         = 500
	MaxNamesPerClaim  = 16
	maxNameBytes      = 100
	maxKindBytes      = 64
	maxComponentBytes = 64
)

// Source pins the release notes file a bundle's claims were read from.
// The normalise command writes exactly this object as source.json.
type Source struct {
	Repo              string `json:"repo"`
	Commit            string `json:"commit"`
	Path              string `json:"path"`
	FileSHA256        string `json:"fileSha256"`
	Section           string `json:"section"`
	NormaliserVersion string `json:"normaliserVersion"`
	NormalisedSHA256  string `json:"normalisedSha256"`
}

// FromRelease is the earlier release, pinned by commit.
type FromRelease struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Tag    string `json:"tag"`
}

// ToRelease is the release whose section is read.
type ToRelease struct {
	Tag string `json:"tag"`
}

// Claim is one proposed removal: a kind and the names it is about. It
// carries no quote, no line numbers and no free text.
type Claim struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Component string   `json:"component,omitempty"`
	Names     []string `json:"names"`
}

// Bundle is a claims document.
type Bundle struct {
	Schema      string      `json:"schema"`
	Source      Source      `json:"source"`
	FromRelease FromRelease `json:"fromRelease"`
	ToRelease   ToRelease   `json:"toRelease"`
	Claims      []Claim     `json:"claims"`
}

var (
	claimIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hexRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pathRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// DecodeBundle reads a claims bundle strictly: one JSON value, no repeated
// or case-variant members, no members the schema does not declare, every
// field present and well formed. It checks the form only; Verify checks
// the content.
func DecodeBundle(raw []byte) (*Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("the claims bundle has %d bytes, at most %d", len(raw), MaxBundleBytes)
	}
	var b Bundle
	if err := strictjson.Decode(raw, &b); err != nil {
		return nil, fmt.Errorf("claims bundle: %w", err)
	}
	if err := b.check(); err != nil {
		return nil, fmt.Errorf("claims bundle: %w", err)
	}
	return &b, nil
}

func (b *Bundle) check() error {
	if b.Schema != BundleSchema {
		return fmt.Errorf("schema %q, want %q", b.Schema, BundleSchema)
	}
	s := b.Source
	if _, err := extract.ParseRepo(s.Repo); err != nil || s.Repo != normalRepo(s.Repo) {
		return errors.New("source.repo must be github.com/<owner>/<name> in lower case")
	}
	if !extract.IsCommitSHA(s.Commit) {
		return errors.New("source.commit must be a full lowercase 40-character SHA")
	}
	if !pathRE.MatchString(s.Path) || len(s.Path) > 512 {
		return errors.New("source.path is not a plain repository path")
	}
	if !hexRE.MatchString(s.FileSHA256) || !hexRE.MatchString(s.NormalisedSHA256) {
		return errors.New("source digests must be 64 lowercase hex characters")
	}
	if s.Section == "" || len(s.Section) > 64 || s.NormaliserVersion == "" || len(s.NormaliserVersion) > 16 {
		return errors.New("source.section and source.normaliserVersion are required")
	}
	f := b.FromRelease
	if _, err := extract.ParseRepo(f.Repo); err != nil || f.Repo != normalRepo(f.Repo) {
		return errors.New("fromRelease.repo must be github.com/<owner>/<name> in lower case")
	}
	if !extract.IsCommitSHA(f.Commit) || f.Tag == "" || len(f.Tag) > 64 {
		return errors.New("fromRelease needs a full commit SHA and a tag")
	}
	if b.ToRelease.Tag == "" || len(b.ToRelease.Tag) > 64 {
		return errors.New("toRelease.tag is required")
	}
	if len(b.Claims) == 0 || len(b.Claims) > MaxClaims {
		return fmt.Errorf("%d claims, want 1-%d", len(b.Claims), MaxClaims)
	}
	ids := map[string]bool{}
	for i, c := range b.Claims {
		if !claimIDRE.MatchString(c.ID) {
			return fmt.Errorf("claim %d: id %q is not [a-z0-9][a-z0-9._-]{0,63}", i, c.ID)
		}
		if ids[c.ID] {
			return fmt.Errorf("claim id %q appears twice", c.ID)
		}
		ids[c.ID] = true
		if c.Kind == "" || len(c.Kind) > maxKindBytes || len(c.Component) > maxComponentBytes {
			return fmt.Errorf("claim %s: kind is required (at most %d bytes)", c.ID, maxKindBytes)
		}
		if len(c.Names) == 0 || len(c.Names) > MaxNamesPerClaim {
			return fmt.Errorf("claim %s: %d names, want 1-%d", c.ID, len(c.Names), MaxNamesPerClaim)
		}
		for _, n := range c.Names {
			if len(n) > maxNameBytes {
				return fmt.Errorf("claim %s: a name is longer than %d bytes", c.ID, maxNameBytes)
			}
		}
	}
	return nil
}

func normalRepo(s string) string {
	r, err := extract.ParseRepo(s)
	if err != nil {
		return ""
	}
	return r.Key
}
