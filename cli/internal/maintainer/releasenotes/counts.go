// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// This file is the only place that knows the shape of the coverage counts
// file. Everything else reads the Counts struct.

const (
	// CountsSchema is the schema string of the counts file.
	CountsSchema = "prufyx.io/coverage-readme-counts/v1"
	// CountsPath is where a tree commits its counts file; the previous
	// release is read from it with `git show <tag>:<path>`.
	CountsPath = "cli/docs/generated/coverage-counts.json"
	// BootstrapTag is the one release that has no counts file at its tag.
	BootstrapTag = "v0.1.0-beta.0"
	// BootstrapCountsPath holds, in the tree being described, the counts
	// recomputed once from the BootstrapTag tree.
	BootstrapCountsPath = "cli/docs/generated/coverage-counts-v0.1.0-beta.0.json"
	// BootstrapCountsSha256 pins that file. The pin is fixed in code: the file was
	// generated once; any other bytes fail closed.
	BootstrapCountsSha256 = "db6de7abaa93a36e8222da29b908b688add5d17bfa1a1f3ad9f5bc9b4d8a98c3"
	// BootstrapApproximationNote is printed in the notes whenever the
	// previous release is the bootstrap baseline.
	BootstrapApproximationNote = "The figures for `" + BootstrapTag + "` in this section are approximate: that release has no counts file, so they were recomputed from its rules with the current pinned release lines."
	maxCounts                  = 64 << 20
)

// Counts is the counts file: the coverage report plus the facts that tie it to
// the README block it was generated with.
type Counts struct {
	Schema            string                `json:"schema"`
	Report            coveragereport.Report `json:"report"`
	InventoryCounts   map[string]int        `json:"inventoryCounts"`
	ReadmeBlockSha256 string                `json:"readmeBlockSha256,omitempty"`

	// Sha256 is the digest of the exact file bytes; it is not in the file.
	Sha256 string `json:"-"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Sum256Hex returns the lower-case hex sha256 of data.
func Sum256Hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// ReadmeBlock returns the bytes between the README coverage markers, the
// scope readmeBlockSha256 covers.
func ReadmeBlock(readme string) (string, error) {
	b, e := coveragereport.READMEBegin, coveragereport.READMEEnd
	if strings.Count(readme, b) != 1 || strings.Count(readme, e) != 1 {
		return "", errors.New("README must have exactly one coverage marker pair")
	}
	i, j := strings.Index(readme, b), strings.Index(readme, e)
	if j < i {
		return "", errors.New("README coverage markers are out of order")
	}
	start := i + len(b)
	if (i > 0 && readme[i-1] != '\n') || start >= len(readme) || readme[start] != '\n' || (j > 0 && readme[j-1] != '\n') || j < start+1 {
		return "", errors.New("README coverage markers must be whole lines")
	}
	return readme[start+1 : j], nil
}

// LoadCounts parses and verifies a counts file. It refuses an unknown schema,
// an unknown field, trailing data, an inconsistent report and, when the file
// carries readmeBlockSha256 and readme is non-nil, a README block that hashes
// differently.
func LoadCounts(data, readme []byte) (*Counts, error) {
	if len(data) == 0 || len(data) > maxCounts {
		return nil, errors.New("counts file is empty or too large")
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("counts file: %w", err)
	}
	if probe.Schema != CountsSchema {
		return nil, fmt.Errorf("counts file: schema %q, want %q", probe.Schema, CountsSchema)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Counts
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("counts file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("counts file: data after the JSON document")
	}
	if c.Report.Schema != coveragereport.Schema {
		return nil, fmt.Errorf("counts file: report schema %q, want %q", c.Report.Schema, coveragereport.Schema)
	}
	if c.InventoryCounts == nil {
		return nil, errors.New("counts file: inventoryCounts missing")
	}
	seen := map[string]bool{}
	for _, p := range c.Report.Projects {
		k := projectKeyOf(p)
		if p.Project == "" || seen[k] {
			return nil, fmt.Errorf("counts file: empty or duplicate project %q", p.Project)
		}
		seen[k] = true
		pairs := map[string]bool{}
		for _, pr := range p.Pairs {
			switch pr.Status {
			case coveragereport.StatusA, coveragereport.StatusB, coveragereport.StatusS, coveragereport.StatusG:
			default:
				return nil, fmt.Errorf("counts file: project %q pair %s->%s has status %q", p.Project, pr.From, pr.To, pr.Status)
			}
			pk := pr.From + "\x00" + pr.To
			if pr.From == "" || pr.To == "" || pairs[pk] {
				return nil, fmt.Errorf("counts file: project %q has an empty or duplicate pair", p.Project)
			}
			pairs[pk] = true
		}
	}
	if c.ReadmeBlockSha256 != "" {
		if !sha256Hex.MatchString(c.ReadmeBlockSha256) {
			return nil, errors.New("counts file: readmeBlockSha256 is not a lower-case sha256")
		}
		if readme != nil {
			block, err := ReadmeBlock(string(readme))
			if err != nil {
				return nil, err
			}
			if Sum256Hex([]byte(block)) != c.ReadmeBlockSha256 {
				return nil, errors.New("counts file: readmeBlockSha256 does not match the README coverage block")
			}
		}
	}
	c.Sha256 = Sum256Hex(data)
	return &c, nil
}

func projectKeyOf(p coveragereport.Project) string { return p.Catalog + "\x00" + p.Project }

// PreviousPin names the previous release the notes compare against.
type PreviousPin struct {
	Tag          string
	Commit       string
	CountsSha256 string
}

// ReadCounts reads the counts file of a tree and verifies it against the
// tree's README. A missing file is an error, never an empty set.
func ReadCounts(t Tree, path string) (*Counts, error) {
	data, err := t.Read(path)
	if err != nil {
		return nil, fmt.Errorf("counts file %s: %w", path, err)
	}
	readme, err := t.Read(readmePath)
	if errors.Is(err, fs.ErrNotExist) {
		readme = nil
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w", readmePath, err)
	}
	c, err := LoadCounts(data, readme)
	if err != nil {
		return nil, err
	}
	if c.ReadmeBlockSha256 != "" && readme == nil {
		return nil, fmt.Errorf("counts file pins a README block but %s is missing", readmePath)
	}
	return c, nil
}

// ReadPreviousCounts reads the previous release's counts through the tree of
// its tag and checks them against the expected sha256 pin. The bootstrap tag
// reads BootstrapCountsPath from cur (the tree being described) and compares
// with BootstrapCountsSha256 instead.
func ReadPreviousCounts(prev, cur Tree, tag, wantSha string) (*Counts, error) {
	path, src := CountsPath, prev
	if tag == BootstrapTag {
		path, src, wantSha = BootstrapCountsPath, cur, BootstrapCountsSha256
	}
	if !sha256Hex.MatchString(wantSha) {
		return nil, fmt.Errorf("no valid sha256 pin for the previous counts of %s", tag)
	}
	data, err := src.Read(path)
	if err != nil {
		return nil, fmt.Errorf("previous counts %s: %w", path, err)
	}
	if got := Sum256Hex(data); got != wantSha {
		return nil, fmt.Errorf("previous counts %s: sha256 %s does not match the pin %s", path, got, wantSha)
	}
	return LoadCounts(data, nil)
}
