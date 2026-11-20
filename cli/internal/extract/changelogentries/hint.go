// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Reasons a source hint is refused (typed; the list is closed). A hint only
// narrows where propose-rows looks; it never relaxes a check.
const (
	HintMalformed       = "HINT_MALFORMED"          // not one closed JSON object, unknown or repeated field, oversized
	HintSourceUnsupport = "HINT_SOURCE_UNSUPPORTED" // the source is not a file of the tree
	HintPathInvalid     = "HINT_PATH_INVALID"       // not a clean repository-relative markdown path
	HintStyleUnknown    = "HINT_STYLE_UNKNOWN"      // the style is not in the closed set of heading styles
	HintPathMissing     = "HINT_PATH_MISSING"       // no such file in the tree at the newest scored tag
	HintNoCandidate     = "HINT_PATH_NOT_CANDIDATE" // the file is not a place the closed candidates read
)

// HintError is the typed refusal of a hint.
type HintError struct{ Code, Detail string }

func (e *HintError) Error() string { return e.Code + ": " + e.Detail }

// Limits of one hint file.
const (
	MaxHintBytes = 2048
	MaxHintPath  = 256
)

// Hint is the closed source hint: where the release notes live (a file of the
// tree at the newest tag) and which closed heading style their version
// headings use. Nothing else is accepted.
type Hint struct {
	Source string `json:"source"`
	Path   string `json:"path,omitempty"`
	Style  string `json:"style"`
}

var hintPathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// DecodeHint is the strict decoder of a hint file: one JSON object, no unknown
// or repeated field, nothing after it, bounded, and a valid hint.
func DecodeHint(raw []byte) (Hint, error) {
	bad := func(d string) (Hint, error) { return Hint{}, &HintError{HintMalformed, d} }
	if len(raw) == 0 || len(raw) > MaxHintBytes {
		return bad("hint file empty or larger than the cap")
	}
	if err := hintUniqueKeys(raw); err != nil {
		return bad(err.Error())
	}
	var h Hint
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return bad("not the closed hint schema: " + err.Error())
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad("trailing data after the hint")
	}
	return h, h.validate()
}

func hintUniqueKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		ks, ok := k.(string)
		if err != nil || !ok {
			return errors.New("not a JSON object")
		}
		// Exact lowercase names only: encoding/json matches field names
		// case-insensitively, so Path or PATH would otherwise be a silent
		// second spelling of path.
		if ks != "source" && ks != "path" && ks != "style" {
			return errors.New("unknown or mis-cased key " + ks)
		}
		if seen[ks] {
			return errors.New("repeated key " + ks)
		}
		seen[ks] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return errors.New("not a JSON object")
		}
	}
	return nil
}

func (h Hint) validate() error {
	if h.Source != "path" {
		return &HintError{HintSourceUnsupport, "source must be path"}
	}
	if _, ok := headingStyles[h.Style]; !ok || !inList(headingOrder, h.Style) {
		return &HintError{HintStyleUnknown, "style is not in the closed set"}
	}
	p := h.Path
	switch {
	case p == "" || len(p) > MaxHintPath:
		return &HintError{HintPathInvalid, "path empty or too long"}
	case !hintPathRE.MatchString(p), path.Clean(p) != p, strings.Contains(p, ".."):
		return &HintError{HintPathInvalid, "path is not a clean repository-relative path"}
	case !strings.HasSuffix(p, ".md"):
		return &HintError{HintPathInvalid, "path is not a markdown file"}
	}
	return nil
}

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// pathMatches reports whether candidate path (a template or a file) names the
// hinted file for some scored tag.
func (h Hint) pathMatches(cand string, window []extract.Tag) bool {
	if cand == h.Path {
		return true
	}
	for _, tag := range window {
		v, ok := tagVersion(tag.Name)
		if !ok {
			continue
		}
		line := v
		if i := strings.LastIndex(v, "."); i > 0 {
			line = v[:i]
		}
		r := strings.NewReplacer(placeholderVersion, v, placeholderLine, line)
		if r.Replace(cand) == h.Path {
			return true
		}
	}
	return false
}

// checkHintFile confirms the hinted file exists in the tree at the newest
// scored tag (a read of a repository-relative path, never the host).
func checkHintFile(src extract.PinnedReader, repo extract.RepoRef, tag extract.Tag, h Hint) error {
	if _, err := src.Read(repo, tag.Commit, h.Path); err != nil {
		if errors.Is(err, extract.ErrNotFound) {
			return &HintError{HintPathMissing, fmt.Sprintf("%s is not in the tree at %s", h.Path, tag.Name)}
		}
		return err
	}
	return nil
}
