// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

// The reviewed rows live in targets.json (schema id
// prufyx.io/changelog-targets/v1), embedded in the binary. Rows are data; the
// schema is closed so that a row can never carry logic:
//
//   - the top level is {"schema", "rows"}; unknown fields and duplicate keys
//     are refused, and so is anything after the document;
//   - rows are not empty and sorted by component, strictly ascending (so no
//     component twice); no two rows name the same repo;
//   - a row is {component, repo, form, path, headingStyle, boundaryStyles};
//   - component is a lower-case slug, repo a canonical github.com/<org>/<repo>
//     key, form one of changelog-file, github-release, post-tag, docs-page,
//     monorepo;
//   - path (a clean repository-relative path, no "..", not absolute),
//     headingStyle and boundaryStyles are present only for the form
//     "changelog-file" (path, headingStyle and at least one boundary style required) and absent for every
//     other form;
//   - headingStyle and each boundary style are names from the closed tables
//     headingStyles and boundaryStyles below. A name maps to a fixed regular
//     expression compiled in code; the data never holds a regular expression.
//
// Adding a row is a data change. Adding a style or a form is a code change.
// A table that does not satisfy the schema is not loaded: Reviewed is empty
// (every component is refused) and LoadError reports why. targets.json is part
// of the embedded source set, so a row change changes the extractor code
// digest that gates pin.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// TargetsSchema is the schema id of targets.json.
const TargetsSchema = "prufyx.io/changelog-targets/v1"

//go:embed targets.json
var targetsJSON []byte

// headingStyles maps a heading style name to its fixed pattern.
var headingStyles = map[string]string{
	"version-slash-date": `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
}

// boundaryStyles maps a boundary style name to its fixed pattern.
var boundaryStyles = map[string]string{
	"main-unreleased":               `^main / unreleased$`,
	"main-unreleased-parenthesised": `^main / \(unreleased\)$`,
}

var componentSlugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

type targetsDoc struct {
	Schema string    `json:"schema"`
	Rows   []rowData `json:"rows"`
}

type rowData struct {
	Component      string   `json:"component"`
	Repo           string   `json:"repo"`
	Form           string   `json:"form"`
	Path           string   `json:"path,omitempty"`
	HeadingStyle   string   `json:"headingStyle,omitempty"`
	BoundaryStyles []string `json:"boundaryStyles,omitempty"`
}

// Reviewed is the reviewed table of changelog targets, loaded from
// targets.json. A component without a row is refused. If the data does not
// load, the table is empty and LoadError says why.
var Reviewed, loadErr = parseTargets(targetsJSON)

// LoadError is the reason the embedded table was refused, or nil.
func LoadError() error { return loadErr }

// parseTargets reads and strictly validates a targets document. It returns no
// rows with an error, never part of a table.
func parseTargets(data []byte) ([]Target, error) {
	if err := noDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("changelog targets: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc targetsDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("changelog targets: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("changelog targets: data after the document")
	}
	if doc.Schema != TargetsSchema {
		return nil, fmt.Errorf("changelog targets: schema %q, want %q", doc.Schema, TargetsSchema)
	}
	if len(doc.Rows) == 0 {
		return nil, errors.New("changelog targets: no rows")
	}
	out := make([]Target, 0, len(doc.Rows))
	prev := ""
	repos := map[string]string{}
	for i, r := range doc.Rows {
		if i > 0 && r.Component <= prev {
			return nil, fmt.Errorf("changelog targets: row %q is not sorted strictly after %q", r.Component, prev)
		}
		prev = r.Component
		if other, dup := repos[r.Repo]; dup {
			return nil, fmt.Errorf("changelog targets: row %q names repo %q already used by %q", r.Component, r.Repo, other)
		}
		repos[r.Repo] = r.Component
		t, err := r.target()
		if err != nil {
			return nil, fmt.Errorf("changelog targets: row %q: %w", r.Component, err)
		}
		out = append(out, t)
	}
	return out, nil
}

func (r rowData) target() (Target, error) {
	if len(r.Component) > 63 || !componentSlugRE.MatchString(r.Component) {
		return Target{}, errors.New("component is not a slug")
	}
	if p, err := extract.ParseRepo(r.Repo); err != nil || p.Key != r.Repo {
		return Target{}, fmt.Errorf("repo %q is not a canonical repository key", r.Repo)
	}
	t := Target{Component: r.Component, Repo: extract.RepoRef{Key: r.Repo}, Form: r.Form}
	switch r.Form {
	case FormGithubRelease, FormPostTag, FormDocsPage, FormMonorepo:
		if r.Path != "" || r.HeadingStyle != "" || r.BoundaryStyles != nil {
			return Target{}, fmt.Errorf("form %q is not read: path, headingStyle and boundaryStyles must be absent", r.Form)
		}
		return t, nil
	case FormFile:
	default:
		return Target{}, fmt.Errorf("form %q is not allowed in the table", r.Form)
	}
	if r.Path == "" || strings.ContainsAny(r.Path, "\x00\\") || path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path ||
		r.Path == "." || r.Path == ".." || strings.HasPrefix(r.Path, "../") {
		return Target{}, fmt.Errorf("path %q must be a clean repository-relative path", r.Path)
	}
	t.Path = r.Path
	h, ok := headingStyles[r.HeadingStyle]
	if !ok {
		return Target{}, fmt.Errorf("heading style %q is not known", r.HeadingStyle)
	}
	t.HeadingPattern = h
	if len(r.BoundaryStyles) == 0 {
		return Target{}, errors.New("a file row needs at least one boundary style")
	}
	seen := map[string]bool{}
	for _, b := range r.BoundaryStyles {
		p, ok := boundaryStyles[b]
		if !ok {
			return Target{}, fmt.Errorf("boundary style %q is not known", b)
		}
		if seen[b] {
			return Target{}, fmt.Errorf("boundary style %q listed twice", b)
		}
		seen[b] = true
		t.BoundaryPatterns = append(t.BoundaryPatterns, p)
	}
	if _, err := t.compile(); err != nil {
		return Target{}, err
	}
	return t, nil
}

// noDuplicateKeys refuses an object that names a key twice, which the decoder
// would otherwise resolve silently to the last value.
func noDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if keys[k] {
					return fmt.Errorf("duplicate key %q", k)
				}
				keys[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token()
		return err
	}
	return walk()
}
