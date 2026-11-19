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
//     key, form one of changelog-file, changelog-per-line-file,
//     changelog-per-version-file, github-release, post-tag, docs-page, monorepo;
//   - for the two template forms, path is a template holding the form's one
//     placeholder ({line} or {version}) once, made of [A-Za-z0-9._/-] only;
//     a per-line row also has headingStyle and boundary styles, a per-version
//     row has neither;
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
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
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
	"version-slash-date":     `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	"version-plain":          `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`,
	"version-v-prefixed":     `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`,
	"version-bracketed":      `^\[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\]$`,
	"version-bracketed-date": `^\[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	"version-dash-date":      `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) - [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	"version-space-date":     `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	"version-v-slash-date":   `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	// RE2 has no backreference: the link target is tied to the row repo and to
	// the version by a post-match check in the reader (linkTargetMatches); a
	// heading whose target differs is not a final heading. A second heading
	// for the same version is refused (EntryDuplicate).
	"version-linked-paren-date": `^\[v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\]\(https://github\.com/(?P<slug>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/tree/(?P<ref>[A-Za-z0-9._-]+)\) \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$`,
	"version-v-paren-date":      `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+) \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$`,
	// A dual heading names two versions; which half is the component's is
	// fixed by the style name, never by the file. The other half is read as
	// plain text, and a tag whose version is the other half is not located.
	"version-dual-first":   `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)/v[0-9]+\.[0-9]+\.[0-9]+$`,
	"version-dual-second":  `^v[0-9]+\.[0-9]+\.[0-9]+/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`,
	"release-v-slash-date": `^Release v(?P<version>[0-9]+\.[0-9]+\.[0-9]+) - [0-9]{4}/[0-9]{2}/[0-9]{2}$`,
}

// boundaryStyles maps a boundary style name to its fixed pattern.
var boundaryStyles = map[string]string{
	"main-unreleased":               `^main / unreleased$`,
	"main-unreleased-parenthesised": `^main / \(unreleased\)$`,
	"unreleased":                    `^Unreleased$`,
	"unreleased-bracketed":          `^\[Unreleased\]$`,
	"prerelease-plain":              `^[0-9]+\.[0-9]+\.[0-9]+-(rc|alpha|beta)\.[0-9]+$`,
	"prerelease-v-prefixed":         `^v[0-9]+\.[0-9]+\.[0-9]+-(rc|alpha|beta)\.[0-9]+$`,
	"master-unreleased":             `^master / unreleased$`,
	// A two-part line heading can never name an entry (no patch part).
	"line-heading-v":               `^v[0-9]+\.[0-9]+$`,
	"prerelease-linked-paren-date": `^\[v[0-9]+\.[0-9]+\.[0-9]+-(?:rc|alpha|beta|ea)\.?[0-9]+\]\(https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/tree/[A-Za-z0-9._-]+\) \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$`,
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
	case FormPerLineFile, FormPerVersionFile:
		return r.templated(t)
	default:
		return Target{}, fmt.Errorf("form %q is not allowed in the table", r.Form)
	}
	if r.Path == "" || strings.ContainsAny(r.Path, "\x00\\") || path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path ||
		r.Path == "." || r.Path == ".." || strings.HasPrefix(r.Path, "../") {
		return Target{}, fmt.Errorf("path %q must be a clean repository-relative path", r.Path)
	}
	if !templateCharsetRE.MatchString(r.Path) || hasDotDotElement(r.Path) {
		return Target{}, fmt.Errorf("path %q uses characters outside [A-Za-z0-9._/-] or a \"..\" element", r.Path)
	}
	if !markdownPath(r.Path) {
		return Target{}, fmt.Errorf("path %q is not a markdown file (.md); toml, yaml and other formats are not read", r.Path)
	}
	t.Path = r.Path
	return r.styled(t)
}

// hasDotDotElement reports a ".." substring (the closed check refuses any).
func hasDotDotElement(p string) bool { return strings.Contains(p, "..") }

// markdownPath reports a path of a markdown file. Only ".md" is read.
func markdownPath(p string) bool {
	return strings.HasSuffix(p, ".md") && len(path.Base(p)) > len(".md")
}

// templated reads a row of the two path-template forms. The path holds the
// form's one placeholder from the closed vocabulary (templatePlaceholders)
// once, and otherwise only the characters of templateCharsetRE; nothing else
// is a template. A per-line row reads headings like a file row; a per-version
// row has none, the file being the entry.
func (r rowData) templated(t Target) (Target, error) {
	ph := templatePlaceholders[r.Form]
	if !markdownPath(r.Path) {
		return Target{}, fmt.Errorf("path template %q is not a markdown file (.md); toml, yaml and other formats are not read", r.Path)
	}
	if !templateCharsetRE.MatchString(strings.Replace(r.Path, ph, "", 1)) {
		return Target{}, fmt.Errorf("path template %q uses characters outside [A-Za-z0-9._/-] and the %s placeholder", r.Path, ph)
	}
	if err := checkTemplate(r.Path, ph); err != nil {
		return Target{}, err
	}
	t.Path = r.Path
	if r.Form == FormPerVersionFile {
		if r.HeadingStyle != "" || r.BoundaryStyles != nil {
			return Target{}, errors.New("a per-version row has no headingStyle or boundaryStyles")
		}
		return t, nil
	}
	return r.styled(t)
}

// templatePlaceholders is the closed placeholder vocabulary: per form, the one
// token a path template holds. {line} is major.minor of the tag, {version}
// the full final version, both without the "v" of a tag.
var templatePlaceholders = map[string]string{
	FormPerLineFile:    placeholderLine,
	FormPerVersionFile: placeholderVersion,
}

var templateCharsetRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// styled adds the heading and boundary styles of a row that reads headings.
func (r rowData) styled(t Target) (Target, error) {
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

// RowDigest is the sha256 (hex) of the canonical, resolved form of a row:
// component, repo, form, path and the fixed patterns of its styles. The same
// row gives the same digest whether it comes from a proposal or from the table.
// Serialization: compact JSON (Go encoding/json, HTML escaping off, no trailing
// newline) of the object {"component","repo","form","path","heading",
// "boundary","maxBytes"} in that key order, boundary an array ([] when none),
// heading and boundary the resolved regular expressions.
func (t Target) RowDigest() string {
	boundary := t.BoundaryPatterns
	if boundary == nil {
		boundary = []string{} // nil and empty are one row
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		Component string   `json:"component"`
		Repo      string   `json:"repo"`
		Form      string   `json:"form"`
		Path      string   `json:"path"`
		Heading   string   `json:"heading"`
		Boundary  []string `json:"boundary"`
		MaxBytes  int      `json:"maxBytes"`
	}{t.Component, t.Repo.Key, t.Form, t.Path, t.HeadingPattern, boundary, t.MaxBytes})
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// RowDigest is the row digest of the proposed row, resolved through the same
// strict loader as targets.json.
func (p Proposal) RowDigest() (string, error) {
	t, err := p.Row.target()
	if err != nil {
		return "", err
	}
	return t.RowDigest(), nil
}
