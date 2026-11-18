// SPDX-License-Identifier: AGPL-3.0-only

// Package k8sdeclared builds the public table of Kubernetes versions that
// upstream projects declare per release. Every row is a citation: the
// upstream repository and tag, the commit the tag resolved to through the
// upstream API, the file path, the cited lines, and digests of the file and
// of the API responses. The table states what upstream declared. It is not a
// Prufyx support statement, a test result or a compatibility verdict.
package k8sdeclared

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Schema and label of the generated document.
const (
	SchemaID = "prufyx.k8s-declared/v1"
	Label    = "Kubernetes versions declared by upstream per project release. These are upstream statements read at a cited tag, not support, test or compatibility claims by Prufyx."
)

// Source kinds. The set is closed.
const (
	KindChart  = "chart_kubeversion"
	KindMatrix = "docs_matrix"
)

// Release statuses.
const (
	StatusDeclared    = "declared"
	StatusNotDeclared = "not_declared"
)

// Shapes of a declaration.
const (
	ShapeMinOnly = "min_only"
	ShapeBounded = "bounded"
)

// Not-declared reasons. The set is closed.
const (
	ReasonNoSource        = "no_source_reviewed"
	ReasonSourceAbsent    = "source_absent_at_tag"
	ReasonNoDeclaration   = "no_declaration_in_source"
	ReasonNotLowerBound   = "constraint_not_single_lower_bound"
	ReasonSourceUnusable  = "source_not_parseable"
	ReasonMatrixRowAbsent = "matrix_row_absent"
	ReasonMatrixLayout    = "matrix_layout_unrecognized"
	ReasonMatrixLowerEdge = "matrix_lower_bound_at_edge"
)

var reasons = map[string]bool{
	ReasonNoSource: true, ReasonSourceAbsent: true, ReasonNoDeclaration: true,
	ReasonNotLowerBound: true, ReasonSourceUnusable: true, ReasonMatrixRowAbsent: true,
	ReasonMatrixLayout: true, ReasonMatrixLowerEdge: true,
}

// Input is the reviewed list of projects, sources and release tags.
type Input struct {
	Schema   string         `json:"schema"`
	Projects []InputProject `json:"projects"`
}

// InputProject is one reviewed project.
type InputProject struct {
	Project string `json:"project"`
	Repo    string `json:"repo"`
	// Source is nil when no upstream declaration was found in review; every
	// tag then lists as not declared without a fetch.
	Source *InputSource `json:"source,omitempty"`
	Tags   []string     `json:"tags"`
}

// InputSource names the one file read for a project.
type InputSource struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	// Matrix is required for docs_matrix and forbidden otherwise.
	Matrix *InputMatrix `json:"matrix,omitempty"`
}

// InputMatrix describes a Markdown compatibility table.
type InputMatrix struct {
	// HeaderFirstCell is the exact text of the header row's first cell.
	HeaderFirstCell string `json:"header_first_cell"`
	// RowKeyPrefix and RowKeySuffix wrap the release line ("0.19") into the
	// code span that names the row ("`release-0.19`").
	RowKeyPrefix string `json:"row_key_prefix"`
	RowKeySuffix string `json:"row_key_suffix"`
}

// CitedLine is one verbatim upstream line.
type CitedLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Citation binds a row to upstream bytes.
type Citation struct {
	Repo                    string      `json:"repo"`
	Tag                     string      `json:"tag"`
	Commit                  string      `json:"commit"`
	TagRefResponseSHA256    string      `json:"tag_ref_response_sha256"`
	TagObjectSHA            string      `json:"tag_object_sha,omitempty"`
	TagObjectResponseSHA256 string      `json:"tag_object_response_sha256,omitempty"`
	Path                    string      `json:"path"`
	BlobSHA                 string      `json:"blob_sha"`
	FileSHA256              string      `json:"file_sha256"`
	ContentsResponseSHA256  string      `json:"contents_response_sha256"`
	LineStart               int         `json:"line_start,omitempty"`
	LineEnd                 int         `json:"line_end,omitempty"`
	CitedLines              []CitedLine `json:"cited_lines,omitempty"`
}

// Release is one project release line (the tag is the latest patch read).
type Release struct {
	Tag    string `json:"tag"`
	Line   string `json:"line"`
	Status string `json:"status"`
	// Reason is set exactly when Status is not_declared.
	Reason string `json:"reason,omitempty"`
	// The fields below are set exactly when Status is declared.
	SourceKind      string `json:"source_kind,omitempty"`
	Shape           string `json:"shape,omitempty"`
	ConstraintRaw   string `json:"constraint_raw,omitempty"`
	Minimum         string `json:"minimum,omitempty"`
	Maximum         string `json:"maximum,omitempty"`
	MaxAtMatrixEdge bool   `json:"max_at_matrix_edge,omitempty"`
	// Citation is required when declared; optional for not_declared, where
	// it records the file that was read and held no usable declaration.
	Citation *Citation `json:"citation,omitempty"`
}

// OutputProject is one project of the generated table.
type OutputProject struct {
	Project  string       `json:"project"`
	Repo     string       `json:"repo"`
	Source   *InputSource `json:"source,omitempty"`
	Releases []Release    `json:"releases"`
}

// Output is the generated document.
type Output struct {
	Schema       string          `json:"schema"`
	Label        string          `json:"label"`
	InputsSHA256 string          `json:"inputs_sha256"`
	Projects     []OutputProject `json:"projects"`
}

var (
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	pathRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,8}$`)
	tagRE    = regexp.MustCompile(`^(?:v|edge-)?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	hex40RE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	affixRE  = regexp.MustCompile("^[`A-Za-z0-9._-]{0,32}$")
	headerRE = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
)

// ReleaseLine returns "major.minor" of a release tag, rejecting any tag
// that is not a plain release (pre-release and build suffixes included).
func ReleaseLine(tag string) (string, error) {
	m := tagRE.FindStringSubmatch(tag)
	if m == nil {
		return "", fmt.Errorf("tag %q is not a plain release tag", tag)
	}
	return m[1] + "." + m[2], nil
}

// DecodeInput parses and validates the reviewed list; unknown fields and
// anything outside the closed shapes are rejected.
func DecodeInput(raw []byte) (Input, error) {
	var in Input
	if err := strictDecode(raw, &in); err != nil {
		return Input{}, fmt.Errorf("projects file: %w", err)
	}
	if in.Schema != "prufyx.k8s-declared-projects/v1" || len(in.Projects) == 0 {
		return Input{}, fmt.Errorf("projects file: unknown schema or empty")
	}
	seen := map[string]bool{}
	for _, p := range in.Projects {
		if !nameRE.MatchString(p.Project) || seen[p.Project] || !repoRE.MatchString(p.Repo) || len(p.Tags) == 0 {
			return Input{}, fmt.Errorf("projects file: invalid project %q", p.Project)
		}
		seen[p.Project] = true
		lines := map[string]bool{}
		for _, t := range p.Tags {
			line, err := ReleaseLine(t)
			if err != nil || lines[line] {
				return Input{}, fmt.Errorf("projects file: %s: invalid or duplicate release line for tag %q", p.Project, t)
			}
			lines[line] = true
		}
		if s := p.Source; s != nil {
			if !pathRE.MatchString(s.Path) || strings.Contains(s.Path, "..") {
				return Input{}, fmt.Errorf("projects file: %s: invalid source path", p.Project)
			}
			switch s.Kind {
			case KindChart:
				if s.Matrix != nil {
					return Input{}, fmt.Errorf("projects file: %s: matrix on a chart source", p.Project)
				}
			case KindMatrix:
				m := s.Matrix
				if m == nil || !headerRE.MatchString(m.HeaderFirstCell) || !affixRE.MatchString(m.RowKeyPrefix) || !affixRE.MatchString(m.RowKeySuffix) {
					return Input{}, fmt.Errorf("projects file: %s: invalid matrix description", p.Project)
				}
			default:
				return Input{}, fmt.Errorf("projects file: %s: unknown source kind", p.Project)
			}
		}
	}
	return in, nil
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}
