// SPDX-License-Identifier: AGPL-3.0-only

package k8sdeclared

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNotFound is returned by a Fetcher when the file does not exist at the
// commit.
var ErrNotFound = errors.New("not found")

// Resolution is a tag resolved to a commit through the upstream API.
type Resolution struct {
	Commit                  string
	TagRefResponseSHA256    string
	TagObjectSHA            string
	TagObjectResponseSHA256 string
}

// File is one file read at a commit.
type File struct {
	BlobSHA                string
	Data                   []byte
	ContentsResponseSHA256 string
}

// Fetcher reads public upstream data. Only the refresh mode has one.
type Fetcher interface {
	ResolveTag(repo, tag string) (Resolution, error)
	ReadFile(repo, path, commit string) (File, error)
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Build reads every reviewed (project, tag) and derives the table. Hard
// failures (network, malformed API data, digest mismatch) abort; an upstream
// file that does not declare a version is a not_declared row.
func Build(in Input, inputsRaw []byte, f Fetcher, only map[string]bool) (Output, error) {
	out := Output{Schema: SchemaID, Label: Label, InputsSHA256: sha256Hex(inputsRaw)}
	for _, p := range in.Projects {
		if only != nil && !only[p.Project] {
			continue
		}
		op := OutputProject{Project: p.Project, Repo: p.Repo, Source: p.Source}
		for _, tag := range p.Tags {
			line, err := ReleaseLine(tag)
			if err != nil {
				return Output{}, err
			}
			rel := Release{Tag: tag, Line: line}
			if p.Source == nil {
				rel.Status, rel.Reason = StatusNotDeclared, ReasonNoSource
				op.Releases = append(op.Releases, rel)
				continue
			}
			res, err := f.ResolveTag(p.Repo, tag)
			if err != nil {
				return Output{}, fmt.Errorf("%s %s: %w", p.Project, tag, err)
			}
			file, err := f.ReadFile(p.Repo, p.Source.Path, res.Commit)
			if errors.Is(err, ErrNotFound) {
				rel.Status, rel.Reason = StatusNotDeclared, ReasonSourceAbsent
				op.Releases = append(op.Releases, rel)
				continue
			}
			if err != nil {
				return Output{}, fmt.Errorf("%s %s: %w", p.Project, tag, err)
			}
			cit := &Citation{
				Repo: p.Repo, Tag: tag, Commit: res.Commit,
				TagRefResponseSHA256: res.TagRefResponseSHA256,
				TagObjectSHA:         res.TagObjectSHA, TagObjectResponseSHA256: res.TagObjectResponseSHA256,
				Path: p.Source.Path, BlobSHA: file.BlobSHA, FileSHA256: sha256Hex(file.Data),
				ContentsResponseSHA256: file.ContentsResponseSHA256,
			}
			var d derived
			if p.Source.Kind == KindChart {
				d = chartDerive(file.Data)
			} else {
				d = matrixDerive(file.Data, p.Source.Matrix, line)
			}
			if d.reason != "" {
				rel.Status, rel.Reason, rel.Citation = StatusNotDeclared, d.reason, cit
				if d.reason == ReasonNotLowerBound {
					rel.ConstraintRaw = d.raw
				}
				op.Releases = append(op.Releases, rel)
				continue
			}
			cit.CitedLines = d.cited
			cit.LineStart, cit.LineEnd = d.cited[0].Line, d.cited[len(d.cited)-1].Line
			rel.Status, rel.SourceKind, rel.Shape = StatusDeclared, p.Source.Kind, d.shape
			rel.ConstraintRaw, rel.Minimum = d.raw, d.minimum
			if d.maxAtEdge {
				// ticks run to the table edge: no upstream maximum is stated
				rel.Shape, rel.TableLastColumn = ShapeMinOnly, d.maximum
			} else {
				rel.Maximum = d.maximum
			}
			rel.Citation = cit
			op.Releases = append(op.Releases, rel)
		}
		out.Projects = append(out.Projects, op)
	}
	if len(out.Projects) == 0 {
		return Output{}, fmt.Errorf("no project selected")
	}
	return out, nil
}

// Marshal is the canonical JSON form: indented, newline terminated.
func Marshal(o Output) ([]byte, error) {
	raw, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Verify checks an Output offline: schema, label, citation completeness, and
// that every declared value re-derives from the cited verbatim lines. When
// in is non-nil the projects, tags and source paths must also match the
// reviewed list. It cannot re-read upstream; the file and API digests are
// checked only for form.
func Verify(o Output, in *Input, inputsRaw []byte) error {
	if o.Schema != SchemaID || o.Label != Label || !hex64RE.MatchString(o.InputsSHA256) {
		return fmt.Errorf("unknown schema, label or inputs digest")
	}
	if in != nil {
		if sha256Hex(inputsRaw) != o.InputsSHA256 {
			return fmt.Errorf("projects file digest differs from the recorded one")
		}
		if len(o.Projects) != len(in.Projects) {
			return fmt.Errorf("project set differs from the projects file")
		}
	}
	for pi, p := range o.Projects {
		if !nameRE.MatchString(p.Project) || !repoRE.MatchString(p.Repo) || len(p.Releases) == 0 {
			return fmt.Errorf("project %q: invalid", p.Project)
		}
		if in != nil {
			ip := in.Projects[pi]
			if ip.Project != p.Project || ip.Repo != p.Repo || len(ip.Tags) != len(p.Releases) || !sameSource(ip.Source, p.Source) {
				return fmt.Errorf("project %q: differs from the projects file", p.Project)
			}
			for i, t := range ip.Tags {
				if p.Releases[i].Tag != t {
					return fmt.Errorf("project %q: tags differ from the projects file", p.Project)
				}
			}
		}
		for _, r := range p.Releases {
			if err := verifyRelease(p, r); err != nil {
				return fmt.Errorf("%s %s: %w", p.Project, r.Tag, err)
			}
		}
	}
	return nil
}

func sameSource(a, b *InputSource) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func verifyRelease(p OutputProject, r Release) error {
	line, err := ReleaseLine(r.Tag)
	if err != nil || line != r.Line {
		return fmt.Errorf("tag or line invalid")
	}
	switch r.Status {
	case StatusNotDeclared:
		if !reasons[r.Reason] || r.SourceKind != "" || r.Shape != "" || r.Minimum != "" || r.Maximum != "" || r.TableLastColumn != "" || (r.ConstraintRaw != "" && r.Reason != ReasonNotLowerBound) {
			return fmt.Errorf("not-declared row carries a declaration or an unknown reason")
		}
		if (r.Reason == ReasonNoSource) != (p.Source == nil) {
			return fmt.Errorf("no-source reason does not match the source")
		}
		if r.Citation != nil {
			return verifyCitation(p, r, *r.Citation, false)
		}
		return nil
	case StatusDeclared:
		if r.Reason != "" || r.Citation == nil || p.Source == nil || r.SourceKind != p.Source.Kind {
			return fmt.Errorf("declared row without citation or with a different source kind")
		}
		c := *r.Citation
		if err := verifyCitation(p, r, c, true); err != nil {
			return err
		}
		var d derived
		switch r.SourceKind {
		case KindChart:
			if len(c.CitedLines) != 1 {
				return fmt.Errorf("chart citation must hold the kubeVersion line")
			}
			d = chartFromLine(c.CitedLines[0].Text)
		case KindMatrix:
			if len(c.CitedLines) != 2 {
				return fmt.Errorf("matrix citation must hold the header and the row")
			}
			key := p.Source.Matrix.RowKeyPrefix + line + p.Source.Matrix.RowKeySuffix
			cs, ok := cells(c.CitedLines[1].Text)
			hs, hok := cells(c.CitedLines[0].Text)
			if !ok || !hok || hs[0] != p.Source.Matrix.HeaderFirstCell || !strings.Contains(cs[0], "`"+key+"`") && cs[0] != key || c.CitedLines[0].Line >= c.CitedLines[1].Line {
				return fmt.Errorf("matrix citation is not the header and the row of this release line")
			}
			d = matrixFromLines(c.CitedLines[0].Text, c.CitedLines[1].Text)
		default:
			return fmt.Errorf("unknown source kind")
		}
		if d.maxAtEdge {
			d.shape = ShapeMinOnly
		}
		if d.reason != "" || d.shape != r.Shape || d.raw != r.ConstraintRaw || d.minimum != r.Minimum || d.maximum != r.Maximum+r.TableLastColumn || d.maxAtEdge != (r.TableLastColumn != "") {
			return fmt.Errorf("declared values do not re-derive from the cited lines")
		}
		if r.Minimum == "" || (r.Shape == ShapeMinOnly && r.Maximum != "") || (r.Shape == ShapeBounded && (r.Maximum == "" || r.TableLastColumn != "")) || (r.SourceKind == KindChart && r.TableLastColumn != "") {
			return fmt.Errorf("shape and values disagree")
		}
		return nil
	}
	return fmt.Errorf("unknown status")
}

func verifyCitation(p OutputProject, r Release, c Citation, declared bool) error {
	if p.Source == nil || c.Repo != p.Repo || c.Tag != r.Tag || c.Path != p.Source.Path {
		return fmt.Errorf("citation repo, tag or path differs from the row")
	}
	if !hex40RE.MatchString(c.Commit) || !hex40RE.MatchString(c.BlobSHA) ||
		!hex64RE.MatchString(c.FileSHA256) || !hex64RE.MatchString(c.TagRefResponseSHA256) || !hex64RE.MatchString(c.ContentsResponseSHA256) {
		return fmt.Errorf("citation digest or commit malformed")
	}
	if (c.TagObjectSHA == "") != (c.TagObjectResponseSHA256 == "") ||
		(c.TagObjectSHA != "" && (!hex40RE.MatchString(c.TagObjectSHA) || !hex64RE.MatchString(c.TagObjectResponseSHA256))) {
		return fmt.Errorf("tag object fields malformed")
	}
	if !declared {
		if c.LineStart != 0 || c.LineEnd != 0 || len(c.CitedLines) != 0 {
			return fmt.Errorf("not-declared citation carries lines")
		}
		return nil
	}
	if c.LineStart < 1 || c.LineEnd < c.LineStart || len(c.CitedLines) == 0 ||
		c.CitedLines[0].Line != c.LineStart || c.CitedLines[len(c.CitedLines)-1].Line != c.LineEnd {
		return fmt.Errorf("citation line span malformed")
	}
	ls := make([]int, len(c.CitedLines))
	for i, l := range c.CitedLines {
		ls[i] = l.Line
		if l.Line < 1 || strings.TrimSpace(l.Text) == "" {
			return fmt.Errorf("cited line malformed")
		}
	}
	if !sort.IntsAreSorted(ls) {
		return fmt.Errorf("cited lines not ascending")
	}
	return nil
}
