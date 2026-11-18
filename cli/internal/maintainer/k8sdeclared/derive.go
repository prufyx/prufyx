// SPDX-License-Identifier: AGPL-3.0-only

package k8sdeclared

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
)

// derived is what a cited source declares.
type derived struct {
	shape, raw, minimum, maximum string
	maxAtEdge                    bool
	reason                       string // non-empty: nothing declared
	cited                        []CitedLine
}

var kubeVersionLineRE = regexp.MustCompile(`^kubeVersion:\s*(?:"([^"]*)"|'([^']*)'|([^\s#"'][^#]*?))\s*(?:#.*)?$`)

// chartFromLine derives the declaration from the single cited
// "kubeVersion:" line. Only a single lower bound is a minimum; an upper
// bound, "||", "~", "^", a wildcard or an exact version is not, and a
// chart constraint is never turned into a maximum.
func chartFromLine(line string) derived {
	m := kubeVersionLineRE.FindStringSubmatch(line)
	if m == nil {
		return derived{reason: ReasonSourceUnusable}
	}
	raw := m[1] + m[2] + m[3]
	k := helmvalues.ParseKubeVersion(raw)
	if k.Shape != "minimum" || k.Minimum == "" {
		return derived{reason: ReasonNotLowerBound, raw: raw}
	}
	return derived{shape: ShapeMinOnly, raw: raw, minimum: k.Minimum}
}

// chartDerive reads Chart.yaml and derives the declaration, cross-checking
// the YAML reading against the cited line.
func chartDerive(data []byte) derived {
	raw, line, err := helmvalues.ChartKubeVersion(data)
	if err != nil {
		return derived{reason: ReasonSourceUnusable}
	}
	if strings.TrimSpace(raw) == "" {
		return derived{reason: ReasonNoDeclaration}
	}
	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return derived{reason: ReasonSourceUnusable}
	}
	text := strings.TrimRight(lines[line-1], "\r")
	d := chartFromLine(text)
	if d.reason == ReasonSourceUnusable || d.raw != raw {
		return derived{reason: ReasonSourceUnusable}
	}
	d.cited = []CitedLine{{Line: line, Text: text}}
	return d
}

var (
	matrixHeaderCellRE = regexp.MustCompile(`^Kubernetes (0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	tickCell           = "✔"
	crossCell          = "x"
)

func cells(line string) ([]string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "|") || !strings.HasSuffix(t, "|") {
		return nil, false
	}
	parts := strings.Split(t[1:len(t)-1], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, true
}

// matrixFromLines derives the declaration from the cited header row and the
// cited release row. The row must hold only tick and cross cells over
// consecutive ascending "Kubernetes X.Y" columns with one contiguous run of
// ticks. The run's first column is the minimum only when a cross precedes
// it; a run that starts at the first column states no lower bound, so
// nothing is declared. The last tick is the maximum; when it is the last
// column it is flagged as the matrix edge.
func matrixFromLines(header, row string) derived {
	h, ok1 := cells(header)
	r, ok2 := cells(row)
	if !ok1 || !ok2 || len(h) < 3 || len(h) != len(r) {
		return derived{reason: ReasonMatrixLayout}
	}
	type col struct{ major, minor int }
	cols := make([]col, 0, len(h)-1)
	for i, c := range h[1:] {
		m := matrixHeaderCellRE.FindStringSubmatch(c)
		if m == nil {
			return derived{reason: ReasonMatrixLayout}
		}
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		if i > 0 && (cols[i-1].major != maj || cols[i-1].minor+1 != min) {
			return derived{reason: ReasonMatrixLayout}
		}
		cols = append(cols, col{maj, min})
	}
	first, last := -1, -1
	for i, c := range r[1:] {
		switch c {
		case tickCell:
			if first < 0 {
				first = i
			} else if last != i-1 {
				return derived{reason: ReasonMatrixLayout} // a gap in the run
			}
			last = i
		case crossCell:
			// a run that ended is checked by the gap test on a later tick
		default:
			return derived{reason: ReasonMatrixLayout}
		}
	}
	if first < 0 {
		return derived{reason: ReasonMatrixLayout}
	}
	if first == 0 {
		return derived{reason: ReasonMatrixLowerEdge}
	}
	return derived{
		shape:     ShapeBounded,
		minimum:   fmt.Sprintf("%d.%d", cols[first].major, cols[first].minor),
		maximum:   fmt.Sprintf("%d.%d", cols[last].major, cols[last].minor),
		maxAtEdge: last == len(cols)-1,
	}
}

// matrixDerive locates the one header row and the one release row in the
// document and derives the declaration. Anything but exactly one of each, in
// one contiguous table, is not declared.
func matrixDerive(data []byte, m *InputMatrix, line string) derived {
	lines := strings.Split(string(data), "\n")
	hdr := -1
	for i, l := range lines {
		if c, ok := cells(l); ok && len(c) > 1 && c[0] == m.HeaderFirstCell {
			if hdr >= 0 {
				return derived{reason: ReasonMatrixLayout}
			}
			hdr = i
		}
	}
	if hdr < 0 {
		return derived{reason: ReasonMatrixLayout}
	}
	key := m.RowKeyPrefix + line + m.RowKeySuffix
	row := -1
	for i := hdr + 1; i < len(lines); i++ {
		c, ok := cells(lines[i])
		if !ok {
			break // end of the table
		}
		if strings.Contains(c[0], "`"+key+"`") || c[0] == key {
			if row >= 0 {
				return derived{reason: ReasonMatrixLayout}
			}
			row = i
		}
	}
	if row < 0 {
		return derived{reason: ReasonMatrixRowAbsent}
	}
	ht, rt := strings.TrimRight(lines[hdr], "\r"), strings.TrimRight(lines[row], "\r")
	d := matrixFromLines(ht, rt)
	d.cited = []CitedLine{{Line: hdr + 1, Text: ht}, {Line: row + 1, Text: rt}}
	return d
}
