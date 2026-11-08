// SPDX-License-Identifier: AGPL-3.0-only

package k8slifecycle

import (
	"go/ast"
	"go/token"
	"reflect"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

const lifecyclePrefix = "prerelease-lifecycle-gen"

// markers is what one comment block set says about one declaration.
type markers struct {
	intro, dep, rem, repl []string
	k8sDeprecated         int
	k8sRemoved            int
	lines                 int
	malformed, unknown    bool
	gen                   []string
}

func (m *markers) lifecycle() bool {
	return len(m.intro)+len(m.dep)+len(m.rem)+len(m.repl) > 0
}

// collect reads the marker lines of comment groups. Only whole "//" lines
// that begin with +k8s: are markers. A block comment that mentions a
// lifecycle marker cannot be read and withholds.
func (m *markers) collect(groups ...*ast.CommentGroup) {
	for _, cg := range groups {
		if cg == nil {
			continue
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "/*") {
				if strings.Contains(c.Text, "+k8s:"+lifecyclePrefix) || strings.Contains(c.Text, "+k8s:deprecated") || strings.Contains(c.Text, "+k8s:removed") {
					m.unknown = true
				}
				continue
			}
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			body, ok := strings.CutPrefix(text, "+k8s:")
			if !ok {
				continue
			}
			m.lines++
			name, val, hasVal := strings.Cut(body, "=")
			switch name {
			case lifecyclePrefix + ":introduced", lifecyclePrefix + ":deprecated", lifecyclePrefix + ":removed", lifecyclePrefix + ":replacement":
				if !hasVal || val == "" {
					m.malformed = true
					continue
				}
				switch name[len(lifecyclePrefix)+1:] {
				case "introduced":
					m.intro = append(m.intro, val)
				case "deprecated":
					m.dep = append(m.dep, val)
				case "removed":
					m.rem = append(m.rem, val)
				default:
					m.repl = append(m.repl, val)
				}
			case lifecyclePrefix:
				if val != "true" && val != "false" {
					m.malformed = true
					continue
				}
				m.gen = append(m.gen, val)
			case "deprecated":
				m.k8sDeprecated++
			case "removed":
				m.k8sRemoved++
			default:
				if strings.HasPrefix(name, lifecyclePrefix) || strings.HasPrefix(name, "deprecated") || strings.HasPrefix(name, "removed") {
					m.unknown = true
				}
			}
		}
	}
}

// docDeprecated reports a paragraph of the doc comment that starts with
// "Deprecated:" or "DEPRECATED:". A mention inside a paragraph is ignored,
// which can miss a deprecation but never invents one.
func docDeprecated(cg *ast.CommentGroup) bool {
	if cg == nil {
		return false
	}
	start := true
	for _, line := range strings.Split(cg.Text(), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			start = true
			continue
		}
		if start && (strings.HasPrefix(t, "Deprecated:") || strings.HasPrefix(t, "DEPRECATED:")) {
			return true
		}
		start = false
	}
	return false
}

// release parses "1.<minor>" into its minor; ok is false otherwise.
func release(v string) (int, bool) {
	if !releaseRE.MatchString(v) {
		return 0, false
	}
	n, err := strconv.Atoi(v[2:])
	return n, err == nil
}

// precedingBlock returns the comment group that ends exactly one blank line
// above line and starts in column one: the second comment block Kubernetes
// tags are allowed in.
func precedingBlock(fset *token.FileSet, f *ast.File, line int, not *ast.CommentGroup) *ast.CommentGroup {
	for _, cg := range f.Comments {
		if cg == not {
			continue
		}
		if fset.Position(cg.End()).Line+2 == line && fset.Position(cg.Pos()).Column == 1 {
			return cg
		}
	}
	return nil
}

func (s *scanner) types(fset *token.FileSet, f *ast.File, group, ver string) error {
	count := map[string]int{}
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
			for _, sp := range gd.Specs {
				count[sp.(*ast.TypeSpec).Name.Name]++
			}
		}
	}
	stable := stableRE.MatchString(ver)
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, sp := range gd.Specs {
			ts := sp.(*ast.TypeSpec)
			kind := ts.Name.Name
			item := itemGroup(group) + "/" + ver + "/" + kind
			doc, startLine := ts.Doc, fset.Position(ts.Pos()).Line
			if len(gd.Specs) == 1 && !gd.Lparen.IsValid() {
				doc, startLine = gd.Doc, fset.Position(gd.Pos()).Line
			}
			if doc != nil {
				startLine = fset.Position(doc.Pos()).Line
			}
			var m markers
			m.collect(doc, precedingBlock(fset, f, startLine, doc))
			// Every declaration of a repeated name is withheld, the first too.
			if count[kind] > 1 && s.g.dup {
				s.add(ReasonDuplicateType, item)
				continue
			}
			s.lifecycleOf(&m, group, ver, kind, item, stable)
			if st, ok := ts.Type.(*ast.StructType); ok {
				s.fields(st, group, ver, kind, item)
			}
		}
	}
	return nil
}

func (s *scanner) lifecycleOf(m *markers, group, ver, kind, item string, stable bool) {
	if m.unknown && s.g.unknown {
		s.add(ReasonMarkerUnknown, item)
		return
	}
	if m.malformed && s.g.malformed {
		s.add(ReasonMarkerBad, item)
		return
	}
	if m.lines > s.g.lim.markerLines && s.g.limits {
		s.add(ReasonTooMany, item)
		return
	}
	if m.k8sDeprecated > 1 || m.k8sRemoved > 1 || len(m.gen) > 1 {
		if s.g.conflict {
			s.add(ReasonMarkerConflict, item)
			return
		}
	}
	if m.k8sDeprecated > 0 {
		s.deprecation(group, ver, kind, "", SourceDeprecated, item)
	}
	if m.k8sRemoved > 0 {
		s.deprecation(group, ver, kind, "", SourceRemoved, item)
	}
	if !m.lifecycle() {
		return
	}
	if s.g.conflict && (len(m.intro) != 1 || len(m.dep) > 1 || len(m.rem) > 1 || len(m.repl) > 1 ||
		(len(m.dep) == 0 && len(m.rem) == 1)) {
		s.add(ReasonMarkerConflict, item)
		return
	}
	var vals [3]string
	var nums [3]int
	for i, list := range [][]string{m.intro, m.dep, m.rem} {
		if len(list) == 0 {
			continue
		}
		n, ok := release(list[0])
		if !ok && s.g.malformed {
			s.add(ReasonMarkerBad, item)
			return
		}
		vals[i], nums[i] = list[0], n
	}
	repl := ""
	if len(m.repl) > 0 {
		repl = m.repl[0]
		if !replaceRE.MatchString(repl) && s.g.malformed {
			s.add(ReasonMarkerBad, item)
			return
		}
	}
	if s.g.order {
		if (vals[1] != "" && nums[0] > nums[1]) || (vals[2] != "" && vals[1] != "" && nums[1] >= nums[2]) {
			s.add(ReasonOrder, item)
			return
		}
	}
	// A stable version may be deprecated (core/v1 ComponentStatus is), never
	// removed: a removal declared on a stable version is skew.
	if s.g.skew && stable && vals[2] != "" {
		s.add(ReasonVersionSkew, item)
		return
	}
	// +k8s:prerelease-lifecycle-gen=false opts the type out of the lifecycle
	// generator. It is checked last on purpose: markers on such a type must
	// still parse and agree, or the run is withheld rather than silently
	// excluding a type.
	if s.g.genOff && len(m.gen) == 1 && m.gen[0] == "false" {
		return
	}
	basis := BasisDraft
	if vals[0] != "" && vals[1] != "" && vals[2] != "" {
		basis = BasisMechanical
	}
	s.lifes = append(s.lifes, Lifecycle{Group: group, Version: ver, Kind: kind, Introduced: vals[0], Deprecated: vals[1], Removed: vals[2], Replacement: repl, Basis: basis})
}

func (s *scanner) deprecation(group, ver, kind, field, source, item string) {
	member := ""
	if field != "" {
		var err error
		mg := group
		if mg == "" {
			mg = CoreMemberGroup // the member encoder needs a non-empty group
		}
		member, err = membercode.Field(mg, kind, []membercode.Seg{{Kind: membercode.Prop, Name: field}})
		if err != nil {
			s.add(ReasonMember, item)
			return
		}
	}
	s.deps = append(s.deps, Deprecation{Group: group, Version: ver, Kind: kind, Field: field, Source: source, Member: member, Basis: BasisDraft, NeedsReview: true})
}

func (s *scanner) fields(st *ast.StructType, group, ver, kind, tItem string) {
	for _, fl := range st.Fields.List {
		// Markers are read from the field's own doc comment only; markers
		// attached elsewhere are ignored on purpose (draft-only).
		var m markers
		m.collect(fl.Doc)
		doc := docDeprecated(fl.Doc)
		if m.k8sDeprecated == 0 && m.k8sRemoved == 0 && !doc {
			continue
		}
		if len(fl.Names) != 1 || !fl.Names[0].IsExported() {
			if len(fl.Names) != 1 && s.g.field {
				s.add(ReasonFieldName, tItem)
			}
			continue // an unexported field is not API
		}
		item := tItem + "." + fl.Names[0].Name
		name := ""
		if fl.Tag != nil {
			if tag, err := strconv.Unquote(fl.Tag.Value); err == nil {
				name, _, _ = strings.Cut(reflect.StructTag(tag).Get("json"), ",")
			}
		}
		if (name == "" || name == "-") && s.g.field {
			s.add(ReasonFieldName, item)
			continue
		}
		if m.unknown && s.g.unknown {
			s.add(ReasonMarkerUnknown, item)
			continue
		}
		if m.k8sDeprecated > 1 || m.k8sRemoved > 1 {
			if s.g.conflict {
				s.add(ReasonMarkerConflict, item)
				continue
			}
		}
		if m.k8sDeprecated > 0 {
			s.deprecation(group, ver, kind, name, SourceDeprecated, item)
		}
		if m.k8sRemoved > 0 {
			s.deprecation(group, ver, kind, name, SourceRemoved, item)
		}
		if doc {
			s.deprecation(group, ver, kind, name, SourceDocComment, item)
		}
	}
}
