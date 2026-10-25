// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Templated spec include.
//
// Some Helm charts keep a CustomResourceDefinition's header in a template and
// its body in a plain file of the chart:
//
//	apiVersion: apiextensions.k8s.io/v1
//	kind: CustomResourceDefinition
//	metadata:
//	  annotations:
//	    some.example.org/key: {{ include "chart.helper" . }}
//	  labels:
//	    {{- include "chart.labels" . | nindent 4 }}
//	  name: widgets.example.org
//	spec:
//	  {{ tpl (.Files.Get "hack/widgets_spec.yaml") . | nindent 2 }}
//
// Such a template is not valid YAML, so it is not read as a manifest. It is
// read, as nothing else, when it has exactly this shape (specIncludeShape),
// and every other file with "{{" stays unreadable as before:
//
//   - the lines are apiVersion, kind, a metadata block, "spec:" and one
//     tpl line, and nothing else; the metadata block holds a literal name
//     (<plural>.<group>) and, under annotations and labels, literal entries,
//     entries whose whole value is one include action and lines that are one
//     include action piped to nindent 4;
//   - the tpl line names a file relative to the chart directory (the nearest
//     directory above the template that holds Chart.yaml, with the template
//     under its templates/ directory); the file is a regular file of the same
//     commit and chart, reached without a symbolic link;
//   - the included file is the bare spec: no apiVersion, kind or metadata,
//     one document, and "{{" only as the whole value of the name or namespace
//     of spec.conversion.webhook.clientConfig.service, where it is replaced by
//     a placeholder before reading.
//
// The header of the template and the spec are then joined into a
// definition and read by parseFile, the reader of every other manifest, so
// the versions and their flags mean what they mean in a plain file. The lines
// recorded for the definition are the lines of the included file, which is the
// file the versions are written in, and its path is the definition's path.

const (
	// specIncludeMaxTemplateBytes and ...Lines bound the template. It is a
	// header: a few lines.
	specIncludeMaxTemplateBytes = 16 << 10
	specIncludeMaxTemplateLines = 128
	specIncludeMaxMetaLines     = 64
	specIncludeMaxPathBytes     = 255
	specIncludeMaxIndent        = 16
	// specIncludeHeaderLines is the number of lines the joined definition
	// has before the included file's first line.
	specIncludeHeaderLines = 5
	// specIncludeMaxAncestors bounds the directories searched for Chart.yaml.
	specIncludeMaxAncestors = 32
)

var (
	specNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// The include name is printable ASCII without quotes, braces and
	// backslashes: a Go string literal that needs no unquoting.
	specIncludeAction  = `include +"([^"{}\\]{1,128})" +\.`
	specMetaNameRE     = regexp.MustCompile(`^  name: (\S+)$`)
	specMetaBlockRE    = regexp.MustCompile(`^  (annotations|labels):$`)
	specMetaEntryRE    = regexp.MustCompile(`^    ([A-Za-z0-9][A-Za-z0-9._/-]{0,252}): ([^{}]+)$`)
	specMetaValueIncRE = regexp.MustCompile(`^    ([A-Za-z0-9][A-Za-z0-9._/-]{0,252}): \{\{ *` + specIncludeAction + ` *\}\}$`)
	specMetaLineIncRE  = regexp.MustCompile(`^    \{\{(?:-[ ]+| *)` + specIncludeAction + ` *\| *nindent +([0-9]{1,2}) *\}\}$`)
	specTplRE          = regexp.MustCompile(`^ *\{\{(?:-[ ]+| *)tpl +\(\.Files\.Get +"([^"{}\\]{1,255})"\) +\. *\| *nindent +([0-9]{1,2})(?:[ ]+-| *)\}\}$`)
	// specServiceRE is a line of the included file that holds "{{": the
	// name or namespace key, and as its whole value one action, bare or in
	// matching quotes (checked in specServiceValue).
	specServiceRE = regexp.MustCompile(`^( +(?:name|namespace): )(['"]?)(\{\{[^{}]*\}\})(['"]?)[ ]*$`)
	// specValuesRE is a chart value reference. Inside quotes it renders one
	// line of text chosen by the chart's user, as the service name and
	// namespace of a conversion webhook are.
	specValuesRE = regexp.MustCompile(`^\.Values(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
)

// specIncludeShape is a template of the admitted shape.
type specIncludeShape struct {
	// CRD is the literal metadata.name; Path the argument of .Files.Get
	// (checked by specIncludePathOK); Indent the nindent of the tpl line.
	CRD    string
	Path   string
	Indent int
}

// parseSpecIncludeTemplate reads the template line by line. It returns nil
// for anything that is not exactly the admitted shape; it never reads more
// than the template's bytes.
func parseSpecIncludeTemplate(data []byte) *specIncludeShape {
	if len(data) == 0 || len(data) > specIncludeMaxTemplateBytes {
		return nil
	}
	for _, b := range data {
		if b != '\n' && (b < 0x20 || b > 0x7e) {
			return nil
		}
	}
	text := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > specIncludeMaxTemplateLines || len(lines) < 6 {
		return nil
	}
	if lines[0] != "apiVersion: "+crdAPIVersion || lines[1] != "kind: "+crdKind || lines[2] != "metadata:" {
		return nil
	}
	spec := -1
	for i := 3; i < len(lines); i++ {
		if lines[i] == "spec:" {
			spec = i
			break
		}
	}
	// "spec:", one tpl line and nothing after it.
	if spec < 0 || spec != len(lines)-2 || spec-3 > specIncludeMaxMetaLines {
		return nil
	}
	sh := &specIncludeShape{}
	m := specTplRE.FindStringSubmatch(lines[spec+1])
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(m[2])
	if err != nil || n < 1 || n > specIncludeMaxIndent {
		return nil
	}
	sh.Path, sh.Indent = m[1], n
	if !specIncludePathOK(sh.Path) {
		return nil
	}
	// The metadata block. Its literal entries and its placeholders are
	// decoded again below, so that what is read as metadata is YAML.
	var decode []string
	block := ""
	for _, line := range lines[3:spec] {
		switch {
		case specMetaNameRE.MatchString(line):
			if sh.CRD != "" {
				return nil
			}
			sh.CRD = specMetaNameRE.FindStringSubmatch(line)[1]
			if len(sh.CRD) > maxNameBytes || !specNameRE.MatchString(sh.CRD) {
				return nil
			}
			block = ""
			decode = append(decode, line)
		case specMetaBlockRE.MatchString(line):
			block = specMetaBlockRE.FindStringSubmatch(line)[1]
			decode = append(decode, line)
		case block == "":
			return nil
		case specMetaValueIncRE.MatchString(line):
			decode = append(decode, specMetaValueIncRE.ReplaceAllString(line, "    $1: "+placeholder))
		case specMetaLineIncRE.MatchString(line):
			// The included lines are indented under the block's key (2) by
			// two: any other indentation would add keys elsewhere.
			if k, err := strconv.Atoi(specMetaLineIncRE.FindStringSubmatch(line)[2]); err != nil || k != 4 {
				return nil
			}
		case specMetaEntryRE.MatchString(line):
			decode = append(decode, line)
		default:
			return nil
		}
	}
	if sh.CRD == "" {
		return nil
	}
	_, values, err := decodeStrict([]byte("metadata:\n" + strings.Join(decode, "\n") + "\n"))
	if err != nil || len(values) != 1 {
		return nil
	}
	root, _ := values[0].(map[string]any)
	meta := mapping(root, "metadata")
	if len(root) != 1 || meta == nil || str(meta, "name") != sh.CRD {
		return nil
	}
	for key, v := range meta {
		if key == "name" {
			continue
		}
		if key != "annotations" && key != "labels" {
			return nil
		}
		if v == nil {
			continue
		}
		entries, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		for _, e := range entries {
			if _, ok := e.(string); !ok {
				return nil
			}
		}
	}
	return sh
}

// specIncludePathOK reports whether p is a path relative to the chart
// directory that names a file without any glob, template or escape: no
// leading slash, no "..", no wildcard, no brace, no backslash, no control
// character, and already in its cleaned form.
func specIncludePathOK(p string) bool {
	if p == "" || len(p) > specIncludeMaxPathBytes || strings.HasPrefix(p, "/") {
		return false
	}
	if strings.ContainsAny(p, "*?[]{}\\") || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return path.Clean(p) == p && p != "."
}

// specIncludeRead is a template and its included file, read.
type specIncludeRead struct {
	// Path is the included file; Data its bytes.
	Path string
	Data []byte
	CRDs []CRD
}

// readSpecInclude resolves the include of a template of the admitted shape
// and reads the definition it builds. It returns nil, nil when the include is
// refused (the file then stays what it was before: unreadable); an error is a
// failure of the reader, not a refusal.
func readSpecInclude(r extract.PinnedReader, repo extract.RepoRef, commit, tpath string, sh *specIncludeShape) (*specIncludeRead, error) {
	chart, ok, err := specChartDir(r, repo, commit, tpath)
	if err != nil || !ok {
		return nil, err
	}
	fpath := path.Join(chart, sh.Path)
	if chart != "" && !strings.HasPrefix(fpath, chart+"/") {
		return nil, nil
	}
	found, err := specRegularFile(r, repo, commit, chart, sh.Path)
	if err != nil || !found {
		return nil, err
	}
	data, err := r.Read(repo, commit, fpath)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	crds := joinSpecInclude(sh, fpath, data)
	if crds == nil {
		return nil, nil
	}
	return &specIncludeRead{Path: fpath, Data: data, CRDs: crds}, nil
}

// specChartDir returns the nearest directory above the template that holds
// a Chart.yaml (a regular file), provided the template lies under its
// templates/ directory.
func specChartDir(r extract.PinnedReader, repo extract.RepoRef, commit, tpath string) (string, bool, error) {
	dir := path.Dir(tpath)
	for i := 0; i < specIncludeMaxAncestors; i++ {
		if dir == "." {
			dir = ""
		}
		entries, err := r.List(repo, commit, dir)
		if err != nil && !isNotFound(err) {
			return "", false, err
		}
		for _, e := range entries {
			if e.Path == path.Join(dir, "Chart.yaml") && e.Type == "blob" && e.Mode != "120000" {
				rel := strings.TrimPrefix(tpath, dir)
				rel = strings.TrimPrefix(rel, "/")
				return dir, strings.HasPrefix(rel, "templates/"), nil
			}
		}
		if dir == "" {
			return "", false, nil
		}
		dir = path.Dir(dir)
	}
	return "", false, nil
}

// specRegularFile reports whether rel, below chart, is a regular file that
// is reached through directories only: a symbolic link, a submodule or a
// missing entry on the way is a refusal.
func specRegularFile(r extract.PinnedReader, repo extract.RepoRef, commit, chart, rel string) (bool, error) {
	parts := strings.Split(rel, "/")
	dir := chart
	for i, part := range parts {
		entries, err := r.List(repo, commit, dir)
		if isNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		want := path.Join(dir, part)
		last := i == len(parts)-1
		found := false
		for _, e := range entries {
			if e.Path != want {
				continue
			}
			switch {
			case last && e.Type == "blob" && (e.Mode == "100644" || e.Mode == "100755"):
				found = true
			case !last && e.Type == "tree":
				found = true
			}
		}
		if !found {
			return false, nil
		}
		dir = want
	}
	return true, nil
}

// joinSpecInclude builds the definition from the template's header and the
// included file and reads it with parseFile. It returns nil when the included
// file is not a bare spec within the admitted use of "{{".
func joinSpecInclude(sh *specIncludeShape, fpath string, frag []byte) []CRD {
	if len(frag) == 0 || len(frag) > MaxFileBytes || bytes.Contains(frag, []byte(placeholder)) {
		return nil
	}
	lines := strings.Split(string(frag), "\n")
	actions := 0
	for i, line := range lines {
		if !strings.Contains(line, templateMarker) {
			continue
		}
		m := specServiceRE.FindStringSubmatch(line)
		if m == nil || m[2] != m[4] || !specServiceValue(m[3], m[2] != "") {
			return nil
		}
		lines[i] = m[1] + m[2] + placeholder + m[4]
		actions++
	}
	text := strings.Join(lines, "\n")
	if strings.Contains(text, templateMarker) {
		return nil
	}
	_, values, err := decodeStrict([]byte(text))
	if err != nil || len(values) != 1 {
		return nil
	}
	spec, ok := values[0].(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"apiVersion", "kind", "metadata"} {
		if _, has := spec[key]; has {
			return nil
		}
	}
	// Every placeholder is the whole name or namespace of the conversion
	// webhook's service, and every action became one.
	if placeholders(spec) != actions || servicePlaceholders(spec) != actions {
		return nil
	}
	pad := strings.Repeat(" ", sh.Indent)
	joined := "apiVersion: " + crdAPIVersion + "\nkind: " + crdKind + "\nmetadata:\n  name: " + sh.CRD + "\nspec:\n" + pad + strings.ReplaceAll(text, "\n", "\n"+pad)
	_, crds, err := parseFile(fpath, []byte(joined))
	if err != nil || len(crds) != 1 || crds[0].Name != sh.CRD {
		return nil
	}
	c := &crds[0]
	// Lines of the joined text are lines of the included file below the
	// header.
	shift := func(l int) int { return l - specIncludeHeaderLines }
	c.StartLine, c.VersionsLine = 1, shift(c.VersionsLine)
	for i := range c.Versions {
		v := &c.Versions[i]
		v.StartLine, v.EndLine, v.ServedLine, v.StorageLine = shift(v.StartLine), shift(v.EndLine), shift(v.ServedLine), shift(v.StorageLine)
		if v.StartLine < 1 || v.EndLine < v.StartLine || v.EndLine > len(lines) {
			return nil
		}
	}
	return crds
}

// specServiceValue reports whether one action, as the whole value of the
// name or namespace of the conversion service, is admitted: the actions the
// template reader admits in spec.conversion (a release or chart name, a
// quoted field), and, in quotes, a reference to a chart value.
func specServiceValue(expr string, quoted bool) bool {
	if strings.HasPrefix(expr, "{{-") || strings.HasSuffix(expr, "-}}") || templateComment(expr) {
		return false
	}
	action, _ := templateAction(expr)
	if strings.Contains(action, "{{") || assignRE.MatchString(action) {
		return false
	}
	if quoted && specValuesRE.MatchString(action) {
		return true
	}
	return !strings.Contains(action, "indent") && !strings.Contains(action, "toYaml") && boundedOutput(action, false) == ""
}

// placeholders counts the occurrences of the placeholder in every string and
// key of a decoded value.
func placeholders(v any) int {
	n := 0
	switch t := v.(type) {
	case string:
		n += strings.Count(t, placeholder)
	case map[string]any:
		for k, c := range t {
			n += strings.Count(k, placeholder) + placeholders(c)
		}
	case []any:
		for _, c := range t {
			n += placeholders(c)
		}
	}
	return n
}

// servicePlaceholders counts the name and namespace of
// spec.conversion.webhook.clientConfig.service that are exactly the
// placeholder.
func servicePlaceholders(spec map[string]any) int {
	svc := mapping(mapping(mapping(mapping(spec, "conversion"), "webhook"), "clientConfig"), "service")
	n := 0
	for _, key := range []string{"name", "namespace"} {
		if s, _ := svc[key].(string); s == placeholder {
			n++
		}
	}
	return n
}

// specIncludeClaims tracks, for one inventory, the included files already
// used: a file included by two templates, or listed itself, is refused.
type specIncludeClaims struct {
	listed map[string]bool
	by     map[string]string
}

func newSpecIncludeClaims(files []string) *specIncludeClaims {
	c := &specIncludeClaims{listed: map[string]bool{}, by: map[string]string{}}
	for _, f := range files {
		c.listed[f] = true
	}
	return c
}

// take records that template includes file and reports whether it may.
func (c *specIncludeClaims) take(template, file string) bool {
	if c.listed[file] || c.by[file] != "" {
		return false
	}
	c.by[file] = template
	return true
}

// records returns the file records of the template (rec, as parseFile
// recorded its bytes) and of its included file.
func (s *specIncludeRead) records(rec FileRecord) []FileRecord {
	rec.Documents, rec.CRDs, rec.OtherDocuments = 1, 1, 0
	sum := sha256.Sum256(s.Data)
	return []FileRecord{rec, {Path: s.Path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: len(s.Data), Lines: extract.CountLines(s.Data), Documents: 1}}
}
