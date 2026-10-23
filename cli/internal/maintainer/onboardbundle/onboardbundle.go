// SPDX-License-Identifier: AGPL-3.0-only

// Package onboardbundle validates a prufyx.io/onboard-bundle/v1 directory.
//
// A bundle is a contributor-supplied HINT for onboarding one public project.
// It is untrusted input: validation checks shape, bounds and leaks only and
// never decides that a claim is true. It is offline (no network, no git, no
// model) and executes nothing from the bundle.
package onboardbundle

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxFileBytes is the size limit of one bundle file.
	MaxFileBytes = 256 * 1024
	// MaxFiles is the limit on the number of files in one bundle.
	MaxFiles = 12
	maxDepth = 24
)

//go:embed schema.json
var schemaJSON []byte

var fileDefs = map[string]string{
	"project.json":          "project",
	"target-draft.json":     "targetDraft",
	"scan-notes.json":       "scanNotes",
	"relnotes-sources.json": "relnotesSources",
	"leads.json":            "leads",
	"receipt.json":          "receipt",
}

var requiredFiles = []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"}

var extractFiles = map[string]bool{"manifest.json": true, "candidates.json": true, "attestations.json": true}

// Names that never belong in a bundle.
var forbiddenNames = map[string]bool{"rules.json": true, "table.json": true, "batch.json": true, "signature": true, "signatures": true, "approval.json": true}

var secretRE = []*regexp.Regexp{
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`xox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]{20,}`),
}

var internalRE = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[\s"'=:(])/Users/[^/\s]+`),
	regexp.MustCompile(`(?:^|[\s"'=:(])/home/[^/\s]+`),
	regexp.MustCompile(`\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b`),
	regexp.MustCompile(`\.claude\b|\.ssh\b|\.kube\b|(?i:\bkubeconfig\b)`),
}

var (
	ctrlRE      = regexp.MustCompile("[\x00-\x08\x0a-\x1f\x7f]")
	quotePathRE = regexp.MustCompile(`^leads\.json\.leads\[\d+\]\.quote\.text$`)
)

// Validate checks the bundle directory dir and returns the findings, sorted in
// a stable order. An empty result means "well-formed", not "true". The error
// is non-nil only for an unusable directory or an unreadable file.
func Validate(dir string) ([]string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory")
	}
	var root map[string]any
	if err := json.Unmarshal(schemaJSON, &root); err != nil {
		return nil, fmt.Errorf("embedded schema: %w", err)
	}
	var out []string
	files, err := collectFiles(dir, &out)
	if err != nil {
		return nil, err
	}
	if len(files) > MaxFiles {
		out = append(out, fmt.Sprintf("%d files, more than %d", len(files), MaxFiles))
	}
	docs := map[string]any{}
	digests := map[string]string{}
	for _, rel := range files {
		base := filepath.Base(rel)
		lower := strings.ToLower(base)
		if forbiddenNames[lower] || strings.HasPrefix(lower, "signature") || strings.HasPrefix(lower, "batch") {
			out = append(out, rel+": forbidden file (rules, table, batch and signatures never belong in a bundle)")
			continue
		}
		inExtract := strings.HasPrefix(rel, "extract-run/")
		if inExtract {
			if strings.Count(rel, "/") != 1 || !extractFiles[base] {
				out = append(out, rel+": only extract-run/{attestations,candidates,manifest}.json allowed")
				continue
			}
		} else if _, ok := fileDefs[rel]; !ok {
			out = append(out, rel+": not a bundle file")
			continue
		}
		raw, tooBig, err := readBounded(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		if tooBig {
			out = append(out, fmt.Sprintf("%s: over %d bytes", rel, MaxFileBytes))
			continue
		}
		doc, err := parseStrict(raw)
		if err != nil {
			out = append(out, fmt.Sprintf("%s: not strict UTF-8 JSON (%v)", rel, err))
			continue
		}
		docs[rel] = doc
		if rel != "receipt.json" {
			sum := sha256.Sum256(raw)
			digests[rel] = hex.EncodeToString(sum[:])
		}
		var strs []pathString
		walkStrings(doc, rel, &strs)
		for _, ps := range strs {
			isQuote := quotePathRE.MatchString(ps.path)
			for _, rx := range secretRE {
				if rx.MatchString(ps.val) {
					out = append(out, ps.path+": secret-shaped value")
				}
			}
			if !isQuote {
				for _, rx := range internalRE {
					if rx.MatchString(ps.val) {
						out = append(out, fmt.Sprintf("%s: internal/owner-environment name (%s)", ps.path, rx.String()))
					}
				}
			}
			v := ps.val
			if isQuote {
				v = strings.NewReplacer("\n", "", "\r", "", "\t", "").Replace(v)
			}
			if ctrlRE.MatchString(v) {
				out = append(out, ps.path+": control character")
			}
		}
		switch {
		case rel == "extract-run/manifest.json":
			check(doc, map[string]any{"$ref": "#/$defs/extractManifest"}, root, rel, &out)
		case inExtract:
			switch doc.(type) {
			case []any, map[string]any:
			default:
				out = append(out, rel+": expected array or object")
			}
		}
		if def, ok := fileDefs[rel]; ok {
			check(doc, map[string]any{"$ref": "#/$defs/" + def}, root, rel, &out)
		}
	}
	for _, need := range requiredFiles {
		if _, ok := docs[need]; ok {
			continue
		}
		reported := false
		for _, o := range out {
			if strings.HasPrefix(o, need) {
				reported = true
				break
			}
		}
		if !reported {
			out = append(out, need+": missing")
		}
	}
	crossChecks(docs, digests, &out)
	return out, nil
}

func crossChecks(docs map[string]any, digests map[string]string, out *[]string) {
	proj, _ := docs["project.json"].(map[string]any)
	rcpt, _ := docs["receipt.json"].(map[string]any)
	if tgt, ok := docs["target-draft.json"].(map[string]any); ok && proj != nil {
		t, isObj := tgt["target"].(map[string]any)
		if isObj && (!eq(t["project"], proj["slug"]) || !eq(t["repo"], proj["repo"])) {
			*out = append(*out, "target-draft.json: project/repo differ from project.json")
		}
	}
	if man, ok := docs["extract-run/manifest.json"].(map[string]any); ok && proj != nil {
		ex, isObj := man["extractor"].(map[string]any)
		slug, _ := proj["slug"].(string)
		if !eq(man["repo"], proj["repo"]) || !isObj || !eq(ex["id"], "crd.version-removal."+slug) {
			*out = append(*out, "extract-run/manifest.json: repo or extractor id differ from project.json")
		}
	}
	if rcpt != nil {
		want := bundleDigest(digests)
		if !eq(rcpt["bundleSha256"], want) {
			*out = append(*out, "receipt.json: bundleSha256 does not match the files (computed "+want+")")
		}
		listed, ok := map[string]string{}, true
		if fl, isArr := rcpt["files"].([]any); isArr {
			for _, x := range fl {
				m, isObj := x.(map[string]any)
				if !isObj {
					ok = false
					break
				}
				n, _ := m["name"].(string)
				h, _ := m["sha256"].(string)
				listed[n] = h
			}
		} else {
			ok = false
		}
		if !ok || !sameMap(listed, digests) {
			*out = append(*out, "receipt.json: files list does not match the bundle files")
		}
	}
	if leads, ok := docs["leads.json"].(map[string]any); ok {
		arr, _ := leads["leads"].([]any)
		for i, ld := range arr {
			m, _ := ld.(map[string]any)
			q, _ := m["quote"].(map[string]any)
			text, tOK := q["text"].(string)
			start, sOK := intOf(q["startLine"])
			end, eOK := intOf(q["endLine"])
			if !tOK || !sOK || !eOK {
				continue
			}
			if strings.HasSuffix(text, "\n") {
				*out = append(*out, fmt.Sprintf("leads.json.leads[%d].quote: text must not end with a newline", i))
			} else if end < start || end-start+1 != int64(strings.Count(text, "\n")+1) {
				*out = append(*out, fmt.Sprintf("leads.json.leads[%d].quote: line span does not match the text", i))
			}
		}
	}
}

// bundleDigest is sha256 over sorted "<name> NUL <sha256> LF" of every file
// except receipt.json.
func bundleDigest(digests map[string]string) string {
	names := make([]string, 0, len(digests))
	for n := range digests {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "\x00" + digests[n] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// collectFiles returns the slash-separated relative names of regular files.
// Symlinks, other irregular files and directories other than a top-level
// extract-run/ are reported as findings and never read.
func collectFiles(dir string, out *[]string) ([]string, error) {
	var files []string
	var walk func(abs, rel string) error
	walk = func(abs, rel string) error {
		entries, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			relName := name
			if rel != "" {
				relName = rel + "/" + name
			}
			switch mode := e.Type(); {
			case mode&os.ModeSymlink != 0:
				*out = append(*out, relName+": symlink refused")
			case mode.IsDir():
				if rel == "" && name == "extract-run" {
					if err := walk(filepath.Join(abs, name), relName); err != nil {
						return err
					}
				} else {
					*out = append(*out, relName+"/: directory not allowed")
				}
			case mode.IsRegular():
				files = append(files, relName)
			default:
				*out = append(*out, relName+": not a regular file")
			}
		}
		return nil
	}
	if err := walk(dir, ""); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// readBounded reads a regular file, never more than MaxFileBytes+1 bytes.
func readBounded(path string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, false, err
	}
	return raw, len(raw) > MaxFileBytes, nil
}

// parseStrict decodes strict UTF-8 JSON: one value, no trailing data, no
// duplicate object keys, nesting at most maxDepth, numbers kept as json.Number.
func parseStrict(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("nesting deeper than %d", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch d {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := kt.(string)
			if _, dup := obj[key]; dup {
				return nil, errors.New("duplicate key " + strconv.Quote(key))
			}
			val, err := parseValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := parseValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, errors.New("unexpected delimiter")
}

type pathString struct{ path, val string }

func walkStrings(v any, path string, sink *[]pathString) {
	switch x := v.(type) {
	case string:
		*sink = append(*sink, pathString{path, x})
	case []any:
		for i, e := range x {
			walkStrings(e, fmt.Sprintf("%s[%d]", path, i), sink)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkStrings(x[k], path+"."+k, sink)
		}
	}
}

func eq(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok || bok {
		return aok && bok && an == bn
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok || bok {
		return aok && bok && as == bs
	}
	ab, aok := a.(bool)
	bb, bok := b.(bool)
	if aok || bok {
		return aok && bok && ab == bb
	}
	return a == nil && b == nil
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func intOf(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func typeOK(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		_, ok := intOf(v)
		return ok
	}
	return false
}

// check is a small JSON Schema subset interpreter: type, required,
// properties, additionalProperties, enum, const, pattern, minLength,
// maxLength, minimum, maximum, maxItems, items and $ref into $defs.
func check(v any, s, root map[string]any, p string, out *[]string) {
	if ref, ok := s["$ref"].(string); ok {
		defs, _ := root["$defs"].(map[string]any)
		target, _ := defs[ref[strings.LastIndex(ref, "/")+1:]].(map[string]any)
		if target == nil {
			*out = append(*out, p+": schema reference "+ref+" is unknown")
			return
		}
		check(v, target, root, p, out)
		return
	}
	t, _ := s["type"].(string)
	if t != "" && !typeOK(v, t) {
		*out = append(*out, fmt.Sprintf("%s: expected %s", p, t))
		return
	}
	if c, ok := s["const"]; ok && !schemaEq(v, c) {
		*out = append(*out, fmt.Sprintf("%s: must be %v", p, c))
	}
	if en, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range en {
			if schemaEq(v, e) {
				found = true
				break
			}
		}
		if !found {
			*out = append(*out, fmt.Sprintf("%s: not one of %v", p, en))
		}
	}
	switch t {
	case "string":
		str := v.(string)
		n := utf8.RuneCountInString(str)
		if m, ok := num(s["minLength"]); ok && int64(n) < m {
			*out = append(*out, p+": too short")
		}
		if m, ok := num(s["maxLength"]); ok && int64(n) > m {
			*out = append(*out, fmt.Sprintf("%s: longer than %d", p, m))
		}
		if pat, ok := s["pattern"].(string); ok {
			rx, err := regexp.Compile(pat)
			if err != nil || !rx.MatchString(str) {
				*out = append(*out, fmt.Sprintf("%s: does not match %s", p, pat))
			}
		}
	case "integer":
		i, _ := intOf(v)
		if m, ok := num(s["minimum"]); ok && i < m {
			*out = append(*out, fmt.Sprintf("%s: below %d", p, m))
		}
		if m, ok := num(s["maximum"]); ok && i > m {
			*out = append(*out, fmt.Sprintf("%s: above %d", p, m))
		}
	case "array":
		arr := v.([]any)
		if m, ok := num(s["maxItems"]); ok && int64(len(arr)) > m {
			*out = append(*out, fmt.Sprintf("%s: more than %d items", p, m))
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range arr {
				check(e, items, root, fmt.Sprintf("%s[%d]", p, i), out)
			}
		}
	case "object":
		obj := v.(map[string]any)
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				k, _ := r.(string)
				if _, present := obj[k]; !present {
					*out = append(*out, fmt.Sprintf("%s: missing %s", p, k))
				}
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if sub, ok := props[k].(map[string]any); ok {
				check(obj[k], sub, root, p+"."+k, out)
			} else if ap, ok := s["additionalProperties"].(bool); ok && !ap {
				*out = append(*out, fmt.Sprintf("%s: unknown field %s", p, k))
			}
		}
	}
}

// schemaEq compares a document value with a schema literal (string, number
// or boolean).
func schemaEq(v, lit any) bool {
	if n, ok := v.(json.Number); ok {
		f, ok := lit.(float64)
		if !ok {
			return false
		}
		g, err := strconv.ParseFloat(string(n), 64)
		return err == nil && g == f
	}
	return eq(v, lit)
}

func num(v any) (int64, bool) {
	f, ok := v.(float64)
	return int64(f), ok
}
