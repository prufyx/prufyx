// SPDX-License-Identifier: AGPL-3.0-only
// Package decision separates extraction decisions from execution origins.
// Equality proves only this versioned byte domain, never admission or safety.
package decision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	Schema        = "prufyx.io/extract-decisions/v2"
	ReceiptSchema = "prufyx.io/extract-execution/v2"
	DecisionFile  = "decision-output.json"
	ReceiptFile   = "execution-receipt.json"
	maxBytes      = 64 << 20
	maxPairBytes  = 128 << 20
	maxFiles      = 10000
)

type File struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data []byte `json:"data"`
}
type Document struct {
	Schema string `json:"schema"`
	Files  []File `json:"files"`
}

// Slot is an origin's offset in the decision file, where exactly null occurs.
type Slot struct {
	Offset int    `json:"offset"`
	Data   []byte `json:"data"`
}
type Original struct {
	File   File   `json:"file"`
	SHA256 string `json:"sha256"`
	Slots  []Slot `json:"slots"`
}
type Receipt struct {
	Schema         string     `json:"schema"`
	DecisionSHA256 string     `json:"decisionSHA256"`
	Originals      []Original `json:"originals"`
}
type Pair struct {
	Decision []byte
	Receipt  []byte
}

func digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func canonical(v any) ([]byte, error) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
func safePath(s string) bool {
	return s != "" && s != "." && s != ".." && path.Clean(s) == s && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00\r\n")
}
func isHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func allowed(s string) bool {
	switch s {
	case "manifest.json", "candidates.json", "vectors.json", "attestations.json", "drafts.json":
		return true
	}
	return strings.HasPrefix(s, "reads/") && strings.Count(s, "/") == 1 && strings.HasSuffix(s, ".tsv") && validCommit(strings.TrimSuffix(strings.TrimPrefix(s, "reads/"), ".tsv"))
}

func validCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Bridge consumes actual output of an unchanged legacy extractor. Originals
// remain intact; decisions replace only the closed origin slots with null.
func Bridge(input []File) (Pair, error) {
	files := append([]File(nil), input...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if len(files) == 0 || len(files) > maxFiles {
		return Pair{}, errors.New("file inventory limit")
	}
	byName := map[string]File{}
	trees := map[string]*node{}
	total := 0
	for _, f := range files {
		if !safePath(f.Path) || !allowed(f.Path) || f.Mode != 0o644 {
			return Pair{}, fmt.Errorf("unsupported file/mode %q", f.Path)
		}
		if _, ok := byName[f.Path]; ok {
			return Pair{}, errors.New("duplicate file path")
		}
		total += len(f.Data)
		if total > maxBytes {
			return Pair{}, errors.New("input size limit")
		}
		byName[f.Path] = f
		if strings.HasSuffix(f.Path, ".json") {
			n, e := parse(f.Data)
			if e != nil {
				return Pair{}, fmt.Errorf("%s: %w", f.Path, e)
			}
			trees[f.Path] = n
		}
	}
	for _, name := range []string{"manifest.json", "candidates.json", "vectors.json"} {
		if _, ok := byName[name]; !ok {
			return Pair{}, fmt.Errorf("missing %s", name)
		}
	}
	man := trees["manifest.json"]
	schema, e := member(man, "schema")
	if e != nil {
		return Pair{}, e
	}
	schemaText, e := text(schema)
	if e != nil || schemaText != "prufyx.io/extractor-run-manifest/v2" {
		return Pair{}, errors.New("unsupported legacy manifest schema")
	}
	ex, e := member(man, "extractor")
	if e != nil {
		return Pair{}, e
	}
	identity, e := extractor(ex)
	if e != nil {
		return Pair{}, e
	}
	codes, e := member(man, "codeFiles")
	if e != nil {
		return Pair{}, e
	}
	if e = codeFiles(codes, identity[2]); e != nil {
		return Pair{}, e
	}
	outputs, e := member(man, "outputs")
	if e != nil || outputs.object == nil {
		return Pair{}, errors.New("missing output inventory")
	}
	if len(outputs.object) != len(files)-1 {
		return Pair{}, errors.New("output inventory differs from files")
	}
	for name, n := range outputs.object {
		f, ok := byName[name]
		v, e := text(n)
		if name == "manifest.json" || !ok || e != nil || v != digest(f.Data) {
			return Pair{}, fmt.Errorf("output binding %q", name)
		}
	}
	doc := Document{Schema: Schema, Files: []File{}}
	rec := Receipt{Schema: ReceiptSchema, Originals: []Original{}}
	for _, f := range files {
		var spans []*node
		switch f.Path {
		case "manifest.json":
			spans = append(spans, ex.object["version"], ex.object["codeDigest"], codes)
			for _, n := range outputs.object {
				spans = append(spans, n)
			}
		case "candidates.json", "attestations.json", "drafts.json":
			if trees[f.Path].array == nil {
				return Pair{}, errors.New("record file must be array")
			}
			for _, item := range trees[f.Path].array {
				n := item
				if f.Path == "candidates.json" {
					n, e = member(n, "rule")
					if e != nil {
						return Pair{}, e
					}
				}
				if f.Path != "drafts.json" {
					n, e = member(n, "evidence")
					if e != nil {
						return Pair{}, e
					}
				}
				x, e := member(n, "extractor")
				if e != nil {
					return Pair{}, e
				}
				got, e := extractor(x)
				if e != nil || got != identity {
					return Pair{}, errors.New("record extractor does not match manifest")
				}
				spans = append(spans, x.object["version"], x.object["codeDigest"])
			}
		case "vectors.json":
			if trees[f.Path].array == nil {
				return Pair{}, errors.New("vectors must be array")
			}
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
		out := []byte{}
		slots := []Slot{}
		pos := 0
		for _, n := range spans {
			if n.start < pos || n.end > len(f.Data) {
				return Pair{}, errors.New("overlapping origin slots")
			}
			out = append(out, f.Data[pos:n.start]...)
			slots = append(slots, Slot{Offset: len(out), Data: bytes.Clone(f.Data[n.start:n.end])})
			out = append(out, "null"...)
			pos = n.end
		}
		out = append(out, f.Data[pos:]...)
		doc.Files = append(doc.Files, File{Path: f.Path, Mode: f.Mode, Data: out})
		rec.Originals = append(rec.Originals, Original{File: f, SHA256: digest(f.Data), Slots: slots})
	}
	db, e := canonical(doc)
	if e != nil {
		return Pair{}, e
	}
	rec.DecisionSHA256 = digest(db)
	rb, e := canonical(rec)
	if e != nil {
		return Pair{}, e
	}
	if len(db)+len(rb) > maxPairBytes {
		return Pair{}, errors.New("encoded pair size limit")
	}
	return Pair{Decision: db, Receipt: rb}, nil
}
func extractor(n *node) ([3]string, error) {
	var id [3]string
	for i, k := range []string{"id", "version", "codeDigest"} {
		v, e := member(n, k)
		if e != nil {
			return id, e
		}
		id[i], e = text(v)
		if e != nil {
			return id, e
		}
	}
	if err := constraintengine.ValidateBasis(constraintengine.BasisMechanical, &constraintengine.Extractor{ID: id[0], Version: id[1], CodeDigest: id[2]}, "2000-01-01T00:00:00Z"); err != nil {
		return id, fmt.Errorf("invalid extractor identity: %w", err)
	}
	return id, nil
}
func codeFiles(n *node, want string) error {
	if len(n.array) == 0 {
		return errors.New("empty or invalid codeFiles")
	}
	seen := map[string]bool{}
	var b strings.Builder
	last := ""
	standard := false
	for _, v := range n.array {
		if v.object == nil || len(v.object) != 2 {
			return errors.New("codeFile must contain only path and sha256")
		}
		p, e := text(v.object["path"])
		if e != nil {
			return e
		}
		s, e := text(v.object["sha256"])
		if e != nil {
			return e
		}
		if !safePath(p) || seen[p] || p <= last || !isHex(s) {
			return errors.New("invalid, duplicate or unordered codeFile")
		}
		if strings.HasPrefix(p, "extract/chartrun/") {
			return errors.New("chart producer is unsupported")
		}
		if p == "extract/run.go" {
			standard = true
		}
		seen[p] = true
		last = p
		b.WriteString(p + "\x00" + s + "\n")
	}
	if !standard {
		return errors.New("unsupported producer: extract/run.go not present")
	}
	if digest([]byte(b.String())) != want {
		return errors.New("codeFiles digest differs from extractor")
	}
	return nil
}
func decodeStrict(raw []byte, out any) error {
	if len(raw) > maxPairBytes {
		return errors.New("pair size limit")
	}
	if _, e := parse(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// Reconstruct assembles every original from decisions plus disjoint origin
// slots, checks full originals, then independently reprojects the exact bytes.
func Reconstruct(p Pair) ([]File, error) {
	if len(p.Decision)+len(p.Receipt) > maxPairBytes {
		return nil, errors.New("encoded pair size limit")
	}
	var d Document
	var r Receipt
	if e := decodeStrict(p.Decision, &d); e != nil {
		return nil, e
	}
	if e := decodeStrict(p.Receipt, &r); e != nil {
		return nil, e
	}
	if d.Schema != Schema || r.Schema != ReceiptSchema || r.DecisionSHA256 != digest(p.Decision) || len(d.Files) != len(r.Originals) || len(d.Files) > maxFiles {
		return nil, errors.New("decision/receipt binding")
	}
	files := []File{}
	total := 0
	for i, f := range d.Files {
		original := r.Originals[i]
		if f.Path != original.File.Path || f.Mode != original.File.Mode {
			return nil, errors.New("original file identity")
		}
		out := []byte{}
		pos := 0
		for _, slot := range original.Slots {
			if slot.Offset < pos || slot.Offset > len(f.Data)-4 || !bytes.Equal(f.Data[slot.Offset:slot.Offset+4], []byte("null")) {
				return nil, errors.New("invalid origin slot")
			}
			out = append(out, f.Data[pos:slot.Offset]...)
			out = append(out, slot.Data...)
			pos = slot.Offset + 4
		}
		out = append(out, f.Data[pos:]...)
		total += len(out)
		if total > maxBytes || !bytes.Equal(out, original.File.Data) || digest(out) != original.SHA256 {
			return nil, errors.New("original reconstruction differs")
		}
		files = append(files, File{Path: f.Path, Mode: f.Mode, Data: out})
	}
	rebuilt, e := Bridge(files)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(rebuilt.Decision, p.Decision) || !bytes.Equal(rebuilt.Receipt, p.Receipt) {
		return nil, errors.New("noncanonical or substituted projection/receipt")
	}
	return files, nil
}
func Validate(p Pair) error { _, e := Reconstruct(p); return e }
func Equal(a, b Pair) (bool, error) {
	if e := Validate(a); e != nil {
		return false, e
	}
	if e := Validate(b); e != nil {
		return false, e
	}
	return bytes.Equal(a.Decision, b.Decision), nil
}

// Record projects one resolved semantic record before or after origin stamping.
// It is not an admission check; Bridge validates actual run identities.
func Record(raw []byte, kind string) ([]byte, error) {
	if kind != "candidate" && kind != "attestation" && kind != "draft" {
		return nil, errors.New("unsupported record kind")
	}
	n, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if kind == "candidate" {
		n, e = member(n, "rule")
		if e != nil {
			return nil, e
		}
	}
	if kind != "draft" {
		n, e = member(n, "evidence")
		if e != nil {
			return nil, e
		}
	}
	x, e := member(n, "extractor")
	if e != nil {
		return nil, e
	}
	var spans []*node
	for _, k := range []string{"version", "codeDigest"} {
		v, e := member(x, k)
		if e != nil {
			return nil, e
		}
		if _, ok := v.value.(string); !ok {
			return nil, errors.New("origin must be string")
		}
		spans = append(spans, v)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	out := []byte{}
	pos := 0
	for _, v := range spans {
		out = append(out, raw[pos:v.start]...)
		out = append(out, "null"...)
		pos = v.end
	}
	return append(out, raw[pos:]...), nil
}
