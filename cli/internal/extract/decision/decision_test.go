// SPDX-License-Identifier: AGPL-3.0-only
package decision

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, version, code string) []File {
	t.Helper()
	codeHash := strings.TrimPrefix(digest([]byte(code)), "sha256:")
	codeDigest := digest([]byte("extract/example.go\x00" + codeHash + "\n"))
	ex := map[string]any{"id": "example", "version": version, "codeDigest": codeDigest}
	evidence := map[string]any{"extractor": ex, "basis": "mechanical", "derivedAt": "2026-11-22T00:00:00Z", "reviewedAt": "2026-11-22T00:00:00Z", "validUntil": "2026-12-22T00:00:00Z", "sources": []any{map[string]any{"contentDigest": "retained", "revision": "pinned"}}, "extension": map[string]any{"version": "semantic", "codeDigest": "semantic"}}
	raw := func(v any) []byte {
		b, e := canonical(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	files := []File{{Path: "candidates.json", Mode: 0o644, Data: raw([]any{map[string]any{"rule": map[string]any{"id": "one", "evidence": evidence, "condition": map[string]any{"members": []string{"a", "b"}}, "unknown": "kept"}}})}, {Path: "vectors.json", Mode: 0o644, Data: raw([]any{map[string]any{"input": map[string]any{"unknown": 1}, "expect": "PASS"}})}, {Path: "attestations.json", Mode: 0o644, Data: raw([]any{map[string]any{"component": "example", "line": "1.2", "factFamily": "family", "evidence": evidence}})}}
	outputs := map[string]string{}
	for _, f := range files {
		outputs[f.Path] = digest(f.Data)
	}
	files = append(files, File{Path: "manifest.json", Mode: 0o644, Data: raw(map[string]any{"schema": "prufyx.io/extractor-run-manifest/v2", "extractor": ex, "codeFiles": []any{map[string]any{"path": "extract/example.go", "sha256": codeHash}}, "outputs": outputs, "pairs": []any{map[string]any{"proof": map[string]any{"unknown": "keep"}}}, "derivedAt": "2026-11-22T00:00:00Z"})})
	return files
}
func bridge(t *testing.T, f []File) Pair {
	t.Helper()
	p, e := Bridge(f)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func rehash(t *testing.T, files []File) {
	t.Helper()
	for i := range files {
		if files[i].Path != "manifest.json" {
			continue
		}
		var m map[string]any
		if e := json.Unmarshal(files[i].Data, &m); e != nil {
			t.Fatal(e)
		}
		outs := m["outputs"].(map[string]any)
		for _, f := range files {
			if f.Path != "manifest.json" {
				outs[f.Path] = digest(f.Data)
			}
		}
		b, e := canonical(m)
		if e != nil {
			t.Fatal(e)
		}
		files[i].Data = b
	}
}
func TestBridgeTruthfulBuildChangeAndRawReconstruction(t *testing.T) {
	aFiles := fixture(t, "1.0", "old code")
	bFiles := fixture(t, "2.0", "new code")
	a, b := bridge(t, aFiles), bridge(t, bFiles)
	same, e := Equal(a, b)
	if e != nil || !same {
		t.Fatalf("decision equality %v %v", same, e)
	}
	if bytes.Equal(a.Receipt, b.Receipt) {
		t.Fatal("execution identities lost")
	}
	got, e := Reconstruct(a)
	if e != nil {
		t.Fatal(e)
	}
	byPath := map[string][]byte{}
	for _, f := range got {
		byPath[f.Path] = f.Data
	}
	for _, f := range aFiles {
		if !bytes.Equal(f.Data, byPath[f.Path]) {
			t.Fatal("original changed", f.Path)
		}
	}
	if len(a.Decision) == 0 {
		t.Fatal("empty decision")
	}
}
func TestDecisionMutationsNeverDisappear(t *testing.T) {
	for _, tt := range []struct{ name, file, old, new string }{
		{"unknown member", "candidates.json", "kept", "changed"}, {"unknown nested stamp-like member", "candidates.json", "semantic", "changed"}, {"time", "candidates.json", "2026-11-22", "2026-11-23"}, {"validity", "attestations.json", "2026-12-22", "2026-12-23"}, {"source", "candidates.json", "pinned", "other"}, {"array order", "candidates.json", "\"a\",\n              \"b\"", "\"b\",\n              \"a\""}, {"proof", "manifest.json", "keep", "changed"}, {"vectors", "vectors.json", "PASS", "UNKNOWN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := fixture(t, "1", "code")
			a := bridge(t, files)
			changed := false
			for i := range files {
				if files[i].Path == tt.file {
					old := files[i].Data
					if tt.name == "array order" {
						var entries []map[string]any
						if e := json.Unmarshal(old, &entries); e != nil {
							t.Fatal(e)
						}
						members := entries[0]["rule"].(map[string]any)["condition"].(map[string]any)["members"].([]any)
						members[0], members[1] = members[1], members[0]
						var e error
						files[i].Data, e = canonical(entries)
						if e != nil {
							t.Fatal(e)
						}
					} else {
						files[i].Data = bytes.Replace(old, []byte(tt.old), []byte(tt.new), 1)
					}
					changed = !bytes.Equal(old, files[i].Data)
				}
			}
			if !changed {
				t.Fatal("mutation fixture did not change")
			}
			rehash(t, files)
			b := bridge(t, files)
			same, e := Equal(a, b)
			if e != nil || same {
				t.Fatalf("mutation disappeared %v %v", same, e)
			}
		})
	}
}
func TestCodeFileClosedShapeAndInventory(t *testing.T) {
	for _, tt := range []struct{ name, old, new string }{
		{"extra", "\"sha256\":", "\"extra\":true,\"sha256\":"}, {"unknown nested", "\"sha256\":", "\"extra\":{},\"sha256\":"}, {"duplicate key", "\"sha256\":", "\"path\":\"other\",\"sha256\":"}, {"unsafe path", "extract/example.go", "../example.go"}, {"wrong type", "\"path\": \"extract/example.go\"", "\"path\": {}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := fixture(t, "1", "code")
			for i := range files {
				if files[i].Path == "manifest.json" {
					old := files[i].Data
					files[i].Data = bytes.Replace(old, []byte(tt.old), []byte(tt.new), 1)
					if bytes.Equal(old, files[i].Data) {
						t.Fatal("no mutation")
					}
				}
			}
			if _, e := Bridge(files); e == nil {
				t.Fatal("malformed CodeFile accepted")
			}
		})
	}
	for _, tt := range []string{"missing", "extra", "duplicate", "mode", "invalid UTF8", "trailing", "schema", "output digest", "record identity"} {
		t.Run(tt, func(t *testing.T) {
			f := fixture(t, "1", "code")
			switch tt {
			case "missing":
				f = f[1:]
			case "extra":
				f = append(f, File{Path: "extra.json", Mode: 0o644, Data: []byte("{}")})
			case "duplicate":
				f = append(f, f[0])
			case "mode":
				f[0].Mode = 0o755
			case "invalid UTF8":
				f[0].Data = []byte{'"', 255, '"'}
			case "trailing":
				f[0].Data = append(f[0].Data, []byte("{}")...)
			case "schema":
				f[3].Data = bytes.Replace(f[3].Data, []byte("manifest/v2"), []byte("manifest/v3"), 1)
			case "output digest":
				f[0].Data = append(f[0].Data, ' ')
			case "record identity":
				f[0].Data = bytes.Replace(f[0].Data, []byte("example\""), []byte("different\""), 1)
				rehash(t, f)
			}
			if _, e := Bridge(f); e == nil {
				t.Fatal("invalid inventory/binding accepted")
			}
		})
	}
}
func TestReceiptCannotHideChangedDecisionOrSlot(t *testing.T) {
	p := bridge(t, fixture(t, "1", "code"))
	for _, which := range []string{"original", "offset", "extra slot", "schema", "unknown envelope"} {
		t.Run(which, func(t *testing.T) {
			var r Receipt
			if e := json.Unmarshal(p.Receipt, &r); e != nil {
				t.Fatal(e)
			}
			switch which {
			case "original":
				r.Originals[0].File.Data[0] = 'x'
			case "offset":
				r.Originals[0].Slots[0].Offset++
			case "extra slot":
				r.Originals[0].Slots = append(r.Originals[0].Slots, Slot{})
			case "schema":
				r.Schema = "unknown"
			}
			raw, e := canonical(r)
			if e != nil {
				t.Fatal(e)
			}
			if which == "unknown envelope" {
				raw = bytes.Replace(raw, []byte("{\n"), []byte("{\n\"unknown\":true,"), 1)
			}
			if e := Validate(Pair{Decision: p.Decision, Receipt: raw}); e == nil {
				t.Fatal("substituted receipt accepted")
			}
		})
	}
}
func TestDirectoryRefusesLinksAndPairExtras(t *testing.T) {
	dir := t.TempDir()
	if e := os.Symlink("/outside", filepath.Join(dir, "manifest.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadDirectory(dir); e == nil {
		t.Fatal("symlink accepted")
	}
	p := bridge(t, fixture(t, "1", "code"))
	files, e := p.Files()
	if e != nil {
		t.Fatal(e)
	}
	dir = t.TempDir()
	for n, b := range files {
		if e := os.WriteFile(filepath.Join(dir, n), b, 0o644); e != nil {
			t.Fatal(e)
		}
	}
	got, e := ReadPair(dir)
	if e != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("read pair %v", e)
	}
	if e := os.WriteFile(filepath.Join(dir, "extra"), nil, 0o644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPair(dir); e == nil {
		t.Fatal("extra pair file accepted")
	}
}
