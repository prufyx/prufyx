// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

func runSumOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// rewriteRunEntries applies edit to the decoded candidates.json entries and
// re-records its digest in the manifest, so that only the entry check (not a
// digest mismatch) can refuse the run.
func rewriteRunEntries(t *testing.T, dir string, edit func([]map[string]any) []map[string]any) {
	t.Helper()
	cpath := filepath.Join(dir, extract.FileCandidates)
	raw, err := os.ReadFile(cpath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(edit(entries))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cpath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	editRunManifest(t, dir, func(m map[string]any) { m["outputs"].(map[string]any)[extract.FileCandidates] = runSumOf(out) })
}

func editRunManifest(t *testing.T, dir string, edit func(map[string]any)) {
	t.Helper()
	mpath := filepath.Join(dir, extract.FileManifest)
	raw, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mpath, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func ruleMap(e map[string]any) map[string]any { return e["rule"].(map[string]any) }

// Test 19: a candidates.json entry carrying a basis or draft key is refused.
func TestLoadRunRefusesBasisAndDraftKeys(t *testing.T) {
	c := cases[0]
	if _, err := extractpack.LoadRun(runDir(t, c, derivedAt)); err != nil {
		t.Fatalf("the clean run is refused: %v", err)
	}
	for name, edit := range map[string]func([]map[string]any) []map[string]any{
		"entry basis":   func(e []map[string]any) []map[string]any { e[0]["basis"] = "mechanical"; return e },
		"entry draft":   func(e []map[string]any) []map[string]any { e[0]["draft"] = true; return e },
		"entry basis d": func(e []map[string]any) []map[string]any { e[0]["basis"] = "draft"; return e },
		"rule basis":    func(e []map[string]any) []map[string]any { ruleMap(e[0])["basis"] = "needs_review"; return e },
		"rule draft":    func(e []map[string]any) []map[string]any { ruleMap(e[0])["draft"] = true; return e },
	} {
		dir := runDir(t, c, derivedAt)
		rewriteRunEntries(t, dir, edit)
		_, err := extractpack.LoadRun(dir)
		if !errors.Is(err, extractpack.ErrRun) || !strings.Contains(err.Error(), "never a pack entry") {
			t.Fatalf("%s: err %v", name, err)
		}
	}
	// A draft-basis evidence block is refused by the existing mechanical check.
	for _, b := range []string{"draft", "needs_review", "reviewed", ""} {
		dir := runDir(t, c, derivedAt)
		rewriteRunEntries(t, dir, func(e []map[string]any) []map[string]any {
			ruleMap(e[0])["evidence"].(map[string]any)["basis"] = b
			return e
		})
		if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("evidence basis %q: err %v", b, err)
		}
	}
}

// Test 19: drafts.json is never read and a run with drafts is not applied.
func TestLoadRunRefusesDrafts(t *testing.T) {
	c := cases[0]
	t.Run("drafts.json present", func(t *testing.T) {
		dir := runDir(t, c, derivedAt)
		if err := os.WriteFile(filepath.Join(dir, extract.FileDrafts), []byte("not json at all"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := extractpack.LoadRun(dir)
		if !errors.Is(err, extractpack.ErrRun) || !strings.Contains(err.Error(), "drafts") || strings.Contains(err.Error(), "invalid character") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("manifest lists drafts.json", func(t *testing.T) {
		dir := runDir(t, c, derivedAt)
		editRunManifest(t, dir, func(m map[string]any) { m["outputs"].(map[string]any)[extract.FileDrafts] = runSumOf([]byte("x")) })
		if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("pair has drafts", func(t *testing.T) {
		dir := runDir(t, c, derivedAt)
		editRunManifest(t, dir, func(m map[string]any) { m["pairs"].([]any)[0].(map[string]any)["drafts"] = 1 })
		if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("totals have drafts", func(t *testing.T) {
		dir := runDir(t, c, derivedAt)
		editRunManifest(t, dir, func(m map[string]any) { m["totals"].(map[string]any)["drafts"] = 1 })
		if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("old manifest schema", func(t *testing.T) {
		dir := runDir(t, c, derivedAt)
		editRunManifest(t, dir, func(m map[string]any) { m["schema"] = "prufyx.io/extractor-run-manifest/v1" })
		if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("err %v", err)
		}
	})
}

// Test 20: the skeleton printed for a reviewer does not load as a pack entry.
func TestSkeletonDoesNotLoadAsPackEntry(t *testing.T) {
	c := cases[0]
	d := extract.DraftEntry{Draft: true, Basis: extract.BasisDraft, From: "1.0.0", To: "2.0.0", Quote: "The flag old is removed.", Reason: "release note names a removal"}
	sk, err := extract.Skeleton(d)
	if err != nil {
		t.Fatal(err)
	}
	var skeleton map[string]any
	if err := json.Unmarshal(sk, &skeleton); err != nil {
		t.Fatal(err)
	}
	dir := runDir(t, c, derivedAt)
	rewriteRunEntries(t, dir, func(e []map[string]any) []map[string]any { e[0] = skeleton; return e })
	if _, err := extractpack.LoadRun(dir); !errors.Is(err, extractpack.ErrRun) {
		t.Fatalf("the skeleton loaded as a pack entry: %v", err)
	}
	// Even with a real rule id and its evidence placeholder removed, the
	// skeleton has no evidence block, so it is not an active mechanical rule.
	dir2 := runDir(t, c, derivedAt)
	rewriteRunEntries(t, dir2, func(e []map[string]any) []map[string]any {
		r := map[string]any{}
		for k, v := range ruleMap(skeleton) {
			r[k] = v
		}
		r["id"] = ruleMap(e[0])["id"]
		delete(r, "evidence")
		sk2 := map[string]any{}
		for k, v := range skeleton {
			sk2[k] = v
		}
		sk2["rule"] = r
		e[0] = sk2
		return e
	})
	if _, err := extractpack.LoadRun(dir2); !errors.Is(err, extractpack.ErrRun) || !strings.Contains(err.Error(), "not an active mechanical rule") {
		t.Fatalf("err %v", err)
	}
}
