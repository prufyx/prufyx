// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const jobsetDir = "../../../../contrib/onboard-bundles/jobset"

const (
	testCommit = "8936f4e8cd4a757d9863eb906fcb781192ae2a82"
	testTime   = "2026-11-17T15:45:00Z"
)

// copyBundle copies the files of src into <tmp>/<name>.
func copyBundle(t *testing.T, src, name string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func jobset(t *testing.T) string { return copyBundle(t, jobsetDir, "jobset") }

func noReceipt(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, "receipt.json")); err != nil {
		t.Fatal(err)
	}
}

func mustValidate(t *testing.T, dir string, want int) []string {
	t.Helper()
	f, err := Validate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != want {
		t.Fatalf("%d findings, want %d: %v", len(f), want, f)
	}
	return f
}

func refused(t *testing.T, dir string, o SealOptions, wantSub string) {
	t.Helper()
	before := snapshotDir(t, dir)
	_, err := Seal(dir, o)
	if err == nil {
		t.Fatalf("seal succeeded, want refusal containing %q", wantSub)
	}
	var re refusal
	if !asRefusal(err, &re) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("error %q lacks %q", err, wantSub)
	}
	if after := snapshotDir(t, dir); after != before {
		t.Fatalf("directory changed by a refused seal")
	}
}

func asRefusal(err error, out *refusal) bool {
	r, ok := err.(refusal)
	if ok {
		*out = r
	}
	return ok
}

// snapshotDir returns a stable text image of every file name and content.
func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			raw, _ := os.ReadFile(p)
			b.WriteString(p + "\x00" + string(raw) + "\x01")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestSealReproducesJobsetReceipt(t *testing.T) {
	orig := mustRead(t, filepath.Join(jobsetDir, "receipt.json"))
	// Stale digests, existing receipt: --force-reseal reproduces the file byte for byte.
	dir := jobset(t)
	rewrite(t, dir, "receipt.json", `"bundleSha256": "eade4a90`, `"bundleSha256": "00000000`)
	if _, err := Seal(dir, SealOptions{}); err == nil {
		t.Fatal("stale receipt sealed without --force-reseal")
	}
	res, err := Seal(dir, SealOptions{ForceReseal: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(dir, "receipt.json")); got != orig {
		t.Fatalf("resealed receipt differs:\n%s", got)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "changed: bundleSha256") {
		t.Fatalf("changes not reported: %v", res.Notes)
	}
	mustValidate(t, dir, 0)

	// No receipt: identical except the documented difference, a new receipt never claims the
	// offline target check passed (seal does not run it): targetCheckOffline is not-run.
	dir = jobset(t)
	noReceipt(t, dir)
	if _, err := Seal(dir, SealOptions{ToolCommit: testCommit, GeneratedAt: testTime}); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, filepath.Join(dir, "receipt.json"))
	if strings.Replace(orig, `"targetCheckOffline": "pass"`, `"targetCheckOffline": "not-run"`, 1) != got {
		t.Fatalf("new receipt differs beyond targetCheckOffline:\n%s", got)
	}
	mustValidate(t, dir, 0)
}

func TestSealedBundleValidatesWithoutHandWrittenDigests(t *testing.T) {
	dir := copyBundle(t, "testdata/valid", "example-operator")
	noReceipt(t, dir)
	mustValidate(t, dir, 1) // receipt.json: missing
	var out, errb bytes.Buffer
	code := Run([]string{"seal", "-tool-commit", testCommit, "-generated-at", testTime, dir}, &out, &errb)
	if code != 0 {
		t.Fatalf("code %d, out %q err %q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "unverified") || !strings.Contains(out.String(), "integrity only") {
		t.Fatalf("output lacks the integrity/unverified notes: %q", out.String())
	}
	out.Reset()
	if code := Run([]string{"validate", "--dir-is-slug", dir}, &out, &errb); code != 0 {
		t.Fatalf("validate after seal: %d %q", code, out.String())
	}
}

func TestSealIsIdempotentAndWritesNothingWhenMatching(t *testing.T) {
	dir := jobset(t)
	before := snapshotDir(t, dir)
	res, err := Seal(dir, SealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "nothing written") || snapshotDir(t, dir) != before {
		t.Fatalf("matching receipt rewritten: %v", res.Notes)
	}
	noReceipt(t, dir)
	if _, err := Seal(dir, SealOptions{ToolCommit: testCommit, GeneratedAt: testTime}); err != nil {
		t.Fatal(err)
	}
	once := snapshotDir(t, dir)
	if _, err := Seal(dir, SealOptions{ToolCommit: testCommit, GeneratedAt: testTime}); err != nil {
		t.Fatal(err)
	}
	if snapshotDir(t, dir) != once {
		t.Fatal("second seal changed the directory")
	}
}

func TestTamperAfterSealFailsValidateAndNeedsForce(t *testing.T) {
	dir := jobset(t)
	noReceipt(t, dir)
	if _, err := Seal(dir, SealOptions{ToolCommit: testCommit, GeneratedAt: testTime}); err != nil {
		t.Fatal(err)
	}
	rewrite(t, dir, "project.json", `"line": "0.13"`, `"line": "0.14"`)
	f := mustValidate(t, dir, 2)
	if !contains(f, "bundleSha256 does not match") || !contains(f, "files list does not match") {
		t.Fatalf("tamper not caught: %v", f)
	}
	before := snapshotDir(t, dir)
	res, err := Seal(dir, SealOptions{})
	if err == nil || snapshotDir(t, dir) != before {
		t.Fatalf("tampered bundle resealed without --force-reseal: %v", err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "changed: project.json") {
		t.Fatalf("refusal does not say what changed: %v", res.Notes)
	}
	// With force the new content is sealed, the changes are printed and the stale offline-check result is reset.
	rewrite(t, dir, "receipt.json", `"targetCheckOffline": "not-run"`, `"targetCheckOffline": "pass"`)
	res, err = Seal(dir, SealOptions{ForceReseal: true})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Notes, "changed: checks.targetCheckOffline reset to not-run (files changed)") {
		t.Fatalf("stale check result kept: %v", res.Notes)
	}
	if strings.Contains(mustRead(t, filepath.Join(dir, "receipt.json")), `"pass"`) {
		t.Fatal("pass survived a content change")
	}
	mustValidate(t, dir, 0)
}

func TestSealRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, dir string)
		want string
	}{
		{"missing file", func(t *testing.T, d string) { _ = os.Remove(filepath.Join(d, "scan-notes.json")) }, "scan-notes.json: missing"},
		{"unknown field", func(t *testing.T, d string) {
			rewrite(t, d, "project.json", `"kind": "project"`, `"kind": "project", "extra": "x"`)
		}, "extra"},
		{"origin-like key", func(t *testing.T, d string) {
			rewrite(t, d, "project.json", `"kind": "project"`, `"kind": "project", "origin": "simulated"`)
		}, "origin"},
		{"unknown receipt field", func(t *testing.T, d string) {
			rewrite(t, d, "receipt.json", `"kit": "k0-v0"`, `"kit": "k0-v0", "origin": "simulated"`)
		}, "origin"},
		{"forbidden file", func(t *testing.T, d string) { write(t, d, "rules.json", "{}") }, "forbidden file"},
		{"extra file", func(t *testing.T, d string) { write(t, d, "notes.txt", "x") }, "not a bundle file"},
		{"symlink", func(t *testing.T, d string) { _ = os.Symlink("project.json", filepath.Join(d, "link.json")) }, "symlink refused"},
		{"secret-shaped", func(t *testing.T, d string) {
			rewrite(t, d, "project.json", `"cncfStatusClaim": "none"`, `"cncfStatusClaim": "none", "x": "ghp_abcdefghijklmnopqrstuvwxyz0123"`)
		}, "x"},
		{"non-ASCII in a note", func(t *testing.T, d string) {
			rewrite(t, d, "target-draft.json", "the two files were byte-equal", "the two files were býte-equal")
		}, "outside printable ASCII"},
		{"oversized field", func(t *testing.T, d string) {
			write(t, d, "extract-run/candidates.json", `["`+strings.Repeat("a", MaxFieldRunes+1)+`"]`)
		}, "more than 2000"},
		{"total size", func(t *testing.T, d string) {
			old := maxBundleBytes
			maxBundleBytes = 4000
			t.Cleanup(func() { maxBundleBytes = old })
		}, "total"},
		{"dir name not slug", nil, "must equal the slug"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := jobset(t)
			if c.edit == nil {
				dir = copyBundle(t, jobsetDir, "other")
			} else {
				c.edit(t, dir)
			}
			// Stale receipt where one exists, so the refusal is never the missing-receipt path.
			refused(t, dir, SealOptions{ToolCommit: testCommit, GeneratedAt: testTime, ForceReseal: true}, c.want)
		})
	}
}

func TestSealQuoteBidiRefused(t *testing.T) {
	docs := map[string]any{"leads.json": map[string]any{"leads": []any{map[string]any{"quote": map[string]any{"text": "a‮b"}}}}}
	if got := fieldFindings(docs); len(got) != 1 || !strings.Contains(got[0], "not allowed") {
		t.Fatalf("%v", got)
	}
	docs["leads.json"] = map[string]any{"leads": []any{map[string]any{"quote": map[string]any{"text": "café\nline"}}}}
	if got := fieldFindings(docs); len(got) != 0 {
		t.Fatalf("ordinary upstream quote refused: %v", got)
	}
}

func TestSealUsage(t *testing.T) {
	dir := jobset(t)
	noReceipt(t, dir)
	for _, args := range [][]string{
		{"seal"},
		{"seal", dir}, // no receipt, no flags
		{"seal", "-tool-commit", "abc", "-generated-at", testTime, dir}, // bad commit
		{"seal", "-tool-commit", strings.ToUpper(testCommit), "-generated-at", testTime, dir},
		{"seal", "-tool-commit", testCommit, "-generated-at", "2026-11-17", dir},
		{"seal", "-bogus", dir},
		{"seal", filepath.Join(t.TempDir(), "absent")},
	} {
		var out, errb bytes.Buffer
		if code := Run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: code %d, want 2 (%s)", args, code, errb.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "receipt.json")); err == nil {
		t.Fatal("receipt written despite usage errors")
	}
	var out, errb bytes.Buffer
	if code := Run([]string{"seal", dir, "-x"}, &out, &errb); code != 2 {
		t.Fatalf("flag after DIR: %d", code)
	}
}

func TestSealHelpStatesIntegrityOnly(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"seal", "-h"}, &out, &errb); code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, w := range []string{"INTEGRITY record only", "not provenance", "not the repository", "never writes origin"} {
		if !strings.Contains(out.String(), w) {
			t.Fatalf("help lacks %q", w)
		}
	}
}

func TestRunSealExitCodes(t *testing.T) {
	var out, errb bytes.Buffer
	dir := jobset(t)
	rewrite(t, dir, "project.json", `"line": "0.13"`, `"line": "0.14"`)
	if code := Run([]string{"seal", dir}, &out, &errb); code != 1 || !strings.Contains(out.String(), "changed: project.json") {
		t.Fatalf("stale receipt: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := Run([]string{"seal", "-force-reseal", dir}, &out, &errb); code != 0 {
		t.Fatalf("force: code %d err %q", code, errb.String())
	}
}

// A receipt carries no slug or repo: it only binds file bytes. Replaying a sealed bundle
// into another directory is therefore caught only by the directory/slug rule, which seal
// enforces and "validate --dir-is-slug" (used by CI) enforces; plain validate does not.
func TestReplayedBundleUnderAnotherSlugRefused(t *testing.T) {
	dir := copyBundle(t, jobsetDir, "other-slug")
	mustValidate(t, dir, 0) // plain validate cannot see it (documented)
	var out, errb bytes.Buffer
	if code := Run([]string{"validate", "--dir-is-slug", dir}, &out, &errb); code != 1 {
		t.Fatalf("validate --dir-is-slug accepted a replay: %d", code)
	}
	if _, err := Seal(dir, SealOptions{ForceReseal: true}); err == nil {
		t.Fatal("seal accepted a replay")
	}
}

func TestBundleDigestIsTheValidatorsFunction(t *testing.T) {
	m := map[string]string{"b.json": strings.Repeat("b", 64), "a.json": strings.Repeat("a", 64)}
	// independent vector: sha256("a.json\0" + 64*"a" + "\n" + "b.json\0" + 64*"b" + "\n")
	if got := BundleDigest(m); got != "b536871ff51f51f4413e2c5dde6528afa3b7f9361cb27e6ca798132fc90c170e" {
		t.Fatalf("digest %s", got)
	}
}
