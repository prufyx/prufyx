// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// componentsEntryFile is a valid components file with one entry, the
// reviewed fixture of the catalog package.
func componentsEntryFile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "cli/internal/cncfcheck/testdata/landscape-components-alertmanager.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newComponentsFixture(t *testing.T, headContent []byte) gatePathFixture {
	t.Helper()
	base, head := trees(t)
	f := gatePathFixture{signFixture: pinFixture(t, base, head, "unused"), file: cncfComponentsPath}
	f.write(t, f.head, string(headContent))
	return f
}

func TestComponentsFileIsGateAndRegistryPath(t *testing.T) {
	t.Parallel()
	l := DefaultLayout()
	if !l.gatePath(cncfComponentsPath) {
		t.Error("the components file is not a gate path")
	}
	found := false
	for _, p := range l.RegistryPaths {
		found = found || p == cncfComponentsPath
	}
	if !found {
		t.Error("the components file is not a registry path")
	}
}

// A change of the components file is refused without an owner approval and
// admitted with one that binds its exact bytes.
func TestComponentsChangeNeedsOwnerApproval(t *testing.T) {
	t.Parallel()
	f := newComponentsFixture(t, componentsEntryFile(t))
	requireGatePathFail(t, f.run(t, "pr-42"))
	f.sign(t, "pr-42")
	requirePass(t, f.run(t, "pr-42"))
	// The approval binds the exact bytes: an edit afterwards is refused.
	f.write(t, f.head, strings.Replace(string(componentsEntryFile(t)), "alertmanager\"", "alertmanager\" ", 1))
	requireGatePathFail(t, f.run(t, "pr-42"))
}

// An approval does not admit a file the catalog checks refuse: the pack is
// admitted from the tree's own components file.
func TestComponentsInvalidRefusedEvenWithApproval(t *testing.T) {
	t.Parallel()
	good := string(componentsEntryFile(t))
	for name, content := range map[string]string{
		"source host":     strings.Replace(good, "https://github.com/prometheus/alertmanager", "https://example.com/prometheus/alertmanager", 1),
		"unknown project": strings.Replace(good, `"prometheus",`, `"no-such-project",`, 1),
		"not json":        "{}x",
		"wrong landscape": strings.Replace(good, "8ee4c10a", "00000000", 1),
	} {
		t.Run(name, func(t *testing.T) {
			f := newComponentsFixture(t, []byte(content))
			f.sign(t, "pr-42")
			requireFail(t, f.run(t, "pr-42"), "admit/cncf")
		})
	}
}

// The gate fails closed when the tree has no components file.
func TestComponentsMissingRefused(t *testing.T) {
	t.Parallel()
	f := newComponentsFixture(t, componentsEntryFile(t))
	if err := os.Remove(filepath.Join(f.head.Root, filepath.FromSlash(cncfComponentsPath))); err != nil {
		t.Fatal(err)
	}
	f.sign(t, "pr-42")
	requireFail(t, f.run(t, "pr-42"), "admit/cncf")
}

// The file moved elsewhere is a delete and an add: refused, even approved.
func TestComponentsRenameRefused(t *testing.T) {
	t.Parallel()
	f := newComponentsFixture(t, componentsEntryFile(t))
	moved := filepath.Join(f.head.Root, "cli/internal/cncfcheck/data/landscape-components-moved.json")
	if err := os.Rename(filepath.Join(f.head.Root, filepath.FromSlash(cncfComponentsPath)), moved); err != nil {
		t.Fatal(err)
	}
	requireGatePathFail(t, f.run(t, "pr-42"))
	f.sign(t, "pr-42")
	requireFail(t, f.run(t, "pr-42"), "admit/cncf")
}

// A symlink in place of the components file is refused, even approved.
func TestComponentsSymlinkRefused(t *testing.T) {
	t.Parallel()
	f := newComponentsFixture(t, componentsEntryFile(t))
	p := filepath.Join(f.head.Root, filepath.FromSlash(cncfComponentsPath))
	other := filepath.Join(f.head.Root, "elsewhere.json")
	if err := os.WriteFile(other, componentsEntryFile(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, p); err != nil {
		t.Skip("symlinks unavailable")
	}
	// The owner tool refuses to sign a non-regular file, and the gate
	// refuses the change without an approval.
	args := append(f.gateArgs("sign", "pr-42"), "--identity", "airstand", "--output", f.approvalFile("pr-42"))
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, append(args, "--key-stdin")...), 2, "not a regular file")
	if f.run(t, "pr-42").Passed() {
		t.Fatal("gate passed with a symlinked components file")
	}
}

// A directory in place of the components file is refused.
func TestComponentsDirectoryRefused(t *testing.T) {
	t.Parallel()
	f := newComponentsFixture(t, componentsEntryFile(t))
	p := filepath.Join(f.head.Root, filepath.FromSlash(cncfComponentsPath))
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if f.run(t, "pr-42").Passed() {
		t.Fatal("gate passed with a directory as the components file")
	}
}

// The README report is computed with the tree's own attributed components,
// and refuses a tree whose components file is invalid.
func TestCoverageReportCountsTreeComponents(t *testing.T) {
	t.Parallel()
	tr := copyKnowledge(t)
	report, _, _, err := coverageReportOf(tr, defaultTablePath)
	if err != nil {
		t.Fatal(err)
	}
	if report.ExtraComponents != 0 {
		t.Fatalf("extraComponents = %d at zero entries", report.ExtraComponents)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(cncfComponentsPath)), componentsEntryFile(t))
	report, _, _, err = coverageReportOf(tr, defaultTablePath)
	if err != nil {
		t.Fatal(err)
	}
	if report.ExtraComponents != 1 {
		t.Fatalf("extraComponents = %d, want 1", report.ExtraComponents)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(cncfComponentsPath)), []byte("{}x"))
	if _, _, _, err = coverageReportOf(tr, defaultTablePath); err == nil {
		t.Fatal("an invalid components file was accepted")
	}
}
