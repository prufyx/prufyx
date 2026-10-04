// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// notLocal serves a fixture but reports some files as not held locally, as
// a mirror cloned without file contents does.
type notLocal struct {
	extract.FixtureReader
	paths map[string]bool
}

func (n notLocal) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if n.paths[commit+":"+p] {
		return nil, factorymirror.ErrBlobNotLocal
	}
	return n.FixtureReader.Read(repo, commit, p)
}

func withMissing(t *testing.T, root string, paths ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	old := openSource
	openSource = func(s *sourceFlags) (extract.PinnedReader, extract.TagSource, History, error) {
		f := extract.FixtureReader{Root: root}
		return notLocal{f, set}, f, FixtureHistory{Root: root}, nil
	}
	t.Cleanup(func() { openSource = old })
}

func run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeBundle(t *testing.T, b *Bundle) string {
	t.Helper()
	raw, err := extract.Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "claims.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConsensusCommands(t *testing.T) {
	root := fixtureWith(t, notes(silentDial+"\n- Removed the OldPortal feature gate. "+prLink("140002")))
	work := t.TempDir()

	// normalise writes the source object a bundle pins, byte for byte.
	out := filepath.Join(work, "norm")
	code, stdout, stderr := run("normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", toCommit, "--path", changelogAt, "--section", toTag, "--out", out)
	if code != ExitOK || !strings.Contains(stdout, "normalised "+changelogAt) {
		t.Fatalf("normalise: %d %s %s", code, stdout, stderr)
	}
	sourceJSON, _ := os.ReadFile(filepath.Join(out, "source.json"))
	want, _ := extract.Canonical(honestBundle(t, root, nil).Source)
	if !bytes.Equal(sourceJSON, want) {
		t.Fatalf("source.json:\n%s\nwant:\n%s", sourceJSON, want)
	}
	text, _ := os.ReadFile(filepath.Join(out, "normalised.txt"))
	lineMap, _ := os.ReadFile(filepath.Join(out, "linemap.json"))
	if !strings.HasPrefix(string(text), "## Changes by Kind\n") || !strings.Contains(string(lineMap), `"normalised": 1`) {
		t.Fatalf("outputs:\n%s\n%s", text, lineMap)
	}
	// Run again: the same bytes.
	if code, _, _ := run("normalise", "--fixture", root, "--repo", "github.com/kubernetes/kubernetes", "--commit", toCommit, "--path", changelogAt, "--section", toTag, "--out", out); code != ExitOK {
		t.Fatal("second normalise")
	}
	again, _ := os.ReadFile(filepath.Join(out, "linemap.json"))
	if !bytes.Equal(again, lineMap) {
		t.Fatal("line map not stable")
	}

	// verify: 0 when every claim verifies, 4 when one does not.
	all := writeBundle(t, honestBundle(t, root, []Claim{
		{ID: "a", Kind: "removed_feature_gate", Names: []string{"SilentDial"}},
		{ID: "b", Kind: "removed_feature_gate", Names: []string{"OldPortal"}},
	}))
	report := filepath.Join(work, "report.json")
	code, stdout, stderr = run("verify", "--claims", all, "--fixture", root, "--out", report)
	if code != ExitOK || stdout != "2 verified, 0 lead, 0 dropped\n" {
		t.Fatalf("verify: %d %q %s", code, stdout, stderr)
	}
	first, _ := os.ReadFile(report)
	run("verify", "--claims", all, "--fixture", root, "--out", report)
	if second, _ := os.ReadFile(report); !bytes.Equal(first, second) {
		t.Fatal("report not stable")
	}
	var parsed Report
	if err := json.Unmarshal(first, &parsed); err != nil || parsed.Schema != ReportSchema || len(parsed.Claims) != 2 {
		t.Fatalf("report: %v %s", err, first)
	}
	mixed := writeBundle(t, honestBundle(t, root, []Claim{
		{ID: "a", Kind: "removed_feature_gate", Names: []string{"SilentDial"}},
		{ID: "b", Kind: "removed_feature_gate", Names: []string{"GhostGate"}},
	}))
	if code, stdout, _ := run("verify", "--claims", mixed, "--fixture", root, "--out", report); code != ExitNotVerified || stdout != "1 verified, 0 lead, 1 dropped\n" {
		t.Fatalf("mixed: %d %q", code, stdout)
	}

	// 3: a file the mirror does not hold. No report; the wants file names
	// every missing file.
	os.Remove(report)
	withMissing(t, root, fromCommit+":pkg/features/kube_features.go", toCommit+":api/openapi-spec/swagger.json")
	wants := filepath.Join(work, "wants.json")
	code, _, stderr = run("verify", "--claims", all, "--fixture", root, "--out", report, "--wants-out", wants)
	if code != ExitIncomplete || !strings.Contains(stderr, "incomplete: 1 file(s)") {
		t.Fatalf("missing blob: %d %s", code, stderr)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatal("a report was written for incomplete inputs")
	}
	raw, _ := os.ReadFile(wants)
	var w struct {
		Wants []factorymirror.Want `json:"wants"`
	}
	if err := json.Unmarshal(raw, &w); err != nil || len(w.Wants) != 1 || w.Wants[0].Commit != fromCommit || w.Wants[0].Paths[0] != "pkg/features/kube_features.go" {
		t.Fatalf("wants: %v %s", err, raw)
	}
	// The source file itself missing: also 3, for both commands.
	withMissing(t, root, toCommit+":"+changelogAt)
	if code, _, _ := run("verify", "--claims", all, "--fixture", root, "--out", report, "--wants-out", wants); code != ExitIncomplete {
		t.Fatalf("missing source: %d", code)
	}
	code, _, _ = run("normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", toCommit, "--path", changelogAt, "--section", toTag, "--out", filepath.Join(work, "n2"), "--wants-out", wants)
	raw, _ = os.ReadFile(wants)
	if code != ExitIncomplete || !strings.Contains(string(raw), changelogAt) {
		t.Fatalf("normalise missing source: %d %s", code, raw)
	}
	openSource = defaultOpenSource

	// 3: a tag the source does not record.
	b := honestBundle(t, root, gateClaim("SilentDial"))
	os.WriteFile(filepath.Join(root, "github.com", "kubernetes", "kubernetes", "tags.json"), []byte(`{"v1.40.0": "`+fromCommit+`"}`), 0o644)
	if code, _, stderr := run("verify", "--claims", writeBundle(t, b), "--fixture", root, "--out", report); code != ExitIncomplete {
		t.Fatalf("missing tag: %d %s", code, stderr)
	}

	// 2: misuse and refused input.
	badBundle := filepath.Join(work, "bad.json")
	os.WriteFile(badBundle, []byte(`{"schema":"`+BundleSchema+`","quote":"x"}`), 0o644)
	for name, args := range map[string][]string{
		"no command":           {},
		"unknown command":      {"publish"},
		"both sources":         {"verify", "--claims", all, "--fixture", root, "--mirror-state", root, "--out", report},
		"no source":            {"verify", "--claims", all, "--out", report},
		"no claims":            {"verify", "--fixture", root, "--out", report},
		"missing claims file":  {"verify", "--claims", filepath.Join(work, "none.json"), "--fixture", root, "--out", report},
		"unknown bundle field": {"verify", "--claims", badBundle, "--fixture", root, "--out", report},
		"extra argument":       {"verify", "--claims", all, "--fixture", root, "--out", report, "x"},
		"short commit":         {"normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", "abc", "--path", changelogAt, "--section", toTag, "--out", out},
		"no section rule":      {"normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", toCommit, "--path", changelogAt, "--section", "v1.40.0", "--out", out},
		"missing path":         {"normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", toCommit, "--path", "CHANGELOG/none.md", "--section", toTag, "--out", out},
		"normalise no out":     {"normalise", "--fixture", root, "--repo", "kubernetes/kubernetes", "--commit", toCommit, "--path", changelogAt, "--section", toTag},
	} {
		if code, _, _ := run(args...); code != ExitMisuse {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	if code, stdout, _ := run("help"); code != ExitOK || stdout != Usage+"\n" {
		t.Fatalf("help: %d %q", code, stdout)
	}
}
