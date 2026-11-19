// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2026-09-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-09-01T00:00:00Z",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func changelogFor(tag string) string { return "# Changes " + tag + "\n\n- item\n" }

// makeClone creates a real clone with one commit per tag (oldest first), a
// CHANGELOG.md and LICENSE in each, plus a file the snapshot never holds.
// It returns the dir and the commit ids in tags order (newest first).
func makeClone(t *testing.T, tags []string, body func(string) string) (string, []string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "clone")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	commits := make([]string, len(tags))
	for i := len(tags) - 1; i >= 0; i-- {
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(body(tags[i])), 0o644))
		must(os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("licence text\n"), 0o644))
		must(os.MkdirAll(filepath.Join(dir, "config"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "config", "other.yaml"), []byte("kind: X "+tags[i]+"\n"), 0o644))
		git(t, dir, "add", "-A")
		git(t, dir, "commit", "-q", "-m", "release "+tags[i])
		git(t, dir, "tag", tags[i])
		commits[i] = git(t, dir, "rev-parse", "HEAD")
	}
	return dir, commits
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func cloneAndSnapshot(t *testing.T) (snap, clone string) {
	t.Helper()
	clone, commits := makeClone(t, threeTags, changelogFor)
	snap = makeSnapshot(t, fixtureOpts{tags: threeTags, commits: commits})
	return snap, clone
}

func withCheckout(o BuildOptions, clone string, scan ...string) BuildOptions {
	o.Checkout, o.ScanPaths = clone, scan
	return o
}

func TestCheckoutEvidenceComesFromSnapshotBlobs(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	out := outDir(t)
	mustBuild(t, withCheckout(baseOpts(snap, out), clone, "CHANGELOG.md:copy:changelog per tag", "LICENSE:other"))
	assertValid(t, out)
	sn := readJSON(t, out, "scan-notes.json")
	entries := sn["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries %v", entries)
	}
	cl := entries[0].(map[string]any)
	if cl["path"] != "CHANGELOG.md" || cl["class"] != "copy" || cl["note"] != "changelog per tag" {
		t.Fatalf("entry %v", cl)
	}
	ev := cl["evidence"].([]any)
	if len(ev) == 0 {
		t.Fatal("no evidence")
	}
	for _, x := range ev {
		e := x.(map[string]any)
		if e["sha256"] != shaHex(changelogFor(e["tag"].(string))) {
			t.Fatalf("evidence %v does not hash the blob", e)
		}
	}
	// the same digests appear in the snapshot-derived relnotes rows
	if td := readJSON(t, out, "target-draft.json"); td["status"] != "no-crds" {
		t.Fatalf("status %v", td["status"])
	}
}

func TestCheckoutRefusesPathsTheSnapshotHoldsNoBlobFor(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	for _, sp := range []string{
		"config/other.yaml:copy",  // committed in the clone, but not a snapshot blob
		"README.md:copy",          // not in the clone at all
		"../CHANGELOG.md:copy",    // dot segment
		"/etc/passwd:copy",        // absolute
		"config/*.yaml:copy",      // glob
		"CHANGELOG.md:bogus",      // class not in the schema
		"CHANGELOG.md:copy:a\\b",  // note charset
		"CHANGELOG.md:copy:a<b>",  // note charset
		"CHANGELOG.md",            // no class
		"config//other.yaml:copy", // empty segment
		"config/:copy",            // trailing slash
		"CHANGELOG.md:copy:" + strings.Repeat("a", 301),
	} {
		out := outDir(t)
		if _, err := Build(withCheckout(baseOpts(snap, out), clone, sp)); err == nil {
			t.Fatalf("%q accepted", sp)
		}
		noOutput(t, out)
	}
	// duplicate path
	out := outDir(t)
	if _, err := Build(withCheckout(baseOpts(snap, out), clone, "CHANGELOG.md:copy", "CHANGELOG.md:extra")); err == nil {
		t.Fatal("duplicate accepted")
	}
	noOutput(t, out)
	// too many
	var many []string
	for i := 0; i < maxScanPaths+1; i++ {
		many = append(many, fmt.Sprintf("d%d/CHANGELOG.md:copy", i))
	}
	out = outDir(t)
	if _, err := Build(withCheckout(baseOpts(snap, out), clone, many...)); err == nil {
		t.Fatal("too many accepted")
	}
	noOutput(t, out)
}

func TestCheckoutNeedsBothFlags(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	out := outDir(t)
	o := baseOpts(snap, out)
	o.ScanPaths = []string{"CHANGELOG.md:copy"}
	if _, err := Build(o); err == nil {
		t.Fatal("--scan-path without --checkout accepted")
	}
	noOutput(t, out)
	if _, err := Build(withCheckout(baseOpts(snap, out), clone)); err == nil {
		t.Fatal("--checkout without --scan-path accepted")
	}
	noOutput(t, out)
}

func TestCheckoutReadsObjectsNotTheWorkingTree(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	if err := os.WriteFile(filepath.Join(clone, "CHANGELOG.md"), []byte("edited after the tag\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(clone, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	out := outDir(t)
	mustBuild(t, withCheckout(baseOpts(snap, out), clone, "CHANGELOG.md:copy", "LICENSE:other"))
	assertValid(t, out)
}

func TestCheckoutRefusesMismatchedClone(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)

	// a tag moved to another commit
	git(t, clone, "commit", "-q", "--allow-empty", "-m", "later")
	git(t, clone, "tag", "-f", "v0.12.0")
	out := outDir(t)
	if _, err := Build(withCheckout(baseOpts(snap, out), clone, "CHANGELOG.md:copy")); err == nil {
		t.Fatal("moved tag accepted")
	}
	noOutput(t, out)

	// a clone that lacks the snapshot commits
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, other, "init", "-q")
	out = outDir(t)
	if _, err := Build(withCheckout(baseOpts(snap, out), other, "CHANGELOG.md:copy")); err == nil {
		t.Fatal("clone without the commits accepted")
	}
	noOutput(t, out)

	// same commits, but the blob differs from what the snapshot recorded
	altClone, commits := makeClone(t, threeTags, func(tag string) string { return "different " + tag + "\n" })
	altSnap := makeSnapshot(t, fixtureOpts{tags: threeTags, commits: commits, logBody: changelogFor})
	out = outDir(t)
	if _, err := Build(withCheckout(baseOpts(altSnap, out), altClone, "CHANGELOG.md:copy")); err == nil || !strings.Contains(err.Error(), "differs from the snapshot") {
		t.Fatalf("blob mismatch: %v", err)
	}
	noOutput(t, out)
}

func TestCheckoutRefusesNonCloneInputs(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(clone, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	os.WriteFile(file, []byte("x"), 0o644)
	sub := filepath.Join(clone, "config") // inside a repo, not its root
	for _, c := range []string{link, file, filepath.Join(base, "missing"), sub} {
		out := outDir(t)
		if _, err := Build(withCheckout(baseOpts(snap, out), c, "CHANGELOG.md:copy")); err == nil {
			t.Fatalf("%s accepted", c)
		}
		noOutput(t, out)
	}
}

func TestCheckoutIgnoresCloneConfigAndReplaceRefs(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	// a config key that would run a program if git consulted it for cat-file
	git(t, clone, "config", "core.fsmonitor", "touch "+filepath.Join(filepath.Dir(clone), "ran"))
	out := outDir(t)
	mustBuild(t, withCheckout(baseOpts(snap, out), clone, "CHANGELOG.md:copy"))
	if _, err := os.Stat(filepath.Join(filepath.Dir(clone), "ran")); err == nil {
		t.Fatal("clone config was executed")
	}
}

// ---- target input ----

func writeInput(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodInput = `{
  "name": "Sample",
  "component": "pkg:github/acme/sample",
  "factProject": "sample",
  "paths": [{"path": "config/crd", "directory": true, "match": "\\.yaml$"}],
  "exclude": [{"path": "vendor/crd", "repo": "github.com/other/lib", "reason": "copied from the library", "evidence": "the files under vendor/crd are byte copies of the library files"}],
  "copiesEvidence": [{"path": "vendor/crd", "comparedWith": "config/crd", "tags": ["v0.13.0"], "note": "compared at the newest tag"}]
}`

func TestTargetInputShapesSkeletonNeverFilled(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.TargetInput = writeInput(t, goodInput)
	o.NoCRDs = false
	res := mustBuild(t, o)
	assertValid(t, out)
	td := readJSON(t, out, "target-draft.json")
	if td["status"] != "skeleton" {
		t.Fatalf("status %v: a target input must never fill", td["status"])
	}
	tg := td["target"].(map[string]any)
	if tg["name"] != "Sample" || len(tg["paths"].([]any)) != 1 || len(tg["exclude"].([]any)) != 1 || len(td["copiesEvidence"].([]any)) != 1 {
		t.Fatalf("hint not applied: %v", td)
	}
	for _, name := range []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
		raw, _ := os.ReadFile(filepath.Join(out, name))
		if strings.Contains(string(raw), "filled") {
			t.Fatalf("%s mentions filled", name)
		}
	}
	rc := readJSON(t, out, "receipt.json")
	if rc["checks"].(map[string]any)["targetCheckOffline"] != "pass" {
		t.Fatalf("checks %v", rc["checks"])
	}
	joined := strings.Join(res.Notes, "\n")
	if !strings.Contains(joined, "offline target check: pass") || !strings.Contains(joined, "status stays skeleton") {
		t.Fatalf("notes %q", joined)
	}
}

func TestTargetInputCannotRequestStatusOrIdentity(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	for _, key := range []string{"status", "origin", "simulated", "project", "repo", "tagPrefixes", "minFrom", "target", "attest", "schema", "kind"} {
		out := outDir(t)
		o := baseOpts(snap, out)
		o.TargetInput = writeInput(t, fmt.Sprintf(`{"%s": "filled", "paths": [{"path": "config/crd"}]}`, key))
		o.NoCRDs = false
		if _, err := Build(o); err == nil {
			t.Fatalf("key %s accepted", key)
		}
		noOutput(t, out)
	}
	out := outDir(t)
	o := baseOpts(snap, out)
	o.NoCRDs = true
	o.TargetInput = writeInput(t, goodInput)
	if _, err := Build(o); err == nil {
		t.Fatal("--no-crds with --target-input accepted")
	}
	noOutput(t, out)
}

func TestTargetInputCapsAndCharset(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	long := func(n int) string { return strings.Repeat("a", n) }
	var many []string
	for i := 0; i < maxTargetListItems+1; i++ {
		many = append(many, fmt.Sprintf(`{"path":"d%d"}`, i))
	}
	cases := map[string]string{
		"not json":          `nope`,
		"array":             `[]`,
		"duplicate key":     `{"paths": [], "paths": []}`,
		"trailing data":     `{"paths": []} {}`,
		"oversize":          `{"name": "` + strings.Repeat("a", maxTargetInput) + `"}`,
		"too many paths":    `{"paths": [` + strings.Join(many, ",") + `]}`,
		"name angle":        `{"name": "a<b", "paths": [{"path": "x"}]}`,
		"name too long":     `{"name": "` + long(101) + `", "paths": [{"path": "x"}]}`,
		"name unicode":      `{"name": "café", "paths": [{"path": "x"}]}`,
		"component":         `{"component": "pkg:npm/x/y", "paths": [{"path": "x"}]}`,
		"factProject":       `{"factProject": "Bad-Name", "paths": [{"path": "x"}]}`,
		"path dotdot":       `{"paths": [{"path": "../x"}]}`,
		"path absolute":     `{"paths": [{"path": "/etc/x"}]}`,
		"path glob":         `{"paths": [{"path": "a/*.yaml"}]}`,
		"path unknown key":  `{"paths": [{"path": "x", "origin": "y"}]}`,
		"match control":     `{"paths": [{"path": "x", "match": "a\u0001b"}]}`,
		"match too long":    `{"paths": [{"path": "x", "match": "` + long(201) + `"}]}`,
		"directory string":  `{"paths": [{"path": "x", "directory": "yes"}]}`,
		"reason short":      `{"paths": [{"path": "x"}], "exclude": [{"path": "y", "repo": "github.com/a/b", "reason": "short", "evidence": "` + long(40) + `"}]}`,
		"evidence backtick": `{"paths": [{"path": "x"}], "exclude": [{"path": "y", "repo": "github.com/a/b", "reason": "` + long(12) + `", "evidence": "` + long(39) + "`" + `"}]}`,
		"evidence long":     `{"paths": [{"path": "x"}], "exclude": [{"path": "y", "repo": "github.com/a/b", "reason": "` + long(12) + `", "evidence": "` + long(801) + `"}]}`,
		"exclude repo":      `{"paths": [{"path": "x"}], "exclude": [{"path": "y", "repo": "gitlab.com/a/b", "reason": "` + long(12) + `", "evidence": "` + long(40) + `"}]}`,
		"copies note":       `{"paths": [{"path": "x"}], "copiesEvidence": [{"path": "x", "comparedWith": "y", "tags": ["v0.13.0"], "note": "a\\b"}]}`,
		"copies tags":       `{"paths": [{"path": "x"}], "copiesEvidence": [{"path": "x", "comparedWith": "y", "tags": ["bad tag"], "note": ""}]}`,
		"secret value":      `{"name": "ghp_` + long(24) + `", "paths": [{"path": "x"}]}`,
		"home path value":   `{"paths": [{"path": "x", "guard": "/home/alice/x"}]}`,
		"internal address":  `{"paths": [{"path": "x", "match": "10.1.2.3"}]}`,
	}
	for name, body := range cases {
		out := outDir(t)
		o := baseOpts(snap, out)
		o.TargetInput = writeInput(t, body)
		o.NoCRDs = false
		if _, err := Build(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
		noOutput(t, out)
	}
	// missing file and symlinked file
	out := outDir(t)
	o := baseOpts(snap, out)
	o.TargetInput = filepath.Join(t.TempDir(), "missing.json")
	o.NoCRDs = false
	if _, err := Build(o); err == nil {
		t.Error("missing file accepted")
	}
	noOutput(t, out)
	real := writeInput(t, goodInput)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	o.TargetInput = link
	o.NoCRDs = false
	if _, err := Build(o); err == nil {
		t.Error("symlinked file accepted")
	}
	noOutput(t, out)
}

func TestOfflineTargetCheckPassAndFail(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	cases := []struct {
		name, body, want, reason string
	}{
		{"pass", `{"paths": [{"path": "config/crd", "directory": true}]}`, "pass", ""},
		{"duplicate path", `{"paths": [{"path": "a"}, {"path": "a"}]}`, "fail", "path a declared twice"},
		{"changelog is not a target path", `{"paths": [{"path": "CHANGELOG.md"}]}`, "fail", "changelog or licence file"},
		{"licence is not a target path", `{"paths": [{"path": "LICENSE"}]}`, "fail", "changelog or licence file"},
		{"overlap with exclusion", `{"paths": [{"path": "config"}], "exclude": [{"path": "config/vendor", "repo": "github.com/acme/sample", "reason": "vendored copy here", "evidence": "the vendored directory is a byte copy of upstream files"}]}`, "fail", "overlaps the exclusion"},
		{"exclusion elsewhere does not overlap", `{"paths": [{"path": "config"}], "exclude": [{"path": "config", "repo": "github.com/other/lib", "reason": "vendored copy there", "evidence": "the other repository holds the same directory as a copy"}]}`, "pass", ""},
		{"copies path undeclared", `{"paths": [{"path": "a"}], "copiesEvidence": [{"path": "z", "comparedWith": "a", "tags": ["v0.13.0"], "note": ""}]}`, "fail", "neither a declared path nor an exclusion"},
		{"copies tag not built", `{"paths": [{"path": "a"}], "copiesEvidence": [{"path": "a", "comparedWith": "b", "tags": ["v9.9.9"], "note": ""}]}`, "fail", "not a built release tag"},
		{"copies no tag", `{"paths": [{"path": "a"}], "copiesEvidence": [{"path": "a", "comparedWith": "b", "tags": [], "note": ""}]}`, "fail", "names no tag"},
	}
	for _, c := range cases {
		out := outDir(t)
		o := baseOpts(snap, out)
		o.TargetInput = writeInput(t, c.body)
		o.NoCRDs = false
		res, err := Build(o)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		assertValid(t, out)
		rc := readJSON(t, out, "receipt.json")
		if got := rc["checks"].(map[string]any)["targetCheckOffline"]; got != c.want {
			t.Errorf("%s: receipt %v, want %s", c.name, got, c.want)
		}
		if td := readJSON(t, out, "target-draft.json"); td["status"] != "skeleton" {
			t.Errorf("%s: status %v", c.name, td["status"])
		}
		if res.CheckFailed != (c.want == "fail") {
			t.Errorf("%s: CheckFailed=%v", c.name, res.CheckFailed)
		}
		joined := strings.Join(res.Notes, "\n")
		if c.want == "pass" && strings.Contains(joined, "check: fail") {
			t.Errorf("%s: notes %q", c.name, joined)
		}
		if c.want == "fail" && (!strings.Contains(joined, "check: fail") || !strings.Contains(joined, c.reason)) {
			t.Errorf("%s: reason %q missing from %q", c.name, c.reason, joined)
		}
	}
}

func TestOfflineTargetCheckNotRunWithoutInput(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.NoCRDs = true
	mustBuild(t, o)
	rc := readJSON(t, out, "receipt.json")
	if got := rc["checks"].(map[string]any)["targetCheckOffline"]; got != "not-run" {
		t.Fatalf("%v, want not-run", got)
	}
}

func TestOfflineCheckResultDoesNotSurviveEditsOrAreForgedByValidate(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.TargetInput = writeInput(t, goodInput)
	o.NoCRDs = false
	mustBuild(t, o)
	// edit the draft, then re-seal: the stale "pass" must reset to not-run
	p := filepath.Join(out, "target-draft.json")
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(raw, []byte(`"Sample"`), []byte(`"Sample 2"`), 1), 0o644)
	if _, err := Seal(out, SealOptions{ForceReseal: true}); err != nil {
		t.Fatal(err)
	}
	rc := readJSON(t, out, "receipt.json")
	if got := rc["checks"].(map[string]any)["targetCheckOffline"]; got != "not-run" {
		t.Fatalf("stale result kept: %v", got)
	}
}

func TestSealRejectsUnknownTargetCheckValue(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	mustBuild(t, baseOpts(snap, out))
	if _, err := Seal(out, SealOptions{TargetCheck: "filled"}); err == nil {
		t.Fatal("unknown target check value accepted")
	}
}

func TestCheckoutAndTargetInputBuildIsReproducible(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	in := writeInput(t, goodInput)
	a, b := outDir(t), outDir(t)
	for _, out := range []string{a, b} {
		o := withCheckout(baseOpts(snap, out), clone, "LICENSE:other", "CHANGELOG.md:copy:per tag")
		o.TargetInput = in
		o.NoCRDs = false
		mustBuild(t, o)
		assertValid(t, out)
	}
	for _, name := range []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
		x, _ := os.ReadFile(filepath.Join(a, name))
		y, _ := os.ReadFile(filepath.Join(b, name))
		if len(x) == 0 || !bytes.Equal(x, y) {
			t.Fatalf("%s differs between two builds", name)
		}
	}
	// scan-path order does not matter
	c := outDir(t)
	o := withCheckout(baseOpts(snap, c), clone, "CHANGELOG.md:copy:per tag", "LICENSE:other")
	o.TargetInput = in
	o.NoCRDs = false
	mustBuild(t, o)
	x, _ := os.ReadFile(filepath.Join(a, "scan-notes.json"))
	y, _ := os.ReadFile(filepath.Join(c, "scan-notes.json"))
	if !bytes.Equal(x, y) {
		t.Fatal("scan-path order changed the output")
	}
}

func TestRunWiresCheckoutAndTargetInputFlags(t *testing.T) {
	snap, clone := cloneAndSnapshot(t)
	out := outDir(t)
	in := writeInput(t, goodInput)
	args := []string{"build", "-snapshot", snap, "-slug", "sample", "-spdx", "Apache-2.0", "-out", out, "-post-tag", "CHANGELOG.md",
		"-checkout", clone, "-scan-path", "CHANGELOG.md:copy", "-target-input", in}
	var so, se bytes.Buffer
	if c := Run(args, &so, &se); c != 0 {
		t.Fatalf("exit %d: %s", c, se.String())
	}
	assertValid(t, out)
	if !strings.Contains(so.String(), "offline target check: pass") {
		t.Fatalf("stdout %q", so.String())
	}
	// refusal exits 1 and writes nothing
	out2 := outDir(t)
	args = []string{"build", "-snapshot", snap, "-slug", "sample", "-spdx", "Apache-2.0", "-out", out2, "-post-tag", "CHANGELOG.md",
		"-checkout", clone, "-scan-path", "config/other.yaml:copy"}
	so.Reset()
	se.Reset()
	if c := Run(args, &so, &se); c != 1 {
		t.Fatalf("exit %d, want 1", c)
	}
	noOutput(t, out2)
}

func TestBuildHelpDescribesCheckoutAndOfflineCheck(t *testing.T) {
	for _, w := range []string{"-checkout", "-scan-path", "-target-input", "never fetched", "SNAPSHOT already holds", "stays skeleton", "does not verify anything upstream", "coverage comes only from"} {
		if !strings.Contains(buildHelp, w) {
			t.Errorf("help lacks %q", w)
		}
	}
}

func TestRunExitsOneOnFailedOfflineCheckButWritesBundle(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	in := writeInput(t, `{"paths": [{"path": "LICENSE"}]}`)
	var so, se bytes.Buffer
	args := []string{"build", "-snapshot", snap, "-slug", "sample", "-spdx", "Apache-2.0", "-out", out, "-post-tag", "CHANGELOG.md", "-target-input", in}
	if c := Run(args, &so, &se); c != 1 {
		t.Fatalf("exit %d, want 1", c)
	}
	if !strings.Contains(so.String(), "changelog or licence file") || !strings.Contains(se.String(), "not ready to submit") {
		t.Fatalf("stdout %q stderr %q", so.String(), se.String())
	}
	assertValid(t, out)
	rc := readJSON(t, out, "receipt.json")
	if rc["checks"].(map[string]any)["targetCheckOffline"] != "fail" {
		t.Fatalf("receipt %v", rc["checks"])
	}
}

func TestBuildRequiresExplicitCRDDeclaration(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.NoCRDs = false
	_, err := Build(o)
	if err == nil || !strings.Contains(err.Error(), "no CRD paths found: pass --no-crds if the project ships no CustomResourceDefinitions, or --target-input with its CRD paths") {
		t.Fatalf("no paths and no flag: %v", err)
	}
	noOutput(t, out)

	o.NoCRDs = true
	mustBuild(t, o)
	if td := readJSON(t, out, "target-draft.json"); td["status"] != "no-crds" {
		t.Fatalf("status %v", td["status"])
	}

	out2 := outDir(t)
	o = baseOpts(snap, out2)
	o.TargetInput = writeInput(t, goodInput)
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Fatalf("--no-crds with paths: %v", err)
	}
	noOutput(t, out2)
}

func TestTagPrefixIgnoresOtherTagsInDefaultWindow(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: []string{"v0.13.0", "chart-0.13.0", "v0.12.0", "chart-0.12.0"}})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.TagPrefix = "v"
	res := mustBuild(t, o)
	if n := strings.Join(res.Notes, "\n"); !strings.Contains(n, "2 tags outside --tag-prefix \"v\" ignored (first: ") {
		t.Fatalf("notes: %q", n)
	}
	ents := readJSON(t, out, "scan-notes.json")["entries"].([]any)
	if len(ents) != 1 {
		t.Fatalf("scan-notes entries: %v", ents)
	}
	if e := ents[0].(map[string]any); e["class"] != "other" || e["path"] != "tags-outside-tag-prefix" || e["note"] != `2 tags outside --tag-prefix "v" ignored (first: chart-0.12.0, chart-0.13.0)` {
		t.Fatalf("scan-notes entry: %v", e)
	}
	assertValid(t, out)
	p := readJSON(t, out, "project.json")
	if p["tagPrefix"] != "v" || len(p["releaseLines"].([]any)) != 2 {
		t.Fatalf("project: %v", p)
	}
	o = baseOpts(snap, outDir(t))
	o.TagPrefix = "v"
	o.Tags = []string{"v0.13.0", "chart-0.12.0"}
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "drop that tag from --tags") {
		t.Fatalf("explicit conflicting tags: %v", err)
	}
}

func TestIgnoredTagNamesAreSortedBeforeCap(t *testing.T) {
	tags := []string{"v0.13.0", "chart-7", "chart-3", "chart-1", "chart-6", "chart-2", "chart-5", "chart-4", "v0.12.0"}
	snap := makeSnapshot(t, fixtureOpts{tags: tags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.TagPrefix = "v"
	mustBuild(t, o)
	ents := readJSON(t, out, "scan-notes.json")["entries"].([]any)
	if got := ents[0].(map[string]any)["note"]; got != `7 tags outside --tag-prefix "v" ignored (first: chart-1, chart-2, chart-3, chart-4, chart-5)` {
		t.Fatalf("note: %v", got)
	}
}
