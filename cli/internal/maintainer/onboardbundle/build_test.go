// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/projectonboarding"
)

type fixtureOpts struct {
	tags      []string // newest first
	exact     bool     // v2 exact-tag snapshot
	noLicence bool
	noLog     bool
	extra     string                  // second changelog-path source, e.g. a chart file
	commits   []string                // real commit ids per tag; default fixCommit
	logBody   func(tag string) string // upstream CHANGELOG bytes; default fixed text
}

func (o fixtureOpts) cid(i int) string {
	if o.commits != nil {
		return o.commits[i]
	}
	return fixCommit(i)
}

func fixCommit(i int) string { return fmt.Sprintf("%02x%038x", i+10, 0xabc) }

func fixtureFetcher(o fixtureOpts) projectonboarding.Fetcher {
	return projectonboarding.FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
		const base = "/repos/acme/sample"
		if host == "api.github.com" {
			switch {
			case path == base:
				return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`), 200, nil
			case strings.HasPrefix(path, base+"/releases?"):
				var rels []map[string]any
				for i, tg := range o.tags {
					rels = append(rels, map[string]any{"id": 100 + i, "tag_name": tg, "published_at": "2026-09-1" + fmt.Sprint(9-i) + "T10:00:00Z", "body": "notes", "draft": false, "prerelease": false})
				}
				b, _ := json.Marshal(rels)
				return b, 200, nil
			case strings.HasPrefix(path, base+"/git/ref/tags/"):
				tg := strings.TrimPrefix(path, base+"/git/ref/tags/")
				for i, x := range o.tags {
					if x == tg {
						return []byte(`{"ref":"refs/tags/` + tg + `","object":{"type":"commit","sha":"` + o.cid(i) + `"}}`), 200, nil
					}
				}
			}
			return nil, 404, nil
		}
		for i := range o.tags {
			pre := "/acme/sample/" + o.cid(i) + "/"
			if path == pre+"CHANGELOG.md" && !o.noLog {
				if o.logBody != nil {
					return []byte(o.logBody(o.tags[i])), 200, nil
				}
				return []byte("# Changes " + o.tags[i] + "\n\n- item\n"), 200, nil
			}
			if o.extra != "" && path == pre+o.extra {
				return []byte("# Changes " + o.tags[i] + "\n\nname: chart\n"), 200, nil
			}
			if path == pre+"LICENSE" && !o.noLicence {
				return []byte("licence text\n"), 200, nil
			}
		}
		return nil, 404, nil
	})
}

// makeSnapshot builds a real snapshot directory through the project command.
func makeSnapshot(t *testing.T, o fixtureOpts) string {
	t.Helper()
	work := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	req := filepath.Join(work, "request.json")
	paths := "CHANGELOG.md"
	if o.extra != "" {
		paths = o.extra // the snapshot keeps the first path found per commit
	}
	args := []string{"init", "--repository", "https://github.com/acme/sample", "--slug", "sample", "--changelog-paths", paths, "--output", req}
	if o.exact {
		args = append(args, "--license-anchor-tag", o.tags[0])
		for _, tg := range o.tags {
			args = append(args, "--exact-tag", tg)
		}
	} else {
		args = append(args, "--release-limit", fmt.Sprint(len(o.tags)))
	}
	var so, se bytes.Buffer
	opt := projectonboarding.Options{Fetcher: fixtureFetcher(o), Now: func() time.Time { return time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC) }}
	if c := projectonboarding.Run(context.Background(), args, &so, &se, opt); c != 0 {
		t.Fatalf("init %d %s", c, se.String())
	}
	parent := filepath.Join(work, "snaps")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	so.Reset()
	if c := projectonboarding.Run(context.Background(), []string{"sync", "--manifest", req, "--output-parent", parent}, &so, &se, opt); c != 0 {
		t.Fatalf("sync %d %s", c, se.String())
	}
	var rc struct {
		OutputName string `json:"outputName"`
	}
	if err := json.Unmarshal(so.Bytes(), &rc); err != nil || rc.OutputName == "" {
		t.Fatalf("sync output %q: %v", so.String(), err)
	}
	return filepath.Join(parent, rc.OutputName)
}

func baseOpts(snap, out string) BuildOptions {
	return BuildOptions{
		SnapshotDir: snap, Slug: "sample", SPDX: "Apache-2.0", CNCF: "none", Out: out, NoCRDs: true,
		PostTag:    map[string]bool{"CHANGELOG.md": true},
		ToolCommit: "",
	}
}

func outDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sample")
}

func readJSON(t *testing.T, dir, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustBuild(t *testing.T, o BuildOptions) BuildResult {
	t.Helper()
	res, err := Build(o)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return res
}

func noOutput(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Lstat(out); err == nil {
		t.Fatalf("output dir %s exists after a refusal", out)
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("leftover files after refusal: %v", entries)
	}
}

func assertValid(t *testing.T, dir string) {
	t.Helper()
	f, err := Validate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s := dirSlugFinding(dir); s != "" {
		f = append(f, s)
	}
	if len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
}

var threeTags = []string{"v0.13.0", "v0.12.0", "v0.11.1"}

func TestBuildFromV1SnapshotValidatesWithNoHandEdits(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	res := mustBuild(t, baseOpts(snap, out))
	assertValid(t, out)
	// the same check through the command's validate path
	var so, se bytes.Buffer
	if c := Run([]string{"validate", "--dir-is-slug", out}, &so, &se); c != 0 {
		t.Fatalf("validate exit %d: %s%s", c, so.String(), se.String())
	}
	proj := readJSON(t, out, "project.json")
	if proj["repo"] != "github.com/acme/sample" || proj["slug"] != "sample" || proj["tagPrefix"] != "v" || proj["cncfStatusClaim"] != "none" {
		t.Fatalf("project: %v", proj)
	}
	lic := proj["licence"].(map[string]any)
	if lic["spdxGuess"] != "Apache-2.0" || lic["path"] != "LICENSE" || lic["commit"] != fixCommit(0) {
		t.Fatalf("licence: %v", lic)
	}
	rl := proj["releaseLines"].([]any)
	if len(rl) != 3 || rl[0].(map[string]any)["tag"] != "v0.13.0" || rl[2].(map[string]any)["line"] != "0.11" {
		t.Fatalf("release lines: %v", rl)
	}
	rel := readJSON(t, out, "relnotes-sources.json")["rows"].([]any)
	if len(rel) != 1 || len(rel[0].(map[string]any)["pairs"].([]any)) != 2 || rel[0].(map[string]any)["postTag"] != true {
		t.Fatalf("relnotes rows: %v", rel)
	}
	if e := readJSON(t, out, "scan-notes.json")["entries"].([]any); len(e) != 0 {
		t.Fatalf("scan entries: %v", e)
	}
	joined := strings.Join(res.Notes, "\n")
	for _, want := range []string{"self-consistent", "not verified against upstream", "unverified"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
}

func TestBuildFromV2ExactTagSnapshot(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags, exact: true})
	out := outDir(t)
	mustBuild(t, baseOpts(snap, out))
	assertValid(t, out)
	if p := readJSON(t, out, "project.json"); p["tagPrefix"] != "v" {
		t.Fatalf("prefix: %v", p["tagPrefix"])
	}
}

func TestBuildTargetDraftIsAlwaysSkeletonAndNoOrigin(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.NoCRDs = true
	mustBuild(t, o)
	td := readJSON(t, out, "target-draft.json")
	if td["status"] != "no-crds" {
		t.Fatalf("status %v, want no-crds", td["status"])
	}
	tg := td["target"].(map[string]any)
	if len(tg["paths"].([]any)) != 0 || len(tg["exclude"].([]any)) != 0 || tg["minFrom"] != "0.11" {
		t.Fatalf("target must be an empty skeleton: %v", tg)
	}
	for _, name := range []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
		raw, _ := os.ReadFile(filepath.Join(out, name))
		low := strings.ToLower(string(raw))
		for _, bad := range []string{"origin", "simulated", "\"filled\""} {
			if strings.Contains(low, bad) {
				t.Fatalf("%s contains %q", name, bad)
			}
		}
	}
}

func TestBuildHasNoFlagThatSetsOriginOrFillsTarget(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	for _, extra := range [][]string{{"-origin", "x"}, {"-target-input", "f.json"}, {"-status", "filled"}, {"-tool-commit", strings.Repeat("a", 40)}, {"-checkout", "."}} {
		out := outDir(t)
		args := append([]string{"build", "-snapshot", snap, "-slug", "sample", "-spdx", "MIT", "-out", out, "-post-tag", "CHANGELOG.md"}, extra...)
		var so, se bytes.Buffer
		if c := Run(args, &so, &se); c == 0 {
			t.Fatalf("%v accepted", extra)
		}
		noOutput(t, out)
	}
}

func TestBuildOriginKeyInBundleIsRefusedByClosedSchema(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	mustBuild(t, baseOpts(snap, out))
	for _, name := range []string{"project.json", "receipt.json", "target-draft.json"} {
		d := copyBundle(t, out, "sample")
		m := readJSON(t, d, name)
		m["origin"] = "simulated"
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(d, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := Validate(d)
		if err != nil {
			t.Fatal(err)
		}
		hit := false
		for _, x := range f {
			if strings.Contains(x, name) && strings.Contains(x, "origin") {
				hit = true
			}
		}
		if !hit {
			t.Fatalf("%s with an origin key not refused: %v", name, f)
		}
	}
}

func TestBuildIsReproducible(t *testing.T) {
	for _, exact := range []bool{false, true} {
		snap := makeSnapshot(t, fixtureOpts{tags: threeTags, exact: exact})
		a, b := outDir(t), outDir(t)
		mustBuild(t, baseOpts(snap, a))
		mustBuild(t, baseOpts(snap, b))
		for _, name := range []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
			x, _ := os.ReadFile(filepath.Join(a, name))
			y, _ := os.ReadFile(filepath.Join(b, name))
			if len(x) == 0 || !bytes.Equal(x, y) {
				t.Fatalf("exact=%v %s differs between two builds", exact, name)
			}
		}
		ea, _ := os.ReadDir(a)
		if len(ea) != 5 {
			t.Fatalf("want exactly 5 files, got %d", len(ea))
		}
		for _, e := range ea {
			info, _ := e.Info()
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("%s mode %v", e.Name(), info.Mode())
			}
		}
		if di, _ := os.Stat(a); di.Mode().Perm() != 0o755 {
			t.Fatalf("dir mode %v", di.Mode())
		}
	}
}

func TestBuildDeclaredFieldMissingNamesTheFlag(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	cases := []struct {
		name string
		mut  func(*BuildOptions)
		flag string
	}{
		{"spdx", func(o *BuildOptions) { o.SPDX = "" }, "--spdx"},
		{"slug", func(o *BuildOptions) { o.Slug = "" }, "--slug"},
		{"out", func(o *BuildOptions) { o.Out = "" }, "--out"},
		{"snapshot", func(o *BuildOptions) { o.SnapshotDir = "" }, "--snapshot"},
		{"posttag", func(o *BuildOptions) { o.PostTag = map[string]bool{} }, "--post-tag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := outDir(t)
			o := baseOpts(snap, out)
			c.mut(&o)
			if c.name == "out" {
				o.Out = ""
			}
			_, err := Build(o)
			if err == nil || !strings.Contains(err.Error(), c.flag) {
				t.Fatalf("want an error naming %s, got %v", c.flag, err)
			}
			noOutput(t, out)
		})
	}
	// through the command: exit code and message
	out := outDir(t)
	var so, se bytes.Buffer
	if c := Run([]string{"build", "-snapshot", snap, "-slug", "sample", "-out", out, "-post-tag", "CHANGELOG.md"}, &so, &se); c == 0 || !strings.Contains(se.String(), "--spdx") {
		t.Fatalf("exit %d stderr %q", c, se.String())
	}
	noOutput(t, out)
}

func TestBuildRefusals(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	long := strings.Repeat("a", 64)
	cases := []struct {
		name string
		mut  func(*BuildOptions)
		want string
	}{
		{"spdx BUSL", func(o *BuildOptions) { o.SPDX = "BUSL-1.1" }, "--spdx"},
		{"spdx lowercase", func(o *BuildOptions) { o.SPDX = "mit" }, "--spdx"},
		{"spdx compound", func(o *BuildOptions) { o.SPDX = "MIT OR Apache-2.0" }, "--spdx"},
		{"cncf unknown value", func(o *BuildOptions) { o.CNCF = "archived" }, "--cncf"},
		{"unknown tag", func(o *BuildOptions) { o.Tags = []string{"v9.9.9"} }, "--tags"},
		{"duplicate tag", func(o *BuildOptions) { o.Tags = []string{"v0.13.0", "v0.13.0"} }, "twice"},
		{"slug mismatch", func(o *BuildOptions) { o.Slug = "other" }, "--out base name"},
		{"slug charset", func(o *BuildOptions) { o.Slug = "Bad_Slug"; o.Out = filepath.Join(filepath.Dir(o.Out), "Bad_Slug") }, "--slug"},
		{"slug oversized", func(o *BuildOptions) { o.Slug = long + "a"; o.Out = filepath.Join(filepath.Dir(o.Out), o.Slug) }, "--slug"},
		{"prefix oversized", func(o *BuildOptions) { o.TagPrefix = strings.Repeat("v", 40) }, "--tag-prefix"},
		{"prefix wrong", func(o *BuildOptions) { o.TagPrefix = "rel-" }, "--tag-prefix"},
		{"min-from not built", func(o *BuildOptions) { o.MinFrom = "0.5" }, "--min-from"},
		{"min-from malformed", func(o *BuildOptions) { o.MinFrom = "x" }, "--min-from"},
		{"post-tag unknown path", func(o *BuildOptions) { o.PostTag = map[string]bool{"CHANGELOG.md": true, "docs/X.md": false} }, "docs/X.md"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := outDir(t)
			o := baseOpts(snap, out)
			c.mut(&o)
			parent := filepath.Dir(o.Out)
			_, err := Build(o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
			if es, _ := os.ReadDir(parent); len(es) != 0 {
				t.Fatalf("leftovers: %v", es)
			}
		})
	}
}

func TestBuildOutRules(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	t.Run("exists", func(t *testing.T) {
		out := outDir(t)
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "keep"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(baseOpts(snap, out)); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("err %v", err)
		}
		if b, _ := os.ReadFile(filepath.Join(out, "keep")); string(b) != "x" {
			t.Fatal("existing output was touched")
		}
	})
	t.Run("out is a symlink", func(t *testing.T) {
		out := outDir(t)
		if err := os.Symlink(t.TempDir(), out); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(baseOpts(snap, out)); err == nil {
			t.Fatal("symlink out accepted")
		}
	})
	t.Run("parent is a symlink", func(t *testing.T) {
		real := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(baseOpts(snap, filepath.Join(link, "sample"))); err == nil {
			t.Fatal("symlinked parent accepted")
		}
		if es, _ := os.ReadDir(real); len(es) != 0 {
			t.Fatalf("wrote through the symlink: %v", es)
		}
	})
	t.Run("parent missing", func(t *testing.T) {
		if _, err := Build(baseOpts(snap, filepath.Join(t.TempDir(), "nope", "sample"))); err == nil {
			t.Fatal("missing parent accepted")
		}
	})
}

func TestBuildRefusesSnapshotThatIsNotVerified(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(fmt.Sprintf("exact=%v", exact), func(t *testing.T) {
			fresh := func() string { return makeSnapshot(t, fixtureOpts{tags: threeTags, exact: exact}) }
			tamper := map[string]func(dir string){
				"object bytes changed": func(dir string) {
					objs, _ := filepath.Glob(filepath.Join(dir, "objects", "sha256", "*"))
					if len(objs) == 0 {
						t.Fatal("no objects")
					}
					if err := os.Chmod(objs[0], 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(objs[0], []byte("tampered"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
				"snapshot json edited": func(dir string) {
					p := filepath.Join(dir, "PROJECT-ONBOARDING-SNAPSHOT.json")
					raw, _ := os.ReadFile(p)
					raw = bytes.Replace(raw, []byte("v0.12.0"), []byte("v0.12.9"), 1)
					if err := os.WriteFile(p, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				},
				"receipt removed": func(dir string) {
					if err := os.Remove(filepath.Join(dir, "SYNC-RECEIPT.json")); err != nil {
						t.Fatal(err)
					}
				},
				"directory renamed": func(dir string) {
					if err := os.Rename(dir, dir+"x"); err != nil {
						t.Fatal(err)
					}
				},
				"extra object": func(dir string) {
					if err := os.WriteFile(filepath.Join(dir, "objects", "sha256", strings.Repeat("e", 64)), []byte("x"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
				"extra file": func(dir string) {
					if err := os.WriteFile(filepath.Join(dir, "extra.json"), []byte("{}"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
			}
			for name, mut := range tamper {
				snap := fresh()
				mut(snap)
				if name == "directory renamed" {
					snap += "x"
				}
				out := outDir(t)
				_, err := Build(baseOpts(snap, out))
				if err == nil {
					t.Fatalf("%s: tampered snapshot accepted", name)
				}
				var re refusal
				if !asRefusal(err, &re) {
					t.Fatalf("%s: not a refusal: %v", name, err)
				}
				noOutput(t, out)
			}
		})
	}
}

func TestBuildRefusesSymlinkedAndMissingSnapshot(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	link := filepath.Join(t.TempDir(), "snapshot-link")
	if err := os.Symlink(snap, link); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{link, filepath.Join(t.TempDir(), "nope")} {
		out := outDir(t)
		if _, err := Build(baseOpts(s, out)); err == nil {
			t.Fatalf("%s accepted", s)
		}
		noOutput(t, out)
	}
}

func TestBuildRefusesSnapshotWithoutLicence(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags, noLicence: true})
	out := outDir(t)
	if _, err := Build(baseOpts(snap, out)); err == nil || !strings.Contains(err.Error(), "licence") {
		t.Fatalf("err %v", err)
	}
	noOutput(t, out)
}

func TestBuildWithoutChangelogHasNoRows(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags, noLog: true})
	out := outDir(t)
	o := baseOpts(snap, out)
	o.PostTag = nil
	res := mustBuild(t, o)
	assertValid(t, out)
	if rows := readJSON(t, out, "relnotes-sources.json")["rows"].([]any); len(rows) != 0 {
		t.Fatalf("rows: %v", rows)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "no changelog bytes in snapshot") {
		t.Fatalf("notes: %v", res.Notes)
	}
	// a declared postTag for a path that is not in the bundle is still refused
	out2 := outDir(t)
	o.Out = out2
	o.PostTag = map[string]bool{"CHANGELOG.md": true}
	if _, err := Build(o); err == nil {
		t.Fatal("postTag for an absent path accepted")
	}
	noOutput(t, out2)
}

func TestBuildTagSelectionAndLines(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: []string{"v0.13.1", "v0.13.0", "v0.12.0"}})
	out := outDir(t)
	res := mustBuild(t, baseOpts(snap, out))
	assertValid(t, out)
	rl := readJSON(t, out, "project.json")["releaseLines"].([]any)
	if len(rl) != 2 || rl[0].(map[string]any)["tag"] != "v0.13.1" {
		t.Fatalf("lines: %v", rl)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "v0.13.0 not used") {
		t.Fatalf("notes: %v", res.Notes)
	}
	out2 := outDir(t)
	o := baseOpts(snap, out2)
	o.Tags = []string{"v0.12.0", "v0.13.0"}
	o.MinFrom = "0.13"
	mustBuild(t, o)
	assertValid(t, out2)
	if td := readJSON(t, out2, "target-draft.json")["target"].(map[string]any); td["minFrom"] != "0.13" {
		t.Fatalf("minFrom %v", td["minFrom"])
	}
}

func TestBuildToolCommitEmbeddedOrUnverified(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	good := strings.Repeat("c", 40)
	for in, want := range map[string]string{good: good, "": unverifiedToolCommit, "main": unverifiedToolCommit, "unbound": unverifiedToolCommit, strings.ToUpper(good): unverifiedToolCommit} {
		out := outDir(t)
		o := baseOpts(snap, out)
		o.ToolCommit = in
		res := mustBuild(t, o)
		assertValid(t, out)
		got := readJSON(t, out, "receipt.json")["tool"].(map[string]any)["prufyxCommit"]
		if got != want {
			t.Fatalf("in %q: commit %v, want %v", in, got, want)
		}
		unverifiedNote := strings.Contains(strings.Join(res.Notes, "\n"), "unverified")
		if (want == unverifiedToolCommit) != unverifiedNote {
			t.Fatalf("in %q: unverified note %v", in, unverifiedNote)
		}
	}
}

func TestBuildReceiptIsIntegrityOnlyAndSealable(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	mustBuild(t, baseOpts(snap, out))
	r := readJSON(t, out, "receipt.json")
	if r["review"].(map[string]any)["state"] != "NOT_REVIEWED" || r["agentLabel"] != "maintainer submission" || r["generatedAt"] != "2026-09-20T11:00:00Z" {
		t.Fatalf("receipt: %v", r)
	}
	if c := r["checks"].(map[string]any); c["targetCheckOffline"] != "not-run" || c["extractRun"] != "not-run" {
		t.Fatalf("checks: %v", c)
	}
	// seal over the built bundle changes nothing
	before, _ := os.ReadFile(filepath.Join(out, "receipt.json"))
	if _, err := Seal(out, SealOptions{}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(out, "receipt.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("seal rewrote a freshly built receipt")
	}
}

func TestBuildCapsRefuseOversizedBundle(t *testing.T) {
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	old := maxBundleBytes
	maxBundleBytes = 200
	defer func() { maxBundleBytes = old }()
	out := outDir(t)
	if _, err := Build(baseOpts(snap, out)); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("err %v", err)
	}
	noOutput(t, out)
}

func TestLeakFindingsRefusesSecretsAndInternalNames(t *testing.T) {
	for _, v := range []string{"/home/alice/x", "ghp_" + strings.Repeat("a", 24), "10.1.2.3", "/Users/bob"} {
		docs := map[string]any{"project.json": map[string]any{"note": v}}
		if len(leakFindings(docs)) == 0 {
			t.Errorf("%q not refused", v)
		}
	}
	if len(leakFindings(map[string]any{"project.json": map[string]any{"note": "fine"}})) != 0 {
		t.Error("clean value refused")
	}
}

func TestBuildHelpStatesLimits(t *testing.T) {
	var so, se bytes.Buffer
	if c := Run([]string{"build", "-h"}, &so, &se); c != 0 {
		t.Fatalf("exit %d", c)
	}
	h := so.String()
	for _, want := range []string{"SELF-CONSISTENT", "not verified against upstream", "is planned to re-check", "ALWAYS a skeleton", "never provenance", "no origin"} {
		if !strings.Contains(h, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func TestBuildRejectsPositionalArgsAndPostTagDuplicates(t *testing.T) {
	var so, se bytes.Buffer
	if c := Run([]string{"build", "extra"}, &so, &se); c != 2 {
		t.Fatalf("exit %d", c)
	}
	snap := makeSnapshot(t, fixtureOpts{tags: threeTags})
	out := outDir(t)
	if c := Run([]string{"build", "-snapshot", snap, "-slug", "sample", "-spdx", "MIT", "-out", out, "-post-tag", "CHANGELOG.md", "-no-post-tag", "CHANGELOG.md"}, &so, &se); c != 2 {
		t.Fatalf("exit %d", c)
	}
	noOutput(t, out)
}

// ---- declared chart hint ----

var threeTagsChart = fixtureOpts{tags: []string{"v1.2.0", "v1.1.0", "v1.0.0"}, extra: "charts/sample/CHANGELOG.md"}

func chartOpts(t *testing.T, path, ver string) BuildOptions {
	t.Helper()
	snap := makeSnapshot(t, threeTagsChart)
	o := baseOpts(snap, outDir(t))
	o.PostTag = map[string]bool{"charts/sample/CHANGELOG.md": false}
	o.ChartPath, o.ChartVersion = path, ver
	return o
}

func TestBuildChartDeclaredIsRecordedAndSetsNothingElse(t *testing.T) {
	for _, p := range []string{"charts/sample/CHANGELOG.md", "charts/sample"} {
		o := chartOpts(t, p, "1.0.0+build.5")
		o.Out = outDir(t)
		if _, err := Build(o); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		proj := readJSON(t, o.Out, "project.json")
		ch, _ := proj["chart"].(map[string]any)
		if ch["path"] != p || ch["version"] != "1.0.0+build.5" || len(ch) != 2 {
			t.Fatalf("chart not recorded: %v", proj["chart"])
		}
		if f, err := Validate(o.Out); err != nil || len(f) != 0 {
			t.Fatalf("bundle with chart does not validate: %v %v", f, err)
		}
		// no verdict or coverage fields; skeleton stays skeleton; receipt has no chart
		td := readJSON(t, o.Out, "target-draft.json")
		if td["status"] != "no-crds" {
			t.Fatalf("status changed: %v", td["status"])
		}
		for _, name := range []string{"target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
			raw, _ := os.ReadFile(filepath.Join(o.Out, name))
			if strings.Contains(string(raw), "1.0.0+build.5") || strings.Contains(string(raw), "charts/sample/CHANGELOG") && name != "relnotes-sources.json" {
				t.Fatalf("%s carries the chart declaration", name)
			}
		}
		for k := range proj {
			if k == "verdict" || k == "coverage" || k == "origin" {
				t.Fatalf("unexpected key %s", k)
			}
		}
	}
}

func TestBuildWithoutChartWritesNoChartKey(t *testing.T) {
	o := chartOpts(t, "", "")
	if _, err := Build(o); err != nil {
		t.Fatal(err)
	}
	if _, ok := readJSON(t, o.Out, "project.json")["chart"]; ok {
		t.Fatal("chart key written without a declaration")
	}
}

func TestBuildChartRefusals(t *testing.T) {
	long := strings.Repeat("a", 254)
	cases := []struct{ name, path, ver, want string }{
		{"version without path", "", "1.0.0", "go together"},
		{"path without version", "charts/sample", "", "go together"},
		{"path not in snapshot", "charts/other", "1.0.0", "snapshot holds no file"},
		{"partial segment is not a directory", "charts/sam", "1.0.0", "snapshot holds no file"},
		{"path over 253", long, "1.0.0", "253"},
		{"path charset", "charts/sam ple", "1.0.0", "plain repo-relative"},
		{"path dot segment", "charts/../x", "1.0.0", "plain repo-relative"},
		{"path absolute", "/charts/sample", "1.0.0", "plain repo-relative"},
		{"path glob", "charts/*", "1.0.0", "plain repo-relative"},
		{"version over 128", "charts/sample", strings.Repeat("1", 129), "128"},
		{"version charset", "charts/sample", "1.0.0;rm", "128 characters"},
		{"version leading dash", "charts/sample", "-1", "128 characters"},
	}
	for _, c := range cases {
		o := chartOpts(t, c.path, c.ver)
		_, err := Build(o)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want refusal containing %q, got %v", c.name, c.want, err)
		}
		if _, e := os.Lstat(o.Out); e == nil {
			t.Errorf("%s: output written on refusal", c.name)
		}
	}
}

func TestBuildChartPathHeldOnlyAtUnbuiltTagIsRefused(t *testing.T) {
	o := chartOpts(t, "charts/sample", "1.0.0")
	o.Tags = []string{"v1.2.0"}
	// the file is held at every tag in this fixture, so build with the real
	// view and drop the sources' commits: no kept tag holds the path.
	sv, err := loadSnapshotView(o.SnapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range sv.Sources {
		sv.Sources[i].Commit = "ffffffffffffffffffffffffffffffffffffffff"
	}
	kept := []snapTag{{Tag: "v1.2.0", Commit: fixCommit(0)}}
	if _, err := chartDecl(o, sv, kept); err == nil {
		t.Fatal("accepted a path the snapshot holds at no built tag")
	}
}

func TestBundleWithoutChartStillValidates(t *testing.T) {
	// the committed fixtures predate the field
	if f, err := Validate("testdata/valid"); err != nil || len(f) != 0 {
		t.Fatalf("old bundle: %v %v", f, err)
	}
}

func TestChartFieldIsClosedInSchema(t *testing.T) {
	d := t.TempDir()
	for _, n := range []string{"project.json", "target-draft.json", "scan-notes.json", "relnotes-sources.json", "receipt.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata/valid", n))
		if err != nil {
			t.Fatal(err)
		}
		if n == "project.json" {
			raw = []byte(strings.Replace(string(raw), `"cncfStatusClaim"`, `"chart": {"path": "c", "version": "1", "verdict": "PASS"}, "cncfStatusClaim"`, 1))
		}
		os.WriteFile(filepath.Join(d, n), raw, 0o600)
	}
	f, _ := Validate(d)
	found := false
	for _, x := range f {
		if strings.Contains(x, "chart") && strings.Contains(x, "verdict") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown key inside chart not refused by the closed schema: %v", f)
	}
}
