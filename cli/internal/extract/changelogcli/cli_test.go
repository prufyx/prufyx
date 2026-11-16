// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"encoding/json"
	"flag"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

var update = flag.Bool("update", false, "rewrite the golden manifests")

const placeholder = "sha256:<code digest>"

var fixtureDir = filepath.Join("..", "changelogentries", "testdata", "fixture")

var promTarget = changelogentries.Target{
	Component: "prometheus", Repo: extract.RepoRef{Key: "github.com/prometheus/prometheus"},
	Form: changelogentries.FormFile, Path: "CHANGELOG.md",
	HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{
		`^(main|master) / unreleased$`,
		`^[0-9]+\.[0-9]+\.[0-9]+-(rc|beta|alpha)\.[0-9]+ / .*$`,
	},
}

var cortexTarget = changelogentries.Target{
	Component: "cortex", Repo: extract.RepoRef{Key: "github.com/cortexproject/cortex"},
	Form: changelogentries.FormFile, Path: "CHANGELOG.md",
	HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{
		`^master / unreleased$`,
		`^[0-9]+\.[0-9]+\.[0-9]+ in progress$`,
		`^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+ .*$`,
	},
}

var thanosTarget = changelogentries.Target{
	Component: "thanos", Repo: extract.RepoRef{Key: "github.com/thanos-io/thanos"},
	Form: changelogentries.FormFile, Path: "CHANGELOG.md",
	HeadingPattern:   `^\[v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\](?:\([^()\s]*\)|\s\S*\))?(?: - [0-9]{2}\.[0-9]{2}\.[0-9]{4})?$`,
	BoundaryPatterns: []string{`^Unreleased$`},
}

var table = []changelogentries.Target{promTarget, cortexTarget, thanosTarget}

func args(t changelogentries.Target, tag, fixture string) []string {
	return []string{"entries", "--component", t.Component, "--repo", t.Repo.Key, "--path", t.Path, "--form", t.Form, "--tag", tag, "--fixture", fixture}
}

func runOK(t *testing.T, tbl []changelogentries.Target, a []string) []byte {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(a, tbl, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	return out.Bytes()
}

func runRefused(t *testing.T, tbl []changelogentries.Target, a []string) {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(a, tbl, &out, &errb); code != 2 {
		t.Fatalf("want exit 2, got %d for %v", code, a)
	}
	if out.Len() != 0 {
		t.Fatalf("a refusal wrote to stdout: %q", out.String())
	}
	if errb.Len() == 0 {
		t.Fatal("a refusal said nothing")
	}
}

func TestGoldenManifests(t *testing.T) {
	digest, err := changelogentries.CodeDigest()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		t   changelogentries.Target
		tag string
	}{
		{promTarget, "v3.5.0"}, {promTarget, "v3.4.0"},
		{cortexTarget, "v1.19.0"}, {thanosTarget, "v0.38.0"}, {thanosTarget, "v0.37.0"},
	}
	for _, c := range cases {
		out := runOK(t, table, args(c.t, c.tag, fixtureDir))
		if !bytes.Contains(out, []byte(`"codeDigest":"`+digest+`"`)) {
			t.Fatalf("%s %s: the manifest does not carry this build's code digest", c.t.Component, c.tag)
		}
		got := bytes.Replace(out, []byte(digest), []byte(placeholder), 1)
		golden := filepath.Join("testdata", c.t.Component+"-"+c.tag+".json")
		if *update {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: manifest differs from the golden file (rerun with -update only after reading the diff)", golden)
		}
		if !bytes.HasSuffix(out, []byte("}\n")) || bytes.Count(out, []byte("\n")) != 1 {
			t.Fatalf("%s: the manifest must be one line", golden)
		}
	}
}

func TestManifestShapeIsStrictAndCarriesNoVerdict(t *testing.T) {
	out := runOK(t, table, args(promTarget, "v3.5.0", fixtureDir))
	var m struct {
		Schema    string `json:"schema"`
		Extractor struct {
			Name, Version, CodeDigest string
		} `json:"extractor"`
		Entry    map[string]json.RawMessage `json:"entry"`
		Withheld json.RawMessage            `json:"withheld"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != "prufyx.io/changelog-entries-manifest/v1" || m.Extractor.Name != "changelog.entries" || m.Extractor.Version != "changelog.entries/1" {
		t.Fatalf("pins: %+v", m)
	}
	if m.Entry == nil || m.Withheld != nil {
		t.Fatal("exactly one of entry and withheld")
	}
	var item map[string]json.RawMessage
	var items []json.RawMessage
	if err := json.Unmarshal(m.Entry["items"], &items); err != nil || len(items) == 0 {
		t.Fatalf("items: %v", err)
	}
	if err := json.Unmarshal(items[0], &item); err != nil {
		t.Fatal(err)
	}
	for k := range item {
		switch k {
		case "digest", "occurrence", "startLine", "endLine", "headingPath", "marker", "kind":
		default:
			t.Fatalf("item field %q: nothing but identity and span may be printed (no class, trigger or disposition)", k)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a := runOK(t, table, args(thanosTarget, "v0.38.0", fixtureDir))
	for i := 0; i < 5; i++ {
		if b := runOK(t, table, args(thanosTarget, "v0.38.0", fixtureDir)); !bytes.Equal(a, b) {
			t.Fatal("two runs differ")
		}
	}
}

// writeRepo makes a one-repository fixture with the given tags and, per
// commit, an optional changelog file.
func writeRepo(t *testing.T, tg changelogentries.Target, tags map[string]string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(tg.Repo.Key))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(tags)
	if err := os.WriteFile(filepath.Join(dir, "tags.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range tags {
		if err := os.MkdirAll(filepath.Join(dir, "commits", c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for c, body := range files {
		if err := os.WriteFile(filepath.Join(dir, "commits", c, tg.Path), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestTypedReasonPerTag(t *testing.T) {
	c := func(n byte) string { return strings.Repeat(string("0123456789abcdef"[n]), 40) }
	good := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] y. #2\n"
	tags := map[string]string{
		"v3.5.0": c(1), "v3.4.0": c(2), "v3.3.0": c(3), "v3.2.0": c(4), "v3.1.0": c(5),
		"v3.0.0-rc.0": c(6), "v3.6.0": c(7),
	}
	files := map[string]string{
		c(1): good,
		c(2): good + "\n## 3.4.0 / 2025-05-18\n\n* [FEATURE] again. #9\n",
		c(3): "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n",
		c(4): "## 3.2.0 / 2025-07-14\n\n* [FEATURE] x. #1\n---\n",
		// c(5): no file at all
		c(6): good,
		c(7): "## 3.6.0 / 2025-08-01\n\nsee the release page\n\n## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n",
	}
	root := writeRepo(t, promTarget, tags, files)
	want := map[string]changelogentries.Code{
		"v3.4.0":      changelogentries.EntryDuplicate,
		"v3.3.0":      changelogentries.EntryMissing,
		"v3.2.0":      changelogentries.EntryParseResidue,
		"v3.1.0":      changelogentries.PathMissingAtTag,
		"v3.0.0-rc.0": changelogentries.EntryNotFinal,
	}
	for tag, code := range want {
		out := runOK(t, table, args(promTarget, tag, root))
		var m changelogentries.Manifest
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatal(err)
		}
		if m.Entry != nil || m.Withheld == nil || m.Withheld.Code != code || m.Withheld.Tag != tag || m.Withheld.TagCommit != tags[tag] || m.Withheld.Component != "prometheus" {
			t.Fatalf("%s: want %s, got %s", tag, code, out)
		}
		if bytes.Contains(out, []byte(`"entry"`)) {
			t.Fatalf("%s: a withheld manifest must not carry an entry", tag)
		}
	}
	// A positive control in the same repository.
	var m changelogentries.Manifest
	if err := json.Unmarshal(runOK(t, table, args(promTarget, "v3.5.0", root)), &m); err != nil || m.Entry == nil || m.Withheld != nil {
		t.Fatalf("control: %v %+v", err, m)
	}
}

func TestFormsThatAreNotReadGiveTheirReason(t *testing.T) {
	root := writeRepo(t, promTarget, map[string]string{"v3.5.0": strings.Repeat("a", 40)}, nil)
	for form, code := range map[string]changelogentries.Code{
		changelogentries.FormGithubRelease: changelogentries.SourceNotPinnedGit,
		changelogentries.FormPostTag:       changelogentries.EntryNotAtTag,
		changelogentries.FormDocsPage:      changelogentries.ShapeNotPerTag,
		changelogentries.FormMonorepo:      changelogentries.MonorepoEntryAmbiguous,
	} {
		tg := promTarget
		tg.Form = form
		var m changelogentries.Manifest
		if err := json.Unmarshal(runOK(t, []changelogentries.Target{tg}, args(tg, "v3.5.0", root)), &m); err != nil {
			t.Fatal(err)
		}
		if m.Entry != nil || m.Withheld == nil || m.Withheld.Code != code {
			t.Fatalf("%s: %+v", form, m.Withheld)
		}
	}
}

func TestRefusals(t *testing.T) {
	ok := args(promTarget, "v3.5.0", fixtureDir)
	with := func(extra ...string) []string { return append(append([]string{}, ok...), extra...) }
	without := func(flagName string) []string {
		var out []string
		for i := 0; i < len(ok); i++ {
			if ok[i] == "--"+flagName {
				i++
				continue
			}
			out = append(out, ok[i])
		}
		return out
	}
	sub := func(flagName, v string) []string {
		out := append([]string{}, ok...)
		for i := range out {
			if out[i] == "--"+flagName {
				out[i+1] = v
			}
		}
		return out
	}
	cases := map[string][]string{
		"no subcommand":         {},
		"other subcommand":      {"list"},
		"unknown flag":          with("--classify"),
		"unknown flag value":    with("--network=1"),
		"positional":            with("extra"),
		"duplicate tag":         with("--tag", "v3.4.0"),
		"duplicate component":   with("--component", "prometheus"),
		"no component":          without("component"),
		"no repo":               without("repo"),
		"no path":               without("path"),
		"no form":               without("form"),
		"no tag":                without("tag"),
		"no source":             without("fixture"),
		"both sources":          with("--mirror-state", t.TempDir()),
		"unknown component":     sub("component", "nope"),
		"other repo":            sub("repo", "github.com/thanos-io/thanos"),
		"other path":            sub("path", "docs/CHANGELOG.md"),
		"other form":            sub("form", changelogentries.FormPostTag),
		"tag not recorded":      sub("tag", "v9.9.9"),
		"tag by prefix":         sub("tag", "v3.5"),
		"missing mirror":        append(without("fixture"), "--mirror-state", filepath.Join(t.TempDir(), "absent")),
		"missing fixture":       sub("fixture", filepath.Join(t.TempDir(), "absent")),
		"empty tag":             sub("tag", ""),
		"component only prefix": sub("component", "prom"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { runRefused(t, table, a) })
	}
	t.Run("two rows for one component", func(t *testing.T) {
		runRefused(t, []changelogentries.Target{promTarget, promTarget}, ok)
	})
	t.Run("a flag may not point the reader at another file", func(t *testing.T) {
		runRefused(t, table, sub("path", "../CHANGELOG.md"))
	})
}

func TestShippedTableIsEmptyAndFailsClosed(t *testing.T) {
	if len(changelogentries.Reviewed) != 0 {
		t.Skip("rows have been reviewed; the refusal cases above cover them")
	}
	var out, errb bytes.Buffer
	if code := Main(args(promTarget, "v3.5.0", fixtureDir), &out, &errb); code != 2 || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q", code, out.String())
	}
}

func TestReadFailureIsNotAReason(t *testing.T) {
	// The tag's commit directory is missing from the fixture: a read failure,
	// not a typed reason and not a manifest.
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(promTarget.Repo.Key))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"v3.5.0":"` + strings.Repeat("b", 40) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "tags.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	runRefused(t, table, args(promTarget, "v3.5.0", root))
}

// The command reads through the pinned reader only: neither package may
// import anything that reaches the network or starts a process.
func TestNoNetworkNoProcessImports(t *testing.T) {
	banned := map[string]bool{"net": true, "net/http": true, "net/rpc": true, "os/exec": true, "syscall": true, "plugin": true}
	for _, dir := range []string{".", filepath.Join("..", "changelogentries")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if banned[p] || strings.HasPrefix(p, "net/") {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}
