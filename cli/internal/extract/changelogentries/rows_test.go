// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// rowsBeforeData are the rows as they were written in code before they became
// data. The data file must load to exactly these values.
var rowsBeforeData = []Target{
	{Component: "vault", Repo: extract.RepoRef{Key: "github.com/hashicorp/vault"}, Form: FormPostTag},
	{Component: "aws-ebs-csi-driver", Repo: extract.RepoRef{Key: "github.com/kubernetes-sigs/aws-ebs-csi-driver"}, Form: FormPostTag},
	{Component: "flannel", Repo: extract.RepoRef{Key: "github.com/flannel-io/flannel"}, Form: FormGithubRelease},
	{Component: "csi-driver-smb", Repo: extract.RepoRef{Key: "github.com/kubernetes-csi/csi-driver-smb"}, Form: FormGithubRelease},
	{
		Component: "prometheus", Repo: extract.RepoRef{Key: "github.com/prometheus/prometheus"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
		BoundaryPatterns: []string{`^main / unreleased$`},
	},
	{
		Component: "alertmanager", Repo: extract.RepoRef{Key: "github.com/prometheus/alertmanager"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
		BoundaryPatterns: []string{`^main / \(unreleased\)$`},
	},
	{
		Component: "antrea", Repo: extract.RepoRef{Key: "github.com/antrea-io/antrea"},
		Form: FormPerLineFile, Path: "CHANGELOG/CHANGELOG-{line}.md",
		HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) - [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
		BoundaryPatterns: []string{`^\[v[0-9]+\.[0-9]+\.[0-9]+-(?:rc|alpha|beta|ea)\.?[0-9]+\]\(https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/tree/[A-Za-z0-9._-]+\) \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$`},
	},
}

// rowsAddedLater are the rows added after the first six. Append further new
// rows here; dropping or editing any pinned row fails the test.
var rowsAddedLater = []Target{
	{Component: "coredns", Repo: extract.RepoRef{Key: "github.com/coredns/coredns"}, Form: FormPerVersionFile, Path: "notes/coredns-{version}.md"},
	{
		Component: "fluentd", Repo: extract.RepoRef{Key: "github.com/fluent/fluentd"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   headingStyles["release-v-slash-date"],
		BoundaryPatterns: []string{boundaryStyles["line-heading-v"]},
	},
	{
		Component: "openfga", Repo: extract.RepoRef{Key: "github.com/openfga/openfga"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   headingStyles["version-bracketed-date"],
		BoundaryPatterns: []string{boundaryStyles["prerelease-linked-paren-date"]},
	},
	{
		Component: "traefik", Repo: extract.RepoRef{Key: "github.com/traefik/traefik"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   headingStyles["version-linked-paren-date"],
		BoundaryPatterns: []string{boundaryStyles["prerelease-linked-paren-date"]},
	},
}

func TestShippedTableLoads(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	pinned := append(append([]Target{}, rowsBeforeData...), rowsAddedLater...)
	if len(Reviewed) != len(pinned) {
		t.Fatalf("%d rows, want exactly %d pinned", len(Reviewed), len(pinned))
	}
	for _, want := range pinned {
		got, err := Lookup(Reviewed, want.Component)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("row %s changed:\n got %+v\nwant %+v", want.Component, got, want)
		}
	}
}

// TestReviewedRows runs every shipped row through the properties its form
// guarantees.
func TestReviewedRows(t *testing.T) {
	withheldCode := map[string]Code{FormPostTag: EntryNotAtTag, FormGithubRelease: SourceNotPinnedGit}
	for _, row := range Reviewed {
		t.Run(row.Component, func(t *testing.T) {
			if _, err := extract.ParseRepo(row.Repo.Key); err != nil {
				t.Fatal(err)
			}
			switch row.Form {
			case FormPostTag, FormGithubRelease:
				if row.Path != "" || row.HeadingPattern != "" || row.BoundaryPatterns != nil {
					t.Fatalf("unexpected row: %+v", row)
				}
				r := &memReader{err: errReadBoom}
				m, err := BuildManifest(r, row, extract.Tag{Name: "v1.0.0", Commit: testCommit}, zeroDigest)
				if err != nil || m.Withheld == nil || m.Entry != nil || m.Withheld.Code != withheldCode[row.Form] {
					t.Fatalf("want withheld %s: %v %+v", withheldCode[row.Form], err, m)
				}
				if r.reads != 0 {
					t.Fatalf("a non-file row read %d times", r.reads)
				}
			case FormFile:
				if _, err := row.compile(); err != nil {
					t.Fatal(err)
				}
				heading := func(v, date string) string {
					switch row.HeadingPattern {
					case headingStyles["version-v-prefixed"]:
						return "v" + v
					case headingStyles["version-bracketed-date"]:
						return "[" + v + "] - " + date
					case headingStyles["version-slash-date"]:
						return v + " / " + date
					case headingStyles["release-v-slash-date"]:
						return "Release v" + v + " - " + strings.ReplaceAll(date, "-", "/")
					case headingStyles["version-linked-paren-date"]:
						return "[v" + v + "](https://" + row.Repo.Key + "/tree/v" + v + ") (" + date + ")"
					}
					t.Fatalf("no sample heading for %q", row.HeadingPattern)
					return ""
				}
				if len(row.BoundaryPatterns) == 0 {
					t.Fatal("a file row has no boundary pattern")
				}
				var boundary string
				switch row.BoundaryPatterns[0] {
				case boundaryStyles["main-unreleased"]:
					boundary = "main / unreleased"
				case boundaryStyles["main-unreleased-parenthesised"]:
					boundary = "main / (unreleased)"
				case boundaryStyles["line-heading-v"]:
					boundary = "v1.3"
				case boundaryStyles["prerelease-linked-paren-date"]:
					boundary = "[v1.3.0-rc1](https://" + row.Repo.Key + "/tree/v1.3.0-rc1) (2026-02-01)"
				default:
					t.Fatalf("no sample boundary for %q", row.BoundaryPatterns[0])
				}
				file := "# Changelog\n\n## " + boundary + "\n\n* [FEATURE] new\n\n" +
					"## " + heading("1.2.3", "2026-01-02") + "\n\n* [BUGFIX] fix\n\n" +
					"## " + heading("1.2.2", "2025-12-01") + "\n\n* [BUGFIX] older\n"
				r := &memReader{files: map[string][]byte{row.Repo.Key + "@" + testCommit + ":" + row.Path: []byte(file)}}
				m, err := BuildManifest(r, row, extract.Tag{Name: "v1.2.3", Commit: testCommit}, zeroDigest)
				if err != nil || m.Entry == nil || m.Withheld != nil {
					t.Fatalf("want an entry: %v %+v", err, m)
				}
				if m.Entry.Version != "1.2.3" || m.Entry.Section.HeadingLine != 7 {
					t.Fatalf("entry %+v", m.Entry)
				}
				// A version the file does not hold is withheld, never read from a
				// neighbour.
				m, err = BuildManifest(r, row, extract.Tag{Name: "v1.2.4", Commit: testCommit}, zeroDigest)
				if err != nil || m.Withheld == nil || m.Entry != nil {
					t.Fatalf("a missing version must be withheld: %v %+v", err, m)
				}
			case FormPerVersionFile:
				path := strings.Replace(row.Path, "{version}", "1.2.3", 1)
				r := &memReader{files: map[string][]byte{row.Repo.Key + "@" + testCommit + ":" + path: []byte("# 1.2.3\n\n* fix\n")}}
				m, err := BuildManifest(r, row, extract.Tag{Name: "v1.2.3", Commit: testCommit}, zeroDigest)
				if err != nil || m.Entry == nil || m.Withheld != nil {
					t.Fatalf("want an entry: %v %+v", err, m)
				}
				if len(m.Entry.Items) == 0 {
					t.Fatalf("the located entry has no items: %+v", m.Entry)
				}
				// A version with no file is withheld, never read from a neighbour.
				m, err = BuildManifest(r, row, extract.Tag{Name: "v1.2.4", Commit: testCommit}, zeroDigest)
				if err != nil || m.Withheld == nil || m.Entry != nil {
					t.Fatalf("a missing version must be withheld: %v %+v", err, m)
				}
			case FormPerLineFile:
				if _, err := row.compile(); err != nil {
					t.Fatal(err)
				}
				if row.Component != "antrea" {
					t.Fatalf("per-line row %s has no sample", row.Component)
				}
				file := "# Changelog 1.2\n\n## 1.2.3 - 2026-01-02\n\n- fix\n\n## 1.2.2 - 2025-12-01\n\n- older\n"
				r := &memReader{files: map[string][]byte{row.Repo.Key + "@" + testCommit + ":" + strings.ReplaceAll(row.Path, "{line}", "1.2"): []byte(file)}}
				m, err := BuildManifest(r, row, extract.Tag{Name: "v1.2.3", Commit: testCommit}, zeroDigest)
				if err != nil || m.Entry == nil || m.Withheld != nil || m.Entry.Version != "1.2.3" || m.Entry.Section.HeadingLine != 3 {
					t.Fatalf("want an entry: %v %+v", err, m)
				}
				m, err = BuildManifest(r, row, extract.Tag{Name: "v1.2.4", Commit: testCommit}, zeroDigest)
				if err != nil || m.Withheld == nil || m.Entry != nil {
					t.Fatalf("a missing version must be withheld: %v %+v", err, m)
				}
			default:
				t.Fatalf("form %q has no test", row.Form)
			}
		})
	}
}

func TestEveryStyleCompiles(t *testing.T) {
	for name, p := range headingStyles {
		re, err := compileAnchored(p)
		if err != nil {
			t.Fatalf("heading style %s: %v", name, err)
		}
		if n := re.SubexpNames(); len(n) < 2 || n[1] != "version" || (len(n) != 2 && !(len(n) == 4 && n[2] == "slug" && (n[3] == "ref" || n[3] == "line"))) {
			t.Fatalf("heading style %s must have one capture named version", name)
		}
	}
	for name, p := range boundaryStyles {
		if _, err := compileAnchored(p); err != nil {
			t.Fatalf("boundary style %s: %v", name, err)
		}
	}
}

const goodFile = `{"schema":"prufyx.io/changelog-targets/v1","rows":[
{"component":"a","repo":"github.com/o/a","form":"changelog-file","path":"CHANGELOG.md","headingStyle":"version-slash-date","boundaryStyles":["main-unreleased"]},
{"component":"b","repo":"github.com/o/b","form":"post-tag"}]}`

func TestParseTargetsAcceptsGood(t *testing.T) {
	rows, err := parseTargets([]byte(goodFile))
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", err, rows)
	}
}

func TestParseTargetsRefusesEverythingOutsideTheSchema(t *testing.T) {
	row := func(extra string) string {
		return `{"schema":"prufyx.io/changelog-targets/v1","rows":[` + extra + `]}`
	}
	file := func(kv string) string {
		return row(`{"component":"a","repo":"github.com/o/a","form":"changelog-file",` + kv + `}`)
	}
	okFile := `"path":"CHANGELOG.md","headingStyle":"version-slash-date"`
	okB := okFile + `,"boundaryStyles":["main-unreleased"]`
	cases := map[string]string{
		"empty":                   ``,
		"not json":                `{`,
		"wrong schema":            `{"schema":"x","rows":[]}`,
		"no schema":               `{"rows":[]}`,
		"unknown top field":       `{"schema":"prufyx.io/changelog-targets/v1","rows":[],"x":1}`,
		"unknown row field":       file(okB + `,"headingPattern":"^(?P<version>x)$"`),
		"regex as heading style":  file(`"path":"CHANGELOG.md","headingStyle":"^(?P<version>[0-9.]+)$"`),
		"regex as boundary style": file(okFile + `,"boundaryStyles":["^main$"]`),
		"unknown heading style":   file(`"path":"CHANGELOG.md","headingStyle":"nope"`),
		"unknown boundary style":  file(okFile + `,"boundaryStyles":["nope"]`),
		"duplicate boundary":      file(okFile + `,"boundaryStyles":["main-unreleased","main-unreleased"]`),
		"file without style":      file(`"path":"CHANGELOG.md"`),
		"file without path":       file(`"headingStyle":"version-slash-date"`),
		"absolute path":           file(`"path":"/CHANGELOG.md","headingStyle":"version-slash-date"`),
		"dotdot path":             file(`"path":"../CHANGELOG.md","headingStyle":"version-slash-date"`),
		"unclean path":            file(`"path":"a/../CHANGELOG.md","headingStyle":"version-slash-date"`),
		"backslash path":          file(`"path":"a\\b.md","headingStyle":"version-slash-date"`),
		"duplicate key":           file(okB + `,"path":"OTHER.md"`),
		"templated form":          row(`{"component":"a","repo":"github.com/o/a","form":"changelog-per-line-file","path":"x/{line}.md","headingStyle":"version-slash-date"}`),
		"unknown form":            row(`{"component":"a","repo":"github.com/o/a","form":"file"}`),
		"post-tag with path":      row(`{"component":"a","repo":"github.com/o/a","form":"post-tag","path":"CHANGELOG.md"}`),
		"release with style":      row(`{"component":"a","repo":"github.com/o/a","form":"github-release","headingStyle":"version-slash-date"}`),
		"release with boundaries": row(`{"component":"a","repo":"github.com/o/a","form":"github-release","boundaryStyles":[]}`),
		"bad slug":                row(`{"component":"A","repo":"github.com/o/a","form":"post-tag"}`),
		"empty component":         row(`{"component":"","repo":"github.com/o/a","form":"post-tag"}`),
		"non-canonical repo":      row(`{"component":"a","repo":"github.com/O/a","form":"post-tag"}`),
		"repo with scheme":        row(`{"component":"a","repo":"https://github.com/o/a","form":"post-tag"}`),
		"repo twice":              row(`{"component":"a","repo":"github.com/o/a","form":"post-tag"},{"component":"b","repo":"github.com/o/a","form":"post-tag"}`),
		"no rows":                 row(``),
		"dot path":                file(`"path":".","headingStyle":"version-slash-date","boundaryStyles":["main-unreleased"]`),
		"dot slash path":          file(`"path":"./","headingStyle":"version-slash-date","boundaryStyles":["main-unreleased"]`),
		"directory path":          file(`"path":"docs/","headingStyle":"version-slash-date","boundaryStyles":["main-unreleased"]`),
		"empty boundary list":     file(okFile + `,"boundaryStyles":[]`),
		"no boundary styles":      file(okFile),
		"unsorted":                row(`{"component":"b","repo":"github.com/o/b","form":"post-tag"},{"component":"a","repo":"github.com/o/a","form":"post-tag"}`),
		"component twice":         row(`{"component":"a","repo":"github.com/o/a","form":"post-tag"},{"component":"a","repo":"github.com/o/b","form":"post-tag"}`),
		"data after the document": goodFile + ` {}`,
		"trailing garbage":        goodFile + `x`,
		"rows is not a list":      `{"schema":"prufyx.io/changelog-targets/v1","rows":{}}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			rows, err := parseTargets([]byte(data))
			if err == nil {
				t.Fatalf("accepted: %v", rows)
			}
			if rows != nil {
				t.Fatalf("returned rows with an error: %v", rows)
			}
		})
	}
}

func TestBadTableIsNotLoadedAndDigestRefuses(t *testing.T) {
	savedRows, savedErr := Reviewed, loadErr
	defer func() { Reviewed, loadErr = savedRows, savedErr }()
	Reviewed, loadErr = parseTargets([]byte(`{"schema":"x","rows":[]}`))
	if loadErr == nil || len(Reviewed) != 0 {
		t.Fatalf("a bad table loaded: %v %v", loadErr, Reviewed)
	}
	if _, err := Lookup(Reviewed, "vault"); err == nil {
		t.Fatal("a component was found in an unloaded table")
	}
	if _, err := CodeDigest(); err == nil {
		t.Fatal("a digest was given for code that loaded a bad table")
	}
}

func TestDigestCoversTargetsData(t *testing.T) {
	dir, files := SourceFiles()
	set, err := extract.CodeFiles(extract.SourceSet{Dir: dir, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range set {
		if strings.HasSuffix(f.Path, "/targets.json") {
			return
		}
	}
	t.Fatal("targets.json is not in the code digest")
}

func TestEmbeddedDataIsTheFileInTheSchema(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal(targetsJSON, &v); err != nil || v["schema"] != TargetsSchema {
		t.Fatalf("%v %v", err, v["schema"])
	}
}

func TestFileRowPathClosedAlphabet(t *testing.T) {
	for _, p := range []string{"docs/é.md", "a b/CHANGELOG.md", "x‮.md", "../CHANGELOG.md", "/CHANGELOG.md", "a..b.md", "a:b.md", "a{b}.md", "docs/a\tb.md"} {
		doc := `{"schema":"` + TargetsSchema + `","rows":[{"component":"x","repo":"github.com/o/x","form":"` + FormFile + `","path":` + jsonStr(p) + `,"headingStyle":"version-v-prefixed","boundaryStyles":["unreleased"]}]}`
		if _, err := parseTargets([]byte(doc)); err == nil {
			t.Errorf("path %q loaded", p)
		}
	}
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// rowsRechecked are the read-form rows whose fixtures were re-run over blobs
// fetched by pinned id and verified (PRUFYX_ROW_BLOBS), at exactly this row
// digest and fixture digest. It is reviewer-owned, like rowsBeforeData: a run
// without blobs passes a read-form row only when it is here and both digests
// still match, so a new row, a changed row or an edited fixture cannot pass
// offline and needs the blob re-run (or a reviewer who re-ran it and updates
// this list).
var rowsRechecked = map[string]RecheckedRow{
	"alertmanager": {RowDigest: "72ec19460e172522ea6203b6c0d2d67ce326131f1731bd0af83c4c865adaadda", FixtureDigest: "sha256:578e27e08e6116ea3272e05fbb1089a9876b39f772b35a32f2ba1b7eb5090e73"},
	"coredns":      {RowDigest: "d54713ca9a1ea2a3a6911f7c8e9d6e1a9221a96fd176611c5288230495bcc1eb", FixtureDigest: "sha256:322c6b4f119b46c2ad740e7e57a48f56e8955d871b8d9d2b95fe4aaeff0bed05"},
	"fluentd":      {RowDigest: "c04f56e65859dca17c627b3b0256da26474265b9f0297b5b6119449f5318d31f", FixtureDigest: "sha256:d48f51a269d8c407295d81380470be8487862dc58dfe1a4b74c6379bd16f7683"},
	"openfga":      {RowDigest: "8a448e38f6f8c0e976acb9077ccf0c80e00b383c1aa32efd81932ecf7302a0b6", FixtureDigest: "sha256:e193dd24074026a881dc9595b15e305d991b6db7ba34ccf0ebee9c62ab7650d6"},
	"prometheus":   {RowDigest: "d7d99823994415c019b8ade914dfea2b65d05e1edac8240eb76a826cce7b9ac7", FixtureDigest: "sha256:eff0f8dad6f786e841316143a70b0dc07f63e6b7d713ac094d6dd1ffc7851bba"},
	"traefik":      {RowDigest: "b228c9c1e0a454baaef4e5fd32a1b729c5324c9bafac5d39557af7a45f19cc71", FixtureDigest: "sha256:fb39b5f85cc3005573266bb27af0ea4c90be73a75f7c84547a2bd8377ccb916c"},
}

// TestShippedRowFixtures recomputes every row's fixture check: one fixture per
// row, no orphan, the row digest recomputed from targets.json (never read from
// a pin), an optional digest-only pins file compared against both. With the
// blobs supplied (PRUFYX_ROW_BLOBS, a directory of files named by blob id) the
// one reader is re-run over blobs fetched by pinned id and verified; a blob
// that does not verify fails the test. Without them the re-run is a visible
// skip, and a read-form row passes only when it is on rowsRechecked at the
// digests it was re-checked at (CheckRowsOffline).
func TestShippedRowFixtures(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	var pins []byte
	if b, err := os.ReadFile(filepath.Join("testdata", RowPinsFile)); err == nil {
		pins = b
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := CheckRowPins(pins, fixtures, digests); err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("PRUFYX_ROW_BLOBS")
	if dir == "" {
		if err := CheckRowsOffline(rows, digests, fixtures, rowsRechecked); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range rows {
		t.Run(row.Component, func(t *testing.T) {
			fx := fixtures[row.Component]
			if readsForm(row.Form) && fx.Status != RowPass {
				t.Fatalf("a read row without a passing fixture: %s", fx.Status)
			}
			if !readsForm(row.Form) {
				return
			}
			if dir == "" {
				t.Skip("PRUFYX_ROW_BLOBS is not set: the reader re-run over pinned blobs was not done; passing offline rests on rowsRechecked")
			}
			if err := RecheckRowFixture(fx, row, digests[row.Component], DirBlobFetcher{Dir: dir}, zeroDigest); err != nil {
				t.Fatal(err)
			}
		})
	}
}
