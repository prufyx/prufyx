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
}

func TestShippedTableLoads(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	if len(Reviewed) != len(rowsBeforeData) {
		t.Fatalf("%d rows, want %d", len(Reviewed), len(rowsBeforeData))
	}
	for _, want := range rowsBeforeData {
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
				file := "# Changelog\n\n## main / unreleased\n\n* [FEATURE] new\n\n" +
					strings.ReplaceAll("## 1.2.3 / 2026-01-02\n\n* [BUGFIX] fix\n\n", "", "") +
					"## 1.2.2 / 2025-12-01\n\n* [BUGFIX] older\n"
				unrel := "main / unreleased"
				if len(row.BoundaryPatterns) == 0 {
					t.Fatal("a file row has no boundary pattern")
				}
				if strings.Contains(row.BoundaryPatterns[0], `\(`) {
					unrel = "main / (unreleased)"
				}
				file = strings.Replace(file, "main / unreleased", unrel, 1)
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
		if n := re.SubexpNames(); len(n) < 2 || n[1] != "version" || (len(n) != 2 && !(len(n) == 4 && n[2] == "slug" && n[3] == "ref")) {
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

// TestShippedRowFixtures recomputes every row's fixture check: one fixture per
// row, no orphan, the row digest recomputed from targets.json (never read from
// a pin), an optional digest-only pins file compared against both. When the
// blobs are supplied (PRUFYX_ROW_BLOBS, a directory of files named by blob
// id), the one reader is re-run over blobs fetched by pinned id and verified;
// a blob that does not verify fails the test.
func TestShippedRowFixtures(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	digests, err := RowDigests()
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := LoadRowFixtures(os.DirFS("testdata"), RowFixtureDir, Reviewed, digests)
	if err != nil {
		t.Fatal(err)
	}
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
		t.Log("offline: fixture structure and row digests recomputed; blobs not supplied, reader re-run not done")
	}
	for _, row := range Reviewed {
		t.Run(row.Component, func(t *testing.T) {
			fx := fixtures[row.Component]
			if readsForm(row.Form) && fx.Status != RowPass {
				t.Fatalf("a read row without a passing fixture: %s", fx.Status)
			}
			if dir == "" {
				return
			}
			if err := RecheckRowFixture(fx, row, digests[row.Component], DirBlobFetcher{Dir: dir}, zeroDigest); err != nil {
				t.Fatal(err)
			}
		})
	}
}
