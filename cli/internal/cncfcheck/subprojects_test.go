// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenLandscapeFileSHA pins the bytes of the landscape copy: the overlay
// change must not touch it (nor the 255 count).
const goldenLandscapeFileSHA = "719482946c4f639e2b557aa1f5e4d3e961d21c49f8c4fa2bbd7f7f4e6aa19c4c"

// goldenSubprojectsFileDigest pins the overlay file: any row change needs a
// reviewed, owner-signed change that also edits this constant.
const goldenSubprojectsFileDigest = "sha256:2da3b11a5f7bc91325d4901c3564b967234eb26bd94ac99e57d926b3b2ca8e0e"

func readData(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("data", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func landscapeNeighbours(t *testing.T) SubprojectNeighbours {
	t.Helper()
	var doc struct {
		Projects []struct {
			Slug          string `json:"slug"`
			RepositoryURL string `json:"repositoryURL"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(readData(t, "landscape-projects.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Projects) != 255 {
		t.Fatalf("landscape copy has %d rows, want 255", len(doc.Projects))
	}
	n := SubprojectNeighbours{Landscape: map[string]string{}, OtherSlugs: map[string]bool{}, OtherRepos: map[string]bool{}}
	for _, p := range doc.Projects {
		n.Landscape[p.Slug] = p.RepositoryURL
	}
	return n
}

// mutate decodes the committed file, applies f to the overlay, re-seals the
// rows digest (so only the rule under test fails) and loads it.
func mutate(t *testing.T, n SubprojectNeighbours, f func(o *SubprojectOverlay)) error {
	t.Helper()
	var o SubprojectOverlay
	if err := json.Unmarshal(readData(t, "cncf-subprojects.json"), &o); err != nil {
		t.Fatal(err)
	}
	f(&o)
	d, err := SubprojectsRowsDigest(o.Rows)
	if err != nil {
		t.Fatal(err)
	}
	o.RowsDigest = d
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadSubprojects(raw, n)
	return err
}

func wantKind(t *testing.T, err error, kind string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s refusal, got nil", kind)
	}
	var se *SubprojectError
	if !errors.As(err, &se) || se.Kind != kind || !errors.Is(err, ErrSubprojectIntegrity) {
		t.Fatalf("want %s integrity refusal, got %v", kind, err)
	}
}

func TestSubprojectsCommittedFileLoads(t *testing.T) {
	raw := readData(t, "cncf-subprojects.json")
	if got := SubprojectsFileDigest(raw); got != goldenSubprojectsFileDigest {
		t.Fatalf("overlay file digest %s changed (golden %s)", got, goldenSubprojectsFileDigest)
	}
	o, err := LoadSubprojects(raw, landscapeNeighbours(t))
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	for _, r := range o.Rows {
		slugs = append(slugs, r.Slug)
	}
	if strings.Join(slugs, ",") != "argo-workflows,cluster-autoscaler,external-dns" {
		t.Fatalf("rows %v; opentelemetry must not be a row", slugs)
	}
	for _, r := range o.Rows {
		if r.Slug == "argo-workflows" && r.Governance.SourceKind != SourceKindReadme {
			t.Error("argo-workflows must be sourceKind readme")
		}
		if r.Slug == "cluster-autoscaler" && (r.RepoPath != "cluster-autoscaler" || r.RepositoryURL != "https://github.com/kubernetes/autoscaler") {
			t.Error("cluster-autoscaler must be the monorepo with its repoPath")
		}
	}
}

// The landscape copy, its 255 rows and the pack are untouched.
func TestSubprojectsLandscapeUntouched(t *testing.T) {
	sum := sha256.Sum256(readData(t, "landscape-projects.json"))
	if hex.EncodeToString(sum[:]) != goldenLandscapeFileSHA {
		t.Fatal("landscape-projects.json changed")
	}
	landscapeNeighbours(t) // asserts 255
	for _, p := range []string{"argo-workflows", "cluster-autoscaler", "external-dns"} {
		if _, ok := landscapeNeighbours(t).Landscape[p]; ok {
			t.Errorf("%s is already a landscape slug", p)
		}
	}
}

func TestSubprojectsRefusals(t *testing.T) {
	n := landscapeNeighbours(t)
	raw := readData(t, "cncf-subprojects.json")
	t.Run("unknown field", func(t *testing.T) {
		bad := strings.Replace(string(raw), `"parent": "argo-cd",`, `"parent": "argo-cd", "stage": "graduated",`, 1)
		_, err := LoadSubprojects([]byte(bad), n)
		wantKind(t, err, KindDecode)
	})
	t.Run("trailing data", func(t *testing.T) {
		_, err := LoadSubprojects(append(append([]byte{}, raw...), []byte("{}")...), n)
		wantKind(t, err, KindDecode)
	})
	t.Run("digest binding: a changed byte", func(t *testing.T) {
		bad := strings.Replace(string(raw), `"name": "ExternalDNS"`, `"name": "ExternalDNs"`, 1)
		_, err := LoadSubprojects([]byte(bad), n)
		wantKind(t, err, KindDigest)
	})
	t.Run("schema", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Schema = "x" }), KindSchema)
	})
	t.Run("no rows", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows = nil }), KindField)
	})
	t.Run("unsorted", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[0], o.Rows[1] = o.Rows[1], o.Rows[0] }), KindOrder)
	})
	t.Run("duplicate slug", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[1] = o.Rows[0] }), KindOrder)
	})
	t.Run("parent missing", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[0].Parent = "no-such-project" }), KindParent)
	})
	t.Run("parent is not landscape", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[0].Parent = "external-dns" }), KindParent)
	})
	t.Run("slug equals a landscape slug", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[0].Slug = "argo-cd" }), KindSlugClash)
	})
	t.Run("slug equals another known slug", func(t *testing.T) {
		m := landscapeNeighbours(t)
		m.OtherSlugs["external-dns"] = true
		wantKind(t, mutate(t, m, func(o *SubprojectOverlay) {}), KindSlugClash)
	})
	t.Run("repo equals a landscape repo", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) {
			o.Rows[0].RepositoryURL = "https://github.com/argoproj/argo-cd"
			o.Rows[0].License.Source = GitHubRawURL("argoproj/argo-cd", o.Rows[0].LicenseCommit, "LICENSE")
		}), KindRepoClash)
	})
	t.Run("repo equals another known repo", func(t *testing.T) {
		m := landscapeNeighbours(t)
		m.OtherRepos["https://github.com/kubernetes-sigs/external-dns"] = true
		wantKind(t, mutate(t, m, func(o *SubprojectOverlay) {}), KindRepoClash)
	})
	t.Run("same repo and path twice", func(t *testing.T) {
		wantKind(t, mutate(t, n, func(o *SubprojectOverlay) {
			o.Rows[2] = o.Rows[1]
			o.Rows[2].Slug = "zz-second"
		}), KindRepoClash)
	})
	for name, f := range map[string]func(r *SubprojectRow){
		"http url":          func(r *SubprojectRow) { r.RepositoryURL = "http://github.com/a/b" },
		"upper-case repo":   func(r *SubprojectRow) { r.RepositoryURL = "https://github.com/A/b" },
		"git suffix":        func(r *SubprojectRow) { r.RepositoryURL = "https://github.com/a/b.git" },
		"other host":        func(r *SubprojectRow) { r.RepositoryURL = "https://gitlab.com/a/b" },
		"userinfo":          func(r *SubprojectRow) { r.RepositoryURL = "https://u@github.com/a/b" },
		"query":             func(r *SubprojectRow) { r.RepositoryURL = "https://github.com/a/b?x=1" },
		"empty name":        func(r *SubprojectRow) { r.Name = "" },
		"bad slug":          func(r *SubprojectRow) { r.Slug = "zz_bad" },
		"repoPath dotdot":   func(r *SubprojectRow) { r.RepoPath = "a/../b" },
		"repoPath absolute": func(r *SubprojectRow) { r.RepoPath = "/a" },
	} {
		f := f
		t.Run(name, func(t *testing.T) {
			wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { f(&o.Rows[2]) }), KindField)
		})
	}
	for name, f := range map[string]func(r *SubprojectRow){
		"short commit":   func(r *SubprojectRow) { r.Governance.Commit = "e5a0e974" },
		"bad line sha":   func(r *SubprojectRow) { r.Governance.LineSHA256 = "abc" },
		"inverted lines": func(r *SubprojectRow) { r.Governance.Line, r.Governance.LineEnd = 9, 3 },
		"zero line":      func(r *SubprojectRow) { r.Governance.Line = 0 },
		"huge range":     func(r *SubprojectRow) { r.Governance.LineEnd = r.Governance.Line + 500 },
		"empty marker":   func(r *SubprojectRow) { r.Governance.EntryMarker = "" },
		"untrimmed mark": func(r *SubprojectRow) { r.Governance.EntryMarker = " " + r.Governance.EntryMarker },
		"url other host": func(r *SubprojectRow) { r.Governance.URL = "https://evil.example/kubernetes/community/x/sigs.yaml" },
		"url other file": func(r *SubprojectRow) { r.Governance.File = "other.yaml" },
		"url branch ref": func(r *SubprojectRow) {
			r.Governance.URL = "https://raw.githubusercontent.com/kubernetes/community/master/sigs.yaml"
		},
		"url with query": func(r *SubprojectRow) { r.Governance.URL += "?x=1" },
		"file traversal": func(r *SubprojectRow) { r.Governance.File = "../sigs.yaml" },
	} {
		f := f
		t.Run(name, func(t *testing.T) {
			wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { f(&o.Rows[2]) }), KindCitation)
		})
	}
	for _, kind := range []string{"", "blog", "Governance"} {
		kind := kind
		t.Run("source kind "+kind, func(t *testing.T) {
			wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { o.Rows[2].Governance.SourceKind = kind }), KindSourceKind)
		})
	}
	for name, f := range map[string]func(r *SubprojectRow){
		"unsupported spdx": func(r *SubprojectRow) { r.License.SPDX = "MIT" },
		"bad spdx":         func(r *SubprojectRow) { r.License.SPDX = "Apache 2" },
		"short blob":       func(r *SubprojectRow) { r.License.BlobSHA = "8dada3ed" },
		"short commit":     func(r *SubprojectRow) { r.LicenseCommit = "fcb24158" },
		"source other repo": func(r *SubprojectRow) {
			r.License.Source = strings.Replace(r.License.Source, "external-dns", "other", 1)
		},
		"source other commit": func(r *SubprojectRow) {
			r.License.Source = strings.Replace(r.License.Source, r.LicenseCommit, strings.Repeat("a", 40), 1)
		},
		"source not a license": func(r *SubprojectRow) {
			r.License.Source = strings.Replace(r.License.Source, "LICENSE.md", "README.md", 1)
		},
		"source other host": func(r *SubprojectRow) {
			r.License.Source = strings.Replace(r.License.Source, "raw.githubusercontent.com", "example.com", 1)
		},
	} {
		f := f
		t.Run(name, func(t *testing.T) {
			wantKind(t, mutate(t, n, func(o *SubprojectOverlay) { f(&o.Rows[2]) }), KindLicense)
		})
	}
}

func TestCheckCitedLines(t *testing.T) {
	sigs := "      - name: external-dns\n        contact:\n          slack: external-dns\n        owners:\n          - https://raw.githubusercontent.com/kubernetes-sigs/external-dns/master/OWNERS\n"
	row := SubprojectRow{Slug: "external-dns", RepositoryURL: "https://github.com/kubernetes-sigs/external-dns",
		Governance: SubprojectGovernance{LineEnd: 5, Line: 1, EntryMarker: "- name: external-dns"}}
	text, lines, ok := CitedLines([]byte(sigs), 1, 5)
	if !ok {
		t.Fatal("lines")
	}
	row.Governance.LineSHA256 = CitedLinesDigest(text)
	if err := CheckCitedLines(row, text, lines); err != nil {
		t.Fatal(err)
	}
	// wrong sha
	bad := row
	bad.Governance.LineSHA256 = strings.Repeat("0", 64)
	wantKind(t, CheckCitedLines(bad, text, lines), KindCitation)
	// marker absent
	bad = row
	bad.Governance.EntryMarker = "- name: other"
	wantKind(t, CheckCitedLines(bad, text, lines), KindCitation)
	// repo not listed under the entry
	bad = row
	bad.RepositoryURL = "https://github.com/kubernetes-sigs/other"
	wantKind(t, CheckCitedLines(bad, text, lines), KindCitation)
	// a prefix of a longer repo name is not a listing
	bad = row
	bad.RepositoryURL = "https://github.com/kubernetes-sigs/external"
	wantKind(t, CheckCitedLines(bad, text, lines), KindCitation)
	// the repo is listed only before the marker
	text2, lines2, _ := CitedLines([]byte("- https://raw.githubusercontent.com/kubernetes-sigs/external-dns/master/OWNERS\n- name: external-dns\n"), 1, 2)
	bad = row
	bad.Governance.LineSHA256 = CitedLinesDigest(text2)
	wantKind(t, CheckCitedLines(bad, text2, lines2), KindCitation)
	// repoPath rows need the path on the listing line
	mono, monoLines, _ := CitedLines([]byte("- name: cluster-autoscaler\n  - https://raw.githubusercontent.com/kubernetes/autoscaler/master/vertical-pod-autoscaler/OWNERS\n"), 1, 2)
	crow := SubprojectRow{Slug: "cluster-autoscaler", RepositoryURL: "https://github.com/kubernetes/autoscaler", RepoPath: "cluster-autoscaler",
		Governance: SubprojectGovernance{EntryMarker: "- name: cluster-autoscaler", LineSHA256: CitedLinesDigest(mono)}}
	wantKind(t, CheckCitedLines(crow, mono, monoLines), KindCitation)
	// out-of-range lines
	if _, _, ok := CitedLines([]byte("a\n"), 1, 3); ok {
		t.Fatal("range beyond the file accepted")
	}
}

// No generator, export or bot may write the overlay file: only the files
// below may even name it, and none of them calls a write API.
func TestSubprojectsNoWriterPath(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	allowed := map[string]bool{
		"cli/internal/cncfcheck/subprojects.go":                            true,
		"cli/internal/cncfcheck/subprojects_test.go":                       true,
		"cli/cmd/prufyx-maintainer/subprojects.go":                         true,
		"cli/cmd/prufyx-maintainer/subprojects_test.go":                    true,
		"cli/internal/maintainer/knowledgegate/gate_paths.go":              true,
		"cli/internal/maintainer/knowledgegate/gate_paths_test.go":         true,
		"cli/internal/maintainer/knowledgepacket/classify.go":              true,
		"cli/internal/maintainer/knowledgepacket/classify_overlay_test.go": true,
	}
	writeAPIs := []string{"os.WriteFile", "ioutil.WriteFile", "os.Create", "os.OpenFile", "os.Rename", "os.Truncate", "os.Remove"}
	found := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".git" || rel == "cli/vendor" || strings.HasSuffix(rel, "/node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if rel == SubprojectsFile {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(raw), "cncf-subprojects.json") {
			return nil
		}
		if !allowed[rel] {
			t.Errorf("%s names the overlay file but is not an allowed reader: a generator, export or workflow must not write it", rel)
			return nil
		}
		found++
		if strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, "gate_paths.go") || strings.HasSuffix(rel, "classify.go") {
			return nil
		}
		for _, api := range writeAPIs {
			if strings.Contains(string(raw), api) {
				t.Errorf("%s names the overlay file and calls %s", rel, api)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no reader found; the guard walks the wrong tree")
	}
}
