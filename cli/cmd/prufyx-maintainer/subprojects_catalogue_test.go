// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func catalogueFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join("..", "..", "..")
	for _, name := range []string{catalogueLandscapeFile, catalogueTableFile, cncfcheck.SubprojectsFile} {
		raw, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		catalogueWrite(t, root, name, raw)
	}
	entries, err := os.ReadDir(filepath.Join(source, catalogueTargetsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "target-") && strings.HasSuffix(entry.Name(), ".json") {
			name := catalogueTargetsDir + "/" + entry.Name()
			raw, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				t.Fatal(err)
			}
			catalogueWrite(t, root, name, raw)
		}
	}
	return root
}
func catalogueWrite(t *testing.T, root, name string, raw []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func catalogueRead(t *testing.T, root, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(root, name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func catalogueEdit(t *testing.T, root, name string, edit func(map[string]any)) {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(catalogueRead(t, root, name), &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	catalogueWrite(t, root, name, b)
}
func TestSubprojectsCatalogueRealSnapshot(t *testing.T) {
	root := catalogueFixture(t)
	old := http.DefaultTransport
	http.DefaultTransport = denyCatalogueNetwork{t}
	defer func() { http.DefaultTransport = old }()
	var out, again bytes.Buffer
	if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runSubprojects([]string{"catalogue", "--root", root}, &again); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("non-deterministic catalogue")
	}
	var got subprojectCatalogue
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "prufyx.io/cncf-subproject-catalogue/v1" || got.OverlayState != "present" || len(got.Rows) != 3 {
		t.Fatalf("unexpected catalogue: %+v", got)
	}
	if got.Rows[0].Slug != "argo-workflows" || got.Rows[1].RepoPath != "cluster-autoscaler" {
		t.Fatalf("wrong approved identities: %+v", got.Rows)
	}
	raw := catalogueRead(t, root, cncfcheck.SubprojectsFile)
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got.InputDigests.Overlay == nil || *got.InputDigests.Overlay != want {
		t.Fatal("not bound to actual overlay bytes")
	}
	// Whitespace mutation changes the input identity even when semantics agree.
	catalogueWrite(t, root, cncfcheck.SubprojectsFile, append(raw, '\n'))
	again.Reset()
	if err := runSubprojects([]string{"catalogue", "--root", root}, &again); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("source mutation retained old digest")
	}
}

type denyCatalogueNetwork struct{ t *testing.T }

func (d denyCatalogueNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	d.t.Fatal("offline catalogue attempted HTTP")
	return nil, nil
}
func TestSubprojectsCatalogueAbsenceAndCompleteTargets(t *testing.T) {
	root := catalogueFixture(t)
	if err := os.Remove(filepath.Join(root, cncfcheck.SubprojectsFile)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err != nil {
		t.Fatal(err)
	}
	var got subprojectCatalogue
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.OverlayState != "absent" || got.InputDigests.Overlay != nil || len(got.Rows) != 0 || got.Rows == nil {
		t.Fatalf("bad legacy absence: %+v", got)
	}
	original := got.InputDigests.Targets
	target := catalogueTargetsDir + "/target-cilium.json"
	raw := catalogueRead(t, root, target)
	catalogueWrite(t, root, target, append(raw, '\n'))
	out.Reset()
	if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.InputDigests.Targets == original {
		t.Fatal("target bytes omitted from digest")
	}
	// An invalid final member must fail even with absent overlay; no partial listing.
	catalogueWrite(t, root, catalogueTargetsDir+"/target-zz-invalid.json", []byte(`{}`))
	out.Reset()
	if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err == nil || out.Len() != 0 {
		t.Fatal("invalid enumerated member accepted")
	}
}
func TestSubprojectsCatalogueRefusals(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"overlay-digest": func(t *testing.T, r string) {
			catalogueEdit(t, r, cncfcheck.SubprojectsFile, func(v map[string]any) { v["rowsDigest"] = "sha256:" + strings.Repeat("0", 64) })
		},
		"overlay-duplicate-key": func(t *testing.T, r string) {
			b := catalogueRead(t, r, cncfcheck.SubprojectsFile)
			b = bytes.Replace(b, []byte(`"schema":`), []byte(`"schema":"forged", "schema":`), 1)
			catalogueWrite(t, r, cncfcheck.SubprojectsFile, b)
		},
		"hidden-landscape-duplicate": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueLandscapeFile, func(v map[string]any) {
				rows := v["projects"].([]any)
				rows = append(rows, rows[5])
				v["projects"] = rows
			})
		},
		"target-missing-member": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueTargetsDir+"/target-cilium.json", func(v map[string]any) { delete(v["target"].(map[string]any), "repo") })
		},
		"target-duplicate-case": func(t *testing.T, r string) {
			p := catalogueTargetsDir + "/target-cilium.json"
			b := catalogueRead(t, r, p)
			b = bytes.Replace(b, []byte(`"repo":`), []byte(`"Repo":"github.com/forged/forged", "repo":`), 1)
			catalogueWrite(t, r, p, b)
		},
		"target-missing-exclude": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueTargetsDir+"/target-cilium.json", func(v map[string]any) { delete(v["target"].(map[string]any), "exclude") })
		},
		"table-unknown": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueTableFile, func(v map[string]any) { v["unknown"] = true })
		},
		"missing-landscape": func(t *testing.T, r string) {
			if err := os.Remove(filepath.Join(r, catalogueLandscapeFile)); err != nil {
				t.Fatal(err)
			}
		},
		"missing-target-directory": func(t *testing.T, r string) {
			if err := os.RemoveAll(filepath.Join(r, catalogueTargetsDir)); err != nil {
				t.Fatal(err)
			}
		},
		"overlay-directory": func(t *testing.T, r string) {
			p := filepath.Join(r, cncfcheck.SubprojectsFile)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-parent": func(t *testing.T, r string) {
			p := filepath.Join(r, "cli/internal/cncfcheck")
			if err := os.Rename(p, p+"-real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("cncfcheck-real", p); err != nil {
				t.Fatal(err)
			}
		},
		"oversized-overlay": func(t *testing.T, r string) {
			catalogueWrite(t, r, cncfcheck.SubprojectsFile, bytes.Repeat([]byte(" "), catalogueMaxFile+1))
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			root := catalogueFixture(t)
			change(t, root)
			var out bytes.Buffer
			err := runSubprojects([]string{"catalogue", "--root", root}, &out)
			if err == nil || out.Len() != 0 {
				t.Fatalf("refusal required: err=%v stdout=%s", err, out.Bytes())
			}
			var ce *commandError
			if !errors.As(err, &ce) || ce.code != 1 {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

func catalogueOverlayChange(t *testing.T, root string, change func(*cncfcheck.SubprojectOverlay)) {
	t.Helper()
	var doc cncfcheck.SubprojectOverlay
	if err := json.Unmarshal(catalogueRead(t, root, cncfcheck.SubprojectsFile), &doc); err != nil {
		t.Fatal(err)
	}
	change(&doc)
	var err error
	doc.RowsDigest, err = cncfcheck.SubprojectsRowsDigest(doc.Rows)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	catalogueWrite(t, root, cncfcheck.SubprojectsFile, raw)
}
func TestSubprojectsCatalogueIdentityClosure(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"missing-parent": func(t *testing.T, r string) {
			catalogueOverlayChange(t, r, func(d *cncfcheck.SubprojectOverlay) { d.Rows[0].Parent = "missing-parent" })
		},
		"landscape-repository-collision": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueLandscapeFile, func(v map[string]any) {
				v["projects"].([]any)[0].(map[string]any)["repositoryURL"] = "https://github.com/argoproj/argo-workflows"
			})
		},
		"target-table-conflict": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueTargetsDir+"/target-cilium.json", func(v map[string]any) {
				x := v["target"].(map[string]any)
				x["repo"] = "github.com/different/repository"
				x["component"] = "pkg:github/different/repository"
			})
		},
		"target-fact-conflict": func(t *testing.T, r string) {
			catalogueEdit(t, r, catalogueTargetsDir+"/target-cilium.json", func(v map[string]any) { v["target"].(map[string]any)["factProject"] = "argo-cd" })
		},
		"ambiguous-monorepo": func(t *testing.T, r string) {
			catalogueOverlayChange(t, r, func(d *cncfcheck.SubprojectOverlay) {
				x := d.Rows[2]
				x.Slug = "zz-another"
				x.RepoPath = "another"
				d.Rows = append(d.Rows, x)
			})
		},
		"output-bound": func(t *testing.T, r string) {
			catalogueOverlayChange(t, r, func(d *cncfcheck.SubprojectOverlay) { d.Rows[0].Name = strings.Repeat("x", catalogueMaxOutput) })
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := catalogueFixture(t)
			change(t, r)
			var out bytes.Buffer
			if err := runSubprojects([]string{"catalogue", "--root", r}, &out); err == nil || out.Len() != 0 {
				t.Fatalf("closure refusal missing: err=%v outputBytes=%d", err, out.Len())
			}
		})
	}
}
func TestSubprojectsCatalogueKnownExactIdentity(t *testing.T) {
	r := catalogueFixture(t)
	// A reviewed table row can already name a subproject. Only its exact
	// identity is removed from neighbours; changing the repo must still refuse.
	var table struct {
		Projects []struct {
			Slug     string `json:"slug"`
			Catalog  string `json:"catalog"`
			Upstream struct {
				Repository string `json:"repository"`
			} `json:"upstream"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(catalogueRead(t, r, catalogueTableFile), &table); err != nil {
		t.Fatal(err)
	}
	slug, repo := "", ""
	for _, p := range table.Projects {
		if p.Catalog == "community" {
			slug = p.Slug
			repo = p.Upstream.Repository
			break
		}
	}
	if slug == "" {
		t.Fatal("no canonical community fixture")
	}
	catalogueOverlayChange(t, r, func(d *cncfcheck.SubprojectOverlay) {
		x := d.Rows[0]
		x.Slug = slug
		x.RepositoryURL = repo
		x.License.Source = "https://raw.githubusercontent.com/" + strings.TrimPrefix(repo, "https://github.com/") + "/" + x.LicenseCommit + "/LICENSE"
		d.Rows = []cncfcheck.SubprojectRow{x}
	})
	var out bytes.Buffer
	if err := runSubprojects([]string{"catalogue", "--root", r}, &out); err != nil {
		t.Fatal(err)
	}
	catalogueOverlayChange(t, r, func(d *cncfcheck.SubprojectOverlay) {
		x := &d.Rows[0]
		x.RepositoryURL = "https://github.com/forged/repository"
		x.License.Source = "https://raw.githubusercontent.com/forged/repository/" + x.LicenseCommit + "/LICENSE"
	})
	out.Reset()
	if err := runSubprojects([]string{"catalogue", "--root", r}, &out); err == nil || out.Len() != 0 {
		t.Fatalf("mismatched known identity accepted: %v", err)
	}
}
func TestSubprojectsCatalogueUsage(t *testing.T) {
	for _, args := range [][]string{{"catalogue"}, {"catalogue", "--root", ".", "extra"}, {"catalogue", "--unknown"}} {
		var out bytes.Buffer
		err := runSubprojects(args, &out)
		var ce *commandError
		if !errors.As(err, &ce) || ce.code != 2 || out.Len() != 0 {
			t.Fatalf("args=%v err=%v stdout=%s", args, err, out.String())
		}
	}
}

func TestSubprojectsCatalogueRejectsRepositoryAliases(t *testing.T) {
	for _, alias := range []string{"https://github.com/argoproj/argo-workflows.git", "https://github.com/argoproj/argo-workflows/", "https://github.com/argoproj/argo%2Dworkflows", "https://github.com:443/argoproj/argo-workflows", "https://github.com/argoproj/argo-workflows?ref=main"} {
		t.Run(alias, func(t *testing.T) {
			root := catalogueFixture(t)
			catalogueEdit(t, root, catalogueLandscapeFile, func(v map[string]any) { v["projects"].([]any)[0].(map[string]any)["repositoryURL"] = alias })
			var out bytes.Buffer
			if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err == nil || out.Len() != 0 {
				t.Fatalf("aliased overlay repo under another slug accepted: err=%v stdoutBytes=%d", err, out.Len())
			}
		})
	}
	for _, repo := range []string{"argoproj/argo-workflows.git", "argoproj/argo-workflows/", "argoproj/argo%2Dworkflows", "argoproj/../argo-workflows", "argoproj/ARGO-workflows"} {
		t.Run("table-"+repo, func(t *testing.T) {
			root := catalogueFixture(t)
			catalogueEdit(t, root, catalogueTableFile, func(v map[string]any) {
				v["projects"] = append(v["projects"].([]any), map[string]any{"slug": "zz-overlay-alias", "catalog": "cncf", "factProject": "zz_overlay_alias", "component": "pkg:github/" + repo, "groups": []any{map[string]any{"name": "alias.example.io", "source": "https://github.com/argoproj/argo-workflows/blob/0123456789abcdef0123456789abcdef01234567/crds/alias.yaml"}}})
			})
			var out bytes.Buffer
			if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err == nil || out.Len() != 0 {
				t.Fatalf("noncanonical table identity accepted: err=%v stdoutBytes=%d", err, out.Len())
			}
		})
	}
}
func TestSubprojectsCatalogueFIFOReplacementDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	name := "input.json"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the exact race window after the regular-file precheck.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := catalogueReadCheckedFile(root, name, before); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO replacement accepted")
		}
	case <-time.After(500 * time.Millisecond):
		// Release the old blocking reader so a regression fails without leaving
		// a stuck goroutine or a fixture that cannot be removed.
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("reader remained blocked after FIFO release")
		}
		t.Fatal("FIFO replacement blocked descriptor acquisition")
	}
	fixture := catalogueFixture(t)
	overlay := filepath.Join(fixture, cncfcheck.SubprojectsFile)
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(overlay, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSubprojects([]string{"catalogue", "--root", fixture}, &out); err == nil || out.Len() != 0 {
		t.Fatalf("FIFO emitted output: err=%v bytes=%d", err, out.Len())
	}
}

func TestSubprojectsCatalogueDescriptorRejectsReplacementLinks(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent=%t", parent), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "parent"), 0700); err != nil {
				t.Fatal(err)
			}
			name := "parent/input.json"
			original := filepath.Join(dir, name)
			if err := os.WriteFile(original, []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			before, err := root.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			if parent {
				if err := os.Rename(filepath.Join(dir, "parent"), filepath.Join(dir, "moved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("moved", filepath.Join(dir, "parent")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(original, filepath.Join(dir, "parent/kept.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("kept.json", original); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := catalogueReadCheckedFile(root, name, before); err == nil {
				t.Fatal("link replacement accepted despite held original inode")
			}
		})
	}
}
func TestSubprojectsCataloguePreservesTypedLandscapeURLs(t *testing.T) {
	// The real fixture also includes CoHDI's organization URL, mixed-case
	// GitHub paths and an archived null repository; none grants an alias.
	for _, repo := range []string{"https://github.com/ExampleOrg/ExampleRepo", "https://github.com/ExampleOrg", "https://gitlab.com/example/project"} {
		t.Run(repo, func(t *testing.T) {
			root := catalogueFixture(t)
			catalogueEdit(t, root, catalogueLandscapeFile, func(v map[string]any) { v["projects"].([]any)[0].(map[string]any)["repositoryURL"] = repo })
			var out bytes.Buffer
			if err := runSubprojects([]string{"catalogue", "--root", root}, &out); err != nil {
				t.Fatal(err)
			}
			var result subprojectCatalogue
			if err := json.Unmarshal(out.Bytes(), &result); err != nil || len(result.Rows) != 3 {
				t.Fatalf("typed landscape changed: %+v %v", result, err)
			}
		})
	}
}
