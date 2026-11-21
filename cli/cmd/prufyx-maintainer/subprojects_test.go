// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const (
	fxCommit  = "e5a0e974e6a15c8f2099eaa65b4529e94a281815"
	fxLicense = "fcb24158b0af22c32299d8123eadece67f82df84"
	fxSigs    = "- name: other\n  owners:\n    - https://raw.githubusercontent.com/kubernetes-sigs/other/master/OWNERS\n- name: external-dns\n  contact:\n    slack: external-dns\n  owners:\n    - https://raw.githubusercontent.com/kubernetes-sigs/external-dns/master/OWNERS\n- name: next\n"
	fxLicBody = "                                 Apache License\n                           Version 2.0, January 2004\n"
)

// world is a fixture raw host and a repository root holding an overlay whose
// citations match the fixture content.
type world struct {
	mu    sync.Mutex
	files map[string]string // URL path -> body
	redir map[string]bool
	root  string
	srv   *httptest.Server
	row   cncfcheck.SubprojectRow
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{files: map[string]string{}, redir: map[string]bool{}, root: t.TempDir()}
	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.redir[r.URL.Path] {
			http.Redirect(rw, r, "https://example.invalid/elsewhere", http.StatusFound)
			return
		}
		body, ok := w.files[r.URL.Path]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(w.srv.Close)
	dataDir := filepath.Join(w.root, "cli", "internal", "cncfcheck", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	landscape, err := os.ReadFile(filepath.Join("..", "..", "internal", "cncfcheck", "data", "landscape-projects.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "landscape-projects.json"), landscape, 0o644); err != nil {
		t.Fatal(err)
	}
	w.files["/kubernetes/community/"+fxCommit+"/sigs.yaml"] = fxSigs
	w.files["/kubernetes-sigs/external-dns/"+fxLicense+"/LICENSE.md"] = fxLicBody
	text, _, ok := cncfcheck.CitedLines([]byte(fxSigs), 4, 8)
	if !ok {
		t.Fatal("fixture lines")
	}
	blob := gitBlobSHA([]byte(fxLicBody))
	w.row = cncfcheck.SubprojectRow{
		Slug: "external-dns", Name: "ExternalDNS", RepositoryURL: "https://github.com/kubernetes-sigs/external-dns", Parent: "kubernetes",
		Governance: cncfcheck.SubprojectGovernance{
			URL: cncfcheck.GitHubRawURL("kubernetes/community", fxCommit, "sigs.yaml"), Commit: fxCommit, File: "sigs.yaml", Line: 4, LineEnd: 8,
			LineSHA256: cncfcheck.CitedLinesDigest(text), EntryMarker: "- name: external-dns", SourceKind: cncfcheck.SourceKindGovernance,
		},
		License:       cncfcheck.SubprojectLicense{SPDX: "Apache-2.0", Source: cncfcheck.GitHubRawURL("kubernetes-sigs/external-dns", fxLicense, "LICENSE.md"), BlobSHA: blob},
		LicenseCommit: fxLicense,
	}
	w.write(t, w.row)
	return w
}

func (w *world) write(t *testing.T, row cncfcheck.SubprojectRow) {
	t.Helper()
	rows := []cncfcheck.SubprojectRow{row}
	digest, err := cncfcheck.SubprojectsRowsDigest(rows)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cncfcheck.SubprojectOverlay{Schema: cncfcheck.SubprojectsSchema, Rows: rows, RowsDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.root, "cli", "internal", "cncfcheck", "data", "cncf-subprojects.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

type rewrite struct{ srv *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	target, _ := url.Parse(r.srv.URL)
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
	return r.srv.Client().Transport.RoundTrip(clone)
}

func (w *world) verify(t *testing.T) (bool, string, error) {
	t.Helper()
	client := &http.Client{Transport: rewrite{w.srv}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var out bytes.Buffer
	ok, err := verifySubprojects(context.Background(), w.root, &rawFetcher{client: client}, &out)
	return ok, out.String(), err
}

func TestSubprojectsVerifyOK(t *testing.T) {
	w := newWorld(t)
	ok, out, err := w.verify(t)
	if err != nil || !ok || !strings.Contains(out, "subprojects verify: OK rows=1 failed=0") || !strings.Contains(out, "marker=found") {
		t.Fatalf("ok=%v err=%v out=%s", ok, err, out)
	}
}

func TestSubprojectsVerifyRefuses(t *testing.T) {
	sigsPath := "/kubernetes/community/" + fxCommit + "/sigs.yaml"
	licPath := "/kubernetes-sigs/external-dns/" + fxLicense + "/LICENSE.md"
	cases := map[string]func(t *testing.T, w *world){
		"line shifted": func(t *testing.T, w *world) { w.files[sigsPath] = "- name: added-above\n" + fxSigs },
		"repo absent from the lines": func(t *testing.T, w *world) {
			w.files[sigsPath] = strings.ReplaceAll(fxSigs, "kubernetes-sigs/external-dns", "kubernetes-sigs/other-dns")
		},
		"entry marker missing": func(t *testing.T, w *world) {
			w.files[sigsPath] = strings.Replace(fxSigs, "- name: external-dns", "- name: external-dns-x", 1)
		},
		"repo listed under another entry": func(t *testing.T, w *world) {
			// the listing moves before the marker line
			w.files[sigsPath] = "- https://raw.githubusercontent.com/kubernetes-sigs/external-dns/master/OWNERS\n- x\n- y\n- name: external-dns\n- z\n- n\n- m\n- k\n"
		},
		"wrong committed sha": func(t *testing.T, w *world) {
			w.row.Governance.LineSHA256 = strings.Repeat("0", 64)
			w.write(t, w.row)
		},
		"lines beyond the file": func(t *testing.T, w *world) { w.files[sigsPath] = "- name: external-dns\n" },
		"license blob mismatch": func(t *testing.T, w *world) { w.files[licPath] = fxLicBody + "tampered\n" },
		"license not apache": func(t *testing.T, w *world) {
			body := "MIT License\n"
			w.files[licPath] = body
			w.row.License.BlobSHA = gitBlobSHA([]byte(body))
			w.write(t, w.row)
		},
		"governance 404":      func(t *testing.T, w *world) { delete(w.files, sigsPath) },
		"license 404":         func(t *testing.T, w *world) { delete(w.files, licPath) },
		"governance redirect": func(t *testing.T, w *world) { w.redir[sigsPath] = true },
		"license redirect":    func(t *testing.T, w *world) { w.redir[licPath] = true },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			mutate(t, w)
			ok, out, err := w.verify(t)
			if err != nil || ok || !strings.Contains(out, "subprojects verify: FAIL rows=1 failed=1") {
				t.Fatalf("ok=%v err=%v out=%s", ok, err, out)
			}
		})
	}
}

// A load failure (here: an overlay whose digest does not match) is an error,
// not a passing run.
func TestSubprojectsVerifyRefusesBadFile(t *testing.T) {
	w := newWorld(t)
	p := filepath.Join(w.root, "cli", "internal", "cncfcheck", "data", "cncf-subprojects.json")
	raw, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.Replace(raw, []byte("ExternalDNS"), []byte("ExternalDNs"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := w.verify(t); err == nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

// The production fetcher refuses any host but the raw host, plain http and
// URL decoration, before any request is made.
func TestRawFetcherRefusesOtherHosts(t *testing.T) {
	f := &rawFetcher{client: &http.Client{Transport: roundTripFail{t}}}
	for _, u := range []string{
		"https://github.com/kubernetes/community/blob/x/sigs.yaml",
		"http://raw.githubusercontent.com/a/b/c/d",
		"https://raw.githubusercontent.com.evil.example/a/b/c/d",
		"https://user@raw.githubusercontent.com/a/b/c/d",
		"https://raw.githubusercontent.com/a/b/c/d?x=1",
		"https://raw.githubusercontent.com/a/b/c/d#f",
	} {
		if _, err := f.Get(context.Background(), u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

type roundTripFail struct{ t *testing.T }

func (r roundTripFail) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("request made to %s", req.URL)
	return nil, http.ErrNotSupported
}

func TestSubprojectsUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"verify"}, {"verify", "--root", "x", "extra"}} {
		if err := runSubprojects(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
