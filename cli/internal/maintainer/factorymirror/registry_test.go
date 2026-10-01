// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRepo(t *testing.T) {
	good := map[string]string{
		"Kubernetes/Kubernetes":               "github.com/kubernetes/kubernetes",
		"github.com/etcd-io/etcd":             "github.com/etcd-io/etcd",
		"https://github.com/Foo/bar.git":      "github.com/foo/bar",
		"gitlab.example.org/group/proj":       "gitlab.example.org/group/proj",
		"github.com/cloud-custodian/c7n.core": "github.com/cloud-custodian/c7n.core",
	}
	for in, want := range good {
		r, err := ParseRepo(in)
		if err != nil || r.Key() != want {
			t.Errorf("%q -> %q %v, want %q", in, r.Key(), err, want)
		}
	}
	for _, bad := range []string{"", "a", "a/b/c/d", "../x", "a/..", "a/b c", "github.com/a/..", "-x/y z", "a/b;rm", "a/.", "file:///x/y/z", "ssh://github.com/a/b"} {
		if _, err := ParseRepo(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted (%v)", bad, err)
		}
	}
}

func TestRegistryRoundTripIsDeterministicAndStrict(t *testing.T) {
	repos, err := ParseRegistry([]byte("repos:\n  - b/z\n  - a/y\n  - A/Y\n"))
	if err != nil || len(repos) != 2 || repos[0].Key() != "github.com/a/y" {
		t.Fatalf("%v %v", repos, err)
	}
	out1 := MarshalRegistry(repos)
	again, err := ParseRegistry(out1)
	if err != nil || !bytes.Equal(out1, MarshalRegistry(again)) {
		t.Fatalf("not stable: %v", err)
	}
	for _, bad := range []string{"repos: [a]\n", "repos:\n  - a/b\nextra: 1\n", "schema: other\nrepos: []\n"} {
		if _, err := ParseRegistry([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

const packJSON = `{"entries":[
 {"project":"p","rule":{"id":"r1","evidence":{"sources":[
  {"id":"s1","url":"https://github.com/Acme/Widget/blob/%s/docs/a.md","revision":"%s","contentDigest":"sha256:x","startLine":1,"endLine":2},
  {"id":"s2","url":"https://raw.githubusercontent.com/other/thing/%s/b.md","revision":"%s","contentDigest":"sha256:y","startLine":3,"endLine":3}]}}},
 {"project":"p","rule":{"id":"r2","evidence":{"sources":[
  {"id":"s1","url":"https://github.com/acme/widget/blob/%s/docs/c.md","revision":"%s","contentDigest":"sha256:z","startLine":1,"endLine":1}]}}}]}`

func writePack(t *testing.T, dir, name, a, b string) string {
	t.Helper()
	body := strings.NewReplacer().Replace(packJSON)
	for _, sha := range []string{a, a, b, b, a, a} {
		body = strings.Replace(body, "%s", sha, 1)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeriveUnionsPacksAndExtrasAndEmitsWants(t *testing.T) {
	dir := t.TempDir()
	sha1, sha2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	p1 := writePack(t, dir, "p1.json", sha1, sha2)
	p2 := writePack(t, dir, "p2.json", sha2, sha1)
	extra := filepath.Join(dir, "extra.yaml")
	if err := os.WriteFile(extra, []byte("repos:\n  - kubernetes/kubernetes\n  - acme/widget\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repos, err := DeriveFromRulePacks([]string{p1, p2}, []string{extra})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range repos {
		keys = append(keys, r.Key())
	}
	want := "github.com/acme/widget,github.com/kubernetes/kubernetes,github.com/other/thing"
	if strings.Join(keys, ",") != want {
		t.Fatalf("got %v", keys)
	}
	wants, err := WantsFromRulePacks([]string{p1, p2})
	if err != nil || len(wants) != 4 {
		t.Fatalf("%+v %v", wants, err)
	}
	if wants[0].Repo != "github.com/acme/widget" || wants[0].Commit != sha1 || len(wants[0].Paths) != 2 {
		t.Fatalf("%+v", wants[0])
	}
	// A pack with an unrecognised citation shape is rejected, not skipped.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"entries":[{"project":"p","rule":{"id":"r","evidence":{"sources":[{"id":"s","url":"https://example.org/x","revision":"`+sha1+`","startLine":1,"endLine":1}]}}}]}`), 0o644)
	if _, err := DeriveFromRulePacks([]string{bad}, nil); err == nil {
		t.Fatal("unparseable citation accepted")
	}
}

func TestDeriveFromShippedPacksCoversEveryCitedRepo(t *testing.T) {
	packs := []string{"../../cncfcheck/data/rules.json", "../../projectcheck/data/rules.json"}
	for _, p := range packs {
		if _, err := os.Stat(p); err != nil {
			t.Skip("shipped packs not available")
		}
	}
	repos, err := DeriveFromRulePacks(packs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) < 60 {
		t.Fatalf("suspiciously few repositories: %d", len(repos))
	}
	have := map[string]bool{}
	for _, r := range repos {
		have[r.Key()] = true
	}
	if !have["github.com/kubernetes/kubernetes"] {
		t.Fatal("kubernetes/kubernetes missing")
	}
}
