// SPDX-License-Identifier: AGPL-3.0-only

package servedlists

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

func swagger(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDerive(t *testing.T) {
	t.Parallel()
	got, err := Derive("1.31", swagger(t))
	if err != nil {
		t.Fatal(err)
	}
	// Watch paths, subresources, beta and alpha versions, a PUT on a path
	// ending in {namespace}, DELETE and connect operations are all left out.
	want := []string{"apps/v1 Deployment", "storage.k8s.io/v1 StorageClass", "v1 Pod"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pairs %v, want %v", got, want)
	}
}

func TestDeriveRefuses(t *testing.T) {
	t.Parallel()
	op := func(path, verb, group, version, kind string) string {
		return `{"swagger":"2.0","paths":{"` + path + `":{"` + verb + `":{"x-kubernetes-action":"` + verb + `","x-kubernetes-group-version-kind":{"group":"` + group + `","version":"` + version + `","kind":"` + kind + `"}}}}}`
	}
	cases := []struct {
		name, line, doc, want string
	}{
		{"bad line", "2.0", string(swagger(t)), "not a Kubernetes 1.N line"},
		{"empty", "1.31", "", "specification of 0 bytes"},
		{"garbage", "1.31", "not json", "specification"},
		{"trailing data", "1.31", string(swagger(t)) + "{}", "specification"},
		{"repeated member", "1.31", `{"swagger":"2.0","paths":{},"paths":{}}`, "specification"},
		{"case-folded member", "1.31", `{"swagger":"2.0","paths":{"/api/v1/x":{}},"Paths":{}}`, "specification"},
		{"no swagger member", "1.31", `{"paths":{"/api/v1/pods":{}}}`, "not a Kubernetes OpenAPI"},
		{"no paths", "1.31", `{"swagger":"2.0","paths":{}}`, "not a Kubernetes OpenAPI"},
		{"zero pairs", "1.31", op("/apis/batch/v1beta1/namespaces/{namespace}/cronjobs", "post", "batch", "v1beta1", "CronJob"), "yields no served pair"},
		{"operation of the wrong shape", "1.31", `{"swagger":"2.0","paths":{"/api/v1/pods":{"post":"x"}}}`, "post /api/v1/pods"},
		{"group not the path's", "1.31", op("/apis/apps/v1/deployments", "post", "extensions", "v1", "Deployment"), "is not the path's"},
		{"version not the path's", "1.31", op("/api/v1/pods", "post", "", "v2", "Pod"), "is not the path's"},
		{"no kind", "1.31", op("/api/v1/pods", "post", "", "v1", ""), "no kind"},
		{"oversized", "1.31", strings.Repeat(" ", MaxSwaggerBytes+1), "specification of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pairs, err := Derive(tc.line, []byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("pairs %v err %v, want %q", pairs, err, tc.want)
			}
		})
	}
}

func TestIdentity(t *testing.T) {
	t.Parallel()
	x, err := Identity()
	if err != nil {
		t.Fatal(err)
	}
	if x.ID != "k8s.served-api-list" || x.Version != "1.0.0" || !strings.HasPrefix(x.CodeDigest, "sha256:") {
		t.Fatalf("identity %+v", x)
	}
	// The digest covers this package and the record format package, and
	// nothing of the extract framework.
	dir, files := servedapis.SourceFiles()
	set, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: source}, extract.SourceSet{Dir: dir, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range set {
		paths = append(paths, f.Path)
	}
	if want := []string{"servedapis/servedapis.go", "servedlists/servedlists.go"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("code files %v, want %v", paths, want)
	}
	if extract.CodeDigest(set) != x.CodeDigest {
		t.Fatal("identity is not the digest of those files")
	}
}

type fakeSource struct {
	tags     []extract.Tag
	files    map[string][]byte
	tagsErr  error
	readErr  error
	readings int
}

func (f *fakeSource) Tags(extract.RepoRef) ([]extract.Tag, error) { return f.tags, f.tagsErr }

func (f *fakeSource) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	f.readings++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if path != SwaggerPath {
		return nil, extract.ErrNotFound
	}
	data, ok := f.files[commit]
	if !ok {
		return nil, extract.ErrNotFound
	}
	return data, nil
}

func (f *fakeSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("no listings")
}

const commit131 = "1111111111111111111111111111111111111111"

func TestBuild(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	src := &fakeSource{tags: []extract.Tag{{Name: "v1.30.0", Commit: strings.Repeat("3", 40)}, {Name: "v1.31.0", Commit: commit131}, {Name: "v1.31.1", Commit: strings.Repeat("4", 40)}}, files: map[string][]byte{commit131: swagger(t)}}
	rec, err := Build(context.Background(), src, src, "1.31", now)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := Identity()
	ev := rec.Evidence
	if rec.Component != servedapis.KubernetesComponent || rec.Line != "1.31" || rec.Completeness != servedapis.CompletenessPartial || len(rec.APIs) != 3 {
		t.Fatalf("record %+v", rec)
	}
	if ev.Basis != "mechanical" || ev.Extractor == nil || *ev.Extractor != x || ev.DerivedAt != "2026-10-22T08:00:00Z" || ev.ReviewedAt != ev.DerivedAt {
		t.Fatalf("evidence %+v", ev)
	}
	if want := now.Add(89 * 24 * time.Hour).Format(time.RFC3339); ev.ValidUntil != want {
		t.Fatalf("validUntil %s, want %s", ev.ValidUntil, want)
	}
	if len(ev.Sources) != 1 {
		t.Fatalf("sources %+v", ev.Sources)
	}
	s := ev.Sources[0]
	if s.ID != "openapi-v1.31.0" || s.Revision != commit131 || s.URL != "https://github.com/kubernetes/kubernetes/blob/"+commit131+"/api/openapi-spec/swagger.json" ||
		s.ContentDigest != SwaggerDigest(swagger(t)) || s.StartLine != 1 || s.EndLine != extract.CountLines(swagger(t)) {
		t.Fatalf("source %+v", s)
	}
	// The same inputs give the same record.
	again, err := Build(context.Background(), src, src, "1.31", now)
	if err != nil || !reflect.DeepEqual(again, rec) {
		t.Fatalf("second build differs: %v", err)
	}
}

func TestBuildRefuses(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	good := func() *fakeSource {
		return &fakeSource{tags: []extract.Tag{{Name: "v1.31.0", Commit: commit131}}, files: map[string][]byte{commit131: swagger(t)}}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name string
		ctx  context.Context
		line string
		now  time.Time
		edit func(*fakeSource)
		want string
	}{
		{"no tag of the line", context.Background(), "1.30", now, nil, "no tag v1.30.0"},
		{"tag without a pinned commit", context.Background(), "1.31", now, func(f *fakeSource) { f.tags[0].Commit = "v1.31.0" }, "no pinned commit"},
		{"tag naming two commits", context.Background(), "1.31", now, func(f *fakeSource) {
			f.tags = append(f.tags, extract.Tag{Name: "v1.31.0", Commit: strings.Repeat("2", 40)})
		}, "two commits"},
		{"tags unreadable", context.Background(), "1.31", now, func(f *fakeSource) { f.tagsErr = errors.New("frozen") }, "tags of"},
		{"specification unreadable", context.Background(), "1.31", now, func(f *fakeSource) { f.readErr = errors.New("boom") }, "boom"},
		{"specification missing at the commit", context.Background(), "1.31", now, func(f *fakeSource) { f.files = nil }, "does not exist"},
		{"specification of another shape", context.Background(), "1.31", now, func(f *fakeSource) { f.files[commit131] = []byte("[]") }, "specification"},
		{"fractional second", context.Background(), "1.31", now.Add(time.Millisecond), nil, "whole seconds"},
		{"canceled", canceled, "1.31", now, nil, "canceled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := good()
			if tc.edit != nil {
				tc.edit(src)
			}
			_, err := Build(tc.ctx, src, src, tc.line, tc.now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAssembleLease(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	for name, until := range map[string]time.Time{"not after": at, "too long": at.Add(Lease + time.Second)} {
		if _, err := Assemble("1.31", commit131, swagger(t), at, until); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := Assemble("1.31", commit131, swagger(t), at, at.Add(24*time.Hour)); err != nil {
		t.Errorf("a shorter lease: %v", err)
	}
}
