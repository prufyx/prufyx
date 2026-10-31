// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/servedlists"
)

var (
	servedDataDir    = filepath.Join("..", "..", "internal", "cncfcheck", "data")
	servedSwaggerRaw = filepath.Join("..", "..", "internal", "servedlists", "testdata", "swagger.json")
)

const servedTestNow = "2026-10-23T10:00:00Z"

// servedFakeSource is a pinned upstream with the tags v1.30.0 and v1.31.0,
// each at its own commit, and one specification for both.
type servedFakeSource struct {
	tags    []extract.Tag
	files   map[string][]byte
	readErr error
	reads   int
}

func (f *servedFakeSource) Tags(extract.RepoRef) ([]extract.Tag, error) { return f.tags, nil }

func (f *servedFakeSource) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	data, ok := f.files[commit]
	if !ok || path != servedlists.SwaggerPath {
		return nil, extract.ErrNotFound
	}
	return data, nil
}

func (f *servedFakeSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("no listings")
}

func newServedFakeSource(t *testing.T) *servedFakeSource {
	t.Helper()
	data, err := os.ReadFile(servedSwaggerRaw)
	if err != nil {
		t.Fatal(err)
	}
	c30, c31 := strings.Repeat("3", 39)+"0", strings.Repeat("3", 39)+"1"
	return &servedFakeSource{
		tags:  []extract.Tag{{Name: "v1.30.0", Commit: c30}, {Name: "v1.31.0", Commit: c31}},
		files: map[string][]byte{c30: data, c31: data},
	}
}

// servedPackDir copies the shipped CNCF pack, without its served-API list
// section and under the level below it, and the registry files the loader
// reads beside it into a temporary directory. The tests build lists into
// that pack; the shipped lists are not their input.
func servedPackDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"rules.json", "landscape-projects.json", "priority-portfolio.json"} {
		raw, err := os.ReadFile(filepath.Join(servedDataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "rules.json" {
			raw = servedFreePack(t, raw)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "rules.json")
}

// servedFreePack is the pack without a servedAPIs member, under the schema
// the build raises it from.
func servedFreePack(t *testing.T, raw []byte) []byte {
	t.Helper()
	pk, err := extractpack.ParsePack(withoutCrossingRules(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	delete(pk.Members, servedapis.PackMember)
	pk.Members["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha4"`)
	out, err := pk.Render()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runServed(t *testing.T, src servedSource, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runServedListsWith(append([]string{"build"}, args...), &out, servedListsDeps{
		source: func(string) (servedSource, error) { return src, nil },
		admit:  extractpack.AdmitFiles,
	})
	return out.String(), err
}

func TestServedListsBuild(t *testing.T) {
	src := newServedFakeSource(t)
	pack := servedPackDir(t)
	before, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runServed(t, src, "--pack", pack, "--lines", "1.30-1.31", "--now", servedTestNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg:github/kubernetes/kubernetes 1.30 pairs=3 commit=" + strings.Repeat("3", 39) + "0", "1.31 pairs=3", "schema prufyx.io/cncf-source-rule-pack/v1alpha4 -> prufyx.io/cncf-source-rule-pack/v1alpha10; 2 lists; pack written"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	first, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}

	// The same inputs and --now give the same bytes.
	out2, err := runServed(t, src, "--pack", pack, "--lines", "1.30-1.31", "--now", servedTestNow)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(pack)
	if !bytes.Equal(first, second) || !strings.Contains(out2, "alpha10 -> prufyx.io/cncf-source-rule-pack/v1alpha10; 2 lists; pack unchanged") {
		t.Fatalf("a second run changed the pack or did not say so:\n%s", out2)
	}

	// Another pack file, built from scratch with the lines one at a time,
	// reaches the same bytes: a list of another line is kept.
	other := servedPackDir(t)
	for _, line := range []string{"1.31", "1.30"} {
		if _, err := runServed(t, src, "--pack", other, "--lines", line, "--now", servedTestNow); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := os.ReadFile(other); !bytes.Equal(got, first) {
		t.Fatal("building the lines one at a time gives other bytes")
	}

	// Every byte but the servedAPIs member and the schema is the base's.
	pk, err := extractpack.ParsePack(first)
	if err != nil {
		t.Fatal(err)
	}
	section := pk.Members[servedapis.PackMember]
	records, err := servedapis.Parse(section)
	if err != nil || len(records) != 2 || records[0].Line != "1.30" || records[1].Line != "1.31" {
		t.Fatalf("records %v err %v", records, err)
	}
	if !reflect.DeepEqual(records[0].APIs, []string{"apps/v1 Deployment", "storage.k8s.io/v1 StorageClass", "v1 Pod"}) {
		t.Fatalf("pairs %v", records[0].APIs)
	}
	if records[0].Evidence.DerivedAt != servedTestNow || records[0].Evidence.Basis != "mechanical" {
		t.Fatalf("evidence %+v", records[0].Evidence)
	}
	delete(pk.Members, servedapis.PackMember)
	pk.Members["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha4"`)
	back, err := pk.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, before) {
		t.Fatal("the build changed bytes outside the servedAPIs member and the schema")
	}
}

func TestServedListsBuildRefusals(t *testing.T) {
	good := func(t *testing.T) (string, *servedFakeSource, []string) {
		return servedPackDir(t), newServedFakeSource(t), nil
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, pack string, src *servedFakeSource) []string // extra args replacing the defaults
		want   string
	}{
		{"missing flag", func(*testing.T, string, *servedFakeSource) []string { return []string{"--lines", "1.30"} }, "usage"},
		{"now with a fraction", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "1.30", "--now", "2026-10-23T10:00:00.5Z"}
		}, "whole seconds"},
		{"now not RFC 3339", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "1.30", "--now", "yesterday"}
		}, "whole seconds"},
		{"range past the covered lines", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "1.30-1.60", "--now", servedTestNow}
		}, "outside the lines"},
		{"range below the covered lines", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "1.5-1.30", "--now", servedTestNow}
		}, "outside the lines"},
		{"line that is not a line", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "2.1", "--now", servedTestNow}
		}, "not a Kubernetes 1.N line"},
		{"line without a tag upstream", func(_ *testing.T, p string, _ *servedFakeSource) []string {
			return []string{"--pack", p, "--lines", "1.30-1.32", "--now", servedTestNow}
		}, "line 1.32"},
		{"upstream read error", func(_ *testing.T, p string, s *servedFakeSource) []string {
			s.readErr = errors.New("503 from upstream")
			return []string{"--pack", p, "--lines", "1.30", "--now", servedTestNow}
		}, "503 from upstream"},
		{"pack that is not canonical", func(t *testing.T, p string, _ *servedFakeSource) []string {
			raw, _ := os.ReadFile(p)
			if err := os.WriteFile(p, bytes.Replace(raw, []byte("\n  \"revision\""), []byte("\n    \"revision\""), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"--pack", p, "--lines", "1.30", "--now", servedTestNow}
		}, "not in canonical form"},
		{"pack that is a symlink", func(t *testing.T, p string, _ *servedFakeSource) []string {
			link := filepath.Join(filepath.Dir(p), "link.json")
			if err := os.Symlink(p, link); err != nil {
				t.Skip("no symlinks")
			}
			return []string{"--pack", link, "--lines", "1.30", "--now", servedTestNow}
		}, "regular file"},
		{"pack of another family", func(t *testing.T, p string, _ *servedFakeSource) []string {
			raw, _ := os.ReadFile(p)
			if err := os.WriteFile(p, bytes.Replace(raw, []byte("cncf-source-rule-pack/v1alpha4"), []byte("community-project-source-rule-pack/v1alpha4"), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"--pack", p, "--lines", "1.30", "--now", servedTestNow}
		}, "not a CNCF rule pack schema"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pack, src, _ := good(t)
			args := tc.mutate(t, pack, src)
			before, _ := os.ReadFile(pack)
			_, err := runServed(t, src, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error with %q, got %v", tc.want, err)
			}
			if after, _ := os.ReadFile(pack); !bytes.Equal(before, after) {
				t.Fatal("a refused build changed the pack")
			}
		})
	}
}

func TestServedListsBuildStopsAtTheFirstFailure(t *testing.T) {
	src := newServedFakeSource(t)
	src.readErr = errors.New("boom")
	pack := servedPackDir(t)
	if _, err := runServed(t, src, "--pack", pack, "--lines", "1.30-1.31", "--now", servedTestNow); err == nil {
		t.Fatal("no error")
	}
	if src.reads != 1 {
		t.Fatalf("%d reads after the first failure, want 1", src.reads)
	}
}

func TestServedListsBuildReportsTheFirstRefusal(t *testing.T) {
	pack := servedPackDir(t)
	calls := 0
	var out bytes.Buffer
	err := runServedListsWith([]string{"build", "--pack", pack, "--lines", "1.30", "--now", servedTestNow}, &out, servedListsDeps{
		source: func(string) (servedSource, error) { return newServedFakeSource(t), nil },
		admit: func(string, []byte) error {
			calls++
			if calls == 1 {
				return errors.New("integrity: list names a removed API")
			}
			return errors.New("unknown schema")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "integrity: list names a removed API") || strings.Contains(err.Error(), "unknown schema") {
		t.Fatalf("want the first refusal only, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("%d admit calls, want the level loop to run", calls)
	}
}

func TestParseServedLines(t *testing.T) {
	covered := [2]int{19, 37}
	for _, tc := range []struct {
		in   string
		want []string
		err  string
	}{
		{in: "1.19-1.21", want: []string{"1.19", "1.20", "1.21"}},
		{in: "1.30,1.28,1.30", want: []string{"1.28", "1.30"}},
		{in: "1.19-1.20,1.37", want: []string{"1.19", "1.20", "1.37"}},
		{in: "1.38", want: []string{"1.38"}}, // named alone and exactly
		{in: "1.5", want: []string{"1.5"}},
		{in: "1.38,1.50", err: "single item"},
		{in: "1.30,1.38", err: "single item"},
		{in: "1.18-1.20", err: "outside the lines"},
		{in: "1.30-1.38", err: "outside the lines"},
		{in: "1.30-1.20", err: "backwards"},
		{in: "", err: "not a Kubernetes"},
		{in: "1.30,", err: "not a Kubernetes"},
		{in: "1.030", err: "not a Kubernetes"},
		{in: "v1.30", err: "not a Kubernetes"},
		{in: "1.0-1.50000", err: "not a Kubernetes"},
	} {
		got, err := parseServedLines(tc.in, covered)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: want %q, got %v %v", tc.in, tc.err, got, err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: %v %v, want %v", tc.in, got, err, tc.want)
		}
	}
	if _, err := parseServedLines("1.0-1.200", [2]int{0, 300}); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a range of 201 lines: %v", err)
	}
}

func TestServedListsCoveredLines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(servedDataDir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	span, err := coveredKubernetesLines(pk)
	if err != nil {
		t.Fatal(err)
	}
	// The shipped pack's Kubernetes attestations run 1.20 to 1.37 and read
	// the line before the first, 1.19.
	if span != [2]int{19, 37} {
		t.Fatalf("span %v", span)
	}
}

func TestServedListsRoutesAndSources(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"served-lists"}, &out, &out); err == nil {
		t.Fatal("no usage error")
	}
	if err := run([]string{"served-lists", "build", "--pack", "x", "--lines", "1.30", "--now", servedTestNow, "--source", "ftp:x"}, &out, &out); err == nil || !strings.Contains(err.Error(), "--source") {
		// The pack is read first, so an unreadable pack may be the error.
		if err == nil || !strings.Contains(err.Error(), "cannot read the pack") {
			t.Fatalf("source error: %v", err)
		}
	}
	if _, err := servedListsSource("ftp:x"); err == nil {
		t.Fatal("a source of an unknown kind was accepted")
	}
	if _, err := servedListsSource("fixture:"); err == nil {
		t.Fatal("an empty fixture directory was accepted")
	}
	if s, err := servedListsSource("fixture:" + t.TempDir()); err != nil || s == nil {
		t.Fatalf("fixture source: %v", err)
	}
}

// withoutCrossingRules is the pack as it was before it held release-note
// removal rules (crossing-only set rules, which need a schema above the one
// this test models).
func withoutCrossingRules(t *testing.T, raw []byte) []byte {
	t.Helper()
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	var kept []json.RawMessage
	for _, entry := range p.Entries {
		var e struct {
			Rule struct {
				Operator string          `json:"operator"`
				Crossing json.RawMessage `json:"crossing"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(entry, &e); err != nil {
			t.Fatal(err)
		}
		if e.Rule.Operator == "forbid_set_member" && len(e.Rule.Crossing) > 0 {
			continue
		}
		kept = append(kept, entry)
	}
	if len(kept) == len(p.Entries) {
		return raw
	}
	p.Entries = kept
	out, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
