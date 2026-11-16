// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fullWindowFixture(t *testing.T, changed, ambiguous bool) (Input, FullWindowSelector) {
	t.Helper()
	dir := t.TempDir()
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	tags := []string{"v1.0.0", "v1.1.0", "v1.1.1"}
	commits := map[string]string{}
	for i, tag := range tags {
		path := filepath.Join(dir, "config", "crd", "widget.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		kind := "Widget"
		if changed && i == 1 {
			kind = "Other"
		}
		if err := os.WriteFile(path, crdText("demo.example.invalid", kind), 0644); err != nil {
			t.Fatal(err)
		}
		if ambiguous {
			if err := os.WriteFile(filepath.Join(filepath.Dir(path), "other.yaml"), crdText("demo.example.invalid", "Other"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(tag+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", tag)
		git("tag", tag)
		commits[tag] = git("rev-parse", tag+"^{commit}")
	}
	in := Input{Slug: "demo", Name: "Demo", Repo: "github.com/example/demo", Catalog: "cncf", Tags: tags, Source: GitSource{Dir: dir}, StrictWindow: true}
	selector := FullWindowSelector{Policy: "singleton-final/v1", Prefix: "v", LinesBack: 5, MinFrom: "1.0", Newest: "v1.1.1", LaterTag: "v1.1.0", TagSetSHA256: "sha256:" + strings.Repeat("a", 64), Commits: commits}
	return in, selector
}

func TestGenerateFullWindowReadsAllPatchesAndCitesLater(t *testing.T) {
	in, selector := fullWindowFixture(t, false, false)
	result, err := GenerateFullWindow(in, selector)
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		Groups []struct {
			Source string   `json:"source"`
			Kinds  []string `json:"kinds"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(result.TableRow, &row); err != nil {
		t.Fatal(err)
	}
	if len(row.Groups) != 1 || !strings.Contains(row.Groups[0].Source, "/blob/"+selector.Commits[selector.LaterTag]+"/") || strings.Contains(row.Groups[0].Source, "/blob/"+selector.Commits[selector.Newest]+"/") {
		t.Fatalf("later source: %+v", row.Groups)
	}
	if len(result.Report.Tags) != len(in.Tags) || len(result.Report.Dropped) != 0 {
		t.Fatalf("incomplete window: %+v", result.Report)
	}
	again, err := GenerateFullWindow(in, selector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.A, again.A) || !bytes.Equal(result.TableRow, again.TableRow) || !bytes.Equal(result.Changelog, again.Changelog) {
		t.Fatal("non-deterministic output")
	}
	if _, err := Generate(in); err == nil {
		t.Fatal("v1 accepted multiple tags per line")
	}
}

func TestGenerateFullWindowRefusesUnsafeInputs(t *testing.T) {
	in, selector := fullWindowFixture(t, false, false)
	for _, tc := range []struct {
		name string
		edit func(*Input, *FullWindowSelector)
	}{
		{"missing selector", func(_ *Input, s *FullWindowSelector) { s.Policy = "" }},
		{"omitted patch", func(i *Input, _ *FullWindowSelector) { i.Tags = append(i.Tags[:1], i.Tags[2:]...) }},
		{"wrong later", func(_ *Input, s *FullWindowSelector) { s.LaterTag = s.Newest }},
		{"wrong commit", func(_ *Input, s *FullWindowSelector) { s.Commits["v1.1.0"] = strings.Repeat("0", 40) }},
		{"missing ref", func(i *Input, s *FullWindowSelector) {
			i.Tags[2] = "v1.1.2"
			delete(s.Commits, "v1.1.1")
			s.Commits["v1.1.2"] = strings.Repeat("a", 40)
			s.Newest = "v1.1.2"
		}},
		{"unordered", func(i *Input, _ *FullWindowSelector) { i.Tags[1], i.Tags[2] = i.Tags[2], i.Tags[1] }},
		{"duplicate", func(i *Input, _ *FullWindowSelector) { i.Tags[1] = i.Tags[2] }},
		{"window shrink", func(i *Input, _ *FullWindowSelector) { i.StrictWindow = false }},
		{"manual rules", func(i *Input, _ *FullWindowSelector) {
			i.Rules = &Rules{Schema: RulesSchema, InstallSurface: []SurfaceRule{{Path: "x", Reason: "x"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyIn := in
			copyIn.Tags = append([]string(nil), in.Tags...)
			copySelector := selector
			copySelector.Commits = map[string]string{}
			for k, v := range selector.Commits {
				copySelector.Commits[k] = v
			}
			tc.edit(&copyIn, &copySelector)
			if got, err := GenerateFullWindow(copyIn, copySelector); err == nil || got != nil {
				t.Fatal("accepted invalid full window")
			}
		})
	}
	changed, changedSelector := fullWindowFixture(t, true, false)
	if got, err := GenerateFullWindow(changed, changedSelector); err == nil || got != nil {
		t.Fatal("accepted changed kinds")
	}
	ambiguous, ambiguousSelector := fullWindowFixture(t, false, true)
	if got, err := GenerateFullWindow(ambiguous, ambiguousSelector); err == nil || got != nil {
		t.Fatal("accepted ambiguous later citation")
	}
}
