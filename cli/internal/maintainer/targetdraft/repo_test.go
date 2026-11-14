// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Every non-canonical repo ends in a typed stop and no files; the stop is
// repo-not-canonical when the value is repo-shaped, bad-input when it is not.
func TestRepoNotCanonicalRefusedBeforeAnything(t *testing.T) {
	cases := []struct {
		repo string
		stop string // empty: accepted
	}{
		{"github.com/knative/serving", ""},
		{"github.com/Knative/serving", StopRepoNotCanonical},
		{"github.com/knative/Serving", StopRepoNotCanonical},
		{"github.com/KNATIVE/SERVING", StopRepoNotCanonical},
		{"github.com/knative/serving.git", StopRepoNotCanonical},
		{"GitHub.com/knative/serving", StopBadInput},
		{"github.com/knative/serving ", StopBadInput},
		{" github.com/knative/serving", StopBadInput},
		{"https://github.com/knative/serving", StopBadInput},
		{"github.com/knative/serving/", StopBadInput},
		{"github.com/knative", StopBadInput},
		{"", StopBadInput},
	}
	for _, c := range cases {
		in := knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json"))
		in.Repo = c.repo
		res, err := Generate(in)
		if c.stop == "" {
			if err != nil || res == nil {
				t.Errorf("%q: refused: %v", c.repo, err)
			}
			continue
		}
		if res != nil {
			t.Errorf("%q: files produced for a refused repo", c.repo)
		}
		if codes := stopCodes(err); len(codes) != 1 || codes[0] != c.stop {
			t.Errorf("%q: stops %v, want [%s]", c.repo, codes, c.stop)
		}
	}
}

// loadsTarget and loadsRow run the extractor's and the table's own loaders.
func loadsTarget(slug string, raw []byte) bool {
	_, err := crdversions.LoadTarget(crdversions.TargetFileName(slug), raw)
	return err == nil
}

func loadsRow(t *testing.T, row []byte) bool {
	t.Helper()
	var r json.RawMessage = row
	doc := `{"schema":"` + customresources.TableSchema + `","projects":[` + string(r) + `],"reserved":[]}`
	_, _, err := customresources.LoadTable([]byte(doc))
	return err == nil
}

// What the generator emits loads through the real loaders, and the values it
// refuses are refused by them too (a .git suffix excepted: the generator is
// deliberately stricter, no repository name can end in it).
func TestEmittedDraftLoadsAndRefusalsMatchLoaders(t *testing.T) {
	kn := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
	if !loadsTarget("knative", kn.A) || !loadsRow(t, kn.TableRow) {
		t.Fatal("the emitted knative draft does not load through the real loaders")
	}
	tr := mustGenerate(t, traefikInput(t, traefikSource(t, nil), rulesFrom(t, "testdata/traefik/rules.json")))
	if !loadsTarget("traefik", tr.A) || !loadsRow(t, tr.TableRow) {
		t.Fatal("the emitted traefik draft does not load through the real loaders")
	}
	for _, repo := range []string{"github.com/Knative/serving", "github.com/knative/Serving", "github.com/KNATIVE/SERVING"} {
		mut := bytes.Replace(kn.A, []byte(`"repo": "github.com/knative/serving"`), []byte(`"repo": "`+repo+`"`), 1)
		if bytes.Equal(mut, kn.A) || loadsTarget("knative", mut) || repoCanonical(repo) {
			t.Errorf("%q: loader accepts or generator accepts", repo)
		}
	}
	// The loader alone accepts the .git spelling; the generator refuses it.
	git := bytes.Replace(kn.A, []byte(`"repo": "github.com/knative/serving"`), []byte(`"repo": "github.com/knative/serving.git"`), 1)
	git = bytes.Replace(git, []byte(`"component": "pkg:github/knative/serving"`), []byte(`"component": "pkg:github/knative/serving.git"`), 1)
	if !loadsTarget("knative", git) || repoCanonical("github.com/knative/serving.git") {
		t.Error(".git: expected loader accepts, generator refuses")
	}
	for _, c := range []string{"pkg:github/Knative/serving", "pkg:github/knative/other", "pkg:gitlab/knative/serving", ""} {
		mut := bytes.Replace(kn.A, []byte(`"component": "pkg:github/knative/serving"`), []byte(`"component": "`+c+`"`), 1)
		if loadsTarget("knative", mut) {
			t.Errorf("component %q: loader accepts", c)
		}
	}
}

func TestComponentMustBeCanonical(t *testing.T) {
	for _, c := range []struct {
		component, stop string
	}{
		{"", ""},
		{"pkg:github/knative/serving", ""},
		{"pkg:github/Knative/serving", StopComponentNotCanonical},
		{"pkg:github/knative/Serving", StopComponentNotCanonical},
		{"pkg:github/knative/other", StopComponentNotCanonical},
		{"pkg:gitlab/knative/serving", StopComponentNotCanonical},
		{"pkg:github/knative/serving ", StopComponentNotCanonical},
		{"github.com/knative/serving", StopComponentNotCanonical},
	} {
		in := knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json"))
		in.Component = c.component
		res, err := Generate(in)
		if c.stop == "" {
			if err != nil || !loadsTarget("knative", res.A) {
				t.Errorf("%q: refused or not loadable: %v", c.component, err)
			}
			continue
		}
		if res != nil {
			t.Errorf("%q: files produced", c.component)
		}
		if codes := stopCodes(err); len(codes) != 1 || codes[0] != c.stop {
			t.Errorf("%q: stops %v, want [%s]", c.component, codes, c.stop)
		}
	}
}

func TestUpstreamMustBeCanonical(t *testing.T) {
	const repo = "https://github.com/traefik/traefik"
	base := mustGenerate(t, traefikInput(t, traefikSource(t, nil), rulesFrom(t, "testdata/traefik/rules.json")))
	cases := []struct {
		name   string
		mutate func(u *Upstream)
	}{
		{"repository differs", func(u *Upstream) { u.Repository = "https://github.com/traefik/other" }},
		{"repository upper case", func(u *Upstream) { u.Repository = "https://github.com/Traefik/traefik" }},
		{"repository without scheme", func(u *Upstream) { u.Repository = "github.com/traefik/traefik" }},
		{"repository with .git", func(u *Upstream) { u.Repository = repo + ".git" }},
		{"licenseSource outside the repository", func(u *Upstream) {
			u.LicenseSource = "https://github.com/other/traefik/blob/04aa6bb4f9776f2ba87e5cd181d250e3610e6419/LICENSE.md"
		}},
		{"licenseSource not a pinned licence file", func(u *Upstream) { u.LicenseSource = repo + "/blob/main/LICENSE.md" }},
		{"licenseSource sibling repository", func(u *Upstream) {
			u.LicenseSource = repo + "x/blob/04aa6bb4f9776f2ba87e5cd181d250e3610e6419/LICENSE.md"
		}},
		{"license empty", func(u *Upstream) { u.License = "" }},
		{"license not an expression", func(u *Upstream) { u.License = "not a licence!" }},
	}
	for _, c := range cases {
		rules := rulesFrom(t, "testdata/traefik/rules.json")
		c.mutate(rules.Upstream)
		res, err := Generate(traefikInput(t, traefikSource(t, nil), rules))
		if res != nil {
			t.Errorf("%s: files produced", c.name)
		}
		want := StopUpstreamNotCanonical
		if c.name == "license empty" {
			want = StopCommunityUpstream // the older non-empty rule stays first
		}
		if codes := stopCodes(err); len(codes) != 1 || codes[0] != want {
			t.Errorf("%s: stops %v, want [%s]", c.name, codes, want)
		}
		// The table loader refuses the same block in the emitted row.
		var row map[string]any
		if err := json.Unmarshal(base.TableRow, &row); err != nil {
			t.Fatal(err)
		}
		u := row["upstream"].(map[string]any)
		u["repository"], u["license"], u["licenseSource"] = rules.Upstream.Repository, rules.Upstream.License, rules.Upstream.LicenseSource
		raw, _ := json.Marshal(row)
		if loadsRow(t, raw) {
			t.Errorf("%s: the table loader accepts the block", c.name)
		}
	}
	if !loadsRow(t, base.TableRow) {
		t.Fatal("canonical upstream row does not load")
	}
}

// A CNCF row takes no upstream block; the table loader refuses one.
func TestCNCFRowRefusesUpstream(t *testing.T) {
	rules := rulesFrom(t, "testdata/knative/rules.json")
	rules.Upstream = &Upstream{Name: "knative", Repository: "https://github.com/knative/serving", License: "Apache-2.0",
		LicenseSource: "https://github.com/knative/serving/blob/04aa6bb4f9776f2ba87e5cd181d250e3610e6419/LICENSE"}
	res, err := Generate(knativeInput(t, knativeSource(t, nil), rules))
	if res != nil {
		t.Fatal("files produced for a cncf row with an upstream block")
	}
	if codes := stopCodes(err); len(codes) != 1 || codes[0] != StopUpstreamNotCanonical {
		t.Fatalf("stops %v", codes)
	}
	kn := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json")))
	var row map[string]any
	if err := json.Unmarshal(kn.TableRow, &row); err != nil {
		t.Fatal(err)
	}
	row["upstream"] = rules.Upstream
	raw, _ := json.Marshal(row)
	if loadsRow(t, raw) {
		t.Fatal("the table loader accepts an upstream block on a cncf row")
	}
}

// Every refusal leaves --out empty: nothing is written for any of the stops.
func TestRefusalsLeaveOutEmpty(t *testing.T) {
	repo := knativeRepo(t)
	withUpstream := filepath.Join(t.TempDir(), "rules.json")
	var rules map[string]any
	if err := json.Unmarshal(readFile(t, "testdata/knative/rules.json"), &rules); err != nil {
		t.Fatal(err)
	}
	rules["upstream"] = map[string]string{"name": "knative", "repository": "https://github.com/knative/serving", "license": "Apache-2.0",
		"licenseSource": "https://github.com/knative/serving/blob/04aa6bb4f9776f2ba87e5cd181d250e3610e6419/LICENSE"}
	raw, _ := json.Marshal(rules)
	if err := os.WriteFile(withUpstream, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, repo, component, rules, stop string
	}{
		{"repo", "github.com/Knative/serving", "", "testdata/knative/rules.json", StopRepoNotCanonical},
		{"component", "github.com/knative/serving", "pkg:github/Knative/serving", "testdata/knative/rules.json", StopComponentNotCanonical},
		{"upstream", "github.com/knative/serving", "", withUpstream, StopUpstreamNotCanonical},
	} {
		out := t.TempDir()
		args := []string{"generate", "--dir", repo, "--slug", "knative", "--name", "Knative", "--repo", c.repo,
			"--tags", strings.Join(knativeTags, ","), "--rules", c.rules, "--out", out}
		if c.component != "" {
			args = append(args, "--component", c.component)
		}
		var so, se bytes.Buffer
		if code := Run(args, &so, &se); code != 1 || !strings.Contains(so.String(), c.stop) {
			t.Errorf("%s: exit %d, output %s", c.name, code, so.String())
		}
		if ents, _ := os.ReadDir(out); len(ents) != 0 {
			t.Errorf("%s: --out holds %d entries", c.name, len(ents))
		}
	}
}

func TestUsageListsNewStops(t *testing.T) {
	for _, w := range []string{StopRepoNotCanonical, StopComponentNotCanonical, StopUpstreamNotCanonical} {
		if !strings.Contains(usage, w) {
			t.Errorf("usage lacks %q", w)
		}
	}
}
