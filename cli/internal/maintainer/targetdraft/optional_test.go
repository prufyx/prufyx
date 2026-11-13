// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	optPath  = "integration/fixtures/operator/01-operator.yml"
	optBadSh = "1111111111111111111111111111111111111111"
)

var optTags = []string{"v3.2.5", "v3.3.7", "v3.4.5", "v3.5.6", "v3.6.25", "v3.7.18"}

// optSpec is the content of one tag of a fixture repository.
type optSpec struct {
	files    map[string]string
	links    map[string]string
	gitlinks []string
}

// optBase is the unmutated window: the mandatory directory at every tag and
// the optional operator definition only at the newest tag.
func optBase(tag string) *optSpec {
	s := &optSpec{files: map[string]string{
		"api/config/crd/alpha.yaml": ipCRD("widgets.example.test", "Alpha"),
		"api/config/crd/beta.yaml":  ipCRD("widgets.example.test", "Beta"),
		"README.md":                 "not a definition",
	}, links: map[string]string{}}
	if tag == optTags[len(optTags)-1] {
		s.files[optPath] = ipCRD("widgets.example.test", "Operator")
	}
	return s
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// optRepo builds a real git repository with one commit and one tag per spec.
func optRepo(t *testing.T, mutate func(tag string, s *optSpec)) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	gitOut(t, dir, "init", "-q")
	for _, tag := range optTags {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.Name() != ".git" {
				if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
		s := optBase(tag)
		if mutate != nil {
			mutate(tag, s)
		}
		for p, b := range s.files {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(b), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for p, target := range s.links {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, full); err != nil {
				t.Fatal(err)
			}
		}
		gitOut(t, dir, "add", "-A")
		for _, p := range s.gitlinks {
			gitOut(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+optBadSh+","+p)
		}
		gitOut(t, dir, "commit", "-q", "--allow-empty", "-m", tag)
		gitOut(t, dir, "tag", tag)
	}
	return dir
}

func optRulesJSON(absent ...string) string {
	q, _ := json.Marshal(absent)
	return `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[` +
		`{"path":"api/config/crd/","reason":"the declared API definitions","evidence":"synthetic fixture"},` +
		`{"path":"` + optPath + `","reason":"operator definition added by a later line","evidence":"synthetic fixture: pinned tree listing","optional":true,"absentTags":` + string(q) + `}]}`
}

func optRules(t *testing.T, absent ...string) *Rules {
	t.Helper()
	r, err := ParseRules([]byte(optRulesJSON(absent...)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func optInput(src Source, rules *Rules) Input {
	return Input{Slug: "widgets", Name: "Widgets", Repo: "github.com/example/widgets", Catalog: "cncf", Tags: optTags, Source: src, Rules: rules}
}

var firstFive = optTags[:5]

func stopCodes(err error) []string {
	var se *StopError
	if !errors.As(err, &se) {
		return nil
	}
	var out []string
	for _, s := range se.Stops {
		out = append(out, s.Code)
	}
	return out
}

func TestOptionalAbsentThenPresentWritesDraft(t *testing.T) {
	repo := optRepo(t, nil)
	res := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	if !bytes.Contains(res.A, []byte(`{"path": "`+optPath+`"}`)) || !bytes.Contains(res.A, []byte(`{"path": "api/config/crd/alpha.yaml"}`)) {
		t.Fatalf("half A misses the operator path or a mandatory path:\n%s", res.A)
	}
	if len(res.Report.Tags) != 6 || len(res.Report.Dropped) != 0 || res.Report.MinFrom != "3.2" {
		t.Fatalf("window: %d tags, dropped %v, minFrom %s", len(res.Report.Tags), res.Report.Dropped, res.Report.MinFrom)
	}
	if res.Report.CRDCount != 3 {
		t.Fatalf("want 3 CRDs (Alpha, Beta, Operator), got %d", res.Report.CRDCount)
	}
	if len(res.Report.OptionalPaths) != 6 {
		t.Fatalf("optional facts: %+v", res.Report.OptionalPaths)
	}
	for i, f := range res.Report.OptionalPaths {
		want := "verified-absent"
		if i == 5 {
			want = "read"
		}
		if f.Tag != optTags[i] || f.Path != optPath || f.Status != want {
			t.Fatalf("optional fact %d: %+v, want status %s", i, f, want)
		}
	}
}

func TestOptionalDeterministic(t *testing.T) {
	repo := optRepo(t, nil)
	a := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	b := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	ra, _ := marshal(a.Report)
	rb, _ := marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(a.TableRow, b.TableRow) || !bytes.Equal(a.Changelog, b.Changelog) || !bytes.Equal(ra, rb) {
		t.Fatal("two runs differ")
	}
}

func TestOptionalDigestOnlyWhenUsed(t *testing.T) {
	repo := optRepo(t, nil)
	with := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	// Same source read without the optional entry (the operator file is then a
	// non-install copy): another digest, and no optional facts at all.
	plain, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[{"path":"api/config/crd/","reason":"r","evidence":"e"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	without := mustGenerate(t, optInput(GitSource{Dir: repo}, plain))
	if without.Report.OptionalPaths != nil {
		t.Fatalf("optional facts without an optional entry: %+v", without.Report.OptionalPaths)
	}
	if with.Report.FactsDigest == without.Report.FactsDigest {
		t.Fatal("digest does not depend on the optional entry")
	}
	// Listing fewer absent tags that are all proven absent changes nothing
	// else; the status of every window tag is part of the digest.
	again := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	if again.Report.FactsDigest != with.Report.FactsDigest {
		t.Fatal("same facts, different digest")
	}
}

func TestOptionalRefusals(t *testing.T) {
	newest := optTags[5]
	cases := []struct {
		name   string
		mutate func(tag string, s *optSpec)
		absent []string
		code   string
	}{
		{"absent at the newest tag", func(tag string, s *optSpec) { delete(s.files, optPath) }, optTags, StopOptionalAbsentNewest},
		{"absent at the newest tag, not listed", func(tag string, s *optSpec) { delete(s.files, optPath) }, firstFive, StopOptionalAbsentNewest},
		{"present at a listed tag", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.files[optPath] = ipCRD("widgets.example.test", "Operator")
			}
		}, firstFive, StopOptionalPresentListed},
		{"gitlink at the path", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.gitlinks = append(s.gitlinks, optPath)
			}
		}, firstFive, StopOptionalLink},
		{"symlink at the path", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.links[optPath] = "../../../api/config/crd/alpha.yaml"
			}
		}, firstFive, StopOptionalLink},
		{"symlink as a parent", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.links["integration/fixtures"] = "../api"
			}
		}, firstFive, StopOptionalLink},
		{"gitlink as a parent", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.gitlinks = append(s.gitlinks, "integration")
			}
		}, firstFive, StopOptionalLink},
		{"regular file as a parent", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.files["integration/fixtures"] = "a file where a directory should be"
			}
		}, firstFive, StopOptionalUnverifiable},
		{"directory at the path", func(tag string, s *optSpec) {
			if tag == "v3.4.5" {
				s.files[optPath+"/x.yaml"] = "x: y"
			}
		}, firstFive, StopOptionalUnverifiable},
		{"present but unreadable at the newest tag", func(tag string, s *optSpec) {
			if tag == newest {
				s.files[optPath] = "kind: CustomResourceDefinition\n{{ .Values.x }}\n"
			}
		}, firstFive, StopOptionalUnverifiable},
		{"present but unreadable at an unlisted older tag", func(tag string, s *optSpec) {
			if tag == "v3.6.25" {
				s.files[optPath] = "kind: CustomResourceDefinition\n{{ .Values.x }}\n"
			}
		}, optTags[:4], StopOptionalUnverifiable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := optRepo(t, c.mutate)
			res, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, c.absent...)))
			if err == nil {
				t.Fatalf("draft written: %d tags", len(res.Report.Tags))
			}
			wantStop(t, err, c.code)
		})
	}
}

func TestOptionalAbsentAtUnlistedTagKeepsTheExistingStop(t *testing.T) {
	repo := optRepo(t, nil)
	// v3.2.5 is absent but not listed: the window shrinks past it, exactly
	// like a mandatory entry that matches nothing.
	res := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, optTags[1:5]...)))
	if len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != "v3.2.5" || !strings.Contains(res.Report.Dropped[0].Reason, StopInstallPathNothing+":"+optPath) {
		t.Fatalf("dropped: %+v", res.Report.Dropped)
	}
	if res.Report.MinFrom != "3.3" || len(res.Report.OptionalPaths) != 5 {
		t.Fatalf("minFrom %s, facts %d", res.Report.MinFrom, len(res.Report.OptionalPaths))
	}
	// Absent at the tag next to the newest and not listed: only the newest
	// tag reads, so there is no window.
	_, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, optTags[:4]...)))
	se := wantStop(t, err, StopWindowTooShort)
	if !strings.Contains(se.Error(), StopInstallPathNothing) {
		t.Fatalf("the withheld reason is missing: %v", se.Error())
	}
	_, err = Generate(Input{Slug: "widgets", Name: "Widgets", Repo: "github.com/example/widgets", Catalog: "cncf", Tags: optTags, Source: GitSource{Dir: repo}, Rules: optRules(t, optTags[1:5]...), StrictWindow: true})
	wantStop(t, err, StopWindowShortened)
}

func TestOptionalNeverHidesAMissingMandatoryEntry(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		if tag == "v3.4.5" {
			delete(s.files, "api/config/crd/alpha.yaml")
			delete(s.files, "api/config/crd/beta.yaml")
		}
	})
	res := mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	if len(res.Report.Dropped) != 3 || res.Report.MinFrom != "3.5" {
		t.Fatalf("dropped %+v minFrom %s", res.Report.Dropped, res.Report.MinFrom)
	}
	var found bool
	for _, d := range res.Report.Dropped {
		if d.Tag == "v3.4.5" && strings.Contains(d.Reason, StopInstallPathNothing+":api/config/crd/") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the mandatory stop is not reported: %+v", res.Report.Dropped)
	}
}

func TestOptionalReadErrorOfAPresentFile(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		if tag == "v3.6.25" {
			s.files[optPath] = ipCRD("widgets.example.test", "OperatorOld")
		}
	})
	sha := gitOut(t, repo, "rev-parse", "v3.6.25:"+optPath)
	if err := os.Remove(filepath.Join(repo, ".git", "objects", sha[:2], sha[2:])); err != nil {
		t.Fatal(err)
	}
	_, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, optTags[:4]...)))
	wantStop(t, err, StopOptionalUnverifiable)
}

func TestOptionalMissingTreeObjectRefuses(t *testing.T) {
	repo := optRepo(t, nil)
	tsha := gitOut(t, repo, "rev-parse", "v3.7.18:integration/fixtures")
	if err := os.Remove(filepath.Join(repo, ".git", "objects", tsha[:2], tsha[2:])); err != nil {
		t.Fatal(err)
	}
	// The recursive listing already fails: no tag reads.
	_, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	if err == nil {
		t.Fatal("a missing tree object did not stop the run")
	}
	// The path probe fails by itself, too.
	commit := gitOut(t, repo, "rev-parse", "v3.7.18^{commit}")
	if k, err := (&gitTree{g: GitSource{Dir: repo}, commit: commit}).Probe(optPath); err == nil {
		t.Fatalf("probe proved %q with a missing tree object", k)
	}
}

func TestOptionalLocalOnlyEnvironmentIsEnforced(t *testing.T) {
	have := map[string]bool{}
	for _, e := range localGitEnv() {
		have[e] = true
	}
	for _, want := range []string{"GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none", "GIT_TERMINAL_PROMPT=0"} {
		if !have[want] {
			t.Fatalf("the reader environment lacks %s", want)
		}
	}
	repo := optRepo(t, nil)
	for _, drop := range []string{"GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none", "GIT_TERMINAL_PROMPT=0"} {
		var env []string
		for _, e := range localGitEnv() {
			if e != drop {
				env = append(env, e)
			}
		}
		_, err := Generate(optInput(GitSource{Dir: repo, env: env}, optRules(t, firstFive...)))
		wantStop(t, err, StopOptionalUnverifiable)
	}
	// Without an optional entry the reader is not asked to probe.
	if _, err := Generate(optInput(GitSource{Dir: repo, env: []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=/nonexistent"}}, nil)); err != nil && len(stopCodes(err)) > 0 && stopCodes(err)[0] == StopOptionalUnverifiable {
		t.Fatal("a run without optional entries was refused for the probe environment")
	}
}

func TestOptionalNeedsAProber(t *testing.T) {
	src := memSource{trees: map[string]*memTree{}}
	for _, tag := range optTags {
		m := newMemTree()
		for p, b := range optBase(tag).files {
			m.files[p] = []byte(b)
		}
		src.trees[tag] = m
	}
	_, err := Generate(optInput(src, optRules(t, firstFive...)))
	wantStop(t, err, StopOptionalUnverifiable)
	// The same trees read fine without an optional entry.
	plain, perr := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[{"path":"api/config/crd/","reason":"r","evidence":"e"}]}`))
	if perr != nil {
		t.Fatal(perr)
	}
	mustGenerate(t, optInput(src, plain))
}

// rawTree writes a tree object with arbitrary modes (git hash-object
// --literally) and returns its id.
func rawTree(t *testing.T, dir string, ents [][3]string) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range ents {
		b.WriteString(e[0] + " " + e[1] + "\x00")
		raw := make([]byte, 20)
		for i := range raw {
			var v byte
			for _, c := range e[2][2*i : 2*i+2] {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= byte(c - '0')
				default:
					v |= byte(c-'a') + 10
				}
			}
			raw[i] = v
		}
		b.Write(raw)
	}
	cmd := exec.Command("git", "-C", dir, "hash-object", "-w", "-t", "tree", "--literally", "--stdin")
	cmd.Stdin = &b
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hash-object: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestOptionalOpaqueTreeEntryRefuses(t *testing.T) {
	repo := optRepo(t, nil)
	blob := gitOut(t, repo, "rev-parse", "v3.7.18:README.md")
	api := gitOut(t, repo, "rev-parse", "v3.3.7:api")
	// At v3.3.7 the directory above the optional path holds a malformed entry
	// (a name with a slash, which git itself writes only for a corrupt tree).
	// git canonicalises odd modes when it lists a tree, so a malformed name is
	// the opaque shape that can be built; the path probe must refuse it.
	leaf := rawTree(t, repo, [][3]string{{"100644", "x/odd.yaml", blob}})
	mid := rawTree(t, repo, [][3]string{{"40000", "operator", leaf}})
	top := rawTree(t, repo, [][3]string{{"40000", "fixtures", mid}})
	root := rawTree(t, repo, [][3]string{{"40000", "api", api}, {"40000", "integration", top}})
	commit := gitOut(t, repo, "commit-tree", root, "-m", "opaque")
	gitOut(t, repo, "tag", "-f", "v3.3.7", commit)
	_, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	wantStop(t, err, StopOptionalUnverifiable)
}

func TestOptionalRulesFailClosed(t *testing.T) {
	entry := func(extra string) string {
		return `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[{"reason":"r","evidence":"e",` + extra + `}]}`
	}
	bad := map[string]string{
		"directory prefix":               entry(`"path":"integration/fixtures/","optional":true,"absentTags":["v1.0.0"]`),
		"not a definition file":          entry(`"path":"integration/README.md","optional":true,"absentTags":["v1.0.0"]`),
		"no absentTags":                  entry(`"path":"a/b.yaml","optional":true`),
		"empty absentTags":               entry(`"path":"a/b.yaml","optional":true,"absentTags":[]`),
		"absentTags without optional":    entry(`"path":"a/b.yaml","absentTags":["v1.0.0"]`),
		"duplicate absent tag":           entry(`"path":"a/b.yaml","optional":true,"absentTags":["v1.0.0","v1.0.0"]`),
		"absent tag is not a tag name":   entry(`"path":"a/b.yaml","optional":true,"absentTags":["--upload-pack=x"]`),
		"unknown field":                  entry(`"path":"a/b.yaml","optional":true,"absentTags":["v1.0.0"],"tolerant":true`),
		"unclean path":                   entry(`"path":"a/../b.yaml","optional":true,"absentTags":["v1.0.0"]`),
		"optional not a boolean":         entry(`"path":"a/b.yaml","optional":"yes","absentTags":["v1.0.0"]`),
		"directory path with the suffix": entry(`"path":"a/b.yaml/","optional":true,"absentTags":["v1.0.0"]`),
	}
	for name, raw := range bad {
		if _, err := ParseRules([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := ParseRules([]byte(entry(`"path":"a/b.yaml","optional":true,"absentTags":["v1.0.0"]`))); err != nil {
		t.Fatalf("a well formed optional entry: %v", err)
	}
	// An absent tag outside the window is bad input at generate time.
	repo := optRepo(t, nil)
	_, err := Generate(optInput(GitSource{Dir: repo}, optRules(t, "v9.9.9")))
	wantStop(t, err, StopBadInput)
}

// The seeded check: if the operator path is dropped from the rules, the
// generated target and the facts digest differ from the reviewed ones, and the
// compare flags exit non-zero. A tree that loses the file at the newest tag
// stops.
func TestOptionalSeededOperatorDropIsCaught(t *testing.T) {
	repo := optRepo(t, nil)
	dir := t.TempDir()
	open := func(string) Source { return GitSource{Dir: repo} }
	rulesFile := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesFile, []byte(optRulesJSON(firstFive...)), 0o644); err != nil {
		t.Fatal(err)
	}
	seededRules := filepath.Join(dir, "seeded.json")
	if err := os.WriteFile(seededRules, []byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[{"path":"api/config/crd/","reason":"r","evidence":"e"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	args := func(out, rules string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "widgets", "--name", "Widgets", "--repo", "github.com/example/widgets",
			"--tags", strings.Join(optTags, ","), "--rules", rules, "--out", out}, extra...)
	}
	var so, se bytes.Buffer
	base := filepath.Join(dir, "base")
	if code := run(args(base, rulesFile), &so, &se, open); code != 0 {
		t.Fatalf("base: exit %d %s %s", code, so.String(), se.String())
	}
	a, b, rep := filepath.Join(base, "a", "target-widgets.json"), filepath.Join(base, "b", "target-widgets.json"), filepath.Join(base, "report.json")
	so.Reset()
	if code := run(args(filepath.Join(dir, "same"), rulesFile, "--compare-a", a, "--compare-b", b, "--compare-report", rep), &so, &se, open); code != 0 {
		t.Fatalf("equal run: exit %d %s", code, so.String())
	}
	so.Reset()
	code := run(args(filepath.Join(dir, "seeded"), seededRules, "--compare-a", a, "--compare-b", b, "--compare-report", rep), &so, &se, open)
	out := so.String()
	if code != 1 || !strings.Contains(out, "DIFF A: path missing from generated: "+optPath) || !strings.Contains(out, "DIFF facts") {
		t.Fatalf("the dropped operator path was not caught: exit %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "seeded")); err == nil {
		t.Fatal("a drifting run wrote a draft")
	}
	// The report carries the optional facts.
	raw, err := os.ReadFile(rep)
	if err != nil || !strings.Contains(string(raw), `"optionalPaths"`) || !strings.Contains(string(raw), `"verified-absent"`) {
		t.Fatalf("report lacks the optional facts: %v", err)
	}
	// The file vanishing at the newest tag stops the run (exit 1, no draft).
	gone := optRepo(t, func(tag string, s *optSpec) { delete(s.files, optPath) })
	so.Reset()
	code = run(args(filepath.Join(dir, "gone"), rulesFile), &so, &se, func(string) Source { return GitSource{Dir: gone} })
	if code != 1 || !strings.Contains(so.String(), StopOptionalAbsentNewest) {
		t.Fatalf("absence at the newest tag: exit %d %s", code, so.String())
	}
}

func TestOptionalUsageTextNamesTheEntry(t *testing.T) {
	for _, w := range []string{"optional", "absentTags", "optional-absent-at-newest"} {
		if !strings.Contains(usage, w) {
			t.Fatalf("usage text lacks %q", w)
		}
	}
}

// TestOptionalSpawnedGitReceivesLocalOnlyEnvironment puts a fake git first on
// PATH. It records the three variables that keep git off the network and then
// runs the real git, so the run still completes. Every call kind of the
// reader must have received them.
func TestOptionalSpawnedGitReceivesLocalOnlyEnvironment(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	repo := optRepo(t, nil)
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	script := "#!/bin/sh\n" +
		"{ echo \"CALL $*\"; echo \"NLF=${GIT_NO_LAZY_FETCH-unset}\"; echo \"AP=${GIT_ALLOW_PROTOCOL-unset}\"; echo \"HOME=${HOME-unset}\"; } >> '" + log + "'\n" +
		"exec '" + realGit + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// The command is looked up on the parent PATH, so the fake goes first there.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	mustGenerate(t, optInput(GitSource{Dir: repo}, optRules(t, firstFive...)))
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the fake git was never run: %v", err)
	}
	kinds := map[string]int{}
	var call string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		switch {
		case strings.HasPrefix(line, "CALL "):
			call = line
			switch {
			case strings.Contains(call, " rev-parse "):
				kinds["rev-parse"]++
			case strings.Contains(call, " ls-tree -r "):
				kinds["ls-tree -r"]++
			case strings.Contains(call, " ls-tree "):
				kinds["ls-tree"]++
			default:
				kinds["other"]++ // blob reads; the variables are still required
			}
		case line == "NLF=1", line == "AP=none", line == "HOME=/nonexistent":
		default:
			t.Fatalf("%s received %q", call, line)
		}
	}
	for _, k := range []string{"rev-parse", "ls-tree -r", "ls-tree"} {
		if kinds[k] == 0 {
			t.Fatalf("call kind %q was never observed (%v)", k, kinds)
		}
	}
}
