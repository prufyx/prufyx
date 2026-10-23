// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

const cliRoot = "../../.."

// realTree copies the files the checks read from the working tree into a
// map, to be mutated by a test.
func realTree(t *testing.T) fstest.MapFS {
	t.Helper()
	root := os.DirFS(cliRoot)
	m := fstest.MapFS{}
	for _, name := range []string{TablePath, GuardPath} {
		raw, err := fs.ReadFile(root, name)
		if err != nil {
			t.Fatal(err)
		}
		m[name] = &fstest.MapFile{Data: raw}
	}
	names, err := fs.Glob(root, TargetDir+"/target-*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("targets: %v %v", names, err)
	}
	for _, name := range names {
		raw, err := fs.ReadFile(root, name)
		if err != nil {
			t.Fatal(err)
		}
		m[name] = &fstest.MapFile{Data: raw}
	}
	return m
}

func edit(t *testing.T, m fstest.MapFS, name string, f func(doc map[string]any)) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(m[name].Data, &doc); err != nil {
		t.Fatal(err)
	}
	f(doc)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	m[name] = &fstest.MapFile{Data: raw}
}

func editTable(t *testing.T, m fstest.MapFS, f func(projects []any, doc map[string]any)) {
	edit(t, m, TablePath, func(doc map[string]any) { f(doc["projects"].([]any), doc) })
}

func editTarget(t *testing.T, m fstest.MapFS, project string, f func(target map[string]any)) {
	edit(t, m, TargetDir+"/target-"+project+".json", func(doc map[string]any) { f(doc["target"].(map[string]any)) })
}

func project(projects []any, slug string) map[string]any {
	for _, p := range projects {
		if p.(map[string]any)["slug"] == slug {
			return p.(map[string]any)
		}
	}
	panic("no project " + slug)
}

func dropProject(doc map[string]any, slug string) {
	var kept []any
	for _, p := range doc["projects"].([]any) {
		if p.(map[string]any)["slug"] != slug {
			kept = append(kept, p)
		}
	}
	doc["projects"] = kept
}

func mustLoad(t *testing.T, m fstest.MapFS, allowMissing bool) Inputs {
	t.Helper()
	in, err := Load(m, allowMissing)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func checks(fs []Finding) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, f.Check+" "+f.Subject)
	}
	return strings.Join(parts, "; ")
}

func wantCheck(t *testing.T, got []Finding, check, subject string) {
	t.Helper()
	for _, f := range got {
		if f.Check == check && strings.Contains(f.Subject, subject) {
			return
		}
	}
	t.Fatalf("want %s for %q, got: %s", check, subject, checks(got))
}

func TestCurrentDataPasses(t *testing.T) {
	in := mustLoad(t, realTree(t), false)
	if len(in.Projects) < 30 || len(in.Targets) < 30 {
		t.Fatalf("projects=%d targets=%d", len(in.Projects), len(in.Targets))
	}
	if got := Structure(in); len(got) != 0 {
		t.Fatalf("structure: %s", checks(got))
	}
	if got := CheckRemovals(in, in); len(got) != 0 {
		t.Fatalf("removals: %s", checks(got))
	}
	if files := PinnedFiles(in); len(files) < 40 {
		t.Fatalf("pinned files=%d", len(files))
	}
}

func TestSourceFormIsRefusedByTheLoaderOrTheCheck(t *testing.T) {
	for name, source := range map[string]string{
		"tag":            "https://github.com/argoproj/argo-cd/blob/v3.0.0/manifests/crds/application-crd.yaml",
		"branch":         "https://github.com/argoproj/argo-cd/blob/master/manifests/crds/application-crd.yaml",
		"short sha":      "https://github.com/argoproj/argo-cd/blob/e98f483/manifests/crds/application-crd.yaml",
		"upper sha":      "https://github.com/argoproj/argo-cd/blob/E98F483BFD5781DF2592FEC9D5B4D0D8F8A4B1C2/manifests/crds/application-crd.yaml",
		"raw host":       "https://raw.githubusercontent.com/argoproj/argo-cd/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml",
		"dot dot":        "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/../x.yaml",
		"query":          "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml?raw=1",
		"empty segment":  "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests//a.yaml",
		"tree not blob":  "https://github.com/argoproj/argo-cd/tree/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/a.yaml",
		"another scheme": "http://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/a.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			m := realTree(t)
			editTable(t, m, func(ps []any, _ map[string]any) {
				project(ps, "argo-cd")["groups"].([]any)[0].(map[string]any)["source"] = source
			})
			in, err := Load(m, false)
			if err == nil && len(Structure(in)) == 0 {
				t.Fatalf("source %q passed", source)
			}
			if _, ok := ParseBlob(source); ok {
				t.Fatalf("ParseBlob accepted %q", source)
			}
		})
	}
}

func TestSourceInAnotherRepositoryFails(t *testing.T) {
	m := realTree(t)
	editTable(t, m, func(ps []any, _ map[string]any) {
		project(ps, "argo-cd")["groups"].([]any)[0].(map[string]any)["source"] = "https://github.com/someone-else/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml"
	})
	wantCheck(t, Structure(mustLoad(t, m, false)), CheckSourceRepo, "argo-cd")
}

func TestRemoteRepositorySourceIsAccepted(t *testing.T) {
	in := mustLoad(t, realTree(t), false)
	for i, p := range in.Projects {
		if p.Slug != "kong-ingress-controller" {
			continue
		}
		var remote string
		for _, tg := range in.Targets {
			if tg.Project == p.Slug {
				remote = tg.Remote.Repo
			}
		}
		in.Projects[i].Groups = append([]customresources.Group(nil), p.Groups...)
		in.Projects[i].Groups[0].Source = "https://" + remote + "/blob/" + strings.Repeat("a", 40) + "/crds/x.yaml"
		if got := Structure(in); len(got) != 0 {
			t.Fatalf("remote repository refused: %s", checks(got))
		}
		in.Projects[i].Groups[0].Source = "https://github.com/third/party/blob/" + strings.Repeat("a", 40) + "/crds/x.yaml"
		wantCheck(t, Structure(in), CheckSourceRepo, p.Slug)
		return
	}
	t.Fatal("no kong-ingress-controller")
}

func TestDuplicateGroupAcrossProjectsFails(t *testing.T) {
	in := mustLoad(t, realTree(t), false)
	a, b := in.Projects[0], in.Projects[1]
	in.Projects = append([]customresources.Project(nil), in.Projects...)
	in.Projects[1].Groups = append(append([]customresources.Group(nil), b.Groups...), a.Groups[0])
	wantCheck(t, Structure(in), CheckDuplicate, "group "+a.Groups[0].Name)
}

func TestProjectWithoutTargetNeedsAReason(t *testing.T) {
	m := realTree(t)
	delete(m, TargetDir+"/target-argo-cd.json")
	in := mustLoad(t, m, false)
	wantCheck(t, Structure(in), CheckNoTarget, "argo-cd")

	editGuard := func(noTarget []any) fstest.MapFS {
		c := realTree(t)
		delete(c, TargetDir+"/target-argo-cd.json")
		edit(t, c, GuardPath, func(doc map[string]any) { doc["noTarget"] = noTarget })
		return c
	}
	ok := editGuard([]any{map[string]any{"project": "argo-cd", "reason": "no CRD manifests in the repository"}})
	if got := Structure(mustLoad(t, ok, false)); len(got) != 0 {
		t.Fatalf("explicit reason refused: %s", checks(got))
	}
	stale := realTree(t)
	edit(t, stale, GuardPath, func(doc map[string]any) {
		doc["noTarget"] = []any{map[string]any{"project": "argo-cd", "reason": "no CRD manifests in the repository"}}
	})
	wantCheck(t, Structure(mustLoad(t, stale, false)), CheckNoTargetStale, "argo-cd")
	unknown := editGuard([]any{map[string]any{"project": "argo-cd", "reason": "x"}})
	if _, err := Load(unknown, false); err == nil {
		t.Fatal("a one-character reason was accepted")
	}
}

func TestTargetMustAgreeWithItsTableRow(t *testing.T) {
	m := realTree(t)
	editTarget(t, m, "argo-cd", func(tg map[string]any) { tg["factProject"] = "argo_cd_other" })
	wantCheck(t, Structure(mustLoad(t, m, false)), CheckTargetTable, "argo-cd")
}

func TestAttestingTargetWithoutTableRowFails(t *testing.T) {
	m := realTree(t)
	editTable(t, m, func(_ []any, doc map[string]any) { dropProject(doc, "argo-cd") })
	wantCheck(t, Structure(mustLoad(t, m, false)), CheckTargetTable, "argo-cd")
}

func TestPinMustBeAFullCommit(t *testing.T) {
	in := mustLoad(t, realTree(t), false)
	for i := range in.Targets {
		if in.Targets[i].Remote != nil {
			in.Targets[i].Remote.Pins[0].Commit = "v1.0.0"
			wantCheck(t, Structure(in), CheckPin, in.Targets[i].Project)
			return
		}
	}
	t.Fatal("no remote target")
}

func TestGuardFileIsStrict(t *testing.T) {
	for name, raw := range map[string]string{
		"schema":          `{"schema":"x","removals":[],"noTarget":[]}`,
		"unknown field":   `{"schema":"` + GuardSchema + `","removals":[],"noTarget":[],"x":1}`,
		"null list":       `{"schema":"` + GuardSchema + `","removals":null,"noTarget":[]}`,
		"trailing":        `{"schema":"` + GuardSchema + `","removals":[],"noTarget":[]} {}`,
		"kind":            `{"schema":"` + GuardSchema + `","removals":[{"kind":"x","project":"a","reason":"a long enough reason"}],"noTarget":[]}`,
		"short reason":    `{"schema":"` + GuardSchema + `","removals":[{"kind":"project","project":"a","reason":"short"}],"noTarget":[]}`,
		"detail missing":  `{"schema":"` + GuardSchema + `","removals":[{"kind":"group","project":"a","reason":"a long enough reason"}],"noTarget":[]}`,
		"detail given":    `{"schema":"` + GuardSchema + `","removals":[{"kind":"target","project":"a","detail":"x","reason":"a long enough reason"}],"noTarget":[]}`,
		"duplicate entry": `{"schema":"` + GuardSchema + `","removals":[{"kind":"project","project":"a","reason":"a long enough reason"},{"kind":"project","project":"a","reason":"another long reason"}],"noTarget":[]}`,
		"unsorted":        `{"schema":"` + GuardSchema + `","removals":[],"noTarget":[{"project":"b","reason":"a long enough reason"},{"project":"a","reason":"a long enough reason"}]}`,
	} {
		if _, err := DecodeGuard([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeGuard([]byte(`{"schema":"` + GuardSchema + `","removals":[],"noTarget":[]}`)); err != nil {
		t.Fatal(err)
	}
}

// removal is one way head can shrink; change mutates a copy of the tree.
type removal struct {
	name   string
	change func(t *testing.T, m fstest.MapFS)
	want   Removal
}

// alsoRequired are the further entries a removal case needs.
var alsoRequired = map[string][]Removal{
	"identity target repo": {{Kind: KindIdentity, Project: "cilium", Detail: "component:pkg:github/evil/cilium"}},
	"channel":              {{Kind: KindNarrowed, Project: "gateway-api", Detail: "declaredChannel:"}},
}

var removals = []removal{
	{"project row", func(t *testing.T, m fstest.MapFS) {
		editTable(t, m, func(_ []any, doc map[string]any) { dropProject(doc, "cilium") })
	}, Removal{Kind: KindProject, Project: "cilium"}},
	{"group", func(t *testing.T, m fstest.MapFS) {
		editTable(t, m, func(ps []any, _ map[string]any) {
			p := project(ps, "antrea")
			p["groups"] = p["groups"].([]any)[:1]
		})
	}, Removal{Kind: KindGroup, Project: "antrea", Detail: "multicluster.crd.antrea.io"}},
	{"target", func(t *testing.T, m fstest.MapFS) { delete(m, TargetDir+"/target-cilium.json") },
		Removal{Kind: KindTarget, Project: "cilium"}},
	{"minFrom", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "cilium", func(tg map[string]any) { tg["minFrom"] = "1.16" })
	}, Removal{Kind: KindNarrowed, Project: "cilium", Detail: "minFrom:1.16"}},
	{"tag prefix", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "kuma", func(tg map[string]any) { tg["tagPrefixes"] = []any{"v"} })
	}, Removal{Kind: KindNarrowed, Project: "kuma", Detail: "tagPrefix:"}},
	{"path", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "antrea", func(tg map[string]any) { tg["paths"] = tg["paths"].([]any)[:1] })
	}, Removal{Kind: KindNarrowed, Project: "antrea", Detail: "path:multicluster/config/crd/bases"}},
	{"path made optional", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "cilium", func(tg map[string]any) { tg["paths"].([]any)[0].(map[string]any)["optional"] = true })
	}, Removal{Kind: KindNarrowed, Project: "cilium", Detail: "pathChanged:pkg/k8s/apis/cilium.io/client/crds/v2"}},
	{"attest", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "argo-cd", func(tg map[string]any) { delete(tg, "attest") })
	}, Removal{Kind: KindNarrowed, Project: "argo-cd", Detail: "attest"}},
	{"remote", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "kong-ingress-controller", func(tg map[string]any) { delete(tg, "remote") })
	}, Removal{Kind: KindNarrowed, Project: "kong-ingress-controller", Detail: "remote"}},
	{"remote pin", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "kong-ingress-controller", func(tg map[string]any) {
			r := tg["remote"].(map[string]any)
			r["pins"] = r["pins"].([]any)[1:]
		})
	}, Removal{Kind: KindNarrowed, Project: "kong-ingress-controller", Detail: "remotePin:v1.0.0"}},
	{"identity component", func(t *testing.T, m fstest.MapFS) {
		editTable(t, m, func(ps []any, _ map[string]any) { project(ps, "cilium")["component"] = "pkg:github/evil/cilium" })
	}, Removal{Kind: KindIdentity, Project: "cilium", Detail: "component:pkg:github/evil/cilium"}},
	{"identity group repo", func(t *testing.T, m fstest.MapFS) {
		editTable(t, m, func(ps []any, _ map[string]any) {
			project(ps, "cilium")["groups"].([]any)[0].(map[string]any)["source"] = "https://github.com/evil/cilium/blob/" + strings.Repeat("b", 40) + "/crds/x.yaml"
		})
	}, Removal{Kind: KindIdentity, Project: "cilium", Detail: "groupRepo:cilium.io:evil/cilium"}},
	{"identity target repo", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "cilium", func(tg map[string]any) {
			tg["repo"] = "github.com/evil/cilium"
			tg["component"] = "pkg:github/evil/cilium"
		})
	}, Removal{Kind: KindIdentity, Project: "cilium", Detail: "repo:github.com/evil/cilium"}},
	{"remote added", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "antrea", func(tg map[string]any) {
			tg["remote"] = map[string]any{"fromLine": "3.0", "kustomization": "k.yaml", "repo": "github.com/other/x", "directory": "d", "pins": []any{map[string]any{"tag": "v1.0.0", "commit": strings.Repeat("c", 40)}}}
		})
	}, Removal{Kind: KindNarrowed, Project: "antrea", Detail: "remoteAdded:github.com/other/x"}},
	{"remote fromLine lowered", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "kong-ingress-controller", func(tg map[string]any) { tg["remote"].(map[string]any)["fromLine"] = "3.3" })
	}, Removal{Kind: KindNarrowed, Project: "kong-ingress-controller", Detail: "remoteFrom:3.3"}},
	{"tag prefix order", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "kuma", func(tg map[string]any) { tg["tagPrefixes"] = []any{"", "v"} })
	}, Removal{Kind: KindNarrowed, Project: "kuma", Detail: "tagPrefixOrder"}},
	{"channel", func(t *testing.T, m fstest.MapFS) {
		editTarget(t, m, "gateway-api", func(tg map[string]any) { delete(tg, "channels"); delete(tg, "declaredChannel") })
	}, Removal{Kind: KindNarrowed, Project: "gateway-api", Detail: "channel:experimental"}},
}

func TestEveryRemovalNeedsAMatchingEntry(t *testing.T) {
	base := mustLoad(t, realTree(t), false)
	for _, rc := range removals {
		t.Run(rc.name, func(t *testing.T) {
			m := realTree(t)
			rc.change(t, m)
			head, err := Load(m, false)
			if err != nil {
				t.Fatalf("fixture does not load: %v", err)
			}
			found := false
			for _, r := range Diff(base, head) {
				if r.id() == rc.want.id() {
					found = true
				}
			}
			if !found {
				t.Fatalf("Diff = %+v, want %+v", Diff(base, head), rc.want)
			}
			// Without an entry: refused.
			wantCheck(t, CheckRemovals(base, head), CheckRemovalUnlisted, rc.want.Project)
			// With an entry added in the same change: accepted.
			edit(t, m, GuardPath, func(doc map[string]any) {
				for _, entry := range append([]Removal{rc.want}, alsoRequired[rc.name]...) {
					entry.Reason = "reviewed: the upstream dropped it"
					b, _ := json.Marshal(entry)
					var e any
					_ = json.Unmarshal(b, &e)
					doc["removals"] = append(doc["removals"].([]any), e)
				}
			})
			head, err = Load(m, false)
			if err != nil {
				t.Fatal(err)
			}
			if got := CheckRemovals(base, head); len(got) != 0 {
				t.Fatalf("listed removal refused: %s", checks(got))
			}
			// The entry is spent once it is in base: removing again needs a new one.
			if got := CheckRemovals(head, head); len(got) != 0 {
				t.Fatalf("no change, no finding: %s", checks(got))
			}
			again := base
			again.Guard = head.Guard
			wantCheck(t, CheckRemovals(again, head), CheckRemovalUnlisted, rc.want.Project)
		})
	}
}

func TestNarrowingTheOtherWayRoundsTrip(t *testing.T) {
	// A widened range, an added row or an added target is not a removal.
	head := mustLoad(t, realTree(t), false)
	m := realTree(t)
	editTarget(t, m, "cilium", func(tg map[string]any) { tg["minFrom"] = "1.16" })
	delete(m, TargetDir+"/target-kuma.json")
	editTable(t, m, func(_ []any, doc map[string]any) { dropProject(doc, "tekton") })
	base := mustLoad(t, m, true)
	if got := Diff(base, head); len(got) != 0 {
		t.Fatalf("widening listed as removal: %+v", got)
	}
}

func TestExclusionAddedIsNarrowing(t *testing.T) {
	head := mustLoad(t, realTree(t), false)
	m := realTree(t)
	editTarget(t, m, "crossplane", func(tg map[string]any) { tg["exclude"] = tg["exclude"].([]any)[1:] })
	base := mustLoad(t, m, false)
	found := false
	for _, r := range Diff(base, head) {
		found = found || (r.Kind == KindNarrowed && r.Project == "crossplane" && strings.HasPrefix(r.Detail, "exclude:"))
	}
	if !found {
		t.Fatalf("diff=%+v", Diff(base, head))
	}
}

func TestEntryWithoutAChangeAndDroppedEntryFail(t *testing.T) {
	base := mustLoad(t, realTree(t), false)
	m := realTree(t)
	edit(t, m, GuardPath, func(doc map[string]any) {
		doc["removals"] = []any{map[string]any{"kind": KindProject, "project": "cilium", "reason": "pre-approved for later"}}
	})
	head := mustLoad(t, m, false)
	wantCheck(t, CheckRemovals(base, head), CheckRemovalStale, "cilium")

	if got := CheckRemovals(head, base); len(got) == 0 {
		t.Fatal("dropping a listed entry passed")
	} else {
		wantCheck(t, got, CheckRemovalDropped, "cilium")
	}
}

func TestMissingGuardInBaseIsEmptyOnlyForTheBase(t *testing.T) {
	m := realTree(t)
	delete(m, GuardPath)
	if _, err := Load(m, false); err == nil {
		t.Fatal("head without guard.json loaded")
	}
	base := mustLoad(t, m, true)
	if base.GuardPresent || len(base.Guard.Removals) != 0 {
		t.Fatalf("base=%+v", base.Guard)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestOfflineCommandAgainstAGitBase runs the command the way CI does: the
// base revision is a commit, the head is the working tree.
func TestOfflineCommandAgainstAGitBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	root := filepath.Join(repo, "cli")
	git(t, repo, "init", "-q")
	write := func(m fstest.MapFS) {
		for name, f := range m {
			p := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, f.Data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	tree := realTree(t)
	write(tree)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base")
	base := git(t, repo, "rev-parse", "HEAD")

	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := Run(append([]string{"offline"}, args...), root, &out, &errOut)
		return code, out.String() + errOut.String()
	}
	if code, out := run("--base-ref", base); code != 0 {
		t.Fatalf("unchanged tree: %d %s", code, out)
	}
	if code, _ := run("--base-ref", "no-such-revision"); code != 2 {
		t.Fatalf("an unknown base revision must be an error, code=%d", code)
	}
	if code, _ := run("--base-ref", "--output=x"); code != 2 {
		t.Fatalf("an option as revision must be refused, code=%d", code)
	}

	// Remove a row (and its target): refused. Then list it: accepted.
	editTable(t, tree, func(_ []any, doc map[string]any) { dropProject(doc, "cilium") })
	delete(tree, TargetDir+"/target-cilium.json")
	_ = os.Remove(filepath.Join(root, TargetDir, "target-cilium.json"))
	write(tree)
	code, out := run("--base-ref", base)
	if code != 1 || !strings.Contains(out, CheckRemovalUnlisted) || !strings.Contains(out, "project cilium") || !strings.Contains(out, "target cilium") {
		t.Fatalf("removal without entry: %d %s", code, out)
	}
	edit(t, tree, GuardPath, func(doc map[string]any) {
		doc["removals"] = append(doc["removals"].([]any),
			map[string]any{"kind": KindProject, "project": "cilium", "detail": "", "reason": "upstream archived the project"},
			map[string]any{"kind": KindTarget, "project": "cilium", "detail": "", "reason": "upstream archived the project"},
		)
	})
	write(tree)
	if code, out := run("--base-ref", base); code != 0 {
		t.Fatalf("listed removal: %d %s", code, out)
	}
	// Without a base the structure is still checked.
	if code, out := run(); code != 0 || !strings.Contains(out, "removal guard not run") {
		t.Fatalf("no base: %d %s", code, out)
	}
}

func TestExtractRefusesUnsafeArchives(t *testing.T) {
	var buf bytes.Buffer
	_ = writeTar(&buf, "../escape.json")
	if err := extract(&buf, t.TempDir()); err == nil {
		t.Fatal("path traversal accepted")
	}
}

// fakeObjects serves the revision and content facts of a fake remote.
type fakeObjects struct {
	commits map[string]bool
	files   map[string]string
}

func (f fakeObjects) ResolveRevision(_ context.Context, _, _, sha string) (rulecheck.ObjectKind, error) {
	if f.commits[sha] {
		return rulecheck.ObjectKind{Commit: true}, nil
	}
	return rulecheck.ObjectKind{}, errors.New("not found")
}

func (f fakeObjects) RevisionReachable(_ context.Context, _, _, sha string) (bool, error) {
	return f.commits[sha], nil
}

func (f fakeObjects) FetchRawBlob(_ context.Context, url string) ([]byte, error) {
	if body, ok := f.files[url]; ok {
		return []byte(body), nil
	}
	return nil, fmt.Errorf("unexpected status 404 Not Found fetching %s", url)
}

func remoteFor(t *testing.T, in Inputs) fakeObjects {
	t.Helper()
	f := fakeObjects{commits: map[string]bool{}, files: map[string]string{}}
	for _, pf := range PinnedFiles(in) {
		b, ok := ParseBlob(pf.URL)
		if !ok {
			t.Fatalf("pinned file %q", pf.URL)
		}
		f.commits[b.Commit] = true
		f.files[fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", b.Owner, b.Repo, b.Commit, b.Path)] = "kind: CustomResourceDefinition\n"
	}
	return f
}

func TestCitationsCommand(t *testing.T) {
	m := realTree(t)
	in := mustLoad(t, m, false)
	root := t.TempDir()
	for name, f := range m {
		p := filepath.Join(root, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(f fakeObjects) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runCitations([]string{"--timeout", "1m"}, root, &out, &errOut, &citationDeps{resolver: f, fetcher: f})
		return code, out.String(), errOut.String()
	}
	good := remoteFor(t, in)
	if code, out, errOut := run(good); code != 0 || !strings.Contains(out, `"pass": true`) {
		t.Fatalf("all present: %d %s %s", code, out, errOut)
	}
	// The path is missing at its commit.
	missing := remoteFor(t, in)
	for k := range missing.files {
		if strings.Contains(k, "/application-crd.yaml") {
			delete(missing.files, k)
		}
	}
	code, _, errOut := run(missing)
	if code != 1 || !strings.Contains(errOut, rulecheck.CheckCitationFetch) || !strings.Contains(errOut, "argo-cd") {
		t.Fatalf("missing path: %d %s", code, errOut)
	}
	// The commit is unknown to the repository.
	unknown := remoteFor(t, in)
	for sha := range unknown.commits {
		delete(unknown.commits, sha)
		break
	}
	if code, _, errOut := run(unknown); code != 1 || !strings.Contains(errOut, "FAIL") {
		t.Fatalf("unknown commit: %d %s", code, errOut)
	}
	// An empty file is not a citation.
	empty := remoteFor(t, in)
	for k := range empty.files {
		empty.files[k] = ""
		break
	}
	if code, _, errOut := run(empty); code != 1 {
		t.Fatalf("empty file: %d %s", code, errOut)
	}
}

func writeTar(w io.Writer, name string) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		return err
	}
	return tw.Close()
}

func TestRemovalAgainAfterRestoreNeedsTheNextSeq(t *testing.T) {
	full := mustLoad(t, realTree(t), false)
	m := realTree(t)
	editTable(t, m, func(_ []any, doc map[string]any) { dropProject(doc, "tekton") })
	removed := mustLoad(t, m, false)
	entry := func(seq int) Removal {
		return Removal{Kind: KindProject, Project: "tekton", Seq: seq, Reason: "reviewed: the upstream dropped it"}
	}
	// The list is append-only: the entries the real tree already holds stay.
	listed := func(es ...Removal) []Removal { return append(append([]Removal(nil), full.Guard.Removals...), es...) }
	// First removal: seq 0.
	removed.Guard.Removals = listed(entry(0))
	if got := CheckRemovals(full, removed); len(got) != 0 {
		t.Fatalf("first removal: %s", checks(got))
	}
	// Restored (base has seq 0 and the row), removed again: seq 0 is spent.
	restored := full
	restored.Guard.Removals = listed(entry(0))
	wantCheck(t, CheckRemovals(restored, removed), CheckRemovalUnlisted, "tekton")
	removed.Guard.Removals = listed(entry(0), entry(1))
	if got := CheckRemovals(restored, removed); len(got) != 0 {
		t.Fatalf("second removal with seq 1: %s", checks(got))
	}
	// A seq that skips ahead is a stale pre-approval.
	removed.Guard.Removals = listed(entry(0), entry(2))
	wantCheck(t, CheckRemovals(restored, removed), CheckRemovalStale, "tekton")
}

// The loader refuses to drop the check of an exclusion under an install
// directory, so the weakening is exercised on the loaded targets directly.
func TestWeakenedExclusionIsNarrowing(t *testing.T) {
	base := mustLoad(t, realTree(t), false)
	head := mustLoad(t, realTree(t), false)
	n := 0
	for i := range head.Targets {
		head.Targets[i].Exclude = append([]crdversions.Exclusion(nil), head.Targets[i].Exclude...)
		for j := range head.Targets[i].Exclude {
			if head.Targets[i].Exclude[j].Copies {
				head.Targets[i].Exclude[j].Copies = false
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no exclusion with copies in the data: the case is void")
	}
	got := 0
	for _, r := range Diff(base, head) {
		if r.Kind == KindNarrowed && strings.HasPrefix(r.Detail, "excludeChanged:") {
			got++
		}
	}
	if got != n {
		t.Fatalf("weakened %d exclusions, Diff lists %d: %+v", n, got, Diff(base, head))
	}
}

// Declaring that an existing entry's files define nothing (a guarded
// exclusion becomes a checked one that //go:embed no longer voids) is a
// changed exclusion, listed as narrowing.
func TestDefinesNoneIsNarrowing(t *testing.T) {
	base := mustLoad(t, realTree(t), false)
	head := mustLoad(t, realTree(t), false)
	n := 0
	for i := range head.Targets {
		head.Targets[i].Exclude = append([]crdversions.Exclusion(nil), head.Targets[i].Exclude...)
		for j := range head.Targets[i].Exclude {
			if e := head.Targets[i].Exclude[j]; !e.Copies && e.PrePatch == "" && !e.DefinesNone {
				head.Targets[i].Exclude[j].DefinesNone = true
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no plain exclusion in the data: the case is void")
	}
	got := 0
	for _, r := range Diff(base, head) {
		if r.Kind == KindNarrowed && strings.HasPrefix(r.Detail, "excludeChanged:") {
			got++
		}
	}
	if got != n {
		t.Fatalf("changed %d exclusions, Diff lists %d", n, got)
	}
}
