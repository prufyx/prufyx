// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

// The proof of the oldest-supported-client pin. A pin other than the legacy one
// must name a released client: a commit on the first-parent line of
// origin/main, tagged with exactly the pinned version, that holds the code of
// every client floor the version reaches. It is offline and refuses on every
// proof it cannot read. It does not replace the publish guard
// (knowledgepinguard), which alone proves publication and attestation, and it
// does not prove that the client reads a feature: the admit tests in
// internal/maintainer/knowledgerelease do that in CI.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepinguard"
)

// clientFloor is one client floor and the files of this directory a pinned ref
// at or above it must hold.
type clientFloor struct {
	name, version string
	files         []string
}

// clientFloors are all four client floors. The provider-facts file also exists
// at releases below its floor, so for that floor the file proves nothing: the
// proof is the version, the tag and main, and safety rests on the publisher
// refusing distribution records.
func clientFloors() []clientFloor {
	return []clientFloor{
		{"ProviderFactsMinClientVersion", ProviderFactsMinClientVersion, []string{"distributions.go"}},
		{"PinnedLeaseMinClientVersion", PinnedLeaseMinClientVersion, []string{"lease.go"}},
		{"ListedFamilyFloor", ListedFamilyFloor, []string{"listedfloor.go"}},
		{"BoundaryCoveredFloor", BoundaryCoveredFloor, []string{"listedfloor.go", "optinfloor.go"}},
	}
}

const pinFloorDir = "cli/internal/cncfcheck/"

// The pin form of the publication workflow (knowledge-publish.yml); a test
// holds these to that file.
var (
	pinWorkflowRefRE     = regexp.MustCompile(`^ref=[0-9a-f]{40}$`)
	pinWorkflowVersionRE = regexp.MustCompile(`^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+\.[0-9]+)?$`)
)

// pinGitEnvironment is the environment of every git call of the proof: nothing
// that redirects the repository, its objects or its history, and no replace
// objects.
func pinGitEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
			"GIT_NAMESPACE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE", "GIT_NO_REPLACE_OBJECTS":
			continue
		}
		if strings.HasPrefix(name, "GIT_CONFIG") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GIT_NO_REPLACE_OBJECTS=1")
}

func pinGit(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = pinGitEnvironment()
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	return stdout.String(), err
}

// pinIsAncestor reads merge-base --is-ancestor strictly: exit 0 is yes, 1 is
// no, anything else is an error.
func pinIsAncestor(repo, ancestor, of string) (bool, error) {
	_, err := pinGit(repo, "merge-base", "--is-ancestor", ancestor, of)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("merge-base --is-ancestor %s %s: %w", ancestor, of, err)
}

// pinProblems lists every way the pin file bytes are not proved for the floors
// in the repository at repo. Empty means proved. A proof that cannot be read is
// a problem.
func pinProblems(floors []clientFloor, pin []byte, repo string) []string {
	if len(floors) == 0 {
		return []string{"no client floor to hold the pin to"}
	}
	for _, floor := range floors {
		if !buildidentity.ValidVersion(floor.version) || len(floor.files) == 0 {
			return []string{fmt.Sprintf("floor %s %q is not a version with its files", floor.name, floor.version)}
		}
	}
	ref, version, err := knowledgepinguard.ParsePin(pin)
	if err != nil {
		return []string{err.Error()}
	}
	lines := strings.Split(strings.TrimSuffix(string(pin), "\n"), "\n")
	if len(lines) != 2 || !pinWorkflowRefRE.MatchString(lines[0]) || !pinWorkflowVersionRE.MatchString(lines[1]) {
		return []string{"the pin is not in the publication workflow's two-line form"}
	}
	var problems []string
	if string(pin) == knowledgepinguard.LegacyPin {
		for _, floor := range floors {
			if buildidentity.AtLeast(knowledgepinguard.LegacyVersion, floor.version) {
				problems = append(problems, fmt.Sprintf("the legacy pin %s is not below the floor %s %s", knowledgepinguard.LegacyVersion, floor.name, floor.version))
			}
		}
		return problems
	}

	// Every other pin, below a floor or not.
	if _, err := exec.LookPath("git"); err != nil {
		return []string{"git is not usable: " + err.Error()}
	}
	top, err := pinGit(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return []string{"the repository cannot be read: " + err.Error()}
	}
	want, err := filepath.Abs(repo)
	if err == nil {
		want, err = filepath.EvalSymlinks(want)
	}
	if err != nil || strings.TrimSuffix(top, "\n") != want {
		return []string{fmt.Sprintf("%s is not the top of a repository", repo)}
	}
	if shallow, err := pinGit(repo, "rev-parse", "--is-shallow-repository"); err != nil || shallow != "false\n" {
		return []string{fmt.Sprintf("the history is shallow or its depth is unknown (%q, %v)", shallow, err)}
	}
	grafts, err := pinGit(repo, "rev-parse", "--git-path", "info/grafts")
	if err != nil {
		return []string{"the grafts path cannot be read: " + err.Error()}
	}
	graftPath := strings.TrimSuffix(grafts, "\n")
	if !filepath.IsAbs(graftPath) {
		graftPath = filepath.Join(repo, graftPath)
	}
	if _, err := os.Lstat(graftPath); !errors.Is(err, os.ErrNotExist) {
		return []string{fmt.Sprintf("the repository has a grafts file, or it cannot be ruled out: %v", err)}
	}
	if kind, err := pinGit(repo, "cat-file", "-t", ref); err != nil || kind != "commit\n" {
		return []string{fmt.Sprintf("the pinned ref %s is not a commit that is present (%q, %v)", ref, strings.TrimSpace(kind), err)}
	}
	// a. on the first-parent line of origin/main.
	line, err := pinGit(repo, "rev-list", "--first-parent", "refs/remotes/origin/main", "--")
	if err != nil {
		problems = append(problems, "refs/remotes/origin/main cannot be read: "+err.Error())
	} else if !strings.Contains("\n"+line, "\n"+ref+"\n") {
		problems = append(problems, "the pinned ref "+ref+" is not on the first-parent line of origin/main")
	}
	// b. the tag of the pinned version is the pinned ref.
	tagged, err := pinGit(repo, "rev-parse", "--verify", "--quiet", "refs/tags/"+version+"^{commit}")
	if err != nil {
		problems = append(problems, "the tag refs/tags/"+version+" cannot be resolved: "+err.Error())
	} else if tagged != ref+"\n" {
		problems = append(problems, fmt.Sprintf("the tag %s is %s, not the pinned ref %s", version, strings.TrimSpace(tagged), ref))
	}
	// c. the code of every reached floor.
	for _, floor := range floors {
		if !buildidentity.AtLeast(version, floor.version) {
			continue
		}
		for _, file := range floor.files {
			path := pinFloorDir + file
			listed, err := pinGit(repo, "ls-tree", ref, "--", path)
			entry := strings.TrimSuffix(listed, "\n")
			if err != nil || strings.Contains(entry, "\n") || !strings.HasPrefix(entry, "100644 blob ") || !strings.HasSuffix(entry, "\t"+path) {
				problems = append(problems, fmt.Sprintf("floor %s: %s is not one regular file at %s (%q, %v)", floor.name, path, ref, entry, err))
				continue
			}
			added, err := pinGit(repo, "log", "--diff-filter=A", "--format=%H", "HEAD", "--", path)
			commits := strings.Fields(added)
			if err != nil || len(commits) == 0 {
				problems = append(problems, fmt.Sprintf("floor %s: the commit that added %s cannot be read: %v", floor.name, path, err))
				continue
			}
			ok, err := pinIsAncestor(repo, commits[len(commits)-1], ref)
			if err != nil {
				problems = append(problems, fmt.Sprintf("floor %s: %v", floor.name, err))
			} else if !ok {
				problems = append(problems, fmt.Sprintf("floor %s: the commit that added %s is not an ancestor of %s", floor.name, path, ref))
			}
		}
	}
	return problems
}

// pinRepoRoot is this source tree's repository root.
var pinRepoRoot = filepath.Join("..", "..", "..")

// The pin of this checkout is proved. A pin other than the legacy one that
// cannot be proved fails everywhere; it is never skipped.
func TestOldestSupportedClientPinProof(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if p := pinProblems(clientFloors(), raw, pinRepoRoot); len(p) != 0 {
		t.Fatalf("pin %q: %s", raw, strings.Join(p, "; "))
	}
}

func TestPinClientFloorTable(t *testing.T) {
	want := map[string]string{
		"ProviderFactsMinClientVersion": "v0.1.0-beta.1 distributions.go",
		"PinnedLeaseMinClientVersion":   "v0.1.0-beta.2 lease.go",
		"ListedFamilyFloor":             "v0.1.0-beta.3 listedfloor.go",
		"BoundaryCoveredFloor":          "v0.1.0-beta.3 listedfloor.go optinfloor.go",
	}
	floors := clientFloors()
	if len(floors) != len(want) {
		t.Fatalf("floors %+v", floors)
	}
	for _, f := range floors {
		if got := f.version + " " + strings.Join(f.files, " "); got != want[f.name] {
			t.Errorf("floor %s: %q, want %q", f.name, got, want[f.name])
		}
		for _, file := range f.files {
			if info, err := os.Lstat(file); err != nil || !info.Mode().IsRegular() {
				t.Errorf("floor %s names %s: %v", f.name, file, err)
			}
		}
	}
}

func TestPinFormMatchesThePublicationWorkflow(t *testing.T) {
	if _, err := os.Stat(filepath.Join(pinRepoRoot, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	workflow, err := os.ReadFile(filepath.Join(pinRepoRoot, ".github", "workflows", "knowledge-publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{pinWorkflowRefRE.String(), pinWorkflowVersionRE.String()} {
		if !strings.Contains(string(workflow), "=~ "+re+" ]]") {
			t.Fatalf("the publication workflow does not match the pin with %s", re)
		}
	}
}

// pinTestRepo is a throwaway repository for the negative cases.
type pinTestRepo struct {
	t    *testing.T
	dir  string
	date int
}

func newPinTestRepo(t *testing.T) *pinTestRepo {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &pinTestRepo{t: t, dir: dir}
	r.git("init", "-q", "-b", "main")
	r.write("README", "root\n")
	r.commit("root")
	return r
}

func (r *pinTestRepo) git(args ...string) string {
	r.t.Helper()
	base := []string{"-C", r.dir, "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false"}
	cmd := exec.Command("git", append(base, args...)...)
	date := fmt.Sprintf("%d +0000", 1700000000+r.date)
	cmd.Env = append(pinGitEnvironment(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *pinTestRepo) write(path, content string) {
	r.t.Helper()
	full := filepath.Join(r.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *pinTestRepo) commit(message string) string {
	r.t.Helper()
	r.date++
	r.git("add", "-A")
	r.git("commit", "-q", "--allow-empty", "-m", message)
	return r.git("rev-parse", "HEAD")
}

func (r *pinTestRepo) floorFiles(files ...string) {
	for _, f := range files {
		r.write(pinFloorDir+f, "package cncfcheck // "+f+"\n")
	}
}

func (r *pinTestRepo) publish(ref string) {
	r.git("update-ref", "refs/remotes/origin/main", ref)
}

var allPinFiles = []string{"distributions.go", "lease.go", "listedfloor.go", "optinfloor.go"}

// released is a repository whose main holds a release of every floor file,
// tagged version, and the pin that proves.
func released(t *testing.T, version string, files ...string) (*pinTestRepo, string) {
	t.Helper()
	r := newPinTestRepo(t)
	r.floorFiles(files...)
	ref := r.commit("release")
	r.git("tag", "-a", "-m", version, version, ref)
	r.publish(ref)
	return r, ref
}

func pinBytes(ref, version string) []byte {
	return []byte("ref=" + ref + "\nversion=" + version + "\n")
}

func requirePinProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	if len(problems) == 0 {
		t.Fatalf("the pin was accepted, want a refusal naming %q", want)
	}
	if !strings.Contains(strings.Join(problems, "; "), want) {
		t.Fatalf("problems %q do not name %q", problems, want)
	}
}

func requirePinProved(t *testing.T, problems []string) {
	t.Helper()
	if len(problems) != 0 {
		t.Fatalf("the pin was refused: %q", problems)
	}
}

func TestPinProblemsAccepts(t *testing.T) {
	t.Run("a full proof at the highest floor", func(t *testing.T) {
		r, ref := released(t, ListedFamilyFloor, allPinFiles...)
		// A later commit on main does not remove the proof.
		r.write("later", "x\n")
		r.publish(r.commit("later"))
		requirePinProved(t, pinProblems(clientFloors(), pinBytes(ref, ListedFamilyFloor), r.dir))
	})
	t.Run("a lightweight tag", func(t *testing.T) {
		r, ref := released(t, "v9.0.0", allPinFiles...)
		r.git("tag", "-d", "v9.0.0")
		r.git("tag", "v9.0.0", ref)
		requirePinProved(t, pinProblems(clientFloors(), pinBytes(ref, "v9.0.0"), r.dir))
	})
	t.Run("a pin that reaches only the lower floors", func(t *testing.T) {
		r, ref := released(t, PinnedLeaseMinClientVersion, "distributions.go", "lease.go")
		requirePinProved(t, pinProblems(clientFloors(), pinBytes(ref, PinnedLeaseMinClientVersion), r.dir))
		// It stays below the later floors: their features are still left out
		// of, or refused in, a publication for it.
		if ships, err := ListedFamilyShips(PinnedLeaseMinClientVersion); ships || err != nil {
			t.Fatalf("the listed family ships to %s: %v %v", PinnedLeaseMinClientVersion, ships, err)
		}
		if atLeastVersion(PinnedLeaseMinClientVersion, BoundaryCoveredFloor) {
			t.Fatal("the opt-in level reaches " + PinnedLeaseMinClientVersion)
		}
	})
	t.Run("the legacy pin needs no repository", func(t *testing.T) {
		requirePinProved(t, pinProblems(clientFloors(), []byte(knowledgepinguard.LegacyPin), t.TempDir()))
	})
}

func TestPinProblemsRefusesTheForm(t *testing.T) {
	r, ref := released(t, ListedFamilyFloor, allPinFiles...)
	good := "version=" + ListedFamilyFloor
	for name, raw := range map[string]string{
		"empty":            "",
		"one line":         "ref=" + ref + "\n",
		"three lines":      "ref=" + ref + "\n" + good + "\nx=1\n",
		"blank third line": "ref=" + ref + "\n" + good + "\n\n",
		"short ref":        "ref=" + ref[:12] + "\n" + good + "\n",
		"uppercase ref":    "ref=" + strings.ToUpper(ref) + "\n" + good + "\n",
		"symbolic ref":     "ref=refs/heads/main\n" + good + "\n",
		"latest":           "ref=" + ref + "\nversion=latest\n",
		"no version":       "ref=" + ref + "\nversion=\n",
		"build metadata":   "ref=" + ref + "\n" + good + "+build\n",
		"bare prerelease":  "ref=" + ref + "\nversion=v0.1.0-rc\n",
		"trailing space":   "ref=" + ref + "\n" + good + " \n",
		"carriage return":  "ref=" + ref + "\r\n" + good + "\n",
		"swapped":          good + "\nref=" + ref + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if p := pinProblems(clientFloors(), []byte(raw), r.dir); len(p) == 0 {
				t.Fatalf("%q accepted", raw)
			}
		})
	}
}

func TestPinProblemsRefusesBadFloors(t *testing.T) {
	legacy := []byte(knowledgepinguard.LegacyPin)
	requirePinProblem(t, pinProblems(nil, legacy, "."), "no client floor")
	requirePinProblem(t, pinProblems([]clientFloor{{"x", "latest", []string{"a.go"}}}, legacy, "."), "is not a version")
	requirePinProblem(t, pinProblems([]clientFloor{{"x", "v1.0.0", nil}}, legacy, "."), "with its files")
	// The legacy pin passes only below every floor.
	for _, floor := range []string{knowledgepinguard.LegacyVersion, "v0.0.1-alpha.1"} {
		requirePinProblem(t, pinProblems(append(clientFloors(), clientFloor{"low", floor, []string{"lease.go"}}), legacy, "."), "the legacy pin")
	}
}

func TestPinProblemsRefusesTheRef(t *testing.T) {
	const v = ListedFamilyFloor
	t.Run("legacy ref with another version", func(t *testing.T) {
		r, _ := released(t, v, allPinFiles...)
		legacyRef, _, err := knowledgepinguard.ParsePin([]byte(knowledgepinguard.LegacyPin))
		if err != nil {
			t.Fatal(err)
		}
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(legacyRef, v), r.dir), "not a commit that is present")
	})
	t.Run("unknown ref", func(t *testing.T) {
		r, _ := released(t, v, allPinFiles...)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(strings.Repeat("a", 40), v), r.dir), "not a commit that is present")
	})
	t.Run("tree object", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(r.git("rev-parse", ref+"^{tree}"), v), r.dir), "not a commit that is present")
	})
	t.Run("tag object", func(t *testing.T) {
		r, _ := released(t, v, allPinFiles...)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(r.git("rev-parse", "refs/tags/"+v), v), r.dir), "not a commit that is present")
	})
	t.Run("commit only on a branch", func(t *testing.T) {
		r, _ := released(t, v, allPinFiles...)
		r.git("checkout", "-q", "-b", "topic")
		r.write("topic", "x\n")
		ref := r.commit("topic")
		r.git("tag", "-f", v, ref)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "first-parent line")
	})
	t.Run("second parent of a merge on main", func(t *testing.T) {
		r, _ := released(t, v, allPinFiles...)
		r.git("checkout", "-q", "-b", "topic")
		r.write("topic", "x\n")
		ref := r.commit("topic")
		r.git("checkout", "-q", "main")
		r.date++
		r.git("merge", "-q", "--no-ff", "-m", "merge", "topic")
		r.publish(r.git("rev-parse", "HEAD"))
		r.git("tag", "-f", v, ref)
		if ok, err := pinIsAncestor(r.dir, ref, "refs/remotes/origin/main"); err != nil || !ok {
			t.Fatalf("setup: the ref must be an ancestor of main: %v %v", ok, err)
		}
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "first-parent line")
	})
	t.Run("origin/main unreadable", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		r.git("update-ref", "-d", "refs/remotes/origin/main")
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "origin/main cannot be read")
	})
	t.Run("no tag", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		r.git("tag", "-d", v)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "cannot be resolved")
	})
	t.Run("tag elsewhere", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		r.write("later", "x\n")
		later := r.commit("later")
		r.publish(later)
		r.git("tag", "-f", v, later)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "not the pinned ref")
	})
	t.Run("a branch named like the version", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		r.git("tag", "-d", v)
		r.git("branch", v, ref)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "cannot be resolved")
	})
	t.Run("below every floor is proved all the same", func(t *testing.T) {
		r, ref := released(t, ListedFamilyFloor, allPinFiles...)
		r.git("tag", "v0.0.9", ref)
		requirePinProved(t, pinProblems(clientFloors(), pinBytes(ref, "v0.0.9"), r.dir))
		r.git("tag", "-d", "v0.0.9")
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, "v0.0.9"), r.dir), "cannot be resolved")
	})
}

func TestPinProblemsRefusesTheFloorFiles(t *testing.T) {
	const v = ListedFamilyFloor
	build := func(t *testing.T, edit func(r *pinTestRepo)) []string {
		t.Helper()
		r := newPinTestRepo(t)
		r.floorFiles(allPinFiles...)
		edit(r)
		ref := r.commit("release")
		r.git("tag", v, ref)
		r.publish(ref)
		return pinProblems(clientFloors(), pinBytes(ref, v), r.dir)
	}
	listed := func(r *pinTestRepo) string {
		return filepath.Join(r.dir, filepath.FromSlash(pinFloorDir+"listedfloor.go"))
	}
	remove := func(r *pinTestRepo) {
		if err := os.Remove(listed(r)); err != nil {
			r.t.Fatal(err)
		}
	}
	t.Run("control", func(t *testing.T) { requirePinProved(t, build(t, func(*pinTestRepo) {})) })
	t.Run("absent", func(t *testing.T) { requirePinProblem(t, build(t, remove), "listedfloor.go is not one regular file") })
	t.Run("directory", func(t *testing.T) {
		requirePinProblem(t, build(t, func(r *pinTestRepo) {
			remove(r)
			r.write(pinFloorDir+"listedfloor.go/inner", "x\n")
		}), "listedfloor.go is not one regular file")
	})
	t.Run("symlink", func(t *testing.T) {
		requirePinProblem(t, build(t, func(r *pinTestRepo) {
			remove(r)
			if err := os.Symlink("lease.go", listed(r)); err != nil {
				r.t.Fatal(err)
			}
		}), "listedfloor.go is not one regular file")
	})
	t.Run("executable", func(t *testing.T) {
		requirePinProblem(t, build(t, func(r *pinTestRepo) {
			if err := os.Chmod(listed(r), 0o755); err != nil {
				r.t.Fatal(err)
			}
		}), "listedfloor.go is not one regular file")
	})
	t.Run("only listedfloor.go refuses the opt-in floor", func(t *testing.T) {
		p := build(t, func(r *pinTestRepo) {
			if err := os.Remove(filepath.Join(r.dir, filepath.FromSlash(pinFloorDir+"optinfloor.go"))); err != nil {
				r.t.Fatal(err)
			}
		})
		requirePinProblem(t, p, "floor BoundaryCoveredFloor")
		if len(p) != 1 {
			t.Fatalf("problems %q", p)
		}
	})
	t.Run("first added outside the history of the ref", func(t *testing.T) {
		r := newPinTestRepo(t)
		root := r.git("rev-parse", "HEAD")
		r.floorFiles(allPinFiles...)
		ref := r.commit("release")
		r.git("tag", v, ref)
		r.publish(ref)
		// The checked-out history added the files in another commit.
		r.git("checkout", "-q", "-b", "other", root)
		r.floorFiles(allPinFiles...)
		r.write("other", "x\n")
		r.commit("other")
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "is not an ancestor of")
	})
	t.Run("no add commit in the checked-out history", func(t *testing.T) {
		r := newPinTestRepo(t)
		root := r.git("rev-parse", "HEAD")
		r.floorFiles(allPinFiles...)
		ref := r.commit("release")
		r.git("tag", v, ref)
		r.publish(ref)
		r.git("checkout", "-q", "--detach", root)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "cannot be read")
	})
}

func TestPinProblemsRefusesUnreadableOrForgedHistory(t *testing.T) {
	const v = ListedFamilyFloor
	t.Run("shallow", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		clone := filepath.Join(t.TempDir(), "shallow")
		r.git("clone", "-q", "--depth", "1", "--branch", "main", "file://"+r.dir, clone)
		clone, err := filepath.EvalSymlinks(clone)
		if err != nil {
			t.Fatal(err)
		}
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), clone), "shallow")
	})
	t.Run("not a repository", func(t *testing.T) {
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(strings.Repeat("a", 40), v), t.TempDir()), "repository")
	})
	t.Run("a directory below the top", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), filepath.Join(r.dir, "cli")), "is not the top")
	})
	t.Run("no git", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		t.Setenv("PATH", t.TempDir())
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "git is not usable")
	})
	t.Run("merge-base error is not a no", func(t *testing.T) {
		r, ref := released(t, v, allPinFiles...)
		if ok, err := pinIsAncestor(r.dir, strings.Repeat("a", 40), ref); err == nil || ok {
			t.Fatalf("an unknown commit read as %v, %v", ok, err)
		}
		r.write("later", "x\n")
		later := r.commit("later")
		if ok, err := pinIsAncestor(r.dir, later, ref); err != nil || ok {
			t.Fatalf("a later commit read as %v, %v", ok, err)
		}
	})
	// forged is a repository whose release is only on a branch, and the main
	// tip.
	forged := func(t *testing.T) (*pinTestRepo, string, string) {
		t.Helper()
		r := newPinTestRepo(t)
		root := r.git("rev-parse", "HEAD")
		r.write("main-only", "x\n")
		tip := r.commit("main")
		r.publish(tip)
		r.git("checkout", "-q", "-b", "topic", root)
		r.floorFiles(allPinFiles...)
		ref := r.commit("release")
		r.git("tag", v, ref)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "first-parent line")
		return r, ref, tip
	}
	t.Run("replace ref", func(t *testing.T) {
		r, ref, tip := forged(t)
		fake := r.git("commit-tree", tip+"^{tree}", "-p", ref, "-m", "fake")
		r.git("replace", tip, fake)
		// Without the proof's environment git follows the replace ref.
		out, err := exec.Command("git", "-C", r.dir, "rev-list", "--first-parent", "refs/remotes/origin/main").Output()
		if err != nil || !strings.Contains(string(out), ref) {
			t.Fatalf("setup: the replace ref does not fake the history: %v %s", err, out)
		}
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "first-parent line")
	})
	t.Run("grafts", func(t *testing.T) {
		r, ref, tip := forged(t)
		r.write(".git/info/grafts", tip+" "+ref+"\n")
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(ref, v), r.dir), "grafts")
	})
	t.Run("GIT_DIR pointing elsewhere", func(t *testing.T) {
		good, goodRef := released(t, v, allPinFiles...)
		bad, badRef, _ := forged(t)
		t.Setenv("GIT_DIR", filepath.Join(good.dir, ".git"))
		t.Setenv("GIT_WORK_TREE", good.dir)
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(goodRef, v), bad.dir), "not a commit that is present")
		requirePinProblem(t, pinProblems(clientFloors(), pinBytes(badRef, v), bad.dir), "first-parent line")
		requirePinProved(t, pinProblems(clientFloors(), pinBytes(goodRef, v), good.dir))
	})
}

// Provider facts have no client-read content: the publisher refuses a pack
// with a distributions section. When that is lifted this test fails, and the
// provider-facts admit case needs real content and a carry assertion first.
func TestProviderFactsAreNotPublishable(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	build := func(base bundle) error {
		_, _, _, err := buildExternalTargetsPolicy(base, "5", "operator_provided", func(string, func(string) ([]byte, error)) (string, error) {
			return "5", nil
		}, &listedPolicy{oldestClient: ProviderFactsMinClientVersion})
		return err
	}
	base.pack.Distributions = nil
	if err := build(base); err != nil {
		t.Fatalf("control without distributions: %v", err)
	}
	base.pack.Distributions = []byte(`[{}]`)
	if err := build(base); !errors.Is(err, ErrDistributionsNotPublishable) {
		t.Fatalf("a pack with distributions: %v", err)
	}
}
