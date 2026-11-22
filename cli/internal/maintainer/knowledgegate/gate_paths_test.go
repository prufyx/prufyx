// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// gatePathFixture is a change that edits a workflow file, with an owner key
// pinned in the base.
type gatePathFixture struct {
	signFixture
	file string
}

func newGatePathFixture(t *testing.T, file string) gatePathFixture {
	t.Helper()
	base, head := trees(t)
	f := gatePathFixture{signFixture: pinFixture(t, base, head, "unused"), file: file}
	f.write(t, f.base, "name: old\n")
	f.write(t, f.head, "name: rewritten\n")
	return f
}

func (f gatePathFixture) write(t *testing.T, tr Tree, content string) {
	t.Helper()
	p := filepath.Join(tr.Root, filepath.FromSlash(f.file))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f gatePathFixture) approvalFile(id string) string {
	return filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), GatePathsPack, id+".json")
}

func (f gatePathFixture) gateArgs(verb, id string) []string {
	return []string{verb, "--subject", ApprovalSubjectGatePaths, "--candidate-id", id,
		"--base-root", f.base.Root, "--head-root", f.head.Root,
		"--keys", f.keysPath(), "--keys-digest", f.keysDigest}
}

func (f gatePathFixture) sign(t *testing.T, id string) {
	t.Helper()
	args := append(f.gateArgs("sign", id), "--identity", "airstand", "--output", f.approvalFile(id))
	r := runApproval(t, f.key.pemKey(t), signNow, append(args, "--key-stdin")...)
	requireCode(t, r, 0, "approval written")
}

func (f gatePathFixture) run(t *testing.T, id string) *Report {
	t.Helper()
	return runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, CandidateID: id})
}

func requireGatePathFail(t *testing.T, r *Report) {
	t.Helper()
	requireFail(t, r, checkGatePaths)
}

func TestGatePathsDefaultList(t *testing.T) {
	t.Parallel()
	l := DefaultLayout()
	for _, p := range []string{
		".github/workflows/ci.yml", ".github/workflows/knowledge-gate.yml", ".github/workflows/new-one.yml",
		".github/CODEOWNERS", "scripts/merge-policy-pr.sh", "scripts/merge-policy-queue.sh",
		"cli/internal/maintainer/knowledgegate/gate.go", "cli/internal/maintainer/mergepolicy/x.go",
		"cli/internal/maintainer/releasedocs/check.go", "cli/internal/maintainer/verifyprworkflow/workflow_test.go",
		"cli/internal/maintainer/targetdraft/classify.go", "cli/cmd/prufyx-maintainer/gate.go",
		"cli/go.mod", "cli/go.sum", "go.mod", "go.sum", "testdata/synthetic-cluster-scenarios/v4/go.mod", "testdata/x/y/go.sum",
		"cli/vendor/golang.org/x/text/a.go", ".github/actions/setup/action.yml", "action.yml", "sub/dir/action.yaml",
		"cli/internal/cncfcheck/data/cncf-subprojects.json", "cli/internal/cncfcheck/subprojects.go",
		"cli/internal/cncfcheck/subprojects_test.go", "cli/cmd/prufyx-maintainer/subprojects_test.go",
		"cli/cmd/prufyx-maintainer/subprojects.go", "cli/internal/maintainer/knowledgepacket/classify.go",
		"scripts/readme-coverage.sh", "scripts/publish-verify.sh", "scripts/action/run.sh", "scripts/brand-new.sh",
	} {
		if !l.gatePath(p) {
			t.Errorf("%s is not a gate path", p)
		}
	}
	for _, p := range []string{"README.md", "cli/knowledge/approvals/cncf/x.json", ".github/ISSUE_TEMPLATE/a.md", ".github/workflowsx", "scriptsx/a.sh", "cli/gomod", "docs/action.md",
		"cli/internal/cncfcheck/data/landscape-projects.json", "cli/internal/cncfcheck/data/cncf-subprojects.json.bak"} {
		if l.gatePath(p) {
			t.Errorf("%s is a gate path", p)
		}
	}
}

// A change that touches no gate file is not affected.
func TestGatePathsUntouchedPasses(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	newApprovalKey(t).pinBoth(t, base, head, "airstand")
	requirePass(t, runGate(t, Options{Base: base, Head: head}))
}

func TestGatePathsNeedOwnerApproval(t *testing.T) {
	t.Parallel()
	for _, file := range []string{
		".github/workflows/knowledge-gate.yml", ".github/workflows/ci.yml", ".github/workflows/merge-policy.yml",
		"scripts/merge-policy-queue.sh", ".github/CODEOWNERS", "cli/internal/maintainer/knowledgegate/gate.go",
		"cli/go.mod", "cli/go.sum", "testdata/synthetic-cluster-scenarios/v4/go.mod", ".github/actions/setup/action.yml",
		"action.yml", "scripts/readme-coverage.sh", "scripts/not-listed-before.sh", "cli/vendor/modules.txt",
		"cli/internal/cncfcheck/data/cncf-subprojects.json", "cli/cmd/prufyx-maintainer/subprojects.go",
		"cli/internal/cncfcheck/subprojects.go", "cli/internal/cncfcheck/subprojects_test.go",
	} {
		t.Run(file, func(t *testing.T) {
			f := newGatePathFixture(t, file)
			requireGatePathFail(t, f.run(t, "pr-42"))
			f.sign(t, "pr-42")
			requirePass(t, f.run(t, "pr-42"))
		})
	}
}

func TestGatePathsDeleteAndAddNeedApproval(t *testing.T) {
	t.Parallel()
	f := newGatePathFixture(t, ".github/workflows/ci.yml")
	if err := os.Remove(filepath.Join(f.head.Root, ".github/workflows/ci.yml")); err != nil {
		t.Fatal(err)
	}
	requireGatePathFail(t, f.run(t, "pr-42"))
	f.sign(t, "pr-42")
	requirePass(t, f.run(t, "pr-42"))

	g := newGatePathFixture(t, ".github/workflows/brand-new.yml")
	if err := os.Remove(filepath.Join(g.base.Root, ".github/workflows/brand-new.yml")); err != nil {
		t.Fatal(err)
	}
	requireGatePathFail(t, g.run(t, "pr-42"))
}

func TestGatePathsNegative(t *testing.T) {
	t.Parallel()
	t.Run("no candidate reference", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		requireGatePathFail(t, f.run(t, ""))
	})
	t.Run("malformed candidate reference", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		for _, id := range []string{"42", "pr-0", "pr-042", "PR-42", "pr-42/../x", "pr-1234567890"} {
			requireGatePathFail(t, f.run(t, id))
		}
	})
	t.Run("approval of another pull request", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		requireGatePathFail(t, f.run(t, "pr-43"))
		// Copied to the other number's file name: the signed record still
		// names pr-42.
		raw, err := os.ReadFile(f.approvalFile("pr-42"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.approvalFile("pr-43"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		requireGatePathFail(t, f.run(t, "pr-43"))
	})
	t.Run("file edited after signing", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		f.write(t, f.head, "name: rewritten again\n")
		requireGatePathFail(t, f.run(t, "pr-42"))
	})
	t.Run("another gate file added after signing", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		other := f
		other.file = "scripts/merge-policy-queue.sh"
		other.write(t, other.head, "exit 0\n")
		requireGatePathFail(t, f.run(t, "pr-42"))
	})
	t.Run("key not pinned in the base", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		stranger := newApprovalKey(t)
		stranger.pin(t, f.base, "airstand")
		raw, err := os.ReadFile(f.keysPath())
		if err != nil {
			t.Fatal(err)
		}
		f.keysDigest = pinnedDigest(raw)
		requireGatePathFail(t, f.run(t, "pr-42"))
	})
	t.Run("no key digest configured", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		requireGatePathFail(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: "none", CandidateID: "pr-42"}))
	})
	t.Run("old approval", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		requireGatePathFail(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, CandidateID: "pr-42", Now: signNow.Add(MaxApprovalAge + 2*time.Hour)}))
	})
	t.Run("signed by an identity that is not an owner", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		args := append(f.gateArgs("sign", "pr-42"), "--identity", "mallory", "--output", f.approvalFile("pr-42"), "--key-stdin")
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "not an owner")
	})
	t.Run("tampered record", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		raw, _ := os.ReadFile(f.approvalFile("pr-42"))
		var env ApprovalEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		env.Record.DecidedAt = signNow.Add(time.Minute).Format("2006-01-02T15:04:05Z")
		out, _ := json.MarshalIndent(env, "", "  ")
		if err := os.WriteFile(f.approvalFile("pr-42"), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		requireGatePathFail(t, f.run(t, "pr-42"))
	})
	t.Run("a rule approval does not stand in", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		// An unrelated file at the approval path is refused.
		if err := os.MkdirAll(filepath.Dir(f.approvalFile("pr-42")), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.approvalFile("pr-42"), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		requireGatePathFail(t, f.run(t, "pr-42"))
	})
	t.Run("approval without a gate file change", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		f.write(t, f.head, "name: old\n") // identical to the base again
		requireFail(t, f.run(t, "pr-42"), "knowledge-records")
	})
	t.Run("approval of a pull request that is not this one", func(t *testing.T) {
		f := newGatePathFixture(t, ".github/workflows/ci.yml")
		f.sign(t, "pr-42")
		raw, _ := os.ReadFile(f.approvalFile("pr-42"))
		if err := os.WriteFile(f.approvalFile("pr-99"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		requireFail(t, f.run(t, "pr-42"), "knowledge-records")
	})
}

func TestGatePathsSignerRoundTripVerify(t *testing.T) {
	t.Parallel()
	f := newGatePathFixture(t, ".github/workflows/ci.yml")
	f.sign(t, "pr-42")
	args := append(f.gateArgs("verify", "pr-42"), "--approval", f.approvalFile("pr-42"))
	requireCode(t, runApproval(t, nil, gateNow, args...), 0, "approval OK")
	f.write(t, f.head, "name: changed after\n")
	requireCode(t, runApproval(t, nil, gateNow, args...), 1, "REFUSED")
	// The refusal text is not allowed to carry file content.
	if r := runApproval(t, nil, gateNow, args...); strings.Contains(r.stdout, "changed after") {
		t.Fatal("content echoed")
	}
}

// The workflow hands the gate the pull request reference only from the
// numeric pull request number, never from free text, so a change to a gate
// file is bound to its own pull request.
func TestWorkflowPassesCandidateID(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"PR_NUMBER: ${{ github.event.pull_request.number }}",
		`[[ "${PR_NUMBER}" =~ ^[1-9][0-9]{0,8}$ ]]`,
		`--candidate-id "pr-${PR_NUMBER}"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("knowledge-gate.yml lacks %q", want)
		}
	}
}

// Every script a workflow calls is a gate path, so a new call of an unlisted
// script cannot slip through.
func TestEveryWorkflowScriptIsGatePath(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join(repoRoot, ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	re := regexp.MustCompile(`scripts/[A-Za-z0-9_./-]*[A-Za-z0-9_]`)
	l := DefaultLayout()
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllString(string(raw), -1) {
			n++
			if !l.gatePath(m) {
				t.Errorf("%s calls %s, which is not a gate path", filepath.Base(f), m)
			}
		}
	}
	if n == 0 {
		t.Fatal("no script call found; the guard reads the wrong files")
	}
}
