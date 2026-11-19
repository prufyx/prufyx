// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Merge queue mode. A merge_group run has no pull request payload, so the
// gate derives the one pull request from the queue ref, reads that pull
// request from the API, and checks that the queue commit is exactly
// (base, that pull request's head). Every gap is an error: the caller
// (a required check) must fail, never skip and never report neutral.

var (
	queueRefRE   = regexp.MustCompile(`^refs/heads/gh-readonly-queue/main/pr-([1-9][0-9]{0,8})-([0-9a-f]{40})$`)
	fullSHARE    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoNameRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	queueLoginRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)
	labelNameRE  = regexp.MustCompile(`^[\x20-\x7e]{1,50}$`)
)

// ParseQueueRef returns the pull request number and the commit named by a
// merge queue ref. Any other shape (another branch, a second number, a
// short or upper-case id, leading zeros, trailing text) is an error.
func ParseQueueRef(ref string) (pr int, sha string, err error) {
	m := queueRefRE.FindStringSubmatch(ref)
	if m == nil {
		return 0, "", fmt.Errorf("unexpected merge queue ref shape %q", logSafe(ref))
	}
	for _, c := range m[1] {
		pr = pr*10 + int(c-'0')
	}
	return pr, m[2], nil
}

// QueueInput is everything the queue context is derived from. Parents are
// the parents of HeadSHA as read from the git objects; PRJSON is the body
// of GET /repos/{repo}/pulls/{number}.
type QueueInput struct {
	Repo    string
	Ref     string // github.ref
	RunSHA  string // github.sha
	HeadRef string // merge_group.head_ref
	HeadSHA string // merge_group.head_sha
	BaseRef string // merge_group.base_ref
	BaseSHA string // merge_group.base_sha
	Parents []string
	PRJSON  []byte
	// Changed are the paths changed between BaseSHA and HeadSHA.
	Changed []string
}

// QueueContext is the verified context of one queue entry.
type QueueContext struct {
	Schema      string   `json:"schema"`
	PR          int      `json:"pr"`
	CandidateID string   `json:"candidateId"`
	Author      string   `json:"author"`
	Labels      []string `json:"labels"`
	Shadow      bool     `json:"shadow"`
	NightlyFix  bool     `json:"nightlyFix"`
	PRHead      string   `json:"prHead"`
	BaseSHA     string   `json:"baseSha"`
	HeadSHA     string   `json:"headSha"`
}

type queuePR struct {
	Number *int   `json:"number"`
	State  string `json:"state"`
	User   *struct {
		Login string `json:"login"`
	} `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Head *struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base *struct {
		Ref  string `json:"ref"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}

// protectedPaths are the files that define or run the checks of a queue
// group. merge_group runs the workflow file of the queued commit, so a change
// to any of them could rewrite the checks that judge it. This list is a
// second line only: the run itself comes from the queued commit, so the real
// protection is the base-defined pull request gate and the ruleset that
// requires it.
func protectedGatePath(p string) bool {
	switch p {
	case ".github/workflows/knowledge-gate.yml", ".github/workflows/merge-policy.yml",
		".github/workflows/ci.yml", ".github/workflows/verify-pr.yml",
		".github/workflows/nightly-main.yml", ".github/CODEOWNERS",
		"cli/cmd/prufyx-maintainer/gate.go":
		return true
	}
	for _, prefix := range []string{"scripts/merge-policy-", "cli/internal/maintainer/knowledgegate/", "cli/internal/maintainer/mergepolicy/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// ProtectedGatePaths returns the changed paths that need the owner's
// trust-path approval. Fail closed: no approval is accepted by this command,
// so a group that changes any of them is refused here.
func ProtectedGatePaths(changed []string) []string {
	var out []string
	for _, p := range changed {
		if protectedGatePath(p) {
			out = append(out, p)
		}
	}
	return out
}

// VerifyQueue checks the merge queue entry and returns its context.
func VerifyQueue(in QueueInput) (*QueueContext, error) {
	if !repoNameRE.MatchString(in.Repo) {
		return nil, errors.New("the repository name is missing or malformed")
	}
	pr, refSHA, err := ParseQueueRef(in.Ref)
	if err != nil {
		return nil, err
	}
	if in.HeadRef != in.Ref {
		return nil, errors.New("merge_group head_ref differs from the run ref")
	}
	if !fullSHARE.MatchString(in.HeadSHA) || !fullSHARE.MatchString(in.BaseSHA) || !fullSHARE.MatchString(in.RunSHA) {
		return nil, errors.New("a queue commit id is missing or not a full commit id")
	}
	if in.RunSHA != in.HeadSHA {
		return nil, errors.New("the run commit is not the merge_group head commit")
	}
	if refSHA != in.HeadSHA {
		return nil, errors.New("the queue ref names a different commit than merge_group head_sha")
	}
	if in.BaseRef != "refs/heads/main" {
		return nil, fmt.Errorf("merge_group base_ref is %q, not refs/heads/main", logSafe(in.BaseRef))
	}
	// Exactly one pull request: the queue commit is a merge of (base, one
	// pull request head). A grouped entry has the previous entry as its
	// first parent, which is not the base of the group.
	if len(in.Parents) != 2 {
		return nil, fmt.Errorf("the queue commit has %d parents, want 2 (one pull request)", len(in.Parents))
	}
	for _, p := range in.Parents {
		if !fullSHARE.MatchString(p) {
			return nil, errors.New("a parent of the queue commit is not a full commit id")
		}
	}
	if in.Parents[0] != in.BaseSHA {
		return nil, errors.New("the first parent of the queue commit is not the merge_group base: more than one pull request in the group")
	}
	if len(in.PRJSON) == 0 {
		return nil, errors.New("the pull request could not be read")
	}
	var p queuePR
	dec := json.NewDecoder(bytes.NewReader(in.PRJSON))
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("the pull request payload is not valid: %w", err)
	}
	if p.Number == nil || *p.Number != pr {
		return nil, errors.New("the pull request payload is for another pull request than the queue ref")
	}
	if p.State != "open" {
		return nil, fmt.Errorf("pull request %d is %q, not open", pr, logSafe(p.State))
	}
	if p.Base == nil || p.Base.Ref != "main" || p.Base.Repo == nil || p.Base.Repo.FullName != in.Repo {
		return nil, fmt.Errorf("pull request %d does not target main of %s", pr, in.Repo)
	}
	if p.Head == nil || !fullSHARE.MatchString(p.Head.SHA) {
		return nil, errors.New("the pull request head is missing")
	}
	if p.Head.SHA != in.Parents[1] {
		return nil, errors.New("the reviewed head of the pull request is not the second parent of the queue commit (head mismatch)")
	}
	if p.User == nil || !queueLoginRE.MatchString(p.User.Login) {
		return nil, errors.New("the pull request author is missing or malformed")
	}
	if p.Labels == nil {
		return nil, errors.New("the pull request labels are missing")
	}
	ctx := &QueueContext{
		Schema: "prufyx.io/knowledge-gate-queue-context/v1", PR: pr, CandidateID: fmt.Sprintf("pr-%d", pr),
		Author: p.User.Login, Labels: []string{}, PRHead: p.Head.SHA, BaseSHA: in.BaseSHA, HeadSHA: in.HeadSHA,
	}
	for _, l := range p.Labels {
		if !labelNameRE.MatchString(l.Name) {
			return nil, errors.New("a pull request label name is malformed")
		}
		ctx.Labels = append(ctx.Labels, l.Name)
		switch l.Name {
		case "shadow":
			ctx.Shadow = true
		case "nightly-fix":
			ctx.NightlyFix = true
		}
	}
	if prot := ProtectedGatePaths(in.Changed); len(prot) > 0 {
		return nil, fmt.Errorf("the group changes files that define its own checks (%s) and needs the owner's trust-path approval for pr-%d; none is accepted in a queue run", logSafe(strings.Join(prot, ", ")), pr)
	}
	return ctx, nil
}

func gitOut(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out, nil
}

func cmdQueueContext(args []string, stdout io.Writer) (int, error) {
	var in QueueInput
	var gitDir, prFile, out string
	f := flag.NewFlagSet("gate queue-context", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&in.Repo, "repo", "", "owner/name")
	f.StringVar(&in.Ref, "ref", "", "github.ref of the run")
	f.StringVar(&in.RunSHA, "run-sha", "", "github.sha of the run")
	f.StringVar(&in.HeadRef, "head-ref", "", "merge_group.head_ref")
	f.StringVar(&in.HeadSHA, "head-sha", "", "merge_group.head_sha")
	f.StringVar(&in.BaseRef, "base-ref", "", "merge_group.base_ref")
	f.StringVar(&in.BaseSHA, "base-sha", "", "merge_group.base_sha")
	f.StringVar(&gitDir, "git-dir", "", "repository holding both commits")
	f.StringVar(&prFile, "pr-json", "", "pull request API payload")
	f.StringVar(&out, "out", "", "file for the context JSON")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if gitDir == "" || prFile == "" || out == "" {
		return 2, errors.New("--git-dir, --pr-json and --out are required\n" + usage)
	}
	if !fullSHARE.MatchString(in.HeadSHA) || !fullSHARE.MatchString(in.BaseSHA) {
		return 2, errors.New("--head-sha and --base-sha must be full commit ids")
	}
	raw, err := os.ReadFile(prFile)
	if err != nil {
		return 2, fmt.Errorf("the pull request payload is unavailable: %w", err)
	}
	in.PRJSON = raw
	parents, err := gitOut(gitDir, "rev-list", "--parents", "-n", "1", in.HeadSHA)
	if err != nil {
		return 2, err
	}
	fields := strings.Fields(string(parents))
	if len(fields) == 0 || fields[0] != in.HeadSHA {
		return 2, errors.New("the queue commit is not in the object store")
	}
	in.Parents = fields[1:]
	if _, err := gitOut(gitDir, "merge-base", "--is-ancestor", in.BaseSHA, in.HeadSHA); err != nil {
		return 2, errors.New("the queue commit does not contain the group base")
	}
	names, err := gitOut(gitDir, "diff", "--name-only", "-z", in.BaseSHA, in.HeadSHA)
	if err != nil {
		return 2, err
	}
	for _, n := range strings.Split(string(names), "\x00") {
		if n != "" {
			in.Changed = append(in.Changed, n)
		}
	}
	qc, err := VerifyQueue(in)
	if err != nil {
		return 2, err
	}
	b, err := json.Marshal(qc)
	if err != nil {
		return 2, err
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "queue entry %s: %s at %s on %s\n", qc.CandidateID, logSafe(qc.Author), qc.PRHead, qc.BaseSHA)
	return 0, nil
}
