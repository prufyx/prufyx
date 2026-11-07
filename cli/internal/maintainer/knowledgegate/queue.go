// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Merge-queue runs.
//
// A merge_group run executes the workflow definition of the queued commit,
// which is the pull request's own content: the queue run of the gate can be
// edited by the change it gates. It is a correctness check (it re-gates the
// exact tree that is about to land, so a main that moved is covered), never a
// trust control. The one gate a change cannot rewrite is the
// pull_request_target run on the pull request head, and a pull request can
// be queued only after its required checks passed on that head.
//
// The sender of a merge_group event is the queue's own account, so the
// rules that depend on who triggered a run cannot read it. A queue run
// instead takes the author from GitHub's record of the pull request, and the
// sender from GitHub's record of the pull_request_target run of this gate on
// that head. QueueMerge is that record; the workflow assembles it from the
// API and the event, and Problems decides whether it proves the queue entry
// is exactly "this pull request head, merged onto this base".
const (
	// QueueMergeSchema names the evidence file of a queue run.
	QueueMergeSchema = "prufyx.io/knowledge-gate-queue-merge/v1"
	// GateWorkflowPath is the workflow whose pull_request_target run on the
	// head is required evidence.
	GateWorkflowPath = ".github/workflows/knowledge-gate.yml"

	maxQueueEvidenceBytes = 4 << 20
	// The pull request commits API lists at most 250 commits; a count at
	// the cap cannot be known to be complete.
	maxQueuePRCommits = 249
)

var (
	queueHeadRefRE = regexp.MustCompile(`^(?:refs/heads/)?gh-readonly-queue/main/pr-([1-9][0-9]{0,8})-([0-9a-f]{40})$`)
	loginRE        = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$`)
)

// QueueMerge is GitHub's record of one merge queue entry.
type QueueMerge struct {
	Schema string `json:"schema"`
	// Event is the triggering event name; only merge_group is accepted.
	Event string `json:"event"`
	// BaseRef, BaseSHA, HeadSHA and HeadRef are the merge_group event's
	// base_ref, base_sha, head_sha and head_ref.
	BaseRef string `json:"baseRef"`
	BaseSHA string `json:"baseSha"`
	HeadSHA string `json:"headSha"`
	HeadRef string `json:"headRef"`
	// MergeParents are the parents of the queue commit, read from git.
	MergeParents []string `json:"mergeParents"`
	// PullRequest is the API record of the pull request named by HeadRef.
	PullRequest QueuePR `json:"pullRequest"`
	// Commits are the pull request's own commits (pulls/N/commits).
	Commits []QueueCommit `json:"commits"`
	// Runs are workflow runs the API lists for the pull request head.
	Runs []QueueRun `json:"runs"`
}

// QueuePR is the part of pulls/N the gate reads.
type QueuePR struct {
	Number      int    `json:"number"`
	State       string `json:"state"`
	BaseRef     string `json:"baseRef"`
	HeadSHA     string `json:"headSha"`
	UserLogin   string `json:"userLogin"`
	CommitCount int    `json:"commitCount"`
}

// QueueCommit is one commit of the pull request. Author and Committer are
// empty when GitHub knows no account for the commit.
type QueueCommit struct {
	SHA       string `json:"sha"`
	Parents   int    `json:"parents"`
	Author    string `json:"author"`
	Committer string `json:"committer"`
	Verified  bool   `json:"verified"`
}

// QueueRun is one workflow run of the head commit.
type QueueRun struct {
	Path            string `json:"path"`
	Event           string `json:"event"`
	HeadSHA         string `json:"headSha"`
	Status          string `json:"status"`
	Conclusion      string `json:"conclusion"`
	CreatedAt       string `json:"createdAt"`
	Actor           string `json:"actor"`
	TriggeringActor string `json:"triggeringActor"`
}

// ParseQueueMerge parses the evidence file; unknown or repeated members are
// refused.
func ParseQueueMerge(raw []byte) (*QueueMerge, error) {
	if len(raw) == 0 || len(raw) > maxQueueEvidenceBytes {
		return nil, errors.New("queue evidence: empty or too large")
	}
	var q QueueMerge
	if err := strictjson.Decode(raw, &q); err != nil {
		return nil, fmt.Errorf("queue evidence: %w", err)
	}
	return &q, nil
}

// gateRuns returns the runs that count as the gate's own pull_request_target
// run on the pull request head, with their times. A run of another path,
// event or commit never counts.
func (q *QueueMerge) gateRuns() (runs []QueueRun, times []time.Time, bad bool) {
	for _, r := range q.Runs {
		if r.Path != GateWorkflowPath || r.Event != "pull_request_target" || r.HeadSHA != q.PullRequest.HeadSHA {
			continue
		}
		at, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			bad = true
			continue
		}
		runs, times = append(runs, r), append(times, at)
	}
	return runs, times, bad
}

// Problems lists everything that stops the evidence from proving the queue
// entry. An empty list means every check held; anything unresolved or
// unknown is a problem.
func (q *QueueMerge) Problems() []string {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	pr := q.PullRequest
	if q.Schema != QueueMergeSchema {
		add("the evidence schema is %q", logSafe(q.Schema))
	}
	if q.Event != "merge_group" {
		add("the triggering event is %q, not merge_group", logSafe(q.Event))
	}
	if q.BaseRef != "refs/heads/main" || pr.BaseRef != "main" {
		add("the queue and the pull request must both be for main (queue base %q, pull request base %q)", logSafe(q.BaseRef), logSafe(pr.BaseRef))
	}
	if !shaRE.MatchString(q.BaseSHA) {
		add("the queue base is not a full commit id")
	}
	if !shaRE.MatchString(q.HeadSHA) {
		add("the queue head is not a full commit id")
	}
	if q.BaseSHA == q.HeadSHA {
		add("the queue base equals the queue head: nothing would merge")
	}
	if !shaRE.MatchString(pr.HeadSHA) {
		add("the pull request head is not a full commit id")
	}
	if pr.HeadSHA == q.BaseSHA || pr.HeadSHA == q.HeadSHA {
		add("the pull request head is the queue base or the queue head")
	}
	m := queueHeadRefRE.FindStringSubmatch(q.HeadRef)
	if m == nil {
		add("the head ref %q is not gh-readonly-queue/main/pr-<number>-<commit>", logSafe(q.HeadRef))
	} else {
		if n, err := strconv.Atoi(m[1]); err != nil || n != pr.Number || pr.Number < 1 {
			add("the pull request %d does not match the head ref's pull request %s", pr.Number, m[1])
		}
		if m[2] != q.BaseSHA {
			add("the head ref chains from %s, not from the queue base", shortSHA(m[2]))
		}
	}
	if pr.Number < 1 || pr.HeadSHA == "" {
		add("the pull request is unresolved")
	}
	if pr.State != "open" {
		add("the pull request is %q, not open", logSafe(pr.State))
	}
	if len(q.MergeParents) != 2 || q.MergeParents[0] != q.BaseSHA || q.MergeParents[1] != pr.HeadSHA {
		add("the queue commit's parents are not [queue base, pull request head]")
	}
	if !loginRE.MatchString(pr.UserLogin) {
		add("the pull request author %q is unknown or not a login", logSafe(pr.UserLogin))
	}
	switch n := len(q.Commits); {
	case n == 0 || pr.CommitCount != n || n > maxQueuePRCommits:
		add("the pull request's commit list is incomplete (%d listed, %d reported)", n, pr.CommitCount)
	case q.Commits[n-1].SHA != pr.HeadSHA:
		add("the pull request's commit list does not end at its head")
	}
	for _, c := range q.Commits {
		if c.Parents != 1 {
			add("commit %s is a merge commit or a root commit (%d parents); a queued change holds single-parent commits only", shortSHA(c.SHA), c.Parents)
		}
	}
	runs, times, badTime := q.gateRuns()
	if badTime {
		add("a run of the gate on the pull request head has no valid time")
	}
	if len(runs) == 0 {
		add("no pull_request_target run of %s exists for the pull request head", GateWorkflowPath)
	} else {
		latest := 0
		for i := range runs {
			if times[i].After(times[latest]) {
				latest = i
			}
		}
		if r := runs[latest]; r.Status != "completed" || r.Conclusion != "success" {
			add("the latest pull_request_target run of the gate on the pull request head is %q/%q, not completed/success", logSafe(r.Status), logSafe(r.Conclusion))
		}
	}
	return p
}

// Sender is the account GitHub recorded as having triggered the gate's
// pull_request_target run on the pull request head: the actor of every such
// run, when each run's actor is also its triggering actor and they all name
// one account. Otherwise it is empty, which no rule treats as the owner or
// the automation account.
func (q *QueueMerge) Sender() string {
	runs, _, _ := q.gateRuns()
	sender := ""
	for i, r := range runs {
		if r.Actor == "" || r.Actor != r.TriggeringActor || !loginRE.MatchString(r.Actor) || (i > 0 && r.Actor != sender) {
			return ""
		}
		sender = r.Actor
	}
	return sender
}

// CommitList is the pull request's own commits as the provenance rules read
// them: strictly ahead of the base, ending at the head.
func (q *QueueMerge) CommitList() *CommitList {
	list := &CommitList{Status: "ahead", AheadBy: len(q.Commits), TotalCommits: len(q.Commits)}
	for _, c := range q.Commits {
		rec := CommitRecord{SHA: c.SHA}
		if c.Author != "" {
			rec.Author = &loginField{c.Author}
		}
		if c.Committer != "" {
			rec.Committer = &loginField{c.Committer}
		}
		rec.Commit.Verification.Verified = c.Verified
		list.Commits = append(list.Commits, rec)
	}
	return list
}

// applyQueue replaces the pull request inputs of a queue run with the
// evidence's. The caller must not have supplied an author, sender, head or
// commit list of its own: a queue run has none (the sender of a merge_group
// event is the queue's own account). It returns the problems; when there are
// any, nobody is named and no commit list is used, so every rule that
// depends on who made the change fails closed.
func (o *Options) applyQueue() []string {
	if o.Queue == nil {
		return nil
	}
	var problems []string
	if o.Sender != "" || o.Author != "" || o.Commits != nil {
		problems = append(problems, "a queue run takes its author, sender and commit list from the evidence; none may be supplied")
	}
	problems = append(problems, o.Queue.Problems()...)
	o.Author, o.Sender, o.Commits = "", "", nil
	if len(problems) > 0 {
		return problems
	}
	o.Author = o.Queue.PullRequest.UserLogin
	o.Sender = o.Queue.Sender()
	o.HeadSHA = o.Queue.PullRequest.HeadSHA
	o.Commits = o.Queue.CommitList()
	return nil
}

func queueDetail(problems []string) string {
	if len(problems) == 0 {
		return "the queue entry is the pull request head merged onto the queue base, and the gate's own pull_request_target run on that head succeeded"
	}
	return "the queue entry is not proven: " + strings.Join(problems, "; ")
}
