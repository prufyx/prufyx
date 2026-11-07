// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	queueBaseSHA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	queueMergeSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherSHA      = "cccccccccccccccccccccccccccccccccccccccc"
)

// validQueue is the evidence of a clean queue entry: pull request 77 by the
// automation account, one commit of its own (ending at testHeadSHA), merged
// by the queue as [base, head], with a successful pull_request_target run of
// the gate workflow on exactly that head.
func validQueue() *QueueMerge {
	return &QueueMerge{
		Schema:       QueueMergeSchema,
		Event:        "merge_group",
		BaseRef:      "refs/heads/main",
		BaseSHA:      queueBaseSHA,
		HeadSHA:      queueMergeSHA,
		HeadRef:      "refs/heads/gh-readonly-queue/main/pr-77-" + queueBaseSHA,
		MergeParents: []string{queueBaseSHA, testHeadSHA},
		PullRequest:  QueuePR{Number: 77, State: "open", BaseRef: "main", HeadSHA: testHeadSHA, UserLogin: DefaultBotLogin, CommitCount: 1},
		Commits:      []QueueCommit{{SHA: testHeadSHA, Parents: 1, Author: DefaultBotLogin, Committer: DefaultBotLogin, Verified: true}},
		Runs: []QueueRun{{Path: GateWorkflowPath, Event: "pull_request_target", HeadSHA: testHeadSHA, Status: "completed", Conclusion: "success",
			CreatedAt: "2026-11-07T10:00:00Z", Actor: DefaultBotLogin, TriggeringActor: DefaultBotLogin}},
	}
}

func TestQueueEvidenceValid(t *testing.T) {
	t.Parallel()
	if p := validQueue().Problems(); len(p) != 0 {
		t.Fatalf("a clean queue entry has problems: %v", p)
	}
	// The head ref may also be given without refs/heads/.
	q := validQueue()
	q.HeadRef = "gh-readonly-queue/main/pr-77-" + queueBaseSHA
	if p := q.Problems(); len(p) != 0 {
		t.Fatalf("short head ref: %v", p)
	}
	// An older failed run does not count once a later one succeeded.
	q = validQueue()
	q.Runs = append(q.Runs, QueueRun{Path: GateWorkflowPath, Event: "pull_request_target", HeadSHA: testHeadSHA, Status: "completed", Conclusion: "failure",
		CreatedAt: "2026-11-07T09:00:00Z", Actor: DefaultBotLogin, TriggeringActor: DefaultBotLogin})
	if p := q.Problems(); len(p) != 0 {
		t.Fatalf("older failure: %v", p)
	}
}

func TestQueueEvidenceRefusals(t *testing.T) {
	t.Parallel()
	failedRun := func(q *QueueMerge, conclusion, status string) {
		q.Runs[0].Conclusion, q.Runs[0].Status = conclusion, status
	}
	cases := map[string]struct {
		edit func(q *QueueMerge)
		want string
	}{
		"unresolved pull request":       {func(q *QueueMerge) { q.PullRequest = QueuePR{} }, "pull request"},
		"head ref names another pr":     {func(q *QueueMerge) { q.PullRequest.Number = 78 }, "pull request"},
		"head ref not a queue ref":      {func(q *QueueMerge) { q.HeadRef = "refs/heads/feature/pr-77-" + queueBaseSHA }, "head ref"},
		"head ref no number":            {func(q *QueueMerge) { q.HeadRef = "gh-readonly-queue/main/pr--" + queueBaseSHA }, "head ref"},
		"head ref leading zero":         {func(q *QueueMerge) { q.HeadRef = "gh-readonly-queue/main/pr-077-" + queueBaseSHA }, "head ref"},
		"head ref chain sha != base":    {func(q *QueueMerge) { q.HeadRef = "gh-readonly-queue/main/pr-77-" + otherSHA }, "base"},
		"head ref for another branch":   {func(q *QueueMerge) { q.HeadRef = "gh-readonly-queue/dev/pr-77-" + queueBaseSHA }, "head ref"},
		"head != pull request head":     {func(q *QueueMerge) { q.PullRequest.HeadSHA = otherSHA }, "head"},
		"merge parents wrong head":      {func(q *QueueMerge) { q.MergeParents = []string{queueBaseSHA, otherSHA} }, "parents"},
		"merge parents wrong base":      {func(q *QueueMerge) { q.MergeParents = []string{otherSHA, testHeadSHA} }, "parents"},
		"merge parents swapped":         {func(q *QueueMerge) { q.MergeParents = []string{testHeadSHA, queueBaseSHA} }, "parents"},
		"merge parents single":          {func(q *QueueMerge) { q.MergeParents = []string{queueBaseSHA} }, "parents"},
		"merge parents octopus":         {func(q *QueueMerge) { q.MergeParents = []string{queueBaseSHA, testHeadSHA, otherSHA} }, "parents"},
		"merge parents missing":         {func(q *QueueMerge) { q.MergeParents = nil }, "parents"},
		"merge commit inside the pr":    {func(q *QueueMerge) { q.Commits[0].Parents = 2 }, "merge commit"},
		"root commit inside the pr":     {func(q *QueueMerge) { q.Commits[0].Parents = 0 }, "merge commit"},
		"commit list incomplete":        {func(q *QueueMerge) { q.PullRequest.CommitCount = 2 }, "commit list"},
		"commit list empty":             {func(q *QueueMerge) { q.Commits, q.PullRequest.CommitCount = nil, 0 }, "commit list"},
		"commit list not at head":       {func(q *QueueMerge) { q.Commits[0].SHA = otherSHA }, "commit list"},
		"commit list at the api cap":    {func(q *QueueMerge) { q.PullRequest.CommitCount = 250 }, "commit list"},
		"empty author":                  {func(q *QueueMerge) { q.PullRequest.UserLogin = "" }, "author"},
		"unsafe author":                 {func(q *QueueMerge) { q.PullRequest.UserLogin = "a b\n" }, "author"},
		"pull request closed":           {func(q *QueueMerge) { q.PullRequest.State = "closed" }, "open"},
		"pull request base is not main": {func(q *QueueMerge) { q.PullRequest.BaseRef = "dev" }, "main"},
		"queue base ref is not main":    {func(q *QueueMerge) { q.BaseRef = "refs/heads/dev" }, "main"},
		"unknown event":                 {func(q *QueueMerge) { q.Event = "push" }, "event"},
		"pull request event":            {func(q *QueueMerge) { q.Event = "pull_request" }, "event"},
		"empty event":                   {func(q *QueueMerge) { q.Event = "" }, "event"},
		"unknown schema":                {func(q *QueueMerge) { q.Schema = "x" }, "schema"},
		"base == head":                  {func(q *QueueMerge) { q.HeadSHA = q.BaseSHA }, "base"},
		"base not a sha":                {func(q *QueueMerge) { q.BaseSHA = "main" }, "base"},
		"head not a sha":                {func(q *QueueMerge) { q.HeadSHA = "HEAD" }, "head"},
		"no pull_request_target run":    {func(q *QueueMerge) { q.Runs = nil }, "run"},
		"failed run":                    {func(q *QueueMerge) { failedRun(q, "failure", "completed") }, "run"},
		"cancelled run":                 {func(q *QueueMerge) { failedRun(q, "cancelled", "completed") }, "run"},
		"run still going":               {func(q *QueueMerge) { failedRun(q, "", "in_progress") }, "run"},
		"run with no conclusion":        {func(q *QueueMerge) { failedRun(q, "", "completed") }, "run"},
		"run for another head":          {func(q *QueueMerge) { q.Runs[0].HeadSHA = otherSHA }, "run"},
		"run for the queue commit":      {func(q *QueueMerge) { q.Runs[0].HeadSHA = queueMergeSHA }, "run"},
		"run of another workflow":       {func(q *QueueMerge) { q.Runs[0].Path = ".github/workflows/other.yml" }, "run"},
		"run of a workflow with suffix": {func(q *QueueMerge) { q.Runs[0].Path = GateWorkflowPath + ".evil" }, "run"},
		"run of another event":          {func(q *QueueMerge) { q.Runs[0].Event = "pull_request" }, "run"},
		"run of the queue itself":       {func(q *QueueMerge) { q.Runs[0].Event = "merge_group" }, "run"},
		"later failed run beats earlier": {func(q *QueueMerge) {
			q.Runs = append(q.Runs, QueueRun{Path: GateWorkflowPath, Event: "pull_request_target", HeadSHA: testHeadSHA, Status: "completed", Conclusion: "failure", CreatedAt: "2026-11-07T11:00:00Z"})
		}, "run"},
		"run without a time": {func(q *QueueMerge) { q.Runs[0].CreatedAt = "" }, "run"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			q := validQueue()
			tc.edit(q)
			p := q.Problems()
			if len(p) == 0 {
				t.Fatal("accepted")
			}
			if !strings.Contains(strings.ToLower(strings.Join(p, "; ")), tc.want) {
				t.Fatalf("problems %v do not mention %q", p, tc.want)
			}
		})
	}
}

// The sender the rules see comes from GitHub's record of the run on the
// head, and only when every such run agrees on one account.
func TestQueueSenderFromRunRecord(t *testing.T) {
	t.Parallel()
	q := validQueue()
	if got := q.Sender(); got != DefaultBotLogin {
		t.Fatalf("sender %q", got)
	}
	q.Runs[0].TriggeringActor = "someone"
	if got := q.Sender(); got != "" {
		t.Fatalf("a re-run by another account must leave the sender unknown, got %q", got)
	}
	q = validQueue()
	q.Runs = append(q.Runs, QueueRun{Path: GateWorkflowPath, Event: "pull_request_target", HeadSHA: testHeadSHA, Status: "completed", Conclusion: "success",
		CreatedAt: "2026-11-07T09:00:00Z", Actor: "someone", TriggeringActor: "someone"})
	if got := q.Sender(); got != "" {
		t.Fatalf("disagreeing runs must leave the sender unknown, got %q", got)
	}
	// Runs the evidence does not accept never name a sender.
	q = validQueue()
	q.Runs = append(q.Runs, QueueRun{Path: ".github/workflows/x.yml", Event: "pull_request_target", HeadSHA: testHeadSHA, Status: "completed", Conclusion: "success",
		CreatedAt: "2026-11-07T09:00:00Z", Actor: "someone", TriggeringActor: "someone"})
	if got := q.Sender(); got != DefaultBotLogin {
		t.Fatalf("sender %q", got)
	}
}

func TestParseQueueMergeIsStrict(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validQueue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseQueueMerge(raw); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"unknown member":   strings.Replace(string(raw), `"event"`, `"extra":1,"event"`, 1),
		"duplicate member": strings.Replace(string(raw), `"event"`, `"event":"merge_group","event"`, 1),
		"trailing data":    string(raw) + `{}`,
		"not json":         `merge_group`,
		"empty":            ``,
		"too large":        strings.Repeat(" ", maxQueueEvidenceBytes+1) + string(raw),
	} {
		if _, err := ParseQueueMerge([]byte(bad)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// bumpTightening makes a tightening-only change (the same one the bot
// tests use), so the queue run has a real diff to gate.
func bumpTightening(t *testing.T) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		ev := evidenceOf(p.find(t, ids[1]))
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
	})
	return base, head
}

func queueOpts(base, head Tree, q *QueueMerge) Options {
	none := 0
	return Options{Base: base, Head: head, Queue: q, DailyLoosening: &none}
}

func prOpts(base, head Tree) Options {
	return Options{Base: base, Head: head, Author: DefaultBotLogin} // runGate completes sender, commits, head
}

// A clean queue entry gets the same verdict as the pull request run on the
// same change.
func TestQueueCleanEntryMatchesPullRequestRun(t *testing.T) {
	t.Parallel()
	base, head := bumpTightening(t)
	pr := runGate(t, prOpts(base, head))
	q := runGate(t, queueOpts(base, head, validQueue()))
	requirePass(t, pr)
	requirePass(t, q)
	if c, ok := check(q, "queue-merge"); !ok || !c.OK {
		t.Fatalf("queue-merge check: %+v", c)
	}
	if pr.Totals != q.Totals || pr.AutoMerge.Eligible != q.AutoMerge.Eligible || !q.AutoMerge.Eligible {
		t.Fatalf("pr %+v eligible=%v, queue %+v eligible=%v %v", pr.Totals, pr.AutoMerge.Eligible, q.Totals, q.AutoMerge.Eligible, q.AutoMerge.Reasons)
	}
	if q.Author != DefaultBotLogin || q.Sender != DefaultBotLogin || q.HeadSHA != testHeadSHA {
		t.Fatalf("report names author %q sender %q head %q", q.Author, q.Sender, q.HeadSHA)
	}
	prNames := []string{}
	for _, c := range pr.Checks {
		prNames = append(prNames, c.Name)
	}
	for _, c := range q.Checks {
		if c.Name != "queue-merge" && !slices.Contains(prNames, c.Name) {
			t.Fatalf("queue run has check %q the pull request run lacks", c.Name)
		}
	}
	// The same change failing at the pull request level fails in the queue.
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) { ruleOf(p.find(t, ids[2]))["nextAction"] = "Changed." })
	if r := runGate(t, prOpts(base, head)); r.Passed() {
		t.Fatal("setup: the corrupted change must fail the pull request run")
	}
	if r := runGate(t, queueOpts(base, head, validQueue())); r.Passed() {
		t.Fatal("the queue run must fail the same change")
	}
}

// Every refusal of the evidence fails the gate itself, not only the check.
func TestQueueBadEvidenceFailsTheGate(t *testing.T) {
	t.Parallel()
	base, head := bumpTightening(t)
	for name, edit := range map[string]func(q *QueueMerge){
		"unresolved pull request": func(q *QueueMerge) { q.PullRequest = QueuePR{} },
		"head != X":               func(q *QueueMerge) { q.MergeParents[1] = otherSHA },
		"wrong parents":           func(q *QueueMerge) { q.MergeParents = []string{otherSHA, testHeadSHA} },
		"merge commit in the pr":  func(q *QueueMerge) { q.Commits[0].Parents = 2 },
		"empty author":            func(q *QueueMerge) { q.PullRequest.UserLogin = "" },
		"unknown event":           func(q *QueueMerge) { q.Event = "workflow_run" },
		"missing run":             func(q *QueueMerge) { q.Runs = nil },
		"failed run":              func(q *QueueMerge) { q.Runs[0].Conclusion = "failure" },
		"run for another head":    func(q *QueueMerge) { q.Runs[0].HeadSHA = otherSHA },
		"run of another path":     func(q *QueueMerge) { q.Runs[0].Path = ".github/workflows/ci.yml" },
	} {
		q := validQueue()
		edit(q)
		r := runGate(t, queueOpts(base, head, q))
		if r.Passed() {
			t.Fatalf("%s: the gate passed", name)
		}
		if c, ok := check(r, "queue-merge"); !ok || c.OK {
			t.Fatalf("%s: queue-merge check %+v", name, c)
		}
		if r.AutoMerge.Eligible {
			t.Fatalf("%s: eligible for automatic merging", name)
		}
	}
	// Bad evidence also leaves nobody named: the rules see an unknown author.
	q := validQueue()
	q.Runs = nil
	if r := runGate(t, queueOpts(base, head, q)); r.Author != "" || r.Sender != "" {
		t.Fatalf("author %q sender %q named from refused evidence", r.Author, r.Sender)
	}
}

// An empty diff must not pass vacuously: a queue entry that changes nothing
// against its base is refused.
func TestQueueEmptyDiffDoesNotPass(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	r := runGate(t, queueOpts(base, head, validQueue()))
	if r.Passed() {
		t.Fatal("an empty queue entry passed")
	}
	if c, ok := check(r, "queue-diff"); !ok || c.OK {
		t.Fatalf("queue-diff check %+v", c)
	}
	// A pull request run keeps passing an empty change (nothing to gate).
	requirePass(t, runGate(t, Options{Base: base, Head: head}))
}

// The sender flag is for pull request runs only; a queue run that is given
// one, or an author, head or commit list of its own, is refused.
func TestQueueRefusesSenderAuthorAndCommits(t *testing.T) {
	t.Parallel()
	base, head := bumpTightening(t)
	for name, edit := range map[string]func(o *Options){
		"sender":  func(o *Options) { o.Sender = DefaultBotLogin },
		"author":  func(o *Options) { o.Author = DefaultBotLogin },
		"commits": func(o *Options) { o.Commits = botCommits() },
	} {
		o := queueOpts(base, head, validQueue())
		edit(&o)
		r := runGate(t, o)
		if r.Passed() {
			t.Fatalf("%s accepted in queue mode", name)
		}
		if c, ok := check(r, "queue-merge"); !ok || c.OK {
			t.Fatalf("%s: %+v", name, c)
		}
	}
}

// The evidence names who may have made the change: a run triggered by
// someone else leaves the change ineligible for automatic merging, and a
// bot author with an unknown sender is not trusted with trust material.
func TestQueueSenderRulesUseTheRunRecord(t *testing.T) {
	t.Parallel()
	base, head := bumpTightening(t)
	q := validQueue()
	q.Runs[0].Actor, q.Runs[0].TriggeringActor = "someone", "someone"
	r := runGate(t, queueOpts(base, head, q))
	requirePass(t, r)
	if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), "not the automation account") {
		t.Fatalf("eligible=%v %v", r.AutoMerge.Eligible, r.AutoMerge.Reasons)
	}
	q = validQueue()
	q.Runs[0].TriggeringActor = "someone"
	r = runGate(t, queueOpts(base, head, q))
	if r.AutoMerge.Eligible || r.Sender != "" {
		t.Fatalf("eligible=%v sender=%q", r.AutoMerge.Eligible, r.Sender)
	}
}

func TestQueueMergeFlagIsExclusive(t *testing.T) {
	t.Parallel()
	base, head := bumpTightening(t)
	dir := t.TempDir()
	raw, err := json.Marshal(validQueue())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "queue.json")
	if err := os.WriteFile(file, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	common := []string{"verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format(time.RFC3339)}
	for name, extra := range map[string][]string{
		"sender":  {"--sender", "x"},
		"author":  {"--author", "x"},
		"commits": {"--commits", file},
	} {
		code, out := runCLI(t, append(append(append([]string{}, common...), "--queue-merge", file, "--head-sha", queueMergeSHA), extra...)...)
		if code != 2 || !strings.Contains(out, "queue") {
			t.Fatalf("%s: %d %s", name, code, out)
		}
	}
	// The head the gate was told must be the queue commit the evidence names.
	code, out := runCLI(t, append(append([]string{}, common...), "--queue-merge", file, "--head-sha", otherSHA)...)
	if code != 2 || !strings.Contains(out, "queue") {
		t.Fatalf("head mismatch: %d %s", code, out)
	}
	code, out = runCLI(t, append(append([]string{}, common...), "--queue-merge", file)...)
	if code != 2 {
		t.Fatalf("no head: %d %s", code, out)
	}
	code, out = runCLI(t, append(append([]string{}, common...), "--queue-merge", filepath.Join(dir, "missing.json"), "--head-sha", queueMergeSHA)...)
	if code != 2 {
		t.Fatalf("missing evidence file: %d %s", code, out)
	}
}
