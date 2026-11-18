// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// The nightly stop. The queue refuses every group while the latest nightly
// run of the CI workflow on main is not a success. The one exception is the
// pull request that carries the nightly-fix label, and only when that pull
// request's own latest run of the same workflow, on its exact head, finished
// with every job green, including each job that was red in the nightly.
// Anything unreadable or ambiguous refuses.

const ciWorkflowPath = ".github/workflows/ci.yml"

// CIRun is one workflow run as the Actions API lists it.
type CIRun struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Event      string `json:"event"`
	HeadBranch string `json:"head_branch"`
	HeadSHA    string `json:"head_sha"`
	Path       string `json:"path"`
	CreatedAt  string `json:"created_at"`
}

// CIJob is one job of a run.
type CIJob struct {
	RunID      int64  `json:"run_id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

// NightlyInput holds the API payloads. Fix is set only when the pull request
// has the nightly-fix label.
type NightlyInput struct {
	Runs             []CIRun
	NightlyJobs      []CIJob
	NightlyJobsTotal int
	Fix              bool
	PRHead           string
	PRRuns           []CIRun
	PRJobs           []CIJob
	PRJobsTotal      int
}

func latestRun(runs []CIRun, keep func(CIRun) bool) (*CIRun, error) {
	var best *CIRun
	var bestAt time.Time
	for i := range runs {
		r := runs[i]
		if !keep(r) {
			continue
		}
		at, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			return nil, errors.New("a run has no valid creation time")
		}
		if best == nil || at.After(bestAt) || (at.Equal(bestAt) && r.ID > best.ID) {
			rr := r
			best, bestAt = &rr, at
		}
	}
	return best, nil
}

func selectNightly(runs []CIRun) (*CIRun, error) {
	return latestRun(runs, func(r CIRun) bool {
		return r.Event == "schedule" && r.HeadBranch == "main" && r.Path == ciWorkflowPath && r.Status == "completed"
	})
}

func selectOwn(runs []CIRun, head string) (*CIRun, error) {
	return latestRun(runs, func(r CIRun) bool {
		return r.HeadSHA == head && r.Path == ciWorkflowPath && r.Status == "completed"
	})
}

// NightlyVerdict returns nil when the queue may proceed. The returned
// string describes what was relied on (for the log).
func NightlyVerdict(in NightlyInput) (string, error) {
	// The run lists are newest-first pages, not complete lists: the newest
	// entry is chosen by its own creation time, never by position.
	last, err := selectNightly(in.Runs)
	if err != nil {
		return "", err
	}
	if last == nil {
		return "", errors.New("no completed nightly run of the CI workflow on main was found")
	}
	if last.Conclusion == "success" {
		return fmt.Sprintf("nightly run %d is green", last.ID), nil
	}
	if !in.Fix {
		return "", fmt.Errorf("the latest nightly run %d on main is %q; only the pull request that fixes it, labelled nightly-fix, may pass", last.ID, logSafe(last.Conclusion))
	}
	// B3: the label alone is no bypass.
	if !fullSHARE.MatchString(in.PRHead) {
		return "", errors.New("the labelled pull request head is not a full commit id")
	}
	if in.NightlyJobsTotal != len(in.NightlyJobs) || in.PRJobsTotal != len(in.PRJobs) {
		return "", errors.New("a job list is incomplete")
	}
	var red []string
	for _, j := range in.NightlyJobs {
		if j.RunID != last.ID {
			return "", errors.New("a nightly job belongs to another run than the latest nightly run")
		}
		switch j.Conclusion {
		case "success", "skipped":
		default:
			if j.Name == "" {
				return "", errors.New("a nightly job has no name")
			}
			red = append(red, j.Name)
		}
	}
	if len(red) == 0 {
		return "", errors.New("the red nightly run names no failed job, so a fix cannot be proven")
	}
	mine, err := selectOwn(in.PRRuns, in.PRHead)
	if err != nil {
		return "", err
	}
	if mine == nil {
		return "", errors.New("the labelled pull request has no completed CI run on its head")
	}
	if mine.Conclusion != "success" {
		return "", fmt.Errorf("the latest CI run %d on the labelled head is %q, not green", mine.ID, logSafe(mine.Conclusion))
	}
	if len(in.PRJobs) == 0 {
		return "", errors.New("the labelled run lists no jobs")
	}
	got := map[string]string{}
	for _, j := range in.PRJobs {
		if j.RunID != mine.ID {
			return "", errors.New("a job belongs to another run than the labelled head's latest run")
		}
		if j.Conclusion != "success" {
			return "", fmt.Errorf("job %q of the labelled run is %q: the whole run must be green", logSafe(j.Name), logSafe(j.Conclusion))
		}
		got[j.Name] = j.Conclusion
	}
	for _, n := range red {
		if got[n] != "success" {
			return "", fmt.Errorf("the previously red job %q has no green result in the labelled run", logSafe(n))
		}
	}
	return fmt.Sprintf("nightly-fix: nightly run %d is %s; run %d on %s is fully green (%s now green)", last.ID, last.Conclusion, mine.ID, in.PRHead, strings.Join(red, ", ")), nil
}

type runList struct {
	Total int     `json:"total_count"`
	Runs  []CIRun `json:"workflow_runs"`
}

type jobList struct {
	Total int     `json:"total_count"`
	Jobs  []CIJob `json:"jobs"`
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s is not valid: %w", path, err)
	}
	return nil
}

func cmdNightly(args []string, stdout io.Writer) (int, error) {
	var runs, njobs, pruns, prjobs, prHead string
	var fix, sel bool
	f := flag.NewFlagSet("gate nightly", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&runs, "runs", "", "nightly runs payload")
	f.StringVar(&njobs, "nightly-jobs", "", "jobs of the latest nightly run")
	f.BoolVar(&fix, "fix", false, "the pull request carries the nightly-fix label")
	f.StringVar(&prHead, "pr-head", "", "head commit of the labelled pull request")
	f.StringVar(&pruns, "pr-runs", "", "CI runs on the pull request head")
	f.StringVar(&prjobs, "pr-jobs", "", "jobs of the latest CI run on the pull request head")
	f.BoolVar(&sel, "select", false, "print the ids of the runs whose jobs are needed")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if runs == "" {
		return 2, errors.New("--runs is required\n" + usage)
	}
	var in NightlyInput
	var rl runList
	if err := readJSON(runs, &rl); err != nil {
		return 2, fmt.Errorf("the nightly runs are unreadable: %w", err)
	}
	in.Runs = rl.Runs
	if sel {
		last, err := selectNightly(rl.Runs)
		if err != nil || last == nil {
			return 2, errors.New("no completed nightly run of the CI workflow on main was found")
		}
		fmt.Fprintf(stdout, "nightly=%d\n", last.ID)
		if pruns != "" {
			var pr runList
			if err := readJSON(pruns, &pr); err != nil {
				return 2, fmt.Errorf("a payload is unreadable: %w", err)
			}
			mine, err := selectOwn(pr.Runs, prHead)
			if err != nil || mine == nil {
				return 2, errors.New("the labelled pull request has no completed CI run on its head")
			}
			fmt.Fprintf(stdout, "pr=%d\n", mine.ID)
		}
		return 0, nil
	}
	in.Fix, in.PRHead = fix, prHead
	// The job lists are read only when the label asks for the exception.
	if fix {
		var nj, pj jobList
		var pr runList
		if njobs == "" || pruns == "" || prjobs == "" {
			return 2, errors.New("--nightly-jobs, --pr-runs and --pr-jobs are required with --fix\n" + usage)
		}
		if err := readJSON(njobs, &nj); err != nil {
			return 2, fmt.Errorf("a payload is unreadable: %w", err)
		}
		if err := readJSON(pruns, &pr); err != nil {
			return 2, fmt.Errorf("a payload is unreadable: %w", err)
		}
		if err := readJSON(prjobs, &pj); err != nil {
			return 2, fmt.Errorf("a payload is unreadable: %w", err)
		}
		in.NightlyJobs, in.NightlyJobsTotal = nj.Jobs, nj.Total
		in.PRRuns = pr.Runs
		in.PRJobs, in.PRJobsTotal = pj.Jobs, pj.Total
	}
	msg, err := NightlyVerdict(in)
	if err != nil {
		return 2, err
	}
	fmt.Fprintln(stdout, msg)
	return 0, nil
}
