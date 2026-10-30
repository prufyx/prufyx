// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/batchcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

// ageRecord collects what a check command learns about the age of the
// knowledge it evaluated against, so one note can be printed after the
// command's own output. It is shared by every copy of the runtime.
type ageRecord struct {
	sources []knowledgeage.Source
	now     time.Time
	// store is set when the knowledge came from a knowledge database.
	store bool
	set   bool
}

// evaluateCurrent is cncfknowledge.EvaluateCurrent under the command's trust
// policy; a successful evaluation records the age of the envelope it used.
func (r runtime) evaluateCurrent(req cncfknowledge.Request) (cncfknowledge.Report, error) {
	report, err := cncfknowledge.EvaluateCurrent(r.withTrustPolicy(req))
	if err == nil && r.age != nil {
		if at, parseErr := time.Parse(time.RFC3339, report.Knowledge.EvaluatedAt); parseErr == nil {
			r.age.sources = append(r.age.sources, report.KnowledgeAge())
			r.age.now, r.age.store, r.age.set = at.UTC(), true, true
		}
	}
	return report, err
}

// knowledgeAgeNote prints the note, when there is one, on standard error.
func (r runtime) knowledgeAgeNote(text string) {
	if text != "" {
		fmt.Fprintf(r.stderr, "prufyx: %s\n", text)
	}
}

// evaluated reports whether a check command's exit status means it
// evaluated knowledge and finished: a verdict, not a usage or integrity
// failure.
func evaluated(exit int) bool {
	return exit == ExitOK || exit == ExitBlocked || exit == ExitUnknown
}

// checkCNCF runs check cncf and prints the age note for the knowledge it
// used: the database's targets, or the embedded knowledge at --now.
func (r runtime) checkCNCF(args []string) int {
	return r.pinnedNowGuard(args, cncfcheck.EmbeddedKnowledgeAge, runtime.checkCNCFAt)
}

func (r runtime) checkCNCFAt(args []string) int {
	r.age = &ageRecord{}
	exit := r.cncf(args)
	if !evaluated(exit) || hasHelp(args) {
		return exit
	}
	switch {
	case r.age.set:
		r.knowledgeAgeNote(knowledgeage.Line(knowledgeage.Summarize(r.age.sources, r.age.now), r.age.now, false))
	case !flagProvided(args, "knowledge-db"):
		r.embeddedAgeNote(args)
	}
	return exit
}

// embeddedAgeNote prints the note for the embedded knowledge evaluated at
// the command's --now.
func (r runtime) embeddedAgeNote(args []string) {
	text, ok := nowFlag(args)
	if !ok {
		return
	}
	now, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return
	}
	sources, err := cncfcheck.EmbeddedKnowledgeAge()
	if err != nil {
		return
	}
	now = now.UTC()
	r.knowledgeAgeNote(knowledgeage.Line(knowledgeage.Summarize(sources, now), now, true))
}

// nowFlag is the value given to --now.
func nowFlag(args []string) (string, bool) {
	for i, arg := range args {
		if arg == "--" {
			break
		}
		name, ok := optionName(arg)
		if !ok || name != "now" {
			continue
		}
		if _, value, found := strings.Cut(arg, "="); found {
			return value, true
		}
		if i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// batchAgeNote words the note for the CNCF knowledge a batch used.
func batchAgeNote(report batchcheck.Report) string {
	now, err := time.Parse(time.RFC3339, report.EvaluatedAt)
	if err != nil {
		return ""
	}
	now = now.UTC()
	sources, embedded := report.KnowledgeAge()
	if len(sources) > 0 {
		return knowledgeage.Line(knowledgeage.Summarize(sources, now), now, false)
	}
	if !embedded {
		return ""
	}
	sources, err = cncfcheck.EmbeddedKnowledgeAge()
	if err != nil {
		return ""
	}
	return knowledgeage.Line(knowledgeage.Summarize(sources, now), now, true)
}

// pinnedNowGuard runs a check that takes --now with embedded knowledge. --now
// pins the evaluation time, but it must not hide knowledge that has expired
// at the real time (autoClock): when rules have expired since the pinned
// time, it warns, and a PASS is only kept if the same check also passes at
// the real time; otherwise the report and exit status of the real-time
// evaluation are given. A replay (--replay-report), a knowledge database or
// a run without --now is left as it was.
func (r runtime) pinnedNowGuard(args []string, sources func() ([]knowledgeage.Source, error), run func(runtime, []string) int) int {
	text, ok := nowFlag(args)
	if !ok || hasHelp(args) || flagProvided(args, "knowledge-db") || flagProvided(args, "replay-report") {
		return run(r, args)
	}
	pinned, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return run(r, args)
	}
	pinned = pinned.UTC()
	wall := autoClock().UTC().Truncate(time.Second)
	aged, err := sources()
	if err != nil || !pinned.Before(wall) {
		return run(r, args)
	}
	expired := knowledgeage.Summarize(aged, wall).Expired
	if expired <= knowledgeage.Summarize(aged, pinned).Expired {
		return run(r, args)
	}
	warning := "prufyx: " + scanrun.PinnedNowText(pinned, wall, expired) + "\n"

	var out, errs bytes.Buffer
	pinnedRun := r
	pinnedRun.stdout, pinnedRun.stderr = &out, &errs
	exit := run(pinnedRun, args)
	if exit == ExitOK {
		wallArgs, replaced := replaceNow(args, wall.Format(time.RFC3339))
		if !replaced {
			return r.fail("--now could not be re-evaluated at the real time", ExitUnknown)
		}
		var wallOut, wallErrs bytes.Buffer
		wallRun := r
		wallRun.stdout, wallRun.stderr = &wallOut, &wallErrs
		wallExit := run(wallRun, wallArgs)
		if wallExit != ExitOK {
			if !evaluated(wallExit) {
				fmt.Fprint(r.stderr, warning)
				return r.fail("the result at the real time could not be evaluated, so the pinned PASS is not given", ExitUnknown)
			}
			out, errs, exit = wallOut, wallErrs, wallExit
		}
	}
	r.stdout.Write(out.Bytes())
	r.stderr.Write(errs.Bytes())
	fmt.Fprint(r.stderr, warning)
	return exit
}

// replaceNow gives args with the value of --now replaced.
func replaceNow(args []string, value string) ([]string, bool) {
	out := append([]string(nil), args...)
	for i, arg := range out {
		if arg == "--" {
			break
		}
		name, ok := optionName(arg)
		if !ok || name != "now" {
			continue
		}
		if eq := strings.Index(arg, "="); eq >= 0 {
			out[i] = arg[:eq+1] + value
			return out, true
		}
		if i+1 < len(out) {
			out[i+1] = value
			return out, true
		}
	}
	return out, false
}
