// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/batchcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
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
