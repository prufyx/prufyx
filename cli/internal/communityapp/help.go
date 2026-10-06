// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const docsURL = "https://github.com/prufyx/prufyx/tree/main/cli/docs"

type helpEntry struct {
	name, summary string
}

type helpGroup struct {
	title   string
	entries []helpEntry
}

// helpGroups is the command set shown by the overview, grouped by purpose.
var helpGroups = []helpGroup{
	{"Check an upgrade:", []helpEntry{
		{"scan", "Scan manifests and configs for known upgrade risks"},
		{"check", "Evaluate one scoped rule route (cncf, project, batch, ...)"},
		{"assess", "Read-only triage of live clusters; suggests which checks to run"},
	}},
	{"Prepare inputs:", []helpEntry{
		{"prepare", "Build a check input from a project's own config (cncf, project)"},
	}},
	{"Knowledge:", []helpEntry{
		{"db", "Verify, import, update and inspect the offline knowledge store"},
		{"catalog", "List supported projects and their embedded check routes"},
	}},
	{"Other:", []helpEntry{
		{"version", "Print the build identity"},
		{"community-preview", "Run public synthetic walkthroughs"},
		{"help", "Show this overview, or help for one command"},
	}},
}

// colorEnabled reports whether help output to w may use ANSI colour.
// PRUFYX_COLOR=never/always decide first; then NO_COLOR (any non-empty
// value, https://no-color.org) and TERM=dumb disable; otherwise colour is on
// only when w is a terminal.
func colorEnabled(w io.Writer, getenv func(string) string) bool {
	switch strings.ToLower(getenv("PRUFYX_COLOR")) {
	case "never":
		return false
	case "always":
		return true
	}
	if getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

type painter struct{ on bool }

func (p painter) bold(s string) string {
	if !p.on {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func (p painter) cmd(s string) string {
	if !p.on {
		return s
	}
	return "\x1b[1;36m" + s + "\x1b[0m"
}

func (r runtime) painter() painter { return painter{colorEnabled(r.stdout, os.Getenv)} }

func (r runtime) rootHelp() int {
	p := r.painter()
	w := r.stdout
	fmt.Fprintf(w, "%s - check whether a Kubernetes upgrade is safe for the inputs you declare.\n\n", p.bold("prufyx Community"))
	fmt.Fprintf(w, "%s prufyx <command> [flags]\n", p.bold("Usage:"))
	for _, g := range helpGroups {
		fmt.Fprintf(w, "\n%s\n", p.bold(g.title))
		for _, e := range g.entries {
			pad := strings.Repeat(" ", 20-len(e.name))
			fmt.Fprintf(w, "  %s%s%s\n", p.cmd(e.name), pad, e.summary)
		}
	}
	fmt.Fprintf(w, "\nRun 'prufyx <command> help' for details.\nDocs: %s\n", docsURL)
	return ExitOK
}

// commandHelp prints the detailed help of one top-level command.
func (r runtime) commandHelp(name string) int {
	var body string
	switch name {
	case "scan":
		body = scanreport.Usage
	case "assess":
		var sb strings.Builder
		r.assessUsage(&sb)
		body = strings.TrimRight(sb.String(), "\n")
	case "prepare":
		body = prepareHelp
	case "check":
		body = checkHelp
	case "catalog":
		body = catalogHelp
	case "db":
		body = dbHelp
	case "community-preview":
		body = communityPreviewHelp
	case "version":
		body = "Usage: prufyx version [--format human|json]\nPrints the build identity (version, commit, release state) as JSON, or as one line of words with --format human."
	case "help":
		return r.rootHelp()
	default:
		return r.usage("unknown command " + name + "; use prufyx help")
	}
	p := r.painter()
	summary := ""
	for _, g := range helpGroups {
		for _, e := range g.entries {
			if e.name == name {
				summary = e.summary
			}
		}
	}
	fmt.Fprintf(r.stdout, "%s - %s\n\n", p.bold("prufyx "+name), summary)
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "Usage:") {
			lines[i] = p.bold("Usage:") + strings.TrimPrefix(l, "Usage:")
		} else if strings.HasPrefix(l, "Exit status") {
			lines[i] = p.bold("Exit status") + strings.TrimPrefix(l, "Exit status")
		}
	}
	fmt.Fprintln(r.stdout, strings.Join(lines, "\n"))
	return ExitOK
}

// isCommand reports whether name is a top-level command with detailed help.
func isCommand(name string) bool {
	switch name {
	case "scan", "assess", "prepare", "check", "catalog", "db", "version", "community-preview":
		return true
	}
	return false
}
