// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"sort"
	"strings"
)

const helpWidth = 100

// legacySource is one former long usage text and the route it described.
type legacySource struct {
	route string
	text  string
}

// legacySources lists the former usage texts, most specific first: a route's
// own text before the check/prepare overview.
var legacySources = []legacySource{
	{"check cncf", checkCNCFLegacy},
	{"check project", checkProjectLegacy},
	{"prepare cncf", prepareCNCFLegacy},
	{"prepare project", prepareProjectLegacy},
	{"check", checkHelpLegacy},
	{"prepare", prepareHelpLegacy},
}

// legacyLine is one non-blank line of a former usage text.
type legacyLine struct {
	text  string   // trimmed; the "Usage:" and "or:" markers are removed
	usage bool     // a "prufyx ..." command line
	route string   // usage lines: "check cncf", "prepare project", "check batch", ...
	slugs []string // usage lines: the projects named by --project; none for SLUG
	notes []string // usage lines: note lines that follow and name one of the slugs
}

// parseLegacy splits a former usage text into lines. Order is kept; the
// result is a pure function of text.
func parseLegacy(text string) []legacyLine {
	var out []legacyLine
	for _, raw := range strings.Split(text, "\n") {
		t := strings.TrimSpace(raw)
		t = strings.TrimSpace(strings.TrimPrefix(t, "Usage:"))
		t = strings.TrimSpace(strings.TrimPrefix(t, "or:"))
		if t == "" {
			continue
		}
		line := legacyLine{text: t}
		if f := strings.Fields(t); strings.HasPrefix(t, "prufyx ") && len(f) >= 3 {
			line.usage = true
			line.route = f[1] + " " + f[2]
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "--project" && f[i+1] == strings.ToLower(f[i+1]) { // SLUG and PROJECT are placeholders
					line.slugs = strings.Split(f[i+1], "|")
				}
			}
		} else if n := len(out); n > 0 {
			// A note that opens with a project name belongs to the usage
			// line above it.
			lower := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(t, "note:")))
			for k := n - 1; k >= 0 && out[k].usage; k-- {
				for _, s := range out[k].slugs {
					if strings.HasPrefix(lower, s) {
						out[k].notes = append(out[k].notes, t)
					}
				}
				break
			}
		}
		out = append(out, line)
	}
	return out
}

// legacyUsage returns the usage lines of the sources whose route family is
// check or prepare, in source order, without duplicates.
func legacyUsage() []legacyLine {
	var out []legacyLine
	seen := map[string]bool{}
	for _, s := range legacySources {
		for _, l := range parseLegacy(s.text) {
			if l.usage && !seen[l.text] {
				seen[l.text] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// legacySlugs lists every project named by a --project in the former usage
// texts, sorted.
func legacySlugs() []string {
	set := map[string]bool{}
	for _, l := range legacyUsage() {
		for _, s := range l.slugs {
			set[s] = true
		}
	}
	slugs := make([]string, 0, len(set))
	for s := range set {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	return slugs
}

// projectUsage returns the usage lines of one project on one route
// ("check cncf", "prepare project", ...). The route's own text decides; the
// overview text fills in only when the route text has nothing for the slug.
func projectUsage(route, slug string) []legacyLine {
	pick := func(sources ...legacySource) []legacyLine {
		var out []legacyLine
		for _, s := range sources {
			for _, l := range parseLegacy(s.text) {
				if !l.usage || l.route != route {
					continue
				}
				for _, ls := range l.slugs {
					if ls == slug {
						out = append(out, l)
						break
					}
				}
			}
		}
		return out
	}
	for _, s := range legacySources {
		if s.route == route {
			if lines := pick(s); len(lines) > 0 {
				return lines
			}
		}
	}
	family := strings.Fields(route)[0]
	for _, s := range legacySources {
		if s.route == family {
			return pick(s)
		}
	}
	return nil
}

// genericUsage returns the route's usage lines that name no particular project.
func genericUsage(route string) []legacyLine {
	var out []legacyLine
	for _, s := range legacySources {
		if s.route != route {
			continue
		}
		for _, l := range parseLegacy(s.text) {
			if l.usage && l.route == route && len(l.slugs) == 0 {
				out = append(out, l)
			}
		}
	}
	return out
}

// wrapUsage breaks a command line at spaces so that no line is wider than
// width. Continuation lines are indented under the command. A word wider than
// the line stays whole.
func wrapUsage(indent, text string, width int) []string {
	var lines []string
	cur := indent
	for _, w := range strings.Fields(text) {
		switch {
		case cur == indent:
			cur += w
		case len(cur)+1+len(w) > width:
			lines = append(lines, cur)
			cur = indent + "    " + w
		default:
			cur += " " + w
		}
	}
	return append(lines, cur)
}

// projectArg returns the value of --project in args, or "".
func projectArg(args []string) string {
	for i, a := range args {
		for _, p := range []string{"--project", "-project"} {
			if a == p && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, p+"=") {
				return strings.TrimPrefix(a, p+"=")
			}
		}
	}
	return ""
}

var routeHelpText = map[string]string{
	"check cncf":      checkCNCFHelp,
	"check project":   checkProjectHelp,
	"prepare cncf":    prepareCNCFHelp,
	"prepare project": prepareProjectHelp,
}

// routeHelp prints the help of a check or prepare route with a project
// choice (cncf, project). With --project SLUG it prints that project's usage;
// otherwise the short route help.
func (r runtime) routeHelp(route string, args []string) int {
	slug := projectArg(args)
	if slug == "" {
		fmt.Fprintln(r.stdout, routeHelpText[route])
		return ExitOK
	}
	lines := projectUsage(route, slug)
	if len(lines) == 0 {
		fmt.Fprintf(r.stdout, "No project-specific form of prufyx %s for %q; use the generic form:\n", route, slug)
		lines = genericUsage(route)
	} else {
		fmt.Fprintf(r.stdout, "Usage of prufyx %s for %s:\n", route, slug)
	}
	for _, l := range lines {
		for _, w := range wrapUsage("  ", l.text, helpWidth) {
			fmt.Fprintln(r.stdout, w)
		}
		for _, n := range l.notes {
			for _, w := range wrapUsage("    ", n, helpWidth) {
				fmt.Fprintln(r.stdout, w)
			}
		}
	}
	fmt.Fprintf(r.stdout, "\nShared flags and exit status: prufyx %s --help\nDocs: %s/projects/%s.md\n", route, docsURL, slug)
	return ExitOK
}

// hiddenHelp lists what the overview leaves out. Everything here still works.
const hiddenHelp = `
Hidden commands and flags (they work; the short help leaves them out):

Commands:
  community-preview   Run public synthetic walkthroughs (prufyx community-preview help)
  community-preview demo-prometheus-mode
                      Legacy form of prufyx check prometheus-mode --demo

Flags of check cncf, to replay a check made with --knowledge-db:
  --knowledge-revision REV
  --knowledge-bundle-digest SHA256
  --knowledge-trust-receipt-digest SHA256`

// helpAll prints the overview and the hidden commands and flags.
func (r runtime) helpAll() int {
	r.rootHelp()
	fmt.Fprintln(r.stdout, hiddenHelp)
	return ExitOK
}
