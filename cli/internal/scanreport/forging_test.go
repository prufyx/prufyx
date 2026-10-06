// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"strings"
	"testing"
	"unicode"
)

// hostileStrings are attacker-derived values: terminal escapes, line breaks
// that forge report lines, and bidirectional controls.
var hostileStrings = []struct{ name, value string }{
	{"csi", "x\x1b[2Jy"},
	{"osc", "x\x1b]0;owned\x07y"},
	{"c1-csi", "x\u009b2Jy"},
	{"carriage-return", "x\rPASS forged line"},
	{"newline", "x\nPASS forged line"},
	{"line-separator", "x\u2028PASS forged line"},
	{"bidi-override", "x\u202eevil\u202cy"},
	{"bidi-isolate", "x\u2066evil\u2069y"},
	{"zero-width", "x\u200by\U0000feffz"},
	{"del", "x\x7fy"},
	{"bad-utf8", "x\xffy"},
}

// forbiddenRune reports a rune that must never reach human or Markdown
// output unescaped (a newline the renderer itself writes is allowed).
func forbiddenRune(r rune) bool {
	return r != '\n' && (unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar)
}

func hostileFull(value string) Report {
	report := fullReport()
	Finalize(&report)
	loc := &report.Findings[0].Locations[0]
	loc.File, loc.Namespace, loc.Name, loc.Kind = "f"+value, "n"+value, "m"+value, "k"+value
	report.Findings[0].Title = "t" + value
	report.Findings[0].Fix = "x" + value
	report.Findings[0].Extractor = "e" + value
	report.Findings[0].RuleID = "r" + value
	report.Notices[0].Text = "n" + value
	report.Notices[1].Text = "n" + value
	report.Gaps[0].Detail = "d" + value
	report.Gaps[0].Action = "a" + value
	report.Notes = []string{"note" + value}
	report.Omissions = []string{"o" + value}
	report.Provenance.KnowledgeOrigin = "ko" + value
	report.Provenance.KnowledgeStore = &KnowledgeStore{Path: "/db" + value, Layout: "l", TargetPath: "/t" + value,
		Projects: []KnowledgeStoreProject{{Project: "p" + value, Status: "present", TargetPath: "/pt" + value}, {Project: "q" + value, Status: "absent"}}}
	report.Findings[0].Citations[0].URL = "https://example.test/" + value
	return report
}

func TestHumanAndMarkdownNeverForge(t *testing.T) {
	for _, hostile := range hostileStrings {
		for _, format := range []string{"human", "markdown"} {
			t.Run(hostile.name+"/"+format, func(t *testing.T) {
				report := hostileFull(hostile.value)
				raw, err := Render(report, format, RenderOptions{ShowPasses: true, Verbose: true})
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range string(raw) {
					if forbiddenRune(r) {
						t.Fatalf("%s output carries %U unescaped:\n%q", format, r, raw)
					}
				}
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.HasPrefix(strings.TrimLeft(line, " |"), "PASS forged") {
						t.Fatalf("%s output has a forged line %q", format, line)
					}
				}
			})
		}
	}
}

func TestJSONAndSARIFNeverCarryRawControls(t *testing.T) {
	for _, hostile := range hostileStrings {
		for _, format := range []string{"json", "sarif"} {
			t.Run(hostile.name+"/"+format, func(t *testing.T) {
				raw, err := Render(hostileFull(hostile.value), format, RenderOptions{})
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range string(raw) {
					if r != '\n' && r != ' ' && forbiddenRune(r) {
						t.Fatalf("%s output carries raw %U", format, r)
					}
				}
			})
		}
	}
}
