// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import "regexp"

// expiryNoteLine is the one-line knowledge age note (see knowledgeage.Line)
// as written to standard error. Its presence depends on the wall clock, so
// tests of unrelated behavior drop exactly this line before asserting on
// standard error; the note itself is tested in the knowledgeage package.
var expiryNoteLine = regexp.MustCompile(`(?m)^prufyx: note: \d+ knowledge (?:rule expires|rules expire|rule has|rules have) [^\n]*\n`)

// withoutExpiryNote removes the knowledge age note lines from stderr text;
// every other line is kept, so any other output still fails the caller.
func withoutExpiryNote(stderr string) string {
	return expiryNoteLine.ReplaceAllString(stderr, "")
}
