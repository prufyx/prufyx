// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"regexp"
	"strings"
	"time"
)

// markerAuthor is the only account whose comments and statuses count.
const markerAuthor = "airstand"

const maxQuotedLine = 240

// gateLine is the strict exact-head gate shape the merge queue accepts. The
// regular expression is built per head: GATE <sha8> ... head=<sha40>.
func gateLine(head string) *regexp.Regexp {
	return regexp.MustCompile("^QA batch gate on the exact head: GATE " + head[:8] +
		" WRONGPASS=0 MISMATCH=0 ERR=0( .*)? head=" + head + "( .*)?$")
}

func firstLine(body string) string {
	body = strings.ReplaceAll(body, "\r", "")
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		body = body[:i]
	}
	return body
}

func quote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxQuotedLine {
		out = out[:maxQuotedLine] + "..."
	}
	return out
}

// checkGate verifies the exact-head gate for head. Comment times were
// validated when the input was parsed.
func checkGate(pr *PRInput, head string, headDate time.Time) Marker {
	if pr == nil {
		return Marker{Status: Unverified, Reason: "no pull request input for this merge"}
	}
	if pr.Head != head {
		return Marker{Status: Unverified, Reason: "input head " + quote(pr.Head) + " is not the merged head"}
	}
	var latest *Status
	for i := range pr.Statuses {
		s := &pr.Statuses[i]
		if s.Context == "qa-gate" && (latest == nil || s.ID > latest.ID) {
			latest = s
		}
	}
	if latest != nil && latest.Creator == markerAuthor && latest.State == "success" {
		return Marker{Status: Verified, Source: "status", Line: "qa-gate status success by " + markerAuthor}
	}
	re := gateLine(head)
	var nearMiss string
	for _, c := range pr.Comments {
		if c.Author != markerAuthor {
			continue
		}
		at, _ := time.Parse(time.RFC3339, c.CreatedAt)
		body := strings.ReplaceAll(c.Body, "\r", "")
		for _, line := range strings.Split(body, "\n") {
			if re.MatchString(line) {
				if at.After(headDate) {
					return Marker{Status: Verified, Source: "comment", Line: quote(line)}
				}
				nearMiss = "strict gate line is not newer than the head commit"
			} else if strings.Contains(line, "GATE ") && nearMiss == "" {
				nearMiss = "gate line is not the strict exact-head shape"
			}
		}
	}
	return gateReason(pr, nearMiss)
}

func gateReason(pr *PRInput, near string) Marker {
	if near == "" {
		return Marker{Status: Unverified, Reason: "no gate marker from " + markerAuthor}
	}
	line := ""
	for _, c := range pr.Comments {
		if c.Author != markerAuthor {
			continue
		}
		for _, l := range strings.Split(strings.ReplaceAll(c.Body, "\r", ""), "\n") {
			if strings.Contains(l, "GATE ") {
				line = quote(l)
			}
		}
	}
	return Marker{Status: Unverified, Reason: near, Line: line}
}

// checkReview verifies the data-review verdict: a comment of the marker
// author, newer than the head commit, whose first line is exactly
// "DATA REVIEW: GO <head>".
func checkReview(pr *PRInput, head string, headDate time.Time) Marker {
	if pr == nil {
		return Marker{Status: Unverified, Reason: "no pull request input for this merge"}
	}
	if pr.Head != head {
		return Marker{Status: Unverified, Reason: "input head " + quote(pr.Head) + " is not the merged head"}
	}
	want := "DATA REVIEW: GO " + head
	near, nearLine := "", ""
	for _, c := range pr.Comments {
		if c.Author != markerAuthor {
			continue
		}
		at, _ := time.Parse(time.RFC3339, c.CreatedAt)
		first := firstLine(c.Body)
		switch {
		case first == want && at.After(headDate):
			return Marker{Status: Verified, Source: "comment", Line: quote(first)}
		case first == want:
			near, nearLine = "verdict is not newer than the head commit", quote(first)
		case strings.HasPrefix(strings.ToLower(first), "data review"):
			near, nearLine = "verdict is not the strict form 'DATA REVIEW: GO <head>'", quote(first)
		}
	}
	if near == "" {
		return Marker{Status: Unverified, Reason: "no data-review verdict from " + markerAuthor}
	}
	return Marker{Status: Unverified, Reason: near, Line: nearLine}
}
