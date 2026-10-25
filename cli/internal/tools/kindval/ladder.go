// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// LadderStep is one rung of the diagnostic ladder: a server dry run of the
// rejected manifests with one validation mode. Dropped are the field paths
// the validation names as unknown.
type LadderStep struct {
	Method string `json:"method"`
	Exit   int    `json:"exit"`
	// Accepted is true when no line is an error other than AlreadyExists
	// (CRDs a partly applied server-side apply left behind).
	Accepted bool     `json:"accepted"`
	Lines    []string `json:"lines"`
	Dropped  []string `json:"dropped"`
}

// ladderMaxDropped caps the dropped paths kept per step.
const ladderMaxDropped = 200

// ladderMethods are the rungs, strictest first. Both are server dry runs:
// nothing is persisted, and neither is a confirming apply. They use create,
// not apply: a client-side apply of a large definition fails on the
// last-applied-configuration annotation size, which would hide the answer.
var ladderMethods = []string{"create --dry-run=server --validate=strict", "create --dry-run=server --validate=warn"}

var (
	unknownFieldPath = regexp.MustCompile(`unknown field "([^"]+)"`)
	// undeclaredPath matches the typed-patch form: ".spec.x: field not declared in schema".
	undeclaredPath = regexp.MustCompile(`^(\.\S+): field not declared in schema`)
)

// ladderClass reports whether the rejection is an unknown-field class: the
// server-side apply typed-patch failure ("field not declared in schema") or a
// strict-validation unknown field. Other rejections, for example a
// non-structural schema, are not diagnosed: validation modes cannot change
// their answer.
func ladderClass(ie *InstallError, err error) bool {
	if ie == nil {
		return false
	}
	text := strings.Join(ie.Lines, "\n")
	var ae *applyError
	if errors.As(err, &ae) {
		text = ae.stderr // the full output, not the capped lines
	}
	return strings.Contains(text, "field not declared in schema") || strings.Contains(text, "unknown field")
}

// droppedPaths lists the unknown-field paths named in lines, deduplicated.
func droppedPaths(lines []string) []string {
	out, seen := []string{}, map[string]bool{}
	add := func(p string) {
		if !seen[p] && len(out) < ladderMaxDropped {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, l := range lines {
		for _, m := range unknownFieldPath.FindAllStringSubmatch(l, -1) {
			add(m[1])
		}
		if m := undeclaredPath.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			add(m[1])
		}
	}
	return out
}

// runLadder runs the rungs against manifest. It only reads the cluster
// (server dry run), never changes a verdict and installs nothing.
func runLadder(ctx context.Context, k kube, manifest []byte) []LadderStep {
	steps := []LadderStep{}
	for _, m := range ladderMethods {
		if ctx.Err() != nil {
			break
		}
		args := append(strings.Fields(m), "-f", "-")
		_, errb, exit := k.run(ctx, "kubectl", k.args(args...), manifest)
		var all []string
		for _, l := range strings.Split(string(errb), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				all = append(all, l)
			}
		}
		// Classify on the full stderr; only the stored lines are capped.
		lines := []string{}
		if len(all) > InstallErrorMaxLines {
			lines = append(lines, all[:InstallErrorMaxLines]...)
		} else {
			lines = append(lines, all...)
		}
		steps = append(steps, LadderStep{Method: m, Exit: exit, Accepted: ladderAccepted(exit, all), Lines: lines, Dropped: droppedPaths(all)})
	}
	return steps
}

// ladderAccepted reports whether a rung found nothing to refuse: exit 0, or
// only AlreadyExists errors.
func ladderAccepted(exit int, lines []string) bool {
	if exit == 0 {
		return true
	}
	all := strings.Join(lines, "\n")
	if exit != 1 || transportFailure(all) || strings.Contains(all, "was refused") {
		return false
	}
	for _, l := range lines {
		// Unknown failure text is not an acceptance.
		if !strings.HasPrefix(l, "Warning:") && !strings.Contains(l, "(AlreadyExists)") {
			return false
		}
	}
	return true
}
