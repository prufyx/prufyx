// SPDX-License-Identifier: AGPL-3.0-only

package upgradeplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Formats are the plan output formats.
func Formats() []string { return []string{"human", "json", "markdown"} }

// Render renders the plan in one of Formats. The format changes only the
// bytes: the plan, its verdict and the exit code are the same for all.
func Render(plan Plan, format string) ([]byte, error) {
	switch format {
	case "json":
		raw, err := json.Marshal(plan)
		if err != nil {
			return nil, err
		}
		return append(raw, '\n'), nil
	case "markdown":
		return render(plan, true), nil
	}
	return render(plan, false), nil
}

func render(plan Plan, md bool) []byte {
	var out bytes.Buffer
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", clean(args)...) }
	head := func(text string) {
		if md {
			line("")
			line("### %s", text)
			line("")
		} else {
			line("")
			line("%s", text)
		}
	}
	line("%s", plan.Headline)
	if plan.Undecided > 0 {
		line("Not decided: %d of %d stages. Prufyx never reports PASS for a stage it cannot prove.", plan.Undecided, len(plan.Stages))
	}
	for _, n := range plan.Notes {
		line("Note: %s", n)
	}
	head("Routes")
	for _, r := range plan.Routes {
		policy := r.Policy
		if policy == "" {
			policy = "no reviewed path policy"
		}
		if r.Gap != "" {
			line("  %s  %s -> %s  not planned (%s)", r.Component, r.From, r.To, r.Gap)
			continue
		}
		line("  %s  %s -> %s  (%s; %d hops)", r.Component, r.From, r.To, policy, r.Hops)
	}
	head("Stages")
	for _, s := range plan.Stages {
		line("Stage %d  %s %s -> %s  %s  [%s order: %s]", s.Index, s.Component, s.From, s.To, s.Verdict, s.Order.Kind, s.Order.Reason)
		line("         hop status: %s", s.HopStatus)
		for _, f := range s.Findings {
			line("         BLOCKED %s: %s", f.RuleID, f.Title)
			if f.Fix != "" {
				line("           fix: %s", f.Fix)
			}
		}
		for _, f := range s.Unsupported {
			line("         UNSUPPORTED %s: %s", f.RuleID, f.Title)
		}
		for _, n := range s.Notices {
			line("         one-way change %s", n)
		}
		for _, g := range s.Gaps {
			line("         gap %s: %s", g.Reason, g.Detail)
		}
		if len(s.Reasons) > 0 {
			line("         not PASS because: %s", strings.Join(s.Reasons, ", "))
		}
	}
	if len(plan.Gaps) > 0 {
		head("Not planned")
		for _, g := range plan.Gaps {
			line("  %s %s: %s", g.Component, g.Reason, g.Detail)
			if g.Action != "" {
				line("    action: %s", g.Action)
			}
		}
	}
	return out.Bytes()
}

// clean strips control characters from rendered strings, so knowledge text
// cannot forge extra lines.
func clean(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			out[i] = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, s)
			continue
		}
		out[i] = a
	}
	return out
}
