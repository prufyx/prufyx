// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

const planUsage = `Usage: prufyx plan [PATH ...] [-] --to COMPONENT=VERSION [--from COMPONENT=VERSION ...] [flags]

Plans the whole upgrade of a cluster and its covered apps: the ordered hops,
one stage per hop, with every blocker, every gap and why a stage is not PASS.
Inputs and flags are those of prufyx scan (see prufyx scan --help), except:

  --to C=latest             not resolved yet: no signed release-line snapshot
                            ships, so the component is reported as not planned.
                            Give an explicit version.
  --format F                human (default), json or markdown

A stage is PASS only when Prufyx can prove it. This version checks no hop
actions and plans no node rolls, so no stage is PASS yet; BLOCKED and
UNSUPPORTED stages are decided. Exit codes: 0 PASS, 10 BLOCKED, 11 otherwise.
See cli/docs/plan.md.`

// plan runs prufyx plan: one scan with the full (current, target) pair of
// every component, mapped to stages by upgradeplan.
func (r runtime) plan(args []string, stdin io.Reader) int {
	if slices.Contains(args, "--help") || slices.Contains(args, "-h") {
		fmt.Fprintln(r.stdout, planUsage)
		return ExitOK
	}
	for _, a := range args {
		if a == "--fail-on" || strings.HasPrefix(a, "--fail-on=") {
			return r.fail("prufyx plan does not take --fail-on: its exit code is the plan verdict (0 PASS, 10 BLOCKED, 11 otherwise)", ExitUsage)
		}
	}
	args, latest := splitLatest(args)
	request, err := scanrun.ParseArgs(args)
	if err != nil {
		return r.scanError(err)
	}
	if !slices.Contains(upgradeplan.Formats(), request.Format) {
		return r.fail("prufyx plan supports --format human, json or markdown", ExitUsage)
	}
	if len(request.To) == 0 && len(latest) > 0 {
		// Every target was latest: plan nothing, say why.
		plan := upgradeplan.Build(scanreport.Report{}, latest, upgradeplan.Capabilities{})
		return r.writePlan(plan, request.Format)
	}
	result, err := scanrun.Run(request, scanrun.Options{Stdin: stdin, AutoLocalDB: true, PinnedRoot: pinnedRootDigest})
	if err != nil {
		return r.scanError(err)
	}
	if result.KnowledgeSource != "" {
		fmt.Fprintln(r.stderr, "prufyx: "+result.KnowledgeSource)
	}
	if result.KnowledgeNote != "" {
		fmt.Fprintln(r.stderr, "prufyx: note: "+result.KnowledgeNote)
	}
	r.knowledgeAgeNote(result.KnowledgeAge)
	plan := upgradeplan.Build(result.Report, latest, upgradeplan.Capabilities{})
	return r.writePlan(plan, request.Format)
}

func (r runtime) writePlan(plan upgradeplan.Plan, format string) int {
	output, err := upgradeplan.Render(plan, format)
	if err != nil {
		return r.fail("plan could not be rendered", ExitIntegrity)
	}
	if _, err := r.stdout.Write(output); err != nil {
		return ExitIntegrity
	}
	return plan.ExitCode
}

// splitLatest removes every --to C=latest (and --to=C=latest) from args and
// returns the components. The scan parser takes only versions.
func splitLatest(args []string) ([]string, []string) {
	var kept, latest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			kept = append(kept, args[i:]...)
			break
		}
		value, inline := "", false
		switch {
		case arg == "--to" && i+1 < len(args):
			value = args[i+1]
		case strings.HasPrefix(arg, "--to="):
			value, inline = strings.TrimPrefix(arg, "--to="), true
		}
		if component, ok := strings.CutSuffix(value, "=latest"); ok && component != "" {
			if !slices.Contains(latest, component) {
				latest = append(latest, component)
			}
			if !inline {
				i++
			}
			continue
		}
		kept = append(kept, arg)
	}
	return kept, latest
}
