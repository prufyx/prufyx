// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
)

var catalogProjectToken = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var catalogVersionToken = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)

func (r runtime) catalogChecks(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx catalog checks --project SLUG [--from VERSION --to VERSION] [--format human|json]\nThe exact pair flags are all-or-nothing. Lists embedded source-rule identities and mechanically bound native input routes. It does not read configuration, evaluate a check, verify source freshness, or assess an upgrade.")
		return ExitOK
	}
	fs := flag.NewFlagSet("catalog checks", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "required exact project slug")
	from := fs.String("from", "", "queried current version; requires --to")
	to := fs.String("to", "", "queried target version; requires --from")
	format := fs.String("format", "human", "human or json")
	fromProvided := flagProvided(args, "from")
	toProvided := flagProvided(args, "to")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || !catalogProjectToken.MatchString(*project) || (*from != "" && !catalogVersionToken.MatchString(*from)) || (*to != "" && !catalogVersionToken.MatchString(*to)) || (*format != "human" && *format != "json") || fromProvided != toProvided || (fromProvided && (*from == "" || *to == "")) {
		return r.usage("invalid check catalogue arguments; use --help")
	}
	result, err := checkroutemetadata.Discover(*project, *from, *to)
	if err != nil {
		return r.fail("embedded check-route catalog integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		if err := json.NewEncoder(r.stdout).Encode(result); err != nil {
			return ExitIntegrity
		}
		return ExitOK
	}
	renderCatalogScope(r.stdout, result)
	if len(result.Checks) == 0 {
		if result.RuleCoverageState == "NO_MATCHING_EMBEDDED_RULE" {
			fmt.Fprintln(r.stdout, "known embedded project, but no matching source-rule transition (neither the reviewed anchor pair nor, where a rule carries one, its reviewed range)")
		} else {
			fmt.Fprintln(r.stdout, "no matching rule in this embedded source-rule catalog")
		}
		fmt.Fprintln(r.stdout, "inspect supported command families with: prufyx check --help")
		renderCatalogHints(r.stdout, result)
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "embedded source-rule identities: %d\n", len(result.Checks))
	for _, item := range result.Checks {
		renderCatalogCheck(r.stdout, item)
	}
	renderCatalogHints(r.stdout, result)
	return ExitOK
}

// renderCatalogCheck prints one check's human-readable listing. A range
// match (item.MatchMode == "range": the query pair fell inside the rule's
// reviewed range rather than at its reviewed anchor) prints the match mode
// and never the native route's exact-pair command, which is always pinned to
// the anchor and would misdescribe the queried pair.
func renderCatalogCheck(out io.Writer, item checkroutemetadata.Check) {
	fmt.Fprintf(out, "%s %s %s -> %s\n", item.Project, item.RuleID, item.From, item.To)
	if item.MatchMode == "range" {
		fmt.Fprintf(out, "  match mode: range (query pair falls inside the reviewed range, not the reviewed anchor)\n")
		fmt.Fprintf(out, "  native route: not shown for a range match; the native command is pinned to the reviewed anchor pair\n")
	} else if item.NativeDescriptor.State == checkroutemetadata.DescriptorExact {
		fmt.Fprintf(out, "  native route: %s\n", renderCatalogCommand(item.NativeDescriptor.Command))
		if item.NativeDescriptor.NativePass != "" {
			fmt.Fprintf(out, "  native PASS: %s\n", item.NativeDescriptor.NativePass)
		}
	} else {
		fmt.Fprintf(out, "  native route: %s\n", item.NativeDescriptor.State)
	}
	fmt.Fprintf(out, "  generic declaration: %s\n", item.GenericDeclarationRoute.State)
	if len(item.GenericDeclarationRoute.Command) != 0 {
		fmt.Fprintf(out, "  generic command: %s\n", renderCatalogCommand(item.GenericDeclarationRoute.Command))
	}
	if item.GenericDeclarationRoute.Limit != "" {
		fmt.Fprintf(out, "  generic limit: %s\n", item.GenericDeclarationRoute.Limit)
	}
	if item.NativeDescriptor.Limit != "" {
		fmt.Fprintf(out, "  native limit: %s\n", item.NativeDescriptor.Limit)
	}
}

func renderCatalogScope(out io.Writer, result checkroutemetadata.Result) {
	fmt.Fprintf(out, "metadata source: %s; source-only state: %s; rule coverage: %s\n", result.MetadataSource, result.SourceOnlyState, result.RuleCoverageState)
	fmt.Fprintf(out, "included families: %s; excluded families: %s; source evidence freshness: %s\n", strings.Join(result.Scope.IncludedFamilies, ","), strings.Join(result.Scope.ExcludedFamilies, ","), result.Scope.SourceEvidenceFreshness)
}

func renderCatalogHints(out io.Writer, result checkroutemetadata.Result) {
	for _, hint := range result.NamedCheckHints {
		fmt.Fprintf(out, "help-only named check hint: %s\n", renderCatalogCommand(hint.Command))
	}
}

func renderCatalogCommand(args []checkroutemetadata.Argument) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, "prufyx")
	for _, arg := range args {
		switch arg.Kind {
		case "literal":
			parts = append(parts, arg.Literal)
		case "file_placeholder":
			parts = append(parts, arg.Name, "FILE")
		case "name_placeholder":
			parts = append(parts, arg.Name, "NAME")
		case "boolean_operator_declaration":
			parts = append(parts, arg.Name+"=BOOL")
			parts = append(parts, "[allowed: "+strings.Join(arg.AllowedValues, ",")+"]")
		case "timestamp_placeholder":
			parts = append(parts, arg.Name, "RFC3339")
		default:
			parts = append(parts, arg.Name+"=CHOICE")
		}
	}
	return strings.Join(parts, " ")
}
