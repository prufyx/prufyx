// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

var projectDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type projectArguments struct {
	project, config, schemaConfig, workload, osdMetadata, mariadbResource, selectedOSDID, from, to, configPin, schemaConfigPin, workloadPin, osdMetadataPin, mariadbResourcePin, now, format, requireInnoDBDefragmentation                                                                                                                                                                                          string
	verbose, complete, precedenceResolved, upstreamDistribution, useReviewedTargetDefault, workloadComplete, osdMetadataComplete, mariadbResourceComplete, mariadbPreOperatorUpdate, currentDefaultWasUsed, preserveHTTP2Enabled, requireHTTP2, fullStatusWithoutMonitor, fullStatusWithoutMonitorDeclared, requireInnoDBDefragmentationDeclared, mariadbResourceCompleteDeclared, mariadbPreOperatorUpdateDeclared bool
}

func parseProjectArguments(args []string, check bool) (projectArguments, bool) {
	fs := flag.NewFlagSet("community project", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var result projectArguments
	fs.StringVar(&result.project, "project", "", "reviewed project slug")
	fs.StringVar(&result.config, "effective-config", "", "native effective configuration")
	fs.StringVar(&result.schemaConfig, "loki-schema-config", "", "native Loki schema configuration")
	fs.StringVar(&result.workload, "workload", "", "native Kubernetes workload JSON")
	fs.StringVar(&result.osdMetadata, "selected-osd-metadata", "", "caller-selected current OSD metadata JSON object")
	fs.StringVar(&result.mariadbResource, "mariadb-resource", "", "caller-selected MariaDB Operator resource JSON")
	fs.StringVar(&result.selectedOSDID, "selected-osd-id", "", "explicit selected current OSD id")
	fs.StringVar(&result.from, "from", "", "current version")
	fs.StringVar(&result.to, "to", "", "target version")
	fs.StringVar(&result.configPin, "effective-config-digest", "", "optional exact configuration SHA-256")
	fs.StringVar(&result.schemaConfigPin, "loki-schema-config-digest", "", "optional exact Loki schema configuration SHA-256")
	fs.StringVar(&result.workloadPin, "workload-digest", "", "optional exact workload SHA-256")
	fs.StringVar(&result.osdMetadataPin, "selected-osd-metadata-digest", "", "optional exact selected metadata SHA-256")
	fs.StringVar(&result.mariadbResourcePin, "mariadb-resource-digest", "", "optional exact MariaDB resource SHA-256")
	fs.StringVar(&result.now, "now", "", "explicit UTC evaluation time")
	fs.StringVar(&result.format, "format", "human", "human, json, or input")
	fs.BoolVar(&result.verbose, "verbose", false, "human output: also list every rule, cited source and the provenance")
	fs.BoolVar(&result.verbose, "v", false, "same as --verbose")
	fs.BoolVar(&result.verbose, "details", false, "same as --verbose")
	fs.BoolVar(&result.complete, "effective-config-complete", false, "declare complete effective configuration")
	fs.BoolVar(&result.precedenceResolved, "precedence-resolved", false, "declare environment and CLI precedence resolved")
	fs.BoolVar(&result.upstreamDistribution, "upstream-distribution", false, "declare the reviewed upstream project distribution")
	fs.StringVar(&result.requireInnoDBDefragmentation, "require-innodb-defragmentation", "", "explicit true or false requirement for removed InnoDB defragmentation behavior")
	fs.BoolVar(&result.useReviewedTargetDefault, "use-reviewed-target-default", false, "explicitly use the reviewed target default for an omitted Loki setting")
	fs.BoolVar(&result.currentDefaultWasUsed, "current-default-was-used", false, "declare that the reviewed current default was used")
	fs.BoolVar(&result.preserveHTTP2Enabled, "preserve-http2-enabled", false, "declare intent to preserve an enabled HTTP/2 setting")
	fs.BoolVar(&result.fullStatusWithoutMonitor, "full-status-without-monitor-required", false, "declare that authenticated callers without monitor privilege require the full Kibana status response")
	fs.BoolVar(&result.requireHTTP2, "require-http2", false, "declare that the selected Fluent Bit OpenTelemetry output requires HTTP/2")
	fs.BoolVar(&result.workloadComplete, "workload-complete", false, "declare complete selected workload argv")
	fs.BoolVar(&result.osdMetadataComplete, "selected-osd-metadata-complete", false, "declare complete selected current OSD metadata object")
	fs.BoolVar(&result.mariadbResourceComplete, "resource-complete", false, "declare complete selected MariaDB resource")
	fs.BoolVar(&result.mariadbPreOperatorUpdate, "pre-operator-update", false, "declare the pre-operator-update phase")
	if duplicateFlags(args) || fs.Parse(args) != nil {
		return projectArguments{}, false
	}
	result.fullStatusWithoutMonitorDeclared = flagProvided(args, "full-status-without-monitor-required")
	result.requireInnoDBDefragmentationDeclared = flagProvided(args, "require-innodb-defragmentation")
	result.mariadbResourceCompleteDeclared = flagProvided(args, "resource-complete")
	result.mariadbPreOperatorUpdateDeclared = flagProvided(args, "pre-operator-update")
	if result.requireInnoDBDefragmentationDeclared && result.requireInnoDBDefragmentation != "true" && result.requireInnoDBDefragmentation != "false" {
		return projectArguments{}, false
	}
	modes := 0
	for _, path := range []string{result.config, result.schemaConfig, result.workload, result.osdMetadata, result.mariadbResource} {
		if path != "" {
			modes++
		}
	}
	if fs.NArg() != 0 || result.project == "" || result.from == "" || result.to == "" || modes != 1 || (flagProvided(args, "effective-config-digest") && !projectDigestRE.MatchString(result.configPin)) || (flagProvided(args, "loki-schema-config-digest") && !projectDigestRE.MatchString(result.schemaConfigPin)) || (flagProvided(args, "workload-digest") && !projectDigestRE.MatchString(result.workloadPin)) || (flagProvided(args, "selected-osd-metadata-digest") && !projectDigestRE.MatchString(result.osdMetadataPin)) || (flagProvided(args, "mariadb-resource-digest") && !projectDigestRE.MatchString(result.mariadbResourcePin)) {
		return projectArguments{}, false
	}
	if result.mariadbResource != "" {
		if result.project != projectprepare.MariaDBOperatorProject || anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "precedence-resolved", "loki-schema-config", "loki-schema-config-digest", "workload", "workload-digest", "workload-complete", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete", "upstream-distribution", "require-innodb-defragmentation", "use-reviewed-target-default", "current-default-was-used", "preserve-http2-enabled", "require-http2") {
			return projectArguments{}, false
		}
	} else if result.schemaConfig != "" {
		if result.project != projectprepare.LokiProject || anyFlagProvided(args, "effective-config", "effective-config-digest", "workload", "workload-digest", "workload-complete", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete", "current-default-was-used", "preserve-http2-enabled", "require-http2") {
			return projectArguments{}, false
		}
	} else if result.config != "" {
		if result.project == projectprepare.ArgoWorkflowsProject || result.project == projectprepare.CephProject || anyFlagProvided(args, "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "workload", "workload-digest", "workload-complete", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete") {
			return projectArguments{}, false
		}
	} else if result.workload != "" {
		if result.project != projectprepare.ArgoWorkflowsProject || anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "precedence-resolved", "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete") {
			return projectArguments{}, false
		}
	} else {
		if result.project != projectprepare.CephProject || result.selectedOSDID == "" || anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "precedence-resolved", "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "workload", "workload-digest", "workload-complete") {
			return projectArguments{}, false
		}
	}
	if result.project != projectprepare.KibanaProject && anyFlagProvided(args, "full-status-without-monitor-required") {
		return projectArguments{}, false
	}
	if result.project != projectprepare.MariaDBProject && anyFlagProvided(args, "upstream-distribution", "require-innodb-defragmentation") {
		return projectArguments{}, false
	}
	if result.project != projectprepare.MariaDBOperatorProject && anyFlagProvided(args, "mariadb-resource", "mariadb-resource-digest", "resource-complete", "pre-operator-update") {
		return projectArguments{}, false
	}
	if result.project == projectprepare.MariaDBOperatorProject && result.mariadbResource == "" {
		return projectArguments{}, false
	}
	if result.project == projectprepare.KibanaProject && anyFlagProvided(args, "full-status-without-monitor-required") && (result.to != "9.5.3" || !projectprepare.KibanaLatestOrigin(result.from)) {
		return projectArguments{}, false
	}
	if result.project != projectprepare.FluentBitProject && result.schemaConfig == "" && anyFlagProvided(args, "current-default-was-used", "preserve-http2-enabled", "require-http2") {
		return projectArguments{}, false
	}
	if result.project == projectprepare.FluentBitProject && anyFlagProvided(args, "require-http2") && anyFlagProvided(args, "current-default-was-used", "preserve-http2-enabled") {
		return projectArguments{}, false
	}
	if result.schemaConfig == "" && anyFlagProvided(args, "use-reviewed-target-default") {
		return projectArguments{}, false
	}
	if check {
		if result.now == "" {
			return projectArguments{}, false
		}
	} else if result.now != "" || (result.format != "human" && result.format != "json" && result.format != "input") {
		return projectArguments{}, false
	}
	return result, true
}

func (r runtime) prepareProject(args []string) int {
	if hasHelp(args) {
		return r.routeHelp("prepare project", args)
	}
	request, ok := parseProjectArguments(args, false)
	if !ok {
		return r.usage("invalid prepare project arguments; use --help")
	}
	prepared, exit := r.prepareProjectInput(request)
	if exit != ExitOK && exit != ExitUnknown {
		return exit
	}
	switch request.format {
	case "input":
		_, _ = r.stdout.Write(prepared.CanonicalInputJSON)
	case "json":
		authority := "CALLER_SUPPLIED_NATIVE_EFFECTIVE_CONFIG"
		if request.schemaConfig != "" {
			authority = "CALLER_SUPPLIED_NATIVE_LOKI_SCHEMA_CONFIG"
		}
		if request.workload != "" {
			authority = "CALLER_SUPPLIED_NATIVE_KUBERNETES_WORKLOAD"
		} else if request.osdMetadata != "" {
			authority = "CALLER_SUPPLIED_SELECTED_CURRENT_OSD_METADATA"
		}
		_ = json.NewEncoder(r.stdout).Encode(map[string]any{
			"schema": "prufyx.io/community-project-preparation/v1alpha1", "project": request.project,
			"state": prepared.State, "reasonCode": prepared.Reason, "sourceDigest": prepared.SourceDigest,
			"inputDigest": prepared.InputDigest, "authority": authority,
			"knowledgeOrigin": "embedded_only", "omissions": prepared.Omissions,
		})
	default:
		inputRole := "effective-config"
		if request.schemaConfig != "" {
			inputRole = "Loki schema configuration"
		}
		if request.workload != "" {
			inputRole = "Kubernetes workload"
		} else if request.osdMetadata != "" {
			inputRole = "selected current OSD metadata"
		}
		fmt.Fprintf(r.stdout, "%s native %s preparation\nstate: %s\nreason: %s\nsource digest: %s\ncanonical input digest: %s\nknowledge: embedded only; external updates unavailable\nwhole-upgrade assessment: UNKNOWN\n", request.project, inputRole, prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest)
		for _, omission := range prepared.Omissions {
			if omission == "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG" {
				fmt.Fprintln(r.stdout, "input qualification: omitted allow_structured_metadata used the reviewed target default under an explicit opt-in; this is source-derived, not observed")
			}
		}
	}
	return exit
}

func (r runtime) project(args []string) int {
	if hasHelp(args) {
		return r.routeHelp("check project", args)
	}
	request, ok := parseProjectArguments(args, true)
	if !ok {
		return r.usage("invalid check project arguments; embedded-only route; use --help")
	}
	if request.format != "human" && request.format != "json" {
		return r.usage(fmt.Sprintf("unsupported --format %q for check; use human or json", request.format))
	}
	now, err := parseUTC(request.now)
	if err != nil || now.Nanosecond() != 0 {
		return r.usage("invalid check project UTC time; use --help")
	}
	prepared, exit := r.prepareProjectInput(request)
	if exit != ExitOK && exit != ExitUnknown {
		return exit
	}
	ruleID := ""
	if request.schemaConfig != "" {
		ruleID = projectprepare.LokiStructuredMetadataRuleID
	} else if request.config != "" && request.project == projectprepare.LokiProject {
		ruleID = projectprepare.LokiCompactorRuleID
	} else if request.project == projectprepare.MariaDBOperatorProject {
		ruleID = "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite"
	}
	var report projectcheck.Report
	if ruleID != "" {
		report, err = projectcheck.CheckRule(request.project, prepared.CanonicalInputJSON, now, ruleID)
	} else {
		report, err = projectcheck.CheckNative(request.project, prepared.CanonicalInputJSON, now)
	}
	if err != nil {
		if err == projectcheck.ErrIntegrity {
			return r.fail("community project check integrity failure", ExitIntegrity)
		}
		return r.fail("community project check input failed admission", ExitUsage)
	}
	encoded, err := projectcheck.MarshalReport(report)
	if err != nil {
		return r.fail("community project report integrity failure", ExitIntegrity)
	}
	removedKeyRoute := request.project == projectprepare.AirflowProject || request.project == projectprepare.OpenSearchProject
	if request.format == "json" {
		if removedKeyRoute {
			encoded = withPreparationOmissions(encoded, prepared.Omissions)
		}
		fmt.Fprintln(r.stdout, string(encoded))
	} else {
		route := humanRoute{
			exit: projectcheck.ClaimExit(report), claims: report.Check.Claims, project: request.project, from: request.from, to: request.to,
			verbose: request.verbose, showPasses: true,
			knowledge: "Knowledge: embedded only; external updates unavailable. No network used.",
			provenance: []string{
				"source digest " + prepared.SourceDigest + "  canonical input digest " + prepared.InputDigest,
				"aggregate UNKNOWN (whole-upgrade assessment: UNKNOWN)",
				"network used: false",
			},
		}
		if request.osdMetadata != "" {
			route.preamble = append(route.preamble, "input qualification: caller-selected current OSD metadata; not a target deployment or cluster inventory observation")
		}
		if slices.Contains(prepared.Omissions, "COMMAND_DEFAULT_DERIVED_FROM_REVIEWED_IMAGE_ENTRYPOINT_SOURCE") {
			route.preamble = append(route.preamble, "input qualification: omitted command resolved from the reviewed exact-image ENTRYPOINT source; not observed at runtime")
		}
		for _, omission := range prepared.Omissions {
			if omission == "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG" {
				route.preamble = append(route.preamble, "input qualification: omitted allow_structured_metadata used the reviewed target default under an explicit opt-in; this is source-derived, not observed")
			}
		}
		if removedKeyRoute {
			route.preamble = append(route.preamble, preparationQualifications(prepared.Omissions)...)
		}
		for _, rule := range report.NotEvaluated {
			route.notEvaluated = append(route.notEvaluated, rule.RuleID+": "+rule.NextAction)
		}
		if len(report.Check.Claims) == 0 {
			route.trailer = []string{"next action: " + report.NextAction}
		}
		if err := writeHumanReport(r.stdout, route); err != nil {
			return ExitIntegrity
		}
	}
	return projectcheck.ClaimExit(report)
}

// preparationQualifications renders each preparer omission as one preamble line.
func preparationQualifications(omissions []string) []string {
	lines := make([]string, 0, len(omissions))
	for _, omission := range omissions {
		lines = append(lines, "input qualification: "+omission)
	}
	return lines
}

// withPreparationOmissions appends the preparer's omissions to a sealed report
// object as one extra key, leaving every other byte as sealed.
func withPreparationOmissions(encoded []byte, omissions []string) []byte {
	if len(omissions) == 0 || len(encoded) == 0 || encoded[len(encoded)-1] != '}' {
		return encoded
	}
	list, err := json.Marshal(omissions)
	if err != nil {
		return encoded
	}
	out := append([]byte(nil), encoded[:len(encoded)-1]...)
	out = append(out, `,"preparationOmissions":`...)
	out = append(out, list...)
	return append(out, '}')
}

func (r runtime) prepareProjectInput(request projectArguments) (projectprepare.Prepared, int) {
	path, pin := request.config, request.configPin
	if request.schemaConfig != "" {
		path, pin = request.schemaConfig, request.schemaConfigPin
	} else if request.workload != "" {
		path, pin = request.workload, request.workloadPin
	} else if request.osdMetadata != "" {
		path, pin = request.osdMetadata, request.osdMetadataPin
	} else if request.mariadbResource != "" {
		path, pin = request.mariadbResource, request.mariadbResourcePin
	}
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return projectprepare.Prepared{}, r.fail(withPermissionHint("community project input failed private-file admission", err), ExitUsage)
	}
	var prepared projectprepare.Prepared
	if request.mariadbResource != "" {
		prepared, err = projectprepare.PrepareMariaDBOperatorResource(raw, request.from, request.to, request.mariadbResourceComplete, request.mariadbPreOperatorUpdate)
	} else if request.schemaConfig != "" {
		prepared, err = projectprepare.PrepareLokiStructuredMetadata(raw, request.from, request.to, request.complete, request.precedenceResolved, request.useReviewedTargetDefault)
	} else if request.workload != "" {
		prepared, err = projectprepare.PrepareWorkload(request.project, raw, request.from, request.to, request.workloadComplete)
	} else if request.osdMetadata != "" {
		prepared, err = projectprepare.PrepareSelectedOSDMetadata(request.project, raw, request.selectedOSDID, request.from, request.to, request.osdMetadataComplete)
	} else {
		if request.project == projectprepare.FluentBitProject {
			if request.requireHTTP2 {
				prepared, err = projectprepare.PrepareFluentBitHTTP2Target(raw, request.from, request.to, request.complete, request.requireHTTP2)
			} else {
				prepared, err = projectprepare.PrepareFluentBit(raw, request.from, request.to, request.complete, request.currentDefaultWasUsed, request.preserveHTTP2Enabled)
			}
		} else if request.project == projectprepare.KibanaProject && request.to == "9.5.3" && projectprepare.KibanaLatestOrigin(request.from) {
			prepared, err = projectprepare.PrepareKibanaStatusPage(raw, request.from, request.to, request.complete, request.precedenceResolved, request.fullStatusWithoutMonitorDeclared, request.fullStatusWithoutMonitor)
		} else if request.project == projectprepare.MariaDBProject {
			prepared, err = projectprepare.PrepareMariaDBEffectiveConfig(raw, request.from, request.to, request.complete, request.precedenceResolved, request.upstreamDistribution, request.requireInnoDBDefragmentationDeclared, request.requireInnoDBDefragmentation == "true")
		} else {
			prepared, err = projectprepare.PrepareEffectiveConfig(request.project, raw, request.from, request.to, request.complete, request.precedenceResolved)
		}
	}
	if err != nil {
		return projectprepare.Prepared{}, r.fail("community project native input unsupported or invalid", ExitUsage)
	}
	if pin != "" && pin != prepared.SourceDigest {
		return projectprepare.Prepared{}, r.fail("community project input digest mismatch", ExitIntegrity)
	}
	if !json.Valid(prepared.CanonicalInputJSON) || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) {
		return projectprepare.Prepared{}, r.fail("community project preparation integrity failure", ExitIntegrity)
	}
	if prepared.State == "UNKNOWN" {
		return prepared, ExitUnknown
	}
	return prepared, ExitOK
}

// writeProjectClaims prints the claims of a community-project report: the
// headline note for combinations outside a documented support range, each
// verdict claim with its sources, then the one-way notices (informational,
// with their basis, sources and scope), then the no-verdict line when nothing
// else was decided. Support-range rules the route could not evaluate are
// listed by writeNotEvaluated.
// No line words the upgrade as safe, an UNSUPPORTED claim as broken, or a
// notice as a verdict.
func writeProjectClaims(out io.Writer, claims []constraintengine.Claim) error {
	if err := writeBasisHeadline(out, claims, nil); err != nil {
		return err
	}
	var notices []constraintengine.Claim
	for _, claim := range claims {
		if claim.IsVerdictNeutral() {
			notices = append(notices, claim)
			continue
		}
		fmt.Fprintf(out, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction)
		fmt.Fprintln(out, claim.EvidenceBasisLine())
		for _, source := range claim.Sources {
			fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest)
		}
	}
	if err := writeNotices(out, notices, true); err != nil {
		return err
	}
	return writeNoVerdictLine(out, claims)
}

// writeNotEvaluated lists the support-range rules the native route left out
// because it cannot declare their dependency. They stay visible: the route
// neither passed nor failed them, and the line names what the user can do.
func writeNotEvaluated(out io.Writer, skipped []projectcheck.NotEvaluatedRule) {
	for _, rule := range skipped {
		fmt.Fprintf(out, "%s: %s\n", rule.RuleID, rule.NextAction)
	}
}
