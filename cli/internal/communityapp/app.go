// SPDX-License-Identifier: AGPL-3.0-only

// Package communityapp is the small public Community command router.
package communityapp

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/observation"
	"github.com/prufyx/prufyx/cli/internal/prometheusmode"
)

const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitIntegrity = 3
	ExitBlocked   = 10
	ExitUnknown   = 11
	// ExitScopedPass is what a check route exits with, instead of ExitOK,
	// when --strict-exit is given and the route's one scoped rule passed.
	ExitScopedPass           = 14
	legacyEnvelopeAPIVersion = "prufyx.io/v1alpha1"
)

type runtime struct {
	stdout, stderr io.Writer
	version        string
	// trust is the evidence-basis trust policy of check cncf
	// (--require-basis); the zero value is the default policy.
	trust cncfcheck.TrustPolicy
	// age collects the age of the knowledge a check command evaluated
	// against; nil for commands that print no knowledge age note.
	age *ageRecord
}

type envelope struct {
	SchemaVersion string         `json:"schemaVersion"`
	Command       string         `json:"command"`
	Result        envelopeResult `json:"result"`
	Data          any            `json:"data,omitempty"`
}
type envelopeResult struct {
	Status   string   `json:"status"`
	Decision string   `json:"decision,omitempty"`
	Scope    string   `json:"scope"`
	Reason   string   `json:"reasonCode"`
	Messages []string `json:"messages,omitempty"`
}

// Run executes one command. For a check route, --strict-exit (see
// cli/docs/exit-codes.md) turns the exit status 0 of a scoped PASS into
// ExitScopedPass; without the flag nothing here changes.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) > 0 && args[0] == "check" {
		if rest, strict := stripStrictExit(args); strict {
			code := run(ctx, rest, stdout, stderr, version)
			return strictExitCode(rest, code, stderr)
		} else if len(rest) != len(args) {
			return run(ctx, rest, stdout, stderr, version)
		}
	}
	return run(ctx, args, stdout, stderr, version)
}

// stripStrictExit removes --strict-exit, --strict-exit=true and
// --strict-exit=false from a check command line; the last one given decides.
func stripStrictExit(args []string) ([]string, bool) {
	rest := make([]string, 0, len(args))
	strict := false
	for _, a := range args {
		switch a {
		case "--strict-exit", "--strict-exit=true":
			strict = true
		case "--strict-exit=false":
			strict = false
		default:
			rest = append(rest, a)
		}
	}
	return rest, strict
}

// strictExitCode maps a check route's exit 0 to ExitScopedPass. Help output
// is not a result and keeps 0; every other exit status is unchanged.
func strictExitCode(args []string, code int, stderr io.Writer) int {
	if code != ExitOK {
		return code
	}
	for _, a := range args[1:] {
		if help(a) {
			return code
		}
	}
	fmt.Fprintf(stderr, "prufyx: note: scoped PASS: exit %d (--strict-exit); this is not a complete PASS, see cli/docs/exit-codes.md\n", ExitScopedPass)
	return ExitScopedPass
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	r := runtime{stdout: stdout, stderr: stderr, version: version}
	if len(args) == 0 || help(args[0]) {
		return r.rootHelp()
	}
	switch args[0] {
	case "assess":
		return r.assess(ctx, args[1:])
	case "prepare":
		if len(args) >= 2 && args[1] == "cncf" {
			return r.prepareCNCF(args[2:])
		}
		if len(args) >= 2 && args[1] == "project" {
			return r.prepareProject(args[2:])
		}
		return r.usage("Usage: prufyx prepare <cncf|project> --help")
	case "catalog":
		if len(args) >= 2 && args[1] == "cncf" {
			return r.cncfCatalog(args[2:])
		}
		if len(args) >= 2 && args[1] == "checks" {
			return r.catalogChecks(args[2:])
		}
		return r.usage("Usage: prufyx catalog <cncf|checks> [flags]")
	case "version":
		identity, err := buildidentity.Report()
		if err != nil {
			return r.fail("build identity integrity failure", ExitIntegrity)
		}
		return r.writeEnvelope(envelope{SchemaVersion: legacyEnvelopeAPIVersion, Command: "version", Result: envelopeResult{Status: "OK", Scope: "local build identity", Reason: "build_identity_reported"}, Data: identity}, ExitOK)
	case "check":
		if len(args) == 2 && help(args[1]) {
			fmt.Fprintln(stdout, "Usage: prufyx check <batch|cert-manager-values|prometheus-mode|cncf|project|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup> [flags]")
			return ExitOK
		}
		if len(args) < 2 {
			return r.usage("Usage: prufyx check <batch|cert-manager-values|prometheus-mode|cncf|project|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup> [flags]")
		}
		switch args[1] {
		case "batch":
			return r.batch(args[2:])
		case "cncf":
			return r.checkCNCF(args[2:])
		case "project":
			return r.project(args[2:])
		case "cert-manager-values":
			return r.certManager(args[2:])
		case "prometheus-mode":
			return r.prometheus(ctx, args[2:], false)
		case "spiffe-x509-svid":
			return r.spiffeX509SVID(args[2:])
		case "cloudevents-structured-json":
			return r.cloudEventsStructuredJSON(args[2:])
		case "tikv-gcp-v2-wif-backup":
			return r.tikvGCPV2WIFBackup(args[2:])
		default:
			return r.usage("unknown check; use prufyx check --help")
		}
	case "db":
		return r.database(ctx, args[1:])
	case "scan":
		return r.scan(args[1:], scanStdin)
	case "community-preview":
		if len(args) >= 2 && args[1] == "example" {
			return r.communityExample(args[2:])
		}
		if len(args) >= 2 && args[1] == "demo-prometheus-mode" {
			return r.legacyPrometheusDemo(args[2:])
		}
		if len(args) >= 2 && args[1] == "validate-prometheus-mode" {
			return r.prometheus(ctx, args[2:], true)
		}
		return r.usage("Usage: prufyx community-preview <example|validate-prometheus-mode> [flags]")
	default:
		return r.usage("unknown command; use prufyx --help")
	}
}

// openObservationRoot is a variable so the unsupported-platform refusal can be
// tested on hosts where observation is supported.
var openObservationRoot = observation.OpenPath

func (r runtime) rootHelp() int {
	fmt.Fprintln(r.stdout, `prufyx Community

Usage:
  prufyx scan [PATH ...] [-] --to COMPONENT=VERSION [--from COMPONENT=VERSION ...] [--config FILE] [--format human|json] [--redact] [--now RFC3339]
  prufyx assess --kubeconfig FILE --acknowledge-kubeconfig-exec-risk [--allow-partial] [--component-configuration-profile v2|v3] [--output DIR] [--format human|json] CONTEXT...
  prufyx prepare project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project mariadb --effective-config FILE --from 10.11.8 --to 11.4.2 --effective-config-complete --precedence-resolved --upstream-distribution --require-innodb-defragmentation true|false [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project mariadb-operator --mariadb-resource FILE --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update [--mariadb-resource-digest SHA256] [--format human|json|input]
  prufyx prepare project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from VERSION --to VERSION --selected-osd-metadata-complete [--selected-osd-metadata-digest SHA256] [--format human|json|input]
  Kibana 9.0.8|9.1.10|9.2.8|9.3.8|9.4.6 -> 9.5.3 additionally requires --full-status-without-monitor-required for the status-page scope.
  prufyx prepare project --project fluent-bit --effective-config FILE --from 3.2.10|4.0.14|4.1.2|4.2.8|5.0.10 --to 5.1.2 --effective-config-complete --require-http2 [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project kyverno --input FILE --container NAME --from VERSION --to VERSION [--distribution official_upstream|custom_build] [--format human|json|input]
  prufyx prepare cncf --project linkerd --input FILE --from 2.13.7 --to 2.14.0 [--distribution official_upstream|custom_build] [--schema-validation required|disabled] [--format human|json|input]
  prufyx prepare cncf --project karmada --input FILE --from 1.18.3 --to 1.19.0 [--distribution official_upstream|custom_build] [--target-policy-crd-admission required|disabled] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project argo-cd --input FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project jaeger --input FILE --from 1.76.0 --to 2.20.0 [--non-memory-storage-required true|false] [--official-jaeger-distribution true|false] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project opencost --input FILE --from 1.119.0 --to 1.120.0 [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project harbor --input FILE --from 2.7.0 --to 2.8.0 or 2.10.3|2.11.2|2.12.4|2.13.5|2.14.4 --to 2.15.2 [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project containerd --input FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only [--input-digest SHA256] [--format human|json|input]
  prufyx catalog cncf [--priority] [--project SLUG] [--format human|json]
  prufyx catalog checks --project SLUG [--from VERSION --to VERSION] [--format human|json]
  prufyx check cncf --project argo-cd --config-map FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] --now RFC3339 [--config-map-digest SHA256] [--format human|json]
  prufyx check cncf --project argo-cd --resource-exclusions-config-map FILE --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete --resource-exclusions-precedence-resolved [--requires-v2-visibility-of-v3-default-excluded-resources true] --now RFC3339 [--resource-exclusions-config-map-digest SHA256] [--format human|json]
  prufyx check cncf --project knative --service FILE --from 1.22.0 --to 1.23.0 --now RFC3339 [--service-digest SHA256] [--format human|json]
  prufyx check cncf --project emissary-ingress --diagd-argv FILE --from 3.10.0 --to 4.0.1 --now RFC3339 [--diagd-argv-digest SHA256] [--format human|json]
  prufyx check cncf --project openfga --effective-config FILE --from 1.17.1 --to 1.18.0 [--effective-config-complete] --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --scrape-config FILE --scrape-job NAME --from 2.55.1 --to 3.1.0 --scrape-config-complete --scrape-config-precedence-resolved --now RFC3339 [--scrape-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --alertmanager-config FILE --from 2.55.1 --to 3.1.0 --alertmanager-config-complete --alertmanager-config-precedence-resolved --now RFC3339 [--alertmanager-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --prometheus-config FILE --prometheus-config-complete --prometheus-config-precedence-resolved --prometheus-rule remote-write-http2-default --prometheus-remote-write-name NAME --prometheus-remote-write-http2-required=true|false --from 2.55.1 --to 3.14.0 --now RFC3339 [--prometheus-config-digest SHA256] [--format human|json]
  prufyx check cncf --project containerd --containerd-config FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only --now RFC3339 [--containerd-config-digest SHA256] [--format human|json]
  prufyx check cncf --project SLUG --input FILE --now RFC3339 [--input-digest SHA256] [--format human|json]
  prufyx check cncf --project SLUG --input FILE --knowledge-db DIR [--input-digest SHA256] [--format human|json]
  prufyx check project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check project --project mariadb --effective-config FILE --from 10.11.8 --to 11.4.2 --effective-config-complete --precedence-resolved --upstream-distribution --require-innodb-defragmentation true|false --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check project --project mariadb-operator --mariadb-resource FILE --from 26.3.0 --to 26.6.0 --resource-complete --pre-operator-update --now RFC3339 [--mariadb-resource-digest SHA256] [--format human|json]
  prufyx check project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved --now RFC3339 [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json]
  prufyx check project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from VERSION --to VERSION --selected-osd-metadata-complete --now RFC3339 [--selected-osd-metadata-digest SHA256] [--format human|json]
  Kibana 9.0.8|9.1.10|9.2.8|9.3.8|9.4.6 -> 9.5.3 additionally requires --full-status-without-monitor-required for the status-page scope.
  prufyx check project --project fluent-bit --effective-config FILE --from 3.2.10|4.0.14|4.1.2|4.2.8|5.0.10 --to 5.1.2 --effective-config-complete --require-http2 --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx db verify FILE --profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup --bootstrap-root FILE --bootstrap-root-digest SHA256 [--expected-package-digest SHA256]
  prufyx db import FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256]
  prufyx db update --source HTTPS_URL --package-out FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256]
  prufyx db status --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--format human|json]
  prufyx db capabilities --profile cncf [--format human|json]
  prufyx check cert-manager-values --from VERSION --to VERSION --values FILE [--schema-validation required|disabled] [--values-digest SHA256] [--format human|json]
  prufyx check batch --plan FILE --root DIR (--now RFC3339 | --knowledge-db DIR) [--format human|json] [--exit-mode legacy|detailed]
  prufyx check prometheus-mode --demo [--format human|json]
  prufyx check prometheus-mode --observation-root DIR --proposed-workload FILE --proposed-digest SHA256 --captured-at RFC3339 --now RFC3339 --max-age DURATION [--format human|json]
  prufyx check spiffe-x509-svid --certificate FILE --now RFC3339 [--certificate-digest SHA256] [--format human|json]
  prufyx check spiffe-x509-svid --certificate FILE --knowledge-db DIR [--certificate-digest SHA256] [--format human|json]
  prufyx check cloudevents-structured-json --event FILE --now RFC3339 [--event-digest SHA256] [--format human|json]
  prufyx check cloudevents-structured-json --event FILE --knowledge-db DIR [--event-digest SHA256] [--format human|json]
  prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --now RFC3339 [--config-digest SHA256] [--format human|json]
  prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --knowledge-db DIR [--config-digest SHA256] [--format human|json]
  prufyx community-preview example <cncf-coredns-latest|cncf-envoy-latest|cncf-etcd|cncf-nats-latest|cncf-opentelemetry|cncf-rook-latest|knowledge-cert-manager|knowledge-cncf|project-ceph-latest>
  prufyx community-preview validate-prometheus-mode ...

Exit status for check cert-manager-values: 0 scoped PASS, 10 scoped BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check prometheus-mode: 0 scoped PASS, 11 ATTENTION or UNKNOWN. The legacy alias always exits 11 because its aggregate remains UNKNOWN.
Exit status for check spiffe-x509-svid: 0 scoped PASS, 10 scoped FAIL, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check cloudevents-structured-json: 0 scoped PASS, 10 scoped FAIL, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check tikv-gcp-v2-wif-backup: 0 scoped PASS, 10 scoped BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check batch: legacy mode preserves 0 PASS, 10 BLOCKED, 11 UNKNOWN or stale, 2 invalid input, 3 integrity failure; detailed mode uses 12 stale evidence and 13 evaluation clock before review.`)
	return ExitOK
}

func (r runtime) certManager(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check cert-manager-values --from VERSION --to VERSION --values FILE [--schema-validation required|disabled] [--values-digest SHA256] [--current-chart-digest SHA256] [--target-chart-digest SHA256] [--knowledge-db DIR [--knowledge-revision REVISION] [--knowledge-bundle-digest SHA256] [--knowledge-trust-receipt-digest SHA256]] [--replay-receipt FILE] [--format human|json]")
		return ExitOK
	}
	fs := flag.NewFlagSet("check cert-manager-values", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	from := fs.String("from", "", "current chart version")
	to := fs.String("to", "", "target chart version")
	values := fs.String("values", "", "merged values JSON")
	valuesDigest := fs.String("values-digest", "", "optional exact values SHA-256")
	currentDigest := fs.String("current-chart-digest", "", "optional current chart manifest assertion")
	targetDigest := fs.String("target-chart-digest", "", "optional target chart manifest assertion")
	schemaValidation := fs.String("schema-validation", "required", "required or disabled")
	replay := fs.String("replay-receipt", "", "prior canonical JSON report")
	knowledgeDB := fs.String("knowledge-db", "", "explicit verified offline knowledge store")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional exact selected knowledge revision")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional exact selected bundle SHA-256")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional exact selected trust receipt SHA-256")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *from == "" || *to == "" || *values == "" || (*format != "human" && *format != "json") || (*schemaValidation != "required" && *schemaValidation != "disabled") || (*replay != "" && *valuesDigest == "") {
		return r.usage("invalid cert-manager-values arguments; use --help")
	}
	externalAssertions := *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != ""
	if (*knowledgeDB == "" && externalAssertions) || (*knowledgeDB != "" && *replay != "" && (*knowledgeRevision == "" || *knowledgeBundleDigest == "" || *knowledgeTrustReceiptDigest == "")) {
		return r.usage("invalid external knowledge selection; use --help")
	}
	if *knowledgeDB != "" {
		return r.externalCertManager(externalCertRequest{
			knowledgeDB: *knowledgeDB, knowledgeRevision: *knowledgeRevision,
			knowledgeBundleDigest: *knowledgeBundleDigest, knowledgeTrustReceiptDigest: *knowledgeTrustReceiptDigest,
			values: *values, valuesDigest: *valuesDigest, from: *from, to: *to,
			currentDigest: *currentDigest, targetDigest: *targetDigest,
			schemaValidation: *schemaValidation, replay: *replay, format: *format,
		})
	}
	artifact, err := certmanagervalues.ReadArtifact(*values, *valuesDigest)
	if err != nil {
		return r.packageError("values input failed admission", err)
	}
	req := certmanagervalues.Request{Values: artifact, From: *from, To: *to, CurrentChartDigest: *currentDigest, TargetChartDigest: *targetDigest, SchemaValidation: *schemaValidation}
	var report certmanagervalues.Report
	if *replay != "" {
		receipt, readErr := currentbundle.ReadBoundedFile(*replay, 1<<20)
		if readErr != nil {
			if errors.Is(readErr, currentbundle.ErrIntegrity) {
				return r.fail("replay receipt identity changed", ExitIntegrity)
			}
			return r.fail("replay receipt failed admission", ExitUsage)
		}
		report, err = certmanagervalues.Replay(req, receipt)
	} else {
		report, err = certmanagervalues.Evaluate(req)
	}
	if err != nil {
		return r.packageError("cert-manager values check failed", err)
	}
	raw, err := certmanagervalues.MarshalReport(report)
	if err != nil {
		return r.fail("report encoding failed", ExitIntegrity)
	}
	if *format == "json" {
		fmt.Fprintln(r.stdout, string(raw))
	} else {
		writeCertHuman(r.stdout, report)
	}
	switch report.Claim.Status {
	case "PASS":
		return ExitOK
	case "BLOCKED":
		return ExitBlocked
	default:
		return ExitUnknown
	}
}

func writeCertHuman(w io.Writer, report certmanagervalues.Report) {
	fmt.Fprintf(w, "cert-manager removed monitor values: %s\n", report.Claim.Status)
	fmt.Fprintf(w, "claim: %s\n", report.Claim.ReasonCode)
	fmt.Fprintf(w, "reason: %s\n", report.Claim.Reason)
	if len(report.MatchedPaths) > 0 {
		fmt.Fprintf(w, "matched curated paths: %s\n", strings.Join(report.MatchedPaths, ", "))
	}
	fmt.Fprintf(w, "values digest: %s\nknowledge revision: %s\n", report.Inputs.ValuesDigest, report.Inputs.KnowledgeRevisionDigest)
	fmt.Fprintf(w, "reviewed charts: %s (%s) -> %s (%s)\n", report.Transition.ReviewedFrom, report.Transition.CurrentChartManifestDigest, report.Transition.ReviewedTo, report.Transition.TargetChartManifestDigest)
	fmt.Fprintf(w, "schema validation: %s\nassumption: %s\n", report.Policy.SchemaValidation, report.Transition.IdentityAssumption)
	if len(report.Sources) > 2 {
		fmt.Fprintf(w, "source: %s\n", report.Sources[2].URL)
	}
	fmt.Fprintf(w, "scope: %s\nremediation: %s\naggregate: UNKNOWN; full target Helm schema validation remains outstanding\n", report.Scope, report.Claim.Remediation)
}

func (r runtime) prometheus(ctx context.Context, args []string, legacy bool) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check prometheus-mode --demo [--format human|json]\n   or: prufyx check prometheus-mode --observation-root DIR --proposed-workload FILE --proposed-digest SHA256 --captured-at RFC3339 --now RFC3339 --max-age DURATION [--format human|json]")
		return ExitOK
	}
	fs := flag.NewFlagSet("check prometheus-mode", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	demo := fs.Bool("demo", false, "run embedded synthetic fixtures")
	format := fs.String("format", "human", "human or json")
	observationPath := fs.String("observation-root", "", "sanitized observation root")
	proposedPath := fs.String("proposed-workload", "", "proposed workload JSON")
	proposedPin := fs.String("proposed-digest", "", "proposed input SHA-256")
	capturedText := fs.String("captured-at", "", "UTC capture time")
	nowText := fs.String("now", "", "UTC evaluation time")
	maxAgeText := fs.String("max-age", "", "maximum age")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || (*format != "human" && *format != "json") {
		return r.usage("invalid prometheus-mode arguments; use --help")
	}
	if legacy && (flagProvided(args, "format") || flagProvided(args, "demo")) {
		return r.usage("legacy validate-prometheus-mode does not accept new check flags")
	}
	if *demo {
		if legacy || *observationPath != "" || *proposedPath != "" || *proposedPin != "" || *capturedText != "" || *nowText != "" || *maxAgeText != "" {
			return r.usage("--demo cannot be combined with observation flags or the legacy alias")
		}
		report, err := prometheusmode.BuildDemoReport()
		if err != nil {
			return r.fail("embedded demo integrity failure", ExitIntegrity)
		}
		if *format == "json" {
			raw, _ := json.Marshal(report)
			fmt.Fprintln(r.stdout, string(raw))
		} else {
			fmt.Fprintln(r.stdout, "Prometheus mode synthetic demo: aggregate UNKNOWN")
			for _, c := range report.Cases {
				fmt.Fprintf(r.stdout, "%s: %s (%s)\n", c.ID, c.Claim.Status, c.Claim.ReasonCode)
			}
		}
		return ExitUnknown
	}
	if *observationPath == "" || *proposedPath == "" || *proposedPin == "" || *capturedText == "" || *nowText == "" || *maxAgeText == "" {
		return r.usage("all Prometheus observation flags are required")
	}
	if legacy && (!filepath.IsAbs(*observationPath) || !filepath.IsAbs(*proposedPath)) {
		return r.usage("legacy validate-prometheus-mode requires absolute input paths")
	}
	captured, err1 := parseUTC(*capturedText)
	now, err2 := parseUTC(*nowText)
	maxAge, err3 := time.ParseDuration(*maxAgeText)
	if err1 != nil || err2 != nil || captured.After(now) || err3 != nil || maxAge <= 0 || maxAge > 30*24*time.Hour || maxAge%time.Second != 0 {
		return r.usage("times must be explicit UTC and max-age must be whole seconds up to 30 days")
	}
	proposed, err := prometheusmode.ReadProposedArtifact(*proposedPath, *proposedPin)
	if err != nil {
		if !legacy && (errors.Is(err, prometheusmode.ErrInvalid) || errors.Is(err, prometheusmode.ErrIO)) {
			return r.fail("proposed workload failed local verification", ExitUsage)
		}
		return r.fail("proposed workload failed local verification", ExitIntegrity)
	}
	root, err := openObservationRoot(*observationPath)
	if err != nil {
		if errors.Is(err, observation.ErrUnsupportedPlatform) {
			return r.fail("real observation is not supported on this platform", ExitUsage)
		}
		return r.fail("observation root failed admission", ExitUsage)
	}
	defer root.Close()
	artifact, err := currentbundle.BuildObservation(ctx, root, currentbundle.Options{CapturedAt: captured, Now: now, RequireSourceCapture: true, FreshnessPolicy: currentbundle.FreshnessPolicy{ID: "community-prometheus-mode-explicit-age-v1", MaxAge: maxAge}})
	if err != nil {
		return r.fail("observation verification failed", ExitIntegrity)
	}
	current, err := currentbundle.IssueVerifiedArtifact(artifact)
	if err != nil {
		return r.fail("current artifact admission failed", ExitIntegrity)
	}
	report, err := prometheusmode.Evaluate(prometheusmode.Request{Current: current, Proposed: proposed, Now: now})
	if err != nil {
		return r.fail("Prometheus evaluation failed", ExitIntegrity)
	}
	raw, err := prometheusmode.MarshalReport(report)
	if err != nil {
		return r.fail("Prometheus report encoding failed", ExitIntegrity)
	}
	if legacy {
		return r.writeEnvelope(envelope{SchemaVersion: "prufyx.io/community-prometheus-mode/v1alpha1", Command: "community-preview", Result: envelopeResult{Status: "OK", Decision: "UNKNOWN", Scope: "declared Prometheus operating-mode preservation for reviewed builds; not whole-upgrade or runtime authority", Reason: "prometheus_mode_assessed"}, Data: json.RawMessage(raw)}, ExitUnknown)
	}
	if *format == "json" {
		fmt.Fprintln(r.stdout, string(raw))
	} else {
		fmt.Fprintf(r.stdout, "Prometheus agent-mode preservation: %s (%s)\naggregate: UNKNOWN\nnext action: %s\n", report.Claim.Status, report.Claim.ReasonCode, report.Claim.NextAction)
	}
	if report.Claim.Status == "PASS" {
		return ExitOK
	}
	return ExitUnknown
}

func (r runtime) legacyPrometheusDemo(args []string) int {
	if len(args) != 0 {
		return r.usage("Usage: prufyx community-preview demo-prometheus-mode")
	}
	report, err := prometheusmode.BuildDemoReport()
	if err != nil {
		return r.fail("Prometheus mode demo inputs failed verification", ExitIntegrity)
	}
	return r.writeEnvelope(envelope{SchemaVersion: prometheusmode.DemoAPIVersion, Command: "community-preview", Result: envelopeResult{Status: "OK", Decision: "UNKNOWN", Scope: "synthetic declared Prometheus mode demonstration; no actual observation or compatibility authority", Reason: "prometheus_mode_synthetic_demo_completed", Messages: []string{"All cases use embedded synthetic current facts and preauthored proposed vectors; aggregate remains UNKNOWN."}}, Data: report}, ExitUnknown)
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("not UTC")
	}
	return parsed, nil
}
func duplicateFlags(args []string) bool {
	seen := map[string]bool{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if seen[name] {
			return true
		}
		seen[name] = true
	}
	return false
}
func flagProvided(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, ok := optionName(arg)
		if ok && name == wanted {
			return true
		}
	}
	return false
}

// optionName recognizes only one- or two-dash Go flag spellings. A positional
// value must not become a selector simply because it has the same text.
func optionName(arg string) (string, bool) {
	if len(arg) < 2 || arg[0] != '-' || arg == "-" {
		return "", false
	}
	trimmed := ""
	if strings.HasPrefix(arg, "--") {
		if len(arg) == 2 || strings.HasPrefix(arg, "---") {
			return "", false
		}
		trimmed = arg[2:]
	} else {
		trimmed = arg[1:]
	}
	name := strings.SplitN(trimmed, "=", 2)[0]
	return name, name != ""
}
func hasHelp(args []string) bool {
	for _, arg := range args {
		if help(arg) {
			return true
		}
	}
	return false
}
func help(arg string) bool                 { return arg == "-h" || arg == "--help" || arg == "help" }
func (r runtime) usage(message string) int { return r.fail(message, ExitUsage) }
func (r runtime) fail(message string, code int) int {
	fmt.Fprintf(r.stderr, "prufyx: %s\n", message)
	return code
}
func (r runtime) packageError(message string, err error) int {
	if errors.Is(err, certmanagervalues.ErrIntegrity) {
		return r.fail(message, ExitIntegrity)
	}
	return r.fail(message, ExitUsage)
}
func (r runtime) writeEnvelope(value envelope, code int) int {
	encoder := json.NewEncoder(r.stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return ExitIntegrity
	}
	return code
}
