// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgecheck"
)

type externalCertRequest struct {
	knowledgeDB, knowledgeRevision, knowledgeBundleDigest, knowledgeTrustReceiptDigest string
	values, valuesDigest, from, to, currentDigest, targetDigest                        string
	schemaValidation, replay, format                                                   string
}

func (r runtime) database(ctx context.Context, args []string) int {
	if len(args) == 0 || help(args[0]) {
		fmt.Fprintln(r.stdout, `Usage:
  prufyx db verify FILE --profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup --bootstrap-root FILE --bootstrap-root-digest SHA256 [--expected-package-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db import FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db update --source HTTPS_URL --package-out FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db status --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--format human|json]
  prufyx db capabilities --profile cncf [--format human|json]

Verify, import and status are offline. Verify requires an independently trusted
bootstrap root and does not inspect a store or establish import eligibility.
Only explicit update fetches a complete package;
no configuration or report is uploaded. The default profile is cert-manager. Use a
separate private directory for each marked profile.
Profiles cannot share trust, selection or rollback state. This source capability
accepts operator-provisioned roots and reports synthetic test knowledge explicitly.`)
		return ExitOK
	}
	switch args[0] {
	case "verify":
		return r.databaseVerify(args[1:])
	case "import":
		return r.databaseImport(args[1:])
	case "update":
		return r.databaseUpdate(ctx, args[1:])
	case "status":
		return r.databaseStatus(args[1:])
	case "capabilities":
		return r.databaseCapabilities(args[1:])
	default:
		return r.usage("unknown database command; use prufyx db --help")
	}
}

func (r runtime) databaseVerify(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx db verify FILE --profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup --bootstrap-root FILE --bootstrap-root-digest SHA256 [--expected-package-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]")
		return ExitOK
	}
	packagePath := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		packagePath = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("db verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "cert-manager", "cert-manager, cncf, cncf-projects, spiffe-x509-svid, cloudevents-structured-json, or tikv-gcp-v2-wif-backup")
	bootstrapRoot := fs.String("bootstrap-root", "", "independently trusted operator-provisioned TUF root")
	bootstrapRootDigest := fs.String("bootstrap-root-digest", "", "exact trusted root SHA-256")
	expectedPackageDigest := fs.String("expected-package-digest", "", "optional exact package SHA-256 assertion")
	expectedRevision := fs.String("expected-revision", "", "optional exact semantic revision assertion")
	expectedBundleDigest := fs.String("expected-bundle-digest", "", "optional exact bundle SHA-256 assertion")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || !validKnowledgeProfile(*profile) || (*format != "human" && *format != "json") {
		return r.usage("invalid database verify arguments; use --help")
	}
	if packagePath == "" && fs.NArg() == 1 {
		packagePath = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return r.usage("database verify requires exactly one package file")
	}
	if packagePath == "" || *bootstrapRoot == "" || *bootstrapRootDigest == "" {
		return r.usage("database verify requires one package and an explicit bootstrap-root path and digest")
	}
	req := knowledge.VerifyRequest{
		PackagePath: packagePath, BootstrapRootPath: *bootstrapRoot, BootstrapRootDigest: *bootstrapRootDigest,
		ExpectedPackageDigest: *expectedPackageDigest, ExpectedRevision: *expectedRevision, ExpectedBundleDigest: *expectedBundleDigest,
	}
	var receipt knowledge.PackageVerificationReceipt
	var err error
	if *profile == "cncf" {
		receipt, err = knowledge.VerifyConstraints(req)
	} else if *profile == "cncf-projects" {
		receipt, err = knowledge.VerifyConstraintsProjects(req)
	} else if *profile == "spiffe-x509-svid" {
		receipt, err = knowledge.VerifySPIFFEX509SVID(req)
	} else if *profile == "cloudevents-structured-json" {
		receipt, err = knowledge.VerifyCloudEventsStructuredJSON(req)
	} else if *profile == "tikv-gcp-v2-wif-backup" {
		receipt, err = knowledge.VerifyTiKVGCPV2WIFBackup(req)
	} else {
		receipt, err = knowledge.Verify(req, knowledgecheck.AdmitBundle)
	}
	if err != nil {
		return r.knowledgeError("knowledge package verification failed", err)
	}
	if *format == "json" {
		return r.writeJSON(receipt, ExitOK)
	}
	fmt.Fprintf(r.stdout, "knowledge package verification: %s\nprofile: %s\nrevision: %s\npurpose: %s\ntrust source: %s\ninitial root digest: %s\npackage digest: %s\ntarget: %s\nbundle digest: %s\nnetwork used: false\nstore used: false\nstore changed: false\nrollback against store checked: false\nimport eligibility: NOT_EVALUATED\n", receipt.Status, receipt.Profile, receipt.KnowledgeRevision, receipt.Purpose, receipt.TrustSource, receipt.InitialRootDigest, receipt.PackageDigest, receipt.TargetPath, receipt.TargetDigest)
	for _, project := range receipt.ProjectTargets {
		fmt.Fprintf(r.stdout, "project target: %s revision %s length %d digest %s\n", project.TargetPath, project.Revision, project.Length, project.Digest)
	}
	if receipt.Purpose == "synthetic_test_only" {
		fmt.Fprintln(r.stdout, "authority: synthetic test knowledge only; no official Prufyx trust root or compatibility proof")
	}
	return ExitOK
}

func (r runtime) databaseImport(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx db import FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]")
		return ExitOK
	}
	packagePath := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		packagePath = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("db import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbRoot := fs.String("db-root", "", "private knowledge store root")
	profile := fs.String("profile", "cert-manager", "cert-manager, cncf, cncf-projects, spiffe-x509-svid, cloudevents-structured-json, or tikv-gcp-v2-wif-backup in separate directories")
	bootstrapRoot := fs.String("bootstrap-root", "", "initial operator-provisioned TUF root")
	bootstrapRootDigest := fs.String("bootstrap-root-digest", "", "exact initial root SHA-256")
	expectedRevision := fs.String("expected-revision", "", "optional exact semantic revision assertion")
	expectedBundleDigest := fs.String("expected-bundle-digest", "", "optional exact bundle SHA-256 assertion")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || *dbRoot == "" || !validKnowledgeProfile(*profile) || (*format != "human" && *format != "json") {
		return r.usage("invalid database import arguments; use --help")
	}
	if packagePath == "" && fs.NArg() == 1 {
		packagePath = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return r.usage("database import requires exactly one package file")
	}
	if packagePath == "" || (*bootstrapRoot == "") != (*bootstrapRootDigest == "") {
		return r.usage("database import requires one package and a complete optional bootstrap-root pair")
	}
	req := knowledge.ImportRequest{
		PackagePath: packagePath, StoreRoot: *dbRoot,
		BootstrapRootPath: *bootstrapRoot, BootstrapRootDigest: *bootstrapRootDigest,
		ExpectedRevision: *expectedRevision, ExpectedBundleDigest: *expectedBundleDigest,
	}
	var receipt knowledge.ImportReceipt
	var err error
	if *profile == "cncf" {
		receipt, err = knowledge.ImportConstraints(req)
	} else if *profile == "cncf-projects" {
		receipt, err = knowledge.ImportConstraintsProjects(req)
	} else if *profile == "spiffe-x509-svid" {
		receipt, err = knowledge.ImportSPIFFEX509SVID(req)
	} else if *profile == "cloudevents-structured-json" {
		receipt, err = knowledge.ImportCloudEventsStructuredJSON(req)
	} else if *profile == "tikv-gcp-v2-wif-backup" {
		receipt, err = knowledge.ImportTiKVGCPV2WIFBackup(req)
	} else {
		receipt, err = knowledge.Import(req, knowledgecheck.AdmitBundle)
	}
	if err != nil {
		if receipt.APIVersion != "" {
			return r.databaseImportRejectedForProfile(receipt, err, *format, *profile)
		}
		return r.knowledgeError("knowledge package import failed", err)
	}
	if *format == "json" {
		return r.writeJSON(receipt, ExitOK)
	}
	if *profile == "cncf" || *profile == "cncf-projects" || *profile == "spiffe-x509-svid" || *profile == "cloudevents-structured-json" || *profile == "tikv-gcp-v2-wif-backup" {
		var output bytes.Buffer
		fmt.Fprintf(&output, "%s knowledge import: %s\nrevision: %s\npurpose: %s\ntrust source: %s\ntarget: %s\nbundle digest: %s\ntrust receipt digest: %s\nnetwork used: false\n", *profile, receipt.Status, receipt.TrustReceipt.KnowledgeRevision, receipt.TrustReceipt.Purpose, receipt.TrustReceipt.TrustSource, receipt.TrustReceipt.TargetPath, receipt.TrustReceipt.TargetDigest, receipt.TrustReceiptDigest)
		if len(receipt.ProjectTargets) > 0 {
			fmt.Fprintf(&output, "project targets: %d\n", len(receipt.ProjectTargets))
		}
		if receipt.TrustReceipt.Purpose == "synthetic_test_only" {
			fmt.Fprintln(&output, "authority: synthetic test knowledge only; no official Prufyx trust root or compatibility proof")
		}
		if _, err := r.stdout.Write(output.Bytes()); err != nil {
			return ExitIntegrity
		}
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "knowledge import: %s\nrevision: %s\npurpose: %s\ntrust source: %s\nbundle digest: %s\ntrust receipt digest: %s\nnetwork used: false\n", receipt.Status, receipt.TrustReceipt.KnowledgeRevision, receipt.TrustReceipt.Purpose, receipt.TrustReceipt.TrustSource, receipt.TrustReceipt.TargetDigest, receipt.TrustReceiptDigest)
	if receipt.TrustReceipt.Purpose == "synthetic_test_only" {
		fmt.Fprintln(r.stdout, "authority: synthetic test knowledge only; no official Prufyx trust root or upstream compatibility authority")
	}
	return ExitOK
}

func (r runtime) databaseStatus(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx db status --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--format human|json]")
		return ExitOK
	}
	fs := flag.NewFlagSet("db status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbRoot := fs.String("db-root", "", "private knowledge store root")
	profile := fs.String("profile", "cert-manager", "cert-manager, cncf, cncf-projects, spiffe-x509-svid, cloudevents-structured-json, or tikv-gcp-v2-wif-backup in separate directories")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *dbRoot == "" || !validKnowledgeProfile(*profile) || (*format != "human" && *format != "json") {
		return r.usage("invalid database status arguments; use --help")
	}
	var status knowledge.Status
	var err error
	if *profile == "cncf" {
		status, err = knowledge.InspectConstraints(*dbRoot)
	} else if *profile == "cncf-projects" {
		status, err = knowledge.InspectConstraintsProjects(*dbRoot)
	} else if *profile == "spiffe-x509-svid" {
		status, err = knowledge.InspectSPIFFEX509SVID(*dbRoot)
	} else if *profile == "cloudevents-structured-json" {
		status, err = knowledge.InspectCloudEventsStructuredJSON(*dbRoot)
	} else if *profile == "tikv-gcp-v2-wif-backup" {
		status, err = knowledge.InspectTiKVGCPV2WIFBackup(*dbRoot)
	} else {
		status, err = knowledge.Inspect(*dbRoot)
	}
	if err != nil {
		if errors.Is(err, knowledge.ErrNoSelection) {
			return r.fail("no verified knowledge database is selected", ExitUnknown)
		}
		return r.knowledgeError("knowledge database status failed", err)
	}
	if *format == "json" {
		return r.writeJSON(status, databaseStatusExit(status))
	}
	if *profile == "cncf" || *profile == "cncf-projects" || *profile == "spiffe-x509-svid" || *profile == "cloudevents-structured-json" || *profile == "tikv-gcp-v2-wif-backup" {
		var output bytes.Buffer
		fmt.Fprintf(&output, "knowledge profile: %s\n", *profile)
		writeKnowledgeStatusHuman(&output, status)
		if status.Purpose == "synthetic_test_only" {
			fmt.Fprintln(&output, "authority: synthetic test knowledge only; no official Prufyx trust root or compatibility proof")
		}
		if _, err := r.stdout.Write(output.Bytes()); err != nil {
			return ExitIntegrity
		}
		return databaseStatusExit(status)
	}
	writeKnowledgeStatusHuman(r.stdout, status)
	if status.Purpose == "synthetic_test_only" {
		fmt.Fprintln(r.stdout, "authority: synthetic test knowledge only; no official Prufyx trust root or upstream compatibility authority")
	}
	return databaseStatusExit(status)
}

func validKnowledgeProfile(profile string) bool {
	return profile == "cert-manager" || profile == "cncf" || profile == "cncf-projects" || profile == "spiffe-x509-svid" || profile == "cloudevents-structured-json" || profile == "tikv-gcp-v2-wif-backup"
}

func writeKnowledgeStatusHuman(w io.Writer, status knowledge.Status) {
	trustFreshness := status.TrustFreshness
	if trustFreshness == "" {
		trustFreshness = status.Freshness
	}
	fmt.Fprintf(w, "knowledge database state: %s\nreason: %s\nnext action: %s\nfreshness: %s\ntrust freshness: %s\nsource evidence freshness: %s\nsource evidence earliest expiry: %s\nchecked at: %s\ntrust source: %s\npurpose: %s\nselected revision: %s\nbundle digest: %s\ntrust receipt digest: %s\ncurrent eligible: %t\ncurrent non-revocation: %s\nnetwork used: false\nreadiness scope: selected-store integrity only; individual rules may remain UNKNOWN\n", status.State, status.Reason, status.NextAction, status.Freshness, trustFreshness, status.SourceEvidenceFreshness, status.SourceEvidenceExpiresAt, status.CheckedAt, status.TrustSource, status.Purpose, status.SelectedRevision, status.SelectedBundleDigest, status.TrustReceiptDigest, status.CurrentEligible, status.CurrentNonRevocation)
}

func databaseStatusExit(status knowledge.Status) int {
	if status.State == "INTEGRITY_FAILURE" {
		return ExitIntegrity
	}
	if !status.CurrentEligible {
		return ExitUnknown
	}
	return ExitOK
}

type rejectedImportOutput struct {
	APIVersion         string `json:"apiVersion"`
	Status             string `json:"status"`
	TrustStateAdvanced bool   `json:"trustStateAdvanced"`
	SelectionChanged   bool   `json:"selectionChanged"`
	TrustStateDigest   string `json:"trustStateDigest"`
	ReasonCode         string `json:"reasonCode"`
	NextAction         string `json:"nextAction"`
}

func (r runtime) databaseImportRejected(receipt knowledge.ImportReceipt, err error, format string) int {
	return r.databaseImportRejectedForProfile(receipt, err, format, "cert-manager")
}

func (r runtime) databaseImportRejectedForProfile(receipt knowledge.ImportReceipt, err error, format, profile string) int {
	output := rejectedKnowledgeImport(receipt, err, profile)
	if format == "json" {
		return r.writeJSON(output, ExitIntegrity)
	}
	_, writeErr := fmt.Fprintf(r.stdout, "knowledge import: %s\ntrust state advanced: %t\nselection changed: %t\ntrust state digest: %s\nreason: %s\nnext action: %s\n", output.Status, output.TrustStateAdvanced, output.SelectionChanged, output.TrustStateDigest, output.ReasonCode, output.NextAction)
	if writeErr != nil {
		return ExitIntegrity
	}
	return ExitIntegrity
}

func rejectedKnowledgeImport(receipt knowledge.ImportReceipt, err error, profile string) rejectedImportOutput {
	reason := "KNOWLEDGE_PACKAGE_REJECTED_AFTER_TRUST_VERIFICATION"
	nextAction := "inspect prufyx db status, correct the package, and retry without bootstrap flags when trust state was established"
	if errors.Is(err, knowledge.ErrRecoveryRequired) {
		reason = "KNOWLEDGE_IMPORT_RECOVERY_REQUIRED"
		nextAction = "retry the exact original signed package with the same expected revision, bundle digest, and original bootstrap arguments, if any"
	} else if errors.Is(err, knowledge.ErrExpired) {
		reason = "KNOWLEDGE_TRUST_METADATA_EXPIRED"
	}
	if profile == "cncf" || profile == "cncf-projects" || profile == "spiffe-x509-svid" || profile == "cloudevents-structured-json" || profile == "tikv-gcp-v2-wif-backup" {
		nextAction = strings.ReplaceAll(nextAction, "prufyx db status", "prufyx db status --profile "+profile)
		if errors.Is(err, knowledge.ErrRecoveryRequired) {
			nextAction += "; retain --profile " + profile + " and the same separate store directory"
		}
	}
	return rejectedImportOutput{
		APIVersion: "prufyx.io/knowledge-import-failure/v1", Status: receipt.Status,
		TrustStateAdvanced: receipt.TrustStateAdvanced, SelectionChanged: receipt.SelectionChanged,
		TrustStateDigest: receipt.TrustStateDigest, ReasonCode: reason, NextAction: nextAction,
	}
}

func (r runtime) externalCertManager(args externalCertRequest) int {
	req := knowledgecheck.Request{
		Selection: knowledge.SelectionRequest{
			StoreRoot: args.knowledgeDB, ExpectedRevision: args.knowledgeRevision,
			ExpectedBundleDigest:       args.knowledgeBundleDigest,
			ExpectedTrustReceiptDigest: args.knowledgeTrustReceiptDigest,
		},
		ValuesPath: args.values, ValuesDigest: args.valuesDigest,
		From: args.from, To: args.to, CurrentChartDigest: args.currentDigest,
		TargetChartDigest: args.targetDigest, SchemaValidation: args.schemaValidation,
	}
	if args.replay != "" {
		receipt, err := currentbundle.ReadBoundedFile(args.replay, 1<<20)
		if err != nil {
			if errors.Is(err, currentbundle.ErrIntegrity) {
				return r.fail("historical replay receipt identity changed", ExitIntegrity)
			}
			return r.fail("historical replay receipt failed admission", ExitUsage)
		}
		replay, err := knowledgecheck.ReplayHistorical(req, receipt)
		if err != nil {
			return r.knowledgeError("historical external knowledge replay failed", err)
		}
		raw, err := knowledgecheck.MarshalHistoricalReplay(replay)
		if err != nil {
			return r.fail("historical replay encoding failed", ExitIntegrity)
		}
		if args.format == "json" {
			fmt.Fprintln(r.stdout, string(raw))
		} else {
			fmt.Fprintf(r.stdout, "historical external knowledge replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\n", replay.OriginalReportDigest)
		}
		return certClaimExit(knowledgecheck.HistoricalClaimStatus(replay))
	}

	report, err := knowledgecheck.EvaluateCurrent(req)
	if err != nil {
		return r.knowledgeError("external cert-manager values check failed", err)
	}
	raw, err := knowledgecheck.MarshalReport(report)
	if err != nil {
		return r.fail("external report encoding failed", ExitIntegrity)
	}
	if args.format == "json" {
		fmt.Fprintln(r.stdout, string(raw))
	} else {
		writeExternalCertHuman(r.stdout, report)
	}
	return certClaimExit(knowledgecheck.ClaimStatus(report))
}

func writeExternalCertHuman(w io.Writer, report knowledgecheck.Report) {
	fmt.Fprintf(w, "cert-manager removed monitor values: %s\n", report.Check.Claim.Status)
	fmt.Fprintf(w, "claim: %s\nreason: %s\n", report.Check.Claim.ReasonCode, report.Check.Claim.Reason)
	if len(report.Check.MatchedPaths) > 0 {
		fmt.Fprintf(w, "matched curated paths: %s\n", strings.Join(report.Check.MatchedPaths, ", "))
	}
	fmt.Fprintf(w, "values digest: %s\nknowledge origin: external\nknowledge revision: %s\nknowledge purpose: %s\nbundle digest: %s\ntrust source: %s\ntrust receipt digest: %s\nevidence freshness: %s\ncurrent non-revocation: %s\n", report.Check.Inputs.ValuesDigest, report.Knowledge.Revision, report.Knowledge.Purpose, report.Knowledge.BundleDigest, report.Knowledge.TrustSource, report.Knowledge.TrustReceiptDigest, report.Knowledge.EvidenceFreshness, report.Knowledge.CurrentNonRevocation)
	if report.Knowledge.Purpose == "synthetic_test_only" {
		fmt.Fprintln(w, "authority: synthetic test knowledge only; no official Prufyx trust root or upstream compatibility authority")
	}
	fmt.Fprintf(w, "scope: %s\nremediation: %s\naggregate: UNKNOWN; full target Helm schema validation remains outstanding\n", report.Check.Scope, report.Check.Claim.Remediation)
}

func certClaimExit(status string) int {
	switch status {
	case "PASS":
		return ExitOK
	case "BLOCKED":
		return ExitBlocked
	default:
		return ExitUnknown
	}
}

func (r runtime) knowledgeError(message string, err error) int {
	if errors.Is(err, knowledge.ErrLayout) {
		return r.fail(message+"; "+knowledgeLayoutNextAction, ExitUsage)
	}
	if errors.Is(err, knowledge.ErrRecoveryRequired) {
		return r.fail(message+"; recovery required: retry the exact original signed package with its original assertions and bootstrap arguments", ExitIntegrity)
	}
	if errors.Is(err, knowledge.ErrInvalid) || errors.Is(err, certmanagervalues.ErrInvalid) {
		return r.fail(message, ExitUsage)
	}
	return r.fail(message, ExitIntegrity)
}

func (r runtime) writeJSON(value any, code int) int {
	encoder := json.NewEncoder(r.stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return ExitIntegrity
	}
	return code
}

// knowledgeLayoutNextAction explains a CNCF layout mismatch between a
// package or store and the selected profile. Nothing was imported.
const knowledgeLayoutNextAction = "the package or store uses the other CNCF knowledge layout: use --profile cncf-projects for per-project packages and --profile cncf for single-target packages, each with its own store directory; nothing was imported and the selection did not change"
