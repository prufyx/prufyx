// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/tikvgcpv2"
	"github.com/prufyx/prufyx/cli/internal/tikvgcpv2knowledge"
)

var tikvDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (r runtime) tikvGCPV2WIFBackup(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --now RFC3339 [--config-digest SHA256] [--format human|json]\n   or: prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --knowledge-db DIR [--knowledge-revision REVISION] [--knowledge-bundle-digest SHA256] [--knowledge-trust-receipt-digest SHA256] [--config-digest SHA256] [--format human|json]\n   replay adds --replay-report FILE and requires --config-digest; external replay also requires all three knowledge pins")
		return ExitOK
	}
	fs := flag.NewFlagSet("check tikv-gcp-v2-wif-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "private local TiKV TOML configuration")
	targetVersion := fs.String("target-version", "", "caller-declared target TiKV version")
	operation := fs.String("operation", "", "caller-declared planned operation")
	configDigest := fs.String("config-digest", "", "optional current, mandatory replay, exact raw configuration SHA-256")
	nowText := fs.String("now", "", "explicit embedded evaluation time")
	knowledgeDB := fs.String("knowledge-db", "", "explicit isolated verified local TiKV preflight profile store")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional current or mandatory historical revision assertion")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional current or mandatory historical bundle assertion")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional current or mandatory historical trust receipt assertion")
	replayPath := fs.String("replay-report", "", "prior canonical target-preflight report")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *config == "" || *targetVersion == "" || *operation == "" || (*format != "human" && *format != "json") || (*configDigest != "" && !tikvDigestRE.MatchString(*configDigest)) || (*knowledgeBundleDigest != "" && !tikvDigestRE.MatchString(*knowledgeBundleDigest)) || (*knowledgeTrustReceiptDigest != "" && !tikvDigestRE.MatchString(*knowledgeTrustReceiptDigest)) {
		return r.usage("invalid tikv-gcp-v2-wif-backup arguments; use --help")
	}
	external := *knowledgeDB != ""
	replay := *replayPath != ""
	anyKnowledge := *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != ""
	allKnowledge := *knowledgeRevision != "" && *knowledgeBundleDigest != "" && *knowledgeTrustReceiptDigest != ""
	if (!external && anyKnowledge) || (external && *nowText != "") || (!external && !replay && *nowText == "") || (!external && replay && *nowText != "") || (replay && *configDigest == "") || (external && replay && !allKnowledge) {
		return r.usage("invalid current/replay knowledge mode; use tikv-gcp-v2-wif-backup --help")
	}
	var now time.Time
	if !external && !replay {
		parsed, err := parseUTC(*nowText)
		if err != nil {
			return r.usage("--now must be canonical whole-second UTC RFC3339")
		}
		now = parsed
	}
	raw, err := readCNCFPrivate(*config, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("configuration input failed private local admission", err), ExitUsage)
	}
	rawDigest := digestCommunityBytes(raw)
	if *configDigest != "" && *configDigest != rawDigest {
		return r.fail("config digest assertion failed", ExitIntegrity)
	}
	observation, err := tikvgcpv2.Prepare(raw, *targetVersion, *operation)
	if err != nil {
		return r.fail("TiKV configuration, target version, or operation failed bounded input admission", ExitUsage)
	}
	selection := knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
	if replay {
		expected, readErr := readCNCFPrivate(*replayPath, 4<<20)
		if readErr != nil {
			return r.fail(withPermissionHint("replay report failed private local admission", readErr), ExitUsage)
		}
		var result tikvgcpv2knowledge.HistoricalReplay
		if external {
			result, err = tikvgcpv2knowledge.ReplayHistorical(tikvgcpv2knowledge.Request{Selection: selection, Observation: observation}, expected)
		} else {
			result, err = tikvgcpv2knowledge.ReplayEmbedded(observation, expected)
		}
		if err != nil {
			return r.tikvKnowledgeError("TiKV GCP v2 WIF full-backup historical replay failed", err)
		}
		encoded, marshalErr := tikvgcpv2knowledge.MarshalHistoricalReplay(result)
		if marshalErr != nil {
			return r.fail("TiKV GCP v2 WIF full-backup replay integrity failure", ExitIntegrity)
		}
		if *format == "json" {
			_, err = r.stdout.Write(encoded)
		} else {
			_, err = fmt.Fprintf(r.stdout, "TiKV GCP v2 WIF full-backup historical replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nraw configuration digest: verified separately for this replay and excluded from report\naggregate backup readiness: UNKNOWN\n", result.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return tikvgcpv2knowledge.HistoricalClaimExit(result)
	}
	var report tikvgcpv2knowledge.Report
	if external {
		report, err = tikvgcpv2knowledge.EvaluateCurrent(tikvgcpv2knowledge.Request{Selection: selection, Observation: observation})
	} else {
		report, err = tikvgcpv2knowledge.EvaluateEmbedded(observation, now)
	}
	if err != nil {
		return r.tikvKnowledgeError("TiKV GCP v2 WIF full-backup preflight failed", err)
	}
	encoded, marshalErr := tikvgcpv2knowledge.MarshalReport(report)
	if marshalErr != nil {
		return r.fail("TiKV GCP v2 WIF full-backup report integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		_, err = r.stdout.Write(encoded)
	} else {
		err = writeTiKVHuman(r.stdout, report)
	}
	if err != nil {
		return ExitIntegrity
	}
	return tikvgcpv2knowledge.ClaimExit(report)
}

func writeTiKVHuman(out io.Writer, report tikvgcpv2knowledge.Report) error {
	o, c := report.Check.Observation, report.Check.Claim
	setting := "unavailable"
	if o.BackupGCPV2Enable != nil {
		setting = fmt.Sprint(*o.BackupGCPV2Enable)
	}
	trustReceipt := ""
	if report.Knowledge.TrustReceiptDigest != "" {
		trustReceipt = "knowledge trust receipt digest: " + report.Knowledge.TrustReceiptDigest + "\n"
	}
	sources := make([]string, 0, len(report.Knowledge.NormativeSources))
	for _, source := range report.Knowledge.NormativeSources {
		sources = append(sources, fmt.Sprintf("%s %s/blob/%s/%s lines %s", source.Role, source.RepositoryURL, source.Commit, source.Path, formatTiKVSpans(source.Spans)))
	}
	_, err := fmt.Fprintf(out, "TiKV 8.5.8 GCS WIF full-backup planned-operation preflight\nscoped result: %s (%s)\nreason: %s\nnext action: %s\ntarget version class: %s\nreviewed operation declared: %t\nexplicit backup GCP v2 setting: %s\nprepared observation digest: %s\nknowledge: %s revision %s\nknowledge purpose: %s\nknowledge bundle digest: %s\n%sevaluated at: %s\nnormative sources: %s\nraw configuration identity: optionally pinned for current checks and required separately for replay; excluded from this report\ninput handling: Prufyx reads but does not modify the config and does not print or store its raw bytes, file path, raw digest, unrelated keys, or unrelated values\nunchecked: %s\naggregate backup readiness: UNKNOWN; effective configuration, credentials, GCS access, backup execution/completion, restore, log backup, installation, startup, runtime behavior, and data safety remain unverified\n", c.Status, c.ReasonCode, c.Reason, c.Action, o.TargetVersionClass, o.PlannedGCSFullBackupWithWIF, setting, report.Check.PreparedObservationDigest, report.Knowledge.Origin, report.Knowledge.Revision, report.Knowledge.Purpose, report.Knowledge.BundleDigest, trustReceipt, report.Knowledge.EvaluatedAt, strings.Join(sources, "; "), strings.Join(report.Check.Unchecked, ", "))
	return err
}
func formatTiKVSpans(spans []tikvgcpv2.SourceSpan) string {
	parts := make([]string, len(spans))
	for i, s := range spans {
		parts[i] = fmt.Sprintf("%d-%d", s.StartLine, s.EndLine)
	}
	return strings.Join(parts, ",")
}
func (r runtime) tikvKnowledgeError(message string, err error) int {
	if errors.Is(err, knowledge.ErrInvalid) || errors.Is(err, tikvgcpv2knowledge.ErrInvalid) || errors.Is(err, currentbundle.ErrInvalid) {
		return r.fail(message, ExitUsage)
	}
	if errors.Is(err, knowledge.ErrNoSelection) {
		return r.fail("selected TiKV GCP v2 WIF full-backup profile has no verified knowledge revision; import one explicitly", ExitUnknown)
	}
	if errors.Is(err, knowledge.ErrExpired) {
		return r.fail("selected TiKV GCP v2 WIF full-backup knowledge metadata expired", ExitUnknown)
	}
	return r.fail(message, ExitIntegrity)
}
