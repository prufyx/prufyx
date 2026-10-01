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

	"github.com/prufyx/prufyx/cli/internal/cloudeventsjsonknowledge"
	"github.com/prufyx/prufyx/cli/internal/cloudeventsstructuredjson"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

var cloudEventsDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (r runtime) cloudEventsStructuredJSON(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check cloudevents-structured-json --event FILE --now RFC3339 [--event-digest SHA256] [--format human|json]\n   or: prufyx check cloudevents-structured-json --event FILE --knowledge-db DIR [--knowledge-revision REVISION] [--knowledge-bundle-digest SHA256] [--knowledge-trust-receipt-digest SHA256] [--event-digest SHA256] [--format human|json]\n   replay adds --replay-report FILE and requires --event-digest; external replay also requires all three knowledge pins")
		return ExitOK
	}
	fs := flag.NewFlagSet("check cloudevents-structured-json", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	event := fs.String("event", "", "private local structured-event JSON")
	eventDigest := fs.String("event-digest", "", "optional current, mandatory replay, exact raw event SHA-256")
	nowText := fs.String("now", "", "explicit embedded evaluation time")
	knowledgeDB := fs.String("knowledge-db", "", "explicit isolated verified local CloudEvents profile store")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional current or mandatory historical revision assertion")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional current or mandatory historical bundle assertion")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional current or mandatory historical trust receipt assertion")
	replayPath := fs.String("replay-report", "", "prior canonical conformance report")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *event == "" || (*format != "human" && *format != "json") || (*eventDigest != "" && !cloudEventsDigestRE.MatchString(*eventDigest)) || (*knowledgeBundleDigest != "" && !cloudEventsDigestRE.MatchString(*knowledgeBundleDigest)) || (*knowledgeTrustReceiptDigest != "" && !cloudEventsDigestRE.MatchString(*knowledgeTrustReceiptDigest)) {
		return r.usage("invalid cloudevents-structured-json arguments; use --help")
	}
	external := *knowledgeDB != ""
	replay := *replayPath != ""
	anyKnowledge := *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != ""
	allKnowledge := *knowledgeRevision != "" && *knowledgeBundleDigest != "" && *knowledgeTrustReceiptDigest != ""
	if (!external && anyKnowledge) || (external && *nowText != "") || (!external && !replay && *nowText == "") || (!external && replay && *nowText != "") || (replay && *eventDigest == "") || (external && replay && !allKnowledge) {
		return r.usage("invalid current/replay knowledge mode; use cloudevents-structured-json --help")
	}
	var now time.Time
	if !external && !replay {
		parsed, err := parseUTC(*nowText)
		if err != nil {
			return r.usage("--now must be canonical whole-second UTC RFC3339")
		}
		now = parsed
	}
	raw, err := readCNCFPrivate(*event, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("event input failed private local admission", err), ExitUsage)
	}
	rawDigest := digestCommunityBytes(raw)
	if *eventDigest != "" && *eventDigest != rawDigest {
		return r.fail("event digest assertion failed", ExitIntegrity)
	}
	observation, err := cloudeventsstructuredjson.Observe(raw)
	if err != nil {
		return r.fail("event input is not one admitted UTF-8 JSON document", ExitUsage)
	}
	selection := knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
	if replay {
		expected, readErr := readCNCFPrivate(*replayPath, 4<<20)
		if readErr != nil {
			return r.fail(withPermissionHint("replay report failed private local admission", readErr), ExitUsage)
		}
		var result cloudeventsjsonknowledge.HistoricalReplay
		if external {
			result, err = cloudeventsjsonknowledge.ReplayHistorical(cloudeventsjsonknowledge.Request{Selection: selection, Observation: observation}, expected)
		} else {
			result, err = cloudeventsjsonknowledge.ReplayEmbedded(observation, expected)
		}
		if err != nil {
			return r.cloudEventsKnowledgeError("CloudEvents structured JSON historical replay failed", err)
		}
		encoded, marshalErr := cloudeventsjsonknowledge.MarshalHistoricalReplay(result)
		if marshalErr != nil {
			return r.fail("CloudEvents structured JSON replay integrity failure", ExitIntegrity)
		}
		if *format == "json" {
			_, err = r.stdout.Write(encoded)
		} else {
			_, err = fmt.Fprintf(r.stdout, "CloudEvents structured JSON historical replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nraw event digest: verified separately for this replay and excluded from report\naggregate scope: named conformance subset only\n", result.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return cloudeventsjsonknowledge.HistoricalClaimExit(result)
	}
	var report cloudeventsjsonknowledge.Report
	if external {
		report, err = cloudeventsjsonknowledge.EvaluateCurrent(cloudeventsjsonknowledge.Request{Selection: selection, Observation: observation})
	} else {
		report, err = cloudeventsjsonknowledge.EvaluateEmbedded(observation, now)
	}
	if err != nil {
		return r.cloudEventsKnowledgeError("CloudEvents structured JSON conformance check failed", err)
	}
	encoded, marshalErr := cloudeventsjsonknowledge.MarshalReport(report)
	if marshalErr != nil {
		return r.fail("CloudEvents structured JSON report integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		_, err = r.stdout.Write(encoded)
	} else {
		err = writeCloudEventsHuman(r.stdout, report)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cloudeventsjsonknowledge.ClaimExit(report)
}

func writeCloudEventsHuman(out io.Writer, report cloudeventsjsonknowledge.Report) error {
	o, c := report.Check.Observation, report.Check.Claim
	value := func(v *bool) string {
		if v == nil {
			return "not evaluated"
		}
		return fmt.Sprint(*v)
	}
	text := func(v *string) string {
		if v == nil {
			return "not evaluated"
		}
		return *v
	}
	trustReceipt := ""
	if report.Knowledge.TrustReceiptDigest != "" {
		trustReceipt = "knowledge trust receipt digest: " + report.Knowledge.TrustReceiptDigest + "\n"
	}
	sources := make([]string, 0, len(report.Knowledge.NormativeSources))
	for _, source := range report.Knowledge.NormativeSources {
		sources = append(sources, fmt.Sprintf("%s %s/blob/%s/%s lines %s", source.Role, source.RepositoryURL, source.Commit, source.Path, formatCloudEventsSpans(source.Spans)))
	}
	_, err := fmt.Fprintf(out, "CloudEvents structured JSON core-envelope subset\nscoped result: %s (%s)\nreason: %s\nnext action: %s\nroot admission: %s\nedition admission: %s\nid valid nonempty String: %s\nsource admission: %s\ntype valid nonempty String: %s\ndata and data_base64 mutually exclusive: %s\nprepared observation digest: %s\nknowledge: %s revision %s\nknowledge purpose: %s\nknowledge bundle digest: %s\n%sevaluated at: %s\nnormative sources: %s\nraw event identity: optionally pinned for current checks and required separately for replay; excluded from this report\ninput handling: Prufyx reads but does not modify the event and does not print or store its raw bytes, file path, raw digest, member names, or member values\nunchecked: %s\naggregate scope: this named standards-conformance subset only; source URI semantics, payload, extensions, transport, SDK, signing, delivery, authentication, runtime behavior, and whole-event conformance remain UNKNOWN\n", c.Status, c.ReasonCode, c.Reason, c.Action, o.RootAdmission, text(o.EditionAdmission), value(o.IDIsNonemptyValidString), text(o.SourceAdmission), value(o.TypeIsNonemptyValidString), value(o.DataAndDataBase64NotBothPresent), report.Check.PreparedObservationDigest, report.Knowledge.Origin, report.Knowledge.Revision, report.Knowledge.Purpose, report.Knowledge.BundleDigest, trustReceipt, report.Knowledge.EvaluatedAt, strings.Join(sources, "; "), strings.Join(report.Check.Unchecked, ", "))
	return err
}
func formatCloudEventsSpans(spans []cloudeventsstructuredjson.SourceSpan) string {
	parts := make([]string, len(spans))
	for i, s := range spans {
		parts[i] = fmt.Sprintf("%d-%d", s.StartLine, s.EndLine)
	}
	return strings.Join(parts, ",")
}
func (r runtime) cloudEventsKnowledgeError(message string, err error) int {
	if errors.Is(err, knowledge.ErrInvalid) || errors.Is(err, cloudeventsjsonknowledge.ErrInvalid) || errors.Is(err, currentbundle.ErrInvalid) {
		return r.fail(message, ExitUsage)
	}
	if errors.Is(err, knowledge.ErrNoSelection) {
		return r.fail("selected CloudEvents structured JSON profile has no verified knowledge revision; import one explicitly", ExitUnknown)
	}
	if errors.Is(err, knowledge.ErrExpired) {
		return r.fail("selected CloudEvents structured JSON knowledge metadata expired", ExitUnknown)
	}
	return r.fail(message, ExitIntegrity)
}
