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
	"github.com/prufyx/prufyx/cli/internal/spiffex509knowledge"
	"github.com/prufyx/prufyx/cli/internal/spiffex509svid"
)

var spiffeDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (r runtime) spiffeX509SVID(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check spiffe-x509-svid --certificate FILE --now RFC3339 [--certificate-digest SHA256] [--format human|json]\n   or: prufyx check spiffe-x509-svid --certificate FILE --knowledge-db DIR [--knowledge-revision REVISION] [--knowledge-bundle-digest SHA256] [--knowledge-trust-receipt-digest SHA256] [--certificate-digest SHA256] [--format human|json]\n   replay adds --replay-report FILE and requires --certificate-digest; external replay also requires all three knowledge pins")
		return ExitOK
	}
	fs := flag.NewFlagSet("check spiffe-x509-svid", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	certificate := fs.String("certificate", "", "private local PEM or DER certificate")
	certificateDigest := fs.String("certificate-digest", "", "optional current, mandatory replay, exact raw certificate SHA-256")
	nowText := fs.String("now", "", "explicit embedded evaluation time")
	knowledgeDB := fs.String("knowledge-db", "", "explicit isolated verified local SPIFFE profile store")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional current or mandatory historical revision assertion")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional current or mandatory historical bundle assertion")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional current or mandatory historical trust receipt assertion")
	replayPath := fs.String("replay-report", "", "prior canonical conformance report")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *certificate == "" || (*format != "human" && *format != "json") || (*certificateDigest != "" && !spiffeDigestRE.MatchString(*certificateDigest)) || (*knowledgeBundleDigest != "" && !spiffeDigestRE.MatchString(*knowledgeBundleDigest)) || (*knowledgeTrustReceiptDigest != "" && !spiffeDigestRE.MatchString(*knowledgeTrustReceiptDigest)) {
		return r.usage("invalid spiffe-x509-svid arguments; use --help")
	}
	external := *knowledgeDB != ""
	replay := *replayPath != ""
	anyKnowledge := *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != ""
	allKnowledge := *knowledgeRevision != "" && *knowledgeBundleDigest != "" && *knowledgeTrustReceiptDigest != ""
	if (!external && anyKnowledge) || (external && *nowText != "") || (!external && !replay && *nowText == "") || (!external && replay && *nowText != "") || (replay && *certificateDigest == "") || (external && replay && !allKnowledge) {
		return r.usage("invalid current/replay knowledge mode; use spiffe-x509-svid --help")
	}
	var now time.Time
	if !external && !replay {
		parsed, err := parseUTC(*nowText)
		if err != nil {
			return r.usage("--now must be canonical whole-second UTC RFC3339")
		}
		now = parsed
	}
	raw, err := readCNCFPrivate(*certificate, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("certificate input failed private local admission", err), ExitUsage)
	}
	rawDigest := digestCommunityBytes(raw)
	if *certificateDigest != "" && *certificateDigest != rawDigest {
		return r.fail("certificate digest assertion failed", ExitIntegrity)
	}
	cert, err := spiffex509svid.ParseCertificate(raw)
	if err != nil {
		return r.fail("certificate input is not one exact DER certificate or one PEM CERTIFICATE block with only whitespace after it", ExitUsage)
	}
	observation := spiffex509svid.Observe(cert)
	selection := knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
	if replay {
		expected, readErr := readCNCFPrivate(*replayPath, 4<<20)
		if readErr != nil {
			return r.fail(withPermissionHint("replay report failed private local admission", readErr), ExitUsage)
		}
		var result spiffex509knowledge.HistoricalReplay
		if external {
			result, err = spiffex509knowledge.ReplayHistorical(spiffex509knowledge.Request{Selection: selection, Observation: observation}, expected)
		} else {
			result, err = spiffex509knowledge.ReplayEmbedded(observation, expected)
		}
		if err != nil {
			return r.spiffeKnowledgeError("SPIFFE X.509-SVID historical replay failed", err)
		}
		encoded, marshalErr := spiffex509knowledge.MarshalHistoricalReplay(result)
		if marshalErr != nil {
			return r.fail("SPIFFE X.509-SVID replay integrity failure", ExitIntegrity)
		}
		if *format == "json" {
			_, err = r.stdout.Write(encoded)
		} else {
			_, err = fmt.Fprintf(r.stdout, "SPIFFE X.509-SVID conformance historical replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nraw certificate digest: verified separately for this replay and excluded from report\naggregate scope: named conformance subset only\n", result.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return spiffex509knowledge.HistoricalClaimExit(result)
	}
	var report spiffex509knowledge.Report
	if external {
		report, err = spiffex509knowledge.EvaluateCurrent(spiffex509knowledge.Request{Selection: selection, Observation: observation})
	} else {
		report, err = spiffex509knowledge.EvaluateEmbedded(observation, now)
	}
	if err != nil {
		return r.spiffeKnowledgeError("SPIFFE X.509-SVID conformance check failed", err)
	}
	encoded, marshalErr := spiffex509knowledge.MarshalReport(report)
	if marshalErr != nil {
		return r.fail("SPIFFE X.509-SVID report integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		_, err = r.stdout.Write(encoded)
	} else {
		err = writeSPIFFEX509Human(r.stdout, report)
	}
	if err != nil {
		return ExitIntegrity
	}
	return spiffex509knowledge.ClaimExit(report)
}

func writeSPIFFEX509Human(out io.Writer, report spiffex509knowledge.Report) error {
	o, c := report.Check.Observation, report.Check.Claim
	cardinality := "not evaluated"
	if o.URISANCardinality != nil {
		cardinality = *o.URISANCardinality
	}
	scheme := "not evaluated"
	if o.URISANSchemeIsSPIFFE != nil {
		scheme = fmt.Sprint(*o.URISANSchemeIsSPIFFE)
	}
	path := "not evaluated"
	if o.URISANPathIsNonRoot != nil {
		path = fmt.Sprint(*o.URISANPathIsNonRoot)
	}
	trustReceipt := ""
	if report.Knowledge.TrustReceiptDigest != "" {
		trustReceipt = "knowledge trust receipt digest: " + report.Knowledge.TrustReceiptDigest + "\n"
	}
	_, err := fmt.Fprintf(out, "SPIFFE X.509-SVID public-leaf URI-SAN subset\nscoped result: %s (%s)\nreason: %s\nnext action: %s\ncertificate is CA: %t\nURI SAN cardinality: %s\nURI SAN scheme is spiffe: %s\nURI SAN path is non-root: %s\nprepared observation digest: %s\nknowledge: %s revision %s\nknowledge purpose: %s\nknowledge bundle digest: %s\n%sevaluated at: %s\nnormative source: %s/blob/%s/%s lines %s\nraw certificate identity: optionally pinned for current checks and required separately for replay; excluded from this report\ninput handling: Prufyx reads but does not modify the certificate and does not print or store its URI, subject, host, path, raw bytes, file path, or raw digest\nunchecked: %s\naggregate scope: this named standards-conformance subset only; full SPIFFE ID, X.509-SVID, trust, possession, authentication, issuance, and runtime behavior remain UNKNOWN\n", c.Status, c.ReasonCode, c.Reason, c.Action, o.IsCA, cardinality, scheme, path, report.Check.PreparedObservationDigest, report.Knowledge.Origin, report.Knowledge.Revision, report.Knowledge.Purpose, report.Knowledge.BundleDigest, trustReceipt, report.Knowledge.EvaluatedAt, report.Knowledge.NormativeSource.RepositoryURL, report.Knowledge.NormativeSource.Commit, report.Knowledge.NormativeSource.Path, formatSPIFFESpans(report.Knowledge.NormativeSource.Spans), strings.Join(report.Check.Unchecked, ", "))
	return err
}

func formatSPIFFESpans(spans []spiffex509svid.SourceSpan) string {
	parts := make([]string, len(spans))
	for i, s := range spans {
		parts[i] = fmt.Sprintf("%d-%d", s.StartLine, s.EndLine)
	}
	return strings.Join(parts, ",")
}

func (r runtime) spiffeKnowledgeError(message string, err error) int {
	if errors.Is(err, knowledge.ErrInvalid) || errors.Is(err, spiffex509knowledge.ErrInvalid) || errors.Is(err, currentbundle.ErrInvalid) {
		return r.fail(message, ExitUsage)
	}
	if errors.Is(err, knowledge.ErrNoSelection) {
		return r.fail("selected SPIFFE X.509-SVID profile has no verified knowledge revision; import one explicitly", ExitUnknown)
	}
	if errors.Is(err, knowledge.ErrExpired) {
		return r.fail("selected SPIFFE X.509-SVID knowledge metadata expired", ExitUnknown)
	}
	return r.fail(message, ExitIntegrity)
}
