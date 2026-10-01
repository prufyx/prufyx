// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

func evidenceReattestError() error {
	return &commandError{code: 2, message: "evidence reattest: command rejected"}
}

// runEvidenceReattest dispatches "evidence reattest prepare|sign|verify".
func runEvidenceReattest(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return evidenceReattestError()
	}
	switch args[0] {
	case "prepare":
		return runEvidenceReattestPrepare(args[1:], stdout, stderr)
	case "sign":
		return runEvidenceReattestSign(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceReattestVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest <prepare|sign|verify> [options]")
		return err
	default:
		return evidenceReattestError()
	}
}

// engineCapabilityDigestFor returns the compiled-engine identity Prepare and
// Verify bind the statement to (see evidencereattest.PackRef.
// EngineCapabilityDigest's doc comment for why the community pack falls
// back to the generic engine contract digest).
func engineCapabilityDigestFor(packName string) (string, error) {
	switch packName {
	case evidencereattest.PackCNCF:
		return cncfcheck.ExternalCapabilityDigest()
	case evidencereattest.PackCommunity:
		return constraintengine.EngineContractDigest(), nil
	default:
		return "", errors.New("unknown pack")
	}
}

func readReattestInput(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, knowledgesign.ErrRejected
	}
	return signerInput(path, limit)
}

// readCanonicalInput reads a file this command itself writes in canonical
// form (statement.json, statement.sig.json, a trust root): on disk it
// carries one trailing newline for POSIX friendliness, but the exact
// canonical bytes this package's strict decoders round-trip-check against
// never include one, so the trailing newline is trimmed here before the
// bytes reach evidencereattest.
func readCanonicalInput(path string, limit int) ([]byte, error) {
	raw, err := readReattestInput(path, limit)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(raw, []byte("\n")), nil
}

// reviewRecordSuffix is the one file extension a review record may have.
// The rule ID is the file name with exactly this suffix removed, so a rule
// ID that itself contains dots maps unambiguously to its file.
const reviewRecordSuffix = ".json"

// loadReviewRecords reads every file in dir (non-recursive) and maps its
// rule ID, the file name without its ".json" extension, to the file's
// exact bytes. It rejects anything that is not a regular file (including
// symlinks and subdirectories), a file without the ".json" extension or
// with nothing before it, and an empty file. The records' content is
// checked by evidencereattest itself (structure, rule ID, project, rule
// digest and decision time; see its reviewsFromRecords), identically in
// prepare and verify.
func loadReviewRecords(dir string) (map[string][]byte, error) {
	records := map[string][]byte{}
	if dir == "" {
		return records, nil
	}
	if !filepath.IsAbs(dir) {
		return nil, knowledgesign.ErrRejected
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, knowledgesign.ErrRejected
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, knowledgesign.ErrRejected
		}
		name := entry.Name()
		if !strings.HasSuffix(name, reviewRecordSuffix) {
			return nil, knowledgesign.ErrRejected
		}
		ruleID := strings.TrimSuffix(name, reviewRecordSuffix)
		if ruleID == "" {
			return nil, knowledgesign.ErrRejected
		}
		if _, dup := records[ruleID]; dup {
			return nil, knowledgesign.ErrRejected
		}
		raw, err := readReattestInput(filepath.Join(dir, name), evidencereattest.MaxReviewRecordBytes)
		if err != nil || len(raw) == 0 {
			return nil, knowledgesign.ErrRejected
		}
		records[ruleID] = raw
	}
	return records, nil
}

const (
	chainStatementSuffix = ".statement.json"
	chainEnvelopeSuffix  = ".statement.sig.json"
)

// readStatementChain reads one pack's statement chain directory: every
// entry must be a regular file (never a symlink or subdirectory) named
// <stem>.statement.json or <stem>.statement.sig.json, and every stem must
// have both. Each file is read through the same bounded, no-follow reader
// as every other input. The chain's order and validity are established by
// evidencereattest itself (signatures and previousAttestationDigest
// links), never by file names.
func readStatementChain(dir, trustRootPath, trustRootDigest string) (*evidencereattest.Chain, error) {
	if !filepath.IsAbs(dir) {
		return nil, knowledgesign.ErrRejected
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, knowledgesign.ErrRejected
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 2*evidencereattest.MaxChainEntries {
		return nil, knowledgesign.ErrRejected
	}
	statements := map[string][]byte{}
	envelopes := map[string][]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, knowledgesign.ErrRejected
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(name, chainEnvelopeSuffix) && len(name) > len(chainEnvelopeSuffix):
			raw, err := readCanonicalInput(path, evidencereattest.MaxEnvelopeBytes)
			if err != nil {
				return nil, knowledgesign.ErrRejected
			}
			envelopes[strings.TrimSuffix(name, chainEnvelopeSuffix)] = raw
		case strings.HasSuffix(name, chainStatementSuffix) && len(name) > len(chainStatementSuffix):
			raw, err := readCanonicalInput(path, evidencereattest.MaxStatementBytes)
			if err != nil {
				return nil, knowledgesign.ErrRejected
			}
			statements[strings.TrimSuffix(name, chainStatementSuffix)] = raw
		default:
			return nil, knowledgesign.ErrRejected
		}
	}
	chain := &evidencereattest.Chain{ExpectedTrustRootDigest: trustRootDigest}
	stems := make([]string, 0, len(statements))
	for stem := range statements {
		if _, ok := envelopes[stem]; !ok {
			return nil, knowledgesign.ErrRejected
		}
		stems = append(stems, stem)
	}
	if len(envelopes) != len(statements) {
		return nil, knowledgesign.ErrRejected
	}
	sort.Strings(stems)
	for _, stem := range stems {
		chain.Entries = append(chain.Entries, evidencereattest.ChainEntry{Name: stem, Statement: statements[stem], Envelope: envelopes[stem]})
	}
	if trustRootPath != "" {
		chain.TrustRoot, err = readCanonicalInput(trustRootPath, evidencereattest.MaxTrustRootBytes)
		if err != nil {
			return nil, knowledgesign.ErrRejected
		}
	}
	return chain, nil
}

func runEvidenceReattestPrepare(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var worklistPath, packName, rulesPath, rulesWorklistPath, nextRevision, reviewRecordDir, outputDir, attestedAtFlag, statementChainDir, trustRootPath, trustRootDigest string
	wave := flags.Int("wave", 0, "1..7 stagger slot this batch renews into")
	flags.StringVar(&worklistPath, "worklist", "", "retained evidence-repin worklist (absolute path)")
	flags.StringVar(&packName, "pack", "", "cncf or community")
	flags.StringVar(&rulesPath, "rules", "", "current rule pack file (absolute path)")
	flags.StringVar(&rulesWorklistPath, "rules-worklist-path", "", "the rule pack path as it appears in the worklist, if different from --rules")
	flags.StringVar(&statementChainDir, "statement-chain-dir", "", "this pack's statement chain directory of <stem>.statement.json and <stem>.statement.sig.json pairs (absolute path; required, may be empty)")
	flags.StringVar(&trustRootPath, "trust-root", "", "trust root the chain's statements are signed under (absolute path; required, with --trust-root-digest, when the chain is not empty)")
	flags.StringVar(&trustRootDigest, "trust-root-digest", "", "the trust root's digest as independently known to the caller, sha256:... (never derived from --trust-root itself)")
	flags.StringVar(&nextRevision, "next-revision", "", "new pack revision string for rules.next.json")
	flags.StringVar(&reviewRecordDir, "review-record-dir", "", "directory of <ruleId>.json individual review records, one per rule (absolute path; optional)")
	flags.StringVar(&outputDir, "output-dir", "", "new directory to write statement.json, rules.next.json, and summary.txt into")
	flags.StringVar(&attestedAtFlag, "attested-at", "", "exact UTC RFC3339 attestation instant, not in the future (default: now)")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest prepare --worklist ABS --pack cncf|community --rules ABS --next-revision STR --wave N --output-dir ABS --statement-chain-dir ABS [--trust-root ABS --trust-root-digest sha256:...] [--rules-worklist-path STR] [--review-record-dir ABS] [--attested-at RFC3339]")
			return e
		}
		return evidenceReattestError()
	}
	if flags.NArg() != 0 || worklistPath == "" || rulesPath == "" || nextRevision == "" || outputDir == "" || !filepath.IsAbs(outputDir) || statementChainDir == "" {
		return evidenceReattestError()
	}
	if (trustRootPath == "") != (trustRootDigest == "") {
		return evidenceReattestError()
	}
	if packName != evidencereattest.PackCNCF && packName != evidencereattest.PackCommunity {
		return evidenceReattestError()
	}
	if rulesWorklistPath == "" {
		rulesWorklistPath = rulesPath
	}
	now := time.Now().UTC()
	attestedAt := now
	if attestedAtFlag != "" {
		parsed, err := time.Parse(time.RFC3339, attestedAtFlag)
		if err != nil {
			return evidenceReattestError()
		}
		attestedAt = parsed.UTC()
	}

	worklistRaw, err := readReattestInput(worklistPath, evidencereattest.MaxWorklistBytes)
	if err != nil {
		return evidenceReattestError()
	}
	packRaw, err := readReattestInput(rulesPath, evidencereattest.MaxPackBytes)
	if err != nil {
		return evidenceReattestError()
	}
	chain, err := readStatementChain(statementChainDir, trustRootPath, trustRootDigest)
	if err != nil {
		return evidenceReattestError()
	}
	reviewRecords, err := loadReviewRecords(reviewRecordDir)
	if err != nil {
		return evidenceReattestError()
	}
	capabilityDigest, err := engineCapabilityDigestFor(packName)
	if err != nil {
		return evidenceReattestError()
	}

	result, err := evidencereattest.Prepare(evidencereattest.PrepareOptions{
		WorklistRaw: worklistRaw, PackName: packName, PackPath: rulesWorklistPath, PackRaw: packRaw,
		Chain: chain, Wave: *wave, AttestedAt: attestedAt, Now: now, NextRevision: nextRevision,
		EngineCapabilityDigest: capabilityDigest, ReviewRecords: reviewRecords,
	})
	if err != nil {
		fmt.Fprintf(stderr, "evidence reattest prepare: %v\n", err)
		return &commandError{code: 2, message: "evidence reattest prepare: rejected", printed: true}
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return evidenceReattestError()
	}
	if err := os.WriteFile(filepath.Join(outputDir, "statement.json"), append(append([]byte(nil), result.StatementCanonical...), '\n'), 0o644); err != nil {
		return evidenceReattestError()
	}
	if err := os.WriteFile(filepath.Join(outputDir, "rules.next.json"), result.NextPack, 0o644); err != nil {
		return evidenceReattestError()
	}
	if err := os.WriteFile(filepath.Join(outputDir, "summary.txt"), result.Summary, 0o644); err != nil {
		return evidenceReattestError()
	}
	fmt.Fprintf(stdout, "evidence reattest prepare: eligible=%d sampled=%d notExtended=%d\n",
		result.EligibleRuleCount, result.SampledRuleCount, result.NotExtendedRuleCount)
	return nil
}

func runEvidenceReattestSign(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statementPath, trustRootPath, trustRootDigest, keyPath, output string
	flags.StringVar(&statementPath, "statement", "", "exact statement.json prepare produced (absolute path)")
	flags.StringVar(&trustRootPath, "trust-root", "", "evidence-reattestation trust root (absolute path; no production path is configured, see evidencereattest.ProductionTrustRootPath)")
	flags.StringVar(&trustRootDigest, "trust-root-digest", "", "the trust root's digest as independently known to the caller, sha256:... (never derived from --trust-root itself)")
	flags.StringVar(&keyPath, "key", "", "encrypted local re-attestation signing key")
	flags.StringVar(&output, "output", "", "new statement.sig.json output path")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest sign --statement ABS --trust-root ABS --trust-root-digest sha256:... --key ABS --output ABS")
			return e
		}
		return evidenceReattestError()
	}
	if flags.NArg() != 0 || statementPath == "" || trustRootPath == "" || trustRootDigest == "" || keyPath == "" || output == "" || !filepath.IsAbs(output) {
		return evidenceReattestError()
	}
	statementRaw, err := readCanonicalInput(statementPath, evidencereattest.MaxStatementBytes)
	if err != nil {
		return evidenceReattestError()
	}
	trustRootRaw, err := readCanonicalInput(trustRootPath, evidencereattest.MaxTrustRootBytes)
	if err != nil {
		return evidenceReattestError()
	}
	keyRaw, err := signerKey(keyPath)
	if err != nil {
		return evidenceReattestError()
	}
	// promptPassphrase refuses off a TTY (see knowledge_sign.go): this is
	// the only place this command acquires secret input, so an unattended
	// or agent-driven shell can never reach Sign with a usable passphrase.
	passphrase, err := promptPassphrase(stderr, false)
	if err != nil {
		return evidenceReattestError()
	}
	envelope, err := evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: statementRaw, TrustRoot: trustRootRaw, EncryptedKey: keyRaw, Passphrase: passphrase,
		ExpectedTrustRootDigest: trustRootDigest, Now: time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "evidence reattest sign: %v\n", err)
		return &commandError{code: 2, message: "evidence reattest sign: rejected", printed: true}
	}
	if err := os.WriteFile(output, append(append([]byte(nil), envelope...), '\n'), 0o644); err != nil {
		return evidenceReattestError()
	}
	fmt.Fprintln(stdout, "evidence reattest sign: signed")
	return nil
}

func runEvidenceReattestVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statementPath, priorPackPath, nextPackPath, worklistPath, packName, rulesWorklistPath, reviewRecordDir, envelopePath, trustRootPath, trustRootDigest, statementChainDir, baseStatementChainDir string
	var structuralOnly bool
	flags.StringVar(&statementPath, "statement", "", "statement.json to verify (absolute path)")
	flags.StringVar(&priorPackPath, "prior-pack", "", "the base-branch rule pack (absolute path)")
	flags.StringVar(&nextPackPath, "next-pack", "", "the changed rule pack, e.g. rules.next.json (absolute path)")
	flags.StringVar(&worklistPath, "worklist", "", "the retained worklist the statement was prepared from (absolute path)")
	flags.StringVar(&packName, "pack", "", "cncf or community, for the eligibility recomputation")
	flags.StringVar(&rulesWorklistPath, "rules-worklist-path", "", "the rule pack path as it appears in the worklist, if different from --prior-pack")
	flags.StringVar(&reviewRecordDir, "review-record-dir", "", "directory of <ruleId>.json individual review records, one per rule (absolute path; optional)")
	flags.StringVar(&statementChainDir, "statement-chain-dir", "", "this pack's statement chain directory of <stem>.statement.json and <stem>.statement.sig.json pairs (absolute path; required, may be empty)")
	flags.StringVar(&baseStatementChainDir, "base-statement-chain-dir", "", "the same pack's statement chain directory as it is on the base branch, checked out separately (absolute path; required, may be empty); --statement-chain-dir must equal it plus at most the statement under verification")
	flags.StringVar(&envelopePath, "envelope", "", "statement.sig.json; required, with --trust-root and --trust-root-digest, whenever the statement renews at least one rule")
	flags.StringVar(&trustRootPath, "trust-root", "", "trust root the statement and the chain are signed under; required with --trust-root-digest whenever --envelope is given or the chain is not empty")
	flags.StringVar(&trustRootDigest, "trust-root-digest", "", "the trust root's digest as independently known to the caller, sha256:... (never derived from --trust-root itself)")
	flags.BoolVar(&structuralOnly, "structural-only", false, "run only the structural checks, skipping the signature requirement; this NEVER counts as a passing publish gate and always exits non-zero, even when every structural check passes")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest verify --statement ABS --prior-pack ABS --next-pack ABS --worklist ABS --pack cncf|community --statement-chain-dir ABS --base-statement-chain-dir ABS (--envelope ABS --trust-root ABS --trust-root-digest sha256:... | --structural-only [--trust-root ABS --trust-root-digest sha256:...]) [--rules-worklist-path STR] [--review-record-dir ABS]")
			return e
		}
		return evidenceReattestError()
	}
	if flags.NArg() != 0 || statementPath == "" || priorPackPath == "" || nextPackPath == "" || worklistPath == "" || packName == "" || statementChainDir == "" || baseStatementChainDir == "" {
		return evidenceReattestError()
	}
	// --trust-root and --trust-root-digest always come as a pair; they pin
	// the root for both the chain's signatures and --envelope.
	if (trustRootPath == "") != (trustRootDigest == "") {
		return evidenceReattestError()
	}
	signatureFlagsGiven := envelopePath != ""
	if signatureFlagsGiven && trustRootPath == "" {
		return evidenceReattestError()
	}
	if structuralOnly && signatureFlagsGiven {
		// --structural-only exists to run the structural checks in
		// isolation (for example, right after prepare, before anyone has
		// signed anything); combining it with --envelope would make the
		// command's own exit code ambiguous about whether the signature
		// was actually checked, so it is rejected outright.
		return evidenceReattestError()
	}

	statementRaw, err := readCanonicalInput(statementPath, evidencereattest.MaxStatementBytes)
	if err != nil {
		return evidenceReattestError()
	}
	priorPackRaw, err := readReattestInput(priorPackPath, evidencereattest.MaxPackBytes)
	if err != nil {
		return evidenceReattestError()
	}
	nextPackRaw, err := readReattestInput(nextPackPath, evidencereattest.MaxPackBytes)
	if err != nil {
		return evidenceReattestError()
	}
	worklistRaw, err := readReattestInput(worklistPath, evidencereattest.MaxWorklistBytes)
	if err != nil {
		return evidenceReattestError()
	}
	chain, err := readStatementChain(statementChainDir, trustRootPath, trustRootDigest)
	if err != nil {
		return evidenceReattestError()
	}
	baseChain, err := readStatementChain(baseStatementChainDir, trustRootPath, trustRootDigest)
	if err != nil {
		return evidenceReattestError()
	}
	reviewRecords, err := loadReviewRecords(reviewRecordDir)
	if err != nil {
		return evidenceReattestError()
	}
	capabilityDigest, err := engineCapabilityDigestFor(packName)
	if err != nil {
		return evidenceReattestError()
	}

	result, err := evidencereattest.Verify(evidencereattest.VerifyOptions{
		StatementRaw: statementRaw, PriorPackRaw: priorPackRaw, NextPackRaw: nextPackRaw,
		WorklistRaw: worklistRaw, Chain: chain, BaseChain: baseChain,
		PackName: packName, PackPath: rulesWorklistPathOrDefault(rulesWorklistPath, priorPackPath), EngineCapabilityDigest: capabilityDigest,
		ReviewRecords: reviewRecords, AttestedAtNow: time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "evidence reattest verify: FAIL: %v\n", err)
		return &commandError{code: 1, message: "evidence reattest verify: invariant violated", printed: true}
	}

	if structuralOnly {
		// Structural success is deliberately never reported as a pass:
		// nothing here checked a signature, so this exit code must never
		// gate a publish.
		fmt.Fprintf(stderr, "evidence reattest verify: structural checks passed (rules=%d sampled=%d notExtended=%d), but --structural-only never passes the publish gate: no signature was checked\n",
			result.RuleCount, result.SampledCount, result.NotExtendedCount)
		return &commandError{code: 1, message: "evidence reattest verify: structural-only is not a publish gate", printed: true}
	}

	if result.RuleCount > 0 && !signatureFlagsGiven {
		fmt.Fprintln(stderr, "evidence reattest verify: FAIL: this statement renews at least one rule; --envelope, --trust-root, and --trust-root-digest are required (or pass --structural-only to explicitly skip the signature, which never passes the gate)")
		return &commandError{code: 1, message: "evidence reattest verify: signature required", printed: true}
	}

	if signatureFlagsGiven {
		envelopeRaw, err := readCanonicalInput(envelopePath, evidencereattest.MaxEnvelopeBytes)
		if err != nil {
			return evidenceReattestError()
		}
		sig, err := evidencereattest.VerifySignature(evidencereattest.VerifySignatureOptions{
			Statement: statementRaw, Envelope: envelopeRaw, TrustRoot: chain.TrustRoot, ExpectedTrustRootDigest: trustRootDigest,
		})
		if err != nil {
			fmt.Fprintf(stderr, "evidence reattest verify: FAIL: signature: %v\n", err)
			return &commandError{code: 1, message: "evidence reattest verify: signature invalid", printed: true}
		}
		keyIDs := append([]string(nil), sig.SignerKeyIDs...)
		sort.Strings(keyIDs)
		fmt.Fprintf(stdout, "evidence reattest verify: OK rules=%d sampled=%d notExtended=%d signedBy=%s\n",
			result.RuleCount, result.SampledCount, result.NotExtendedCount, strings.Join(keyIDs, ","))
		return nil
	}
	fmt.Fprintf(stdout, "evidence reattest verify: OK rules=%d sampled=%d notExtended=%d (nothing renewed; no signature required)\n",
		result.RuleCount, result.SampledCount, result.NotExtendedCount)
	return nil
}

func rulesWorklistPathOrDefault(rulesWorklistPath, priorPackPath string) string {
	if rulesWorklistPath == "" {
		return priorPackPath
	}
	return rulesWorklistPath
}
