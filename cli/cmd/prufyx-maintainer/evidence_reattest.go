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
	case "trust-root":
		if len(args) > 1 && args[1] == "migrate" {
			return runEvidenceReattestTrustRootMigrate(args[2:], stdout, stderr)
		}
		return evidenceReattestError()
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest <prepare|sign|verify|trust-root migrate> [options]")
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

// reviewRecordTempPrefix and reviewRecordTempSuffix name the temporary
// file review-record new writes before linking the record into place. One
// is left behind only if that command was killed mid-write.
const (
	reviewRecordTempPrefix = ".review-record-"
	reviewRecordTempSuffix = ".tmp"
)

// leftoverTempError is a review-record new temporary file found in a
// review record directory.
type leftoverTempError struct{ name string }

func (e leftoverTempError) Error() string {
	return e.name + " is a temporary file an interrupted review-record new left behind; delete it and run the command again"
}

// reviewRecordDirError reports why a review record directory was refused:
// a leftover temporary file by name, anything else generically.
func reviewRecordDirError(err error, stderr io.Writer) error {
	var leftover leftoverTempError
	if errors.As(err, &leftover) {
		fmt.Fprintf(stderr, "evidence reattest: review record directory: %v\n", leftover)
		return &commandError{code: 2, message: "evidence reattest: command rejected", printed: true}
	}
	return evidenceReattestError()
}

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
		if strings.HasPrefix(name, reviewRecordTempPrefix) && strings.HasSuffix(name, reviewRecordTempSuffix) {
			return nil, leftoverTempError{name: name}
		}
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
	wave := flags.Int("wave", 0, "1..7 stagger slot this batch renews into (human mode only)")
	mode := flags.String("mode", evidencereattest.ModeHuman, "human (a reviewer's batch: wave, sample, terminal signing) or automated (no sample, per-rule schedule, automation-key signing)")
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
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest prepare --worklist ABS --pack cncf|community --rules ABS --next-revision STR (--wave N | --mode automated) --output-dir ABS --statement-chain-dir ABS [--trust-root ABS --trust-root-digest sha256:...] [--rules-worklist-path STR] [--review-record-dir ABS] [--attested-at RFC3339]")
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
	if *mode != evidencereattest.ModeHuman && *mode != evidencereattest.ModeAutomated {
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
		return reviewRecordDirError(err, stderr)
	}
	capabilityDigest, err := engineCapabilityDigestFor(packName)
	if err != nil {
		return evidenceReattestError()
	}

	result, err := evidencereattest.Prepare(evidencereattest.PrepareOptions{
		WorklistRaw: worklistRaw, PackName: packName, PackPath: rulesWorklistPath, PackRaw: packRaw,
		Chain: chain, Mode: *mode, Wave: *wave, AttestedAt: attestedAt, Now: now, NextRevision: nextRevision,
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
	fmt.Fprintf(stdout, "evidence reattest prepare: mode=%s signerRole=%s eligible=%d sampled=%d notExtended=%d\n",
		*mode, result.Statement.SignerRole, result.EligibleRuleCount, result.SampledRuleCount, result.NotExtendedRuleCount)
	return nil
}

const evidenceReattestSignUsage = "usage: prufyx-maintainer evidence reattest sign --statement ABS --trust-root ABS --trust-root-digest sha256:... --output ABS [--role human] --key ABS | --role automation (--key ABS | --key-env NAME) (--passphrase-file ABS | --passphrase-env NAME)"

func runEvidenceReattestSign(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statementPath, trustRootPath, trustRootDigest, keyPath, keyEnv, passphrasePath, passphraseEnv, output, role string
	flags.StringVar(&statementPath, "statement", "", "exact statement.json prepare produced (absolute path)")
	flags.StringVar(&trustRootPath, "trust-root", "", "evidence-reattestation trust root (absolute path; no production path is configured, see evidencereattest.ProductionTrustRootPath)")
	flags.StringVar(&trustRootDigest, "trust-root-digest", "", "the trust root's digest as independently known to the caller, sha256:... (never derived from --trust-root itself)")
	flags.StringVar(&role, "role", evidencereattest.RoleHuman, "the role to sign as: human (terminal passphrase prompt only) or automation (unattended; key and passphrase from files or environment variables)")
	flags.StringVar(&keyPath, "key", "", "encrypted re-attestation signing key file (absolute path, mode 0600, owned by the current user)")
	flags.StringVar(&keyEnv, "key-env", "", "automation role only: name of an environment variable holding the encrypted signing key PEM")
	flags.StringVar(&passphrasePath, "passphrase-file", "", "automation role only: file holding the key's passphrase (absolute path, mode 0600, owned by the current user; one trailing newline is ignored)")
	flags.StringVar(&passphraseEnv, "passphrase-env", "", "automation role only: name of an environment variable holding the key's passphrase")
	flags.StringVar(&output, "output", "", "new statement.sig.json output path")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, evidenceReattestSignUsage)
			return e
		}
		return evidenceReattestError()
	}
	if flags.NArg() != 0 || statementPath == "" || trustRootPath == "" || trustRootDigest == "" || output == "" || !filepath.IsAbs(output) {
		return evidenceReattestError()
	}
	switch role {
	case evidencereattest.RoleHuman:
		// A human key is unlocked only at a terminal: none of the
		// unattended inputs may be given.
		if keyPath == "" || keyEnv != "" || passphrasePath != "" || passphraseEnv != "" {
			fmt.Fprintln(stderr, "evidence reattest sign: the human role takes --key and reads its passphrase only at a terminal")
			return evidenceReattestError()
		}
	case evidencereattest.RoleAutomation:
		if (keyPath == "") == (keyEnv == "") || (passphrasePath == "") == (passphraseEnv == "") {
			return evidenceReattestError()
		}
	default:
		return evidenceReattestError()
	}
	statementRaw, err := readCanonicalInput(statementPath, evidencereattest.MaxStatementBytes)
	if err != nil {
		return evidenceReattestError()
	}
	// Refuse a statement prepared for the other role before any secret is
	// read: an automation key never signs a human statement, and a human
	// key never signs an automated one. Sign enforces the same binding.
	statementRole, err := evidencereattest.StatementSignerRole(statementRaw)
	if err != nil || statementRole != role {
		fmt.Fprintf(stderr, "evidence reattest sign: the statement must be signed with role %q, not %q\n", statementRole, role)
		return &commandError{code: 2, message: "evidence reattest sign: rejected", printed: true}
	}
	trustRootRaw, err := readCanonicalInput(trustRootPath, evidencereattest.MaxTrustRootBytes)
	if err != nil {
		return evidenceReattestError()
	}
	var keyRaw, passphrase []byte
	if role == evidencereattest.RoleHuman {
		keyRaw, err = signerKey(keyPath)
		if err != nil {
			return evidenceReattestError()
		}
		// promptPassphrase refuses off a TTY (see knowledge_sign.go): a
		// human key is only ever unlocked by a person at a terminal, so an
		// unattended or agent-driven shell can never reach Sign with it.
		passphrase, err = promptPassphrase(stderr, false)
		if err != nil {
			return evidenceReattestError()
		}
	} else {
		keyRaw, passphrase, err = automationSecrets(keyPath, keyEnv, passphrasePath, passphraseEnv)
		if err != nil {
			fmt.Fprintln(stderr, "evidence reattest sign: the automation key or its passphrase is unavailable or empty")
			return evidenceReattestError()
		}
	}
	envelope, err := evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: statementRaw, TrustRoot: trustRootRaw, EncryptedKey: keyRaw, Passphrase: passphrase, Role: role,
		ExpectedTrustRootDigest: trustRootDigest, Now: time.Now().UTC(),
	})
	// Sign wipes the passphrase; wipe the key copy too.
	for i := range keyRaw {
		keyRaw[i] = 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "evidence reattest sign: %v\n", err)
		return &commandError{code: 2, message: "evidence reattest sign: rejected", printed: true}
	}
	if err := os.WriteFile(output, append(append([]byte(nil), envelope...), '\n'), 0o644); err != nil {
		return evidenceReattestError()
	}
	fmt.Fprintf(stdout, "evidence reattest sign: signed (role %s)\n", role)
	return nil
}

// automationSecrets reads an automation key and its passphrase for
// unattended signing, as a CI job provides them from its secrets: each
// either from a file (absolute, mode 0600, owned by the current user, read
// through the same bounded no-follow reader as every other input) or from
// a named environment variable. A passphrase file's one trailing newline
// is dropped. Empty values are rejected.
func automationSecrets(keyPath, keyEnv, passphrasePath, passphraseEnv string) (key, passphrase []byte, err error) {
	if keyPath != "" {
		key, err = signerKey(keyPath)
		if err != nil {
			return nil, nil, err
		}
	} else {
		value, ok := os.LookupEnv(keyEnv)
		// Remove the variable as soon as it is read, so nothing the
		// process starts afterwards inherits the secret.
		_ = os.Unsetenv(keyEnv)
		if !ok || value == "" || len(value) > knowledgesign.MaxKeyBytes {
			return nil, nil, knowledgesign.ErrRejected
		}
		key = []byte(value)
	}
	if passphrasePath != "" {
		raw, err := signerKey(passphrasePath)
		if err != nil {
			return nil, nil, err
		}
		passphrase = bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	} else {
		value, ok := os.LookupEnv(passphraseEnv)
		_ = os.Unsetenv(passphraseEnv)
		if !ok {
			return nil, nil, knowledgesign.ErrRejected
		}
		passphrase = []byte(value)
	}
	if len(passphrase) == 0 {
		return nil, nil, knowledgesign.ErrRejected
	}
	return key, passphrase, nil
}

// runEvidenceReattestTrustRootMigrate writes a v2 trust root derived from
// an existing v1 or v2 one (see evidencereattest.MigrateTrustRoot). It
// reads and writes public keys only.
func runEvidenceReattestTrustRootMigrate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest trust-root migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var fromPath, fromDigest, output, expires string
	var addKeys, removeKeys stringList
	flags.StringVar(&fromPath, "from", "", "current trust root, v1 or v2 (absolute path)")
	flags.StringVar(&fromDigest, "from-digest", "", "the current trust root's pinned digest, sha256:...")
	flags.StringVar(&output, "output", "", "new file to write the v2 trust root to (absolute path; must not exist)")
	flags.StringVar(&expires, "expires", "", "new expiry as exact UTC RFC3339 (default: keep the current root's)")
	flags.Var(&addKeys, "add-automation-key", "hex Ed25519 public key to add with the automation role (repeatable)")
	flags.Var(&removeKeys, "remove-key", "key ID to remove (repeatable)")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest trust-root migrate --from ABS --from-digest sha256:... --output ABS [--expires RFC3339] [--add-automation-key HEX]... [--remove-key KEYID]...")
			return e
		}
		return evidenceReattestError()
	}
	if flags.NArg() != 0 || fromPath == "" || fromDigest == "" || output == "" || !filepath.IsAbs(output) {
		return evidenceReattestError()
	}
	fromRaw, err := readCanonicalInput(fromPath, evidencereattest.MaxTrustRootBytes)
	if err != nil {
		return evidenceReattestError()
	}
	result, err := evidencereattest.MigrateTrustRoot(evidencereattest.MigrateTrustRootOptions{
		From: fromRaw, ExpectedFromDigest: fromDigest, Now: time.Now().UTC(), Expires: expires,
		AddAutomationKeys: addKeys, RemoveKeyIDs: removeKeys,
	})
	if err != nil {
		fmt.Fprintf(stderr, "evidence reattest trust-root migrate: %v\n", err)
		return &commandError{code: 2, message: "evidence reattest trust-root migrate: rejected", printed: true}
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return evidenceReattestError()
	}
	_, writeErr := file.Write(append(append([]byte(nil), result.TrustRoot...), '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return evidenceReattestError()
	}
	fmt.Fprintf(stdout, "evidence reattest trust-root migrate: schemaVersion=%s trustRootDigest=%s\n", evidencereattest.TrustRootSchema, result.Digest)
	for _, key := range result.Keys {
		fmt.Fprintf(stdout, "  key %s role %s\n", key.KeyID, key.Role)
	}
	return nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func runEvidenceReattestVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("evidence reattest verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statementPath, priorPackPath, nextPackPath, worklistPath, rerunWorklistPath, packName, rulesWorklistPath, reviewRecordDir, envelopePath, trustRootPath, trustRootDigest, statementChainDir, baseStatementChainDir string
	var structuralOnly bool
	flags.StringVar(&statementPath, "statement", "", "statement.json to verify (absolute path)")
	flags.StringVar(&priorPackPath, "prior-pack", "", "the base-branch rule pack (absolute path)")
	flags.StringVar(&nextPackPath, "next-pack", "", "the changed rule pack, e.g. rules.next.json (absolute path)")
	flags.StringVar(&worklistPath, "worklist", "", "the retained worklist the statement was prepared from (absolute path)")
	flags.StringVar(&rerunWorklistPath, "rerun-worklist", "", "a worklist the verifying job produced itself with its own \"evidence repin\" run (absolute path); every citation of every rule the statement renews must match it. Required whenever an automated statement renews a rule")
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
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer evidence reattest verify --statement ABS --prior-pack ABS --next-pack ABS --worklist ABS --pack cncf|community --statement-chain-dir ABS --base-statement-chain-dir ABS (--envelope ABS --trust-root ABS --trust-root-digest sha256:... | --structural-only [--trust-root ABS --trust-root-digest sha256:...]) [--rerun-worklist ABS] [--rules-worklist-path STR] [--review-record-dir ABS]")
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
	var rerunWorklistRaw []byte
	if rerunWorklistPath != "" {
		rerunWorklistRaw, err = readReattestInput(rerunWorklistPath, evidencereattest.MaxWorklistBytes)
		if err != nil {
			return evidenceReattestError()
		}
	}
	reviewRecords, err := loadReviewRecords(reviewRecordDir)
	if err != nil {
		return reviewRecordDirError(err, stderr)
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
		PreSign: structuralOnly, IndependentWorklistRaw: rerunWorklistRaw,
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

	if result.SignerRole == evidencereattest.RoleAutomation && result.RuleCount > 0 && len(rerunWorklistRaw) == 0 {
		fmt.Fprintln(stderr, "evidence reattest verify: FAIL: an automated statement that renews rules is only accepted against a worklist this job produced itself; pass --rerun-worklist")
		return &commandError{code: 1, message: "evidence reattest verify: independent worklist required", printed: true}
	}

	if (result.RuleCount > 0 || result.ReviewCount > 0) && !signatureFlagsGiven {
		fmt.Fprintln(stderr, "evidence reattest verify: FAIL: this statement renews at least one rule or records an individual review; --envelope, --trust-root, and --trust-root-digest are required (or pass --structural-only to explicitly skip the signature, which never passes the gate)")
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
		fmt.Fprintf(stdout, "evidence reattest verify: OK role=%s rules=%d sampled=%d notExtended=%d signedBy=%s\n",
			sig.SignerRole, result.RuleCount, result.SampledCount, result.NotExtendedCount, strings.Join(keyIDs, ","))
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
