// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Signing many rule approvals with one command ("approval sign
// --rules-file"). The owner names the rules in a file (one id per line); the
// command reads them from the base and head packs with RuleApprovalSubject
// and signs each with SignApproval, the single-rule path, so every record
// has the same shape, validation and expiry as one signed alone. The list of
// exact subjects has a digest the owner confirms once. The key is read once,
// after every subject has been checked and the list confirmed, and nothing is
// written unless every record was signed and verified.

// MaxRulesPerSigning bounds one multi-rule signing.
const MaxRulesPerSigning = 64

const maxRulesFileBytes = 16 << 10

// ParseRulesFile reads the rule ids of a rules file: one id per line, blank
// lines ignored, no comments. A duplicate or an invalid id is refused. The
// result is sorted, so the list digest does not depend on the file's order.
func ParseRulesFile(raw []byte) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !approvalTokenRE.MatchString(line) {
			return nil, fmt.Errorf("rules file line %d is not a valid rule id", i+1)
		}
		if seen[line] {
			return nil, fmt.Errorf("rules file names rule %s twice", logSafe(line))
		}
		seen[line] = true
		ids = append(ids, line)
	}
	if len(ids) == 0 {
		return nil, errors.New("the rules file names no rule")
	}
	if len(ids) > MaxRulesPerSigning {
		return nil, fmt.Errorf("the rules file names %d rules, more than the %d one signing takes", len(ids), MaxRulesPerSigning)
	}
	sort.Strings(ids)
	return ids, nil
}

// RulesListDigest is the digest of the exact list of subjects: for every
// rule, sorted by id, its pack, id, base digest and candidate digest.
func RulesListDigest(subjects []ApprovalSubject) string {
	var b bytes.Buffer
	for _, s := range subjects {
		fmt.Fprintf(&b, "rule\t%s\t%s\t%s\t%s\n", s.Pack, s.RuleID, s.BaseDigest(), CandidateDigest(s.Candidate))
	}
	sum := sha256.Sum256(b.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RuleApprovalSubjects reads every rule of ids (sorted, distinct) with the
// single-rule reader; the first refusal refuses the whole list.
func RuleApprovalSubjects(spec PackSpec, basePack, headPack []byte, ids []string) ([]ApprovalSubject, error) {
	out := make([]ApprovalSubject, 0, len(ids))
	for _, id := range ids {
		s, err := RuleApprovalSubject(spec, basePack, headPack, id)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func printRulesList(w io.Writer, subjects []ApprovalSubject, digest string) {
	fmt.Fprintf(w, "rules to approve: %d\n", len(subjects))
	for _, s := range subjects {
		fmt.Fprintf(w, "  %s/%s  base %s  candidate %s\n", s.Pack, s.RuleID, rulesShortDigest(s.BaseDigest()), rulesShortDigest(CandidateDigest(s.Candidate)))
	}
	fmt.Fprintf(w, "list digest: %s\n", digest)
}

func rulesShortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}

// SignApprovals signs every subject with SignApproval at one time. It
// returns nothing unless every record was signed and verified.
func SignApprovals(subjects []ApprovalSubject, o SignApprovalOptions) ([][]byte, []ApprovalRecord, error) {
	var raws [][]byte
	var recs []ApprovalRecord
	for _, s := range subjects {
		o.Subject = s
		raw, rec, err := SignApproval(o)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %s: %w", logSafe(s.RuleID), err)
		}
		raws, recs = append(raws, raw), append(recs, rec)
	}
	return raws, recs, nil
}

func cmdApprovalSignRules(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var pack, basePack, headPack, keysPath, keysDigest, rulesFile, outDir string
	var identity, candidateID, expectDigest string
	var expectCount int
	var dryRun bool
	var k keyFlags
	f := flag.NewFlagSet("approval sign --rules-file", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	k.register(f)
	f.StringVar(&pack, "pack", "", "pack name: cncf or community")
	f.StringVar(&basePack, "base-pack", "", "the pack file as it is on the base branch")
	f.StringVar(&headPack, "head-pack", "", "the pack file as the change proposes it")
	f.StringVar(&keysPath, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&keysDigest, "keys-digest", "", "the pinned digest of the key file")
	f.StringVar(&rulesFile, "rules-file", "", "file with the rule ids to approve, one per line")
	f.StringVar(&outDir, "output-dir", "", "the approvals directory of the pack (cli/knowledge/approvals/<pack>)")
	f.StringVar(&identity, "identity", "", "the owner's login, as pinned in the key file")
	f.StringVar(&candidateID, "candidate-id", "", "a reference for the change, for example its pull request")
	f.BoolVar(&dryRun, "dry-run", false, "print the list and its digest; read no key, write nothing")
	f.IntVar(&expectCount, "expect-count", -1, "the number of rules the owner reviewed (with --expect-list-digest)")
	f.StringVar(&expectDigest, "expect-list-digest", "", "the list digest the owner reviewed (with --expect-count)")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if pack == "" || basePack == "" || headPack == "" || rulesFile == "" {
		return 2, usageError{"--pack, --base-pack, --head-pack and --rules-file are required"}
	}
	if dryRun {
		if k.file != "" || k.stdin || expectCount != -1 || expectDigest != "" || outDir != "" {
			return 2, usageError{"--dry-run reads no key and writes nothing: it takes none of --key, --key-stdin, --output-dir, --expect-count and --expect-list-digest"}
		}
	} else {
		if keysPath == "" || keysDigest == "" || identity == "" || candidateID == "" || outDir == "" {
			return 2, usageError{"--keys, --keys-digest, --identity, --candidate-id and --output-dir are required"}
		}
		if (expectCount == -1) != (expectDigest == "") {
			return 2, usageError{"give both --expect-count and --expect-list-digest, or neither (the owner then confirms on the terminal)"}
		}
		if expectCount == -1 && (env.confirm == nil) {
			return 2, errors.New("no terminal confirmation is available; give --expect-count and --expect-list-digest")
		}
		if filepath.Base(filepath.Clean(outDir)) != pack {
			return 2, fmt.Errorf("--output-dir must end in %s, the directory under the approvals directory the gate reads", pack)
		}
	}
	var spec *PackSpec
	for i := range layout.Packs {
		if layout.Packs[i].Name == pack {
			spec = &layout.Packs[i]
		}
	}
	if spec == nil {
		return 2, fmt.Errorf("unknown pack %q", pack)
	}
	rulesRaw, err := readBoundedFile(rulesFile, maxRulesFileBytes)
	if err != nil {
		return 2, err
	}
	ids, err := ParseRulesFile(rulesRaw)
	if err != nil {
		return 2, err
	}
	base, err := readBoundedFile(basePack, MaxFileBytes)
	if err != nil {
		return 2, err
	}
	head, err := readBoundedFile(headPack, MaxFileBytes)
	if err != nil {
		return 2, err
	}
	subjects, err := RuleApprovalSubjects(*spec, base, head, ids)
	if err != nil {
		return 2, err
	}
	digest := RulesListDigest(subjects)
	printRulesList(stdout, subjects, digest)
	if dryRun {
		fmt.Fprintln(stdout, "dry run: no key was read, nothing was written")
		return 0, nil
	}
	keys, err := loadKeysFile(keysPath, keysDigest)
	if err != nil {
		return 2, err
	}
	paths := make([]string, len(subjects))
	for i, s := range subjects {
		paths[i] = filepath.Join(outDir, s.RuleID+".json")
		if _, err := os.Lstat(paths[i]); err == nil {
			return 2, fmt.Errorf("%s already exists; remove the old approval first", logSafe(paths[i]))
		}
	}
	if expectCount != -1 {
		if expectCount != len(subjects) {
			return 2, fmt.Errorf("--expect-count is %d but the list holds %d rules; nothing was signed", expectCount, len(subjects))
		}
		if expectDigest != digest {
			return 2, errors.New("--expect-list-digest does not match the list digest above; nothing was signed")
		}
	} else {
		want := fmt.Sprintf("sign %d %s", len(subjects), rulesShortDigest(digest))
		line, err := env.confirm(fmt.Sprintf("Type %q to sign these %d approvals: ", want, len(subjects)))
		if err != nil {
			return 2, err
		}
		if line != want {
			return 2, errors.New("the confirmation does not match; nothing was signed")
		}
	}
	key, err := k.load(env)
	if err != nil {
		return 2, err
	}
	keyID := ApprovalKeyID(key.Public().(ed25519.PublicKey))
	raws, recs, err := SignApprovals(subjects, SignApprovalOptions{CandidateID: candidateID, Identity: identity, Keys: keys, Key: key, Now: env.now()})
	wipe(key)
	if err != nil {
		return 2, err
	}
	if err := writeApprovalFiles(outDir, ids, raws); err != nil {
		return 2, err
	}
	var pinned ApprovalKey
	for _, pk := range keys.Keys {
		if pk.KeyID == keyID {
			pinned = pk
		}
	}
	fmt.Fprintf(stdout, "approvals written: %d in %s\n", len(raws), logSafe(outDir))
	for _, rec := range recs {
		printApproval(stdout, rec, pinned)
	}
	return 0, nil
}

// writeApprovalFiles writes <ids[i]>.json with raws[i] into dir, all or
// none. Every file is first written (no-follow, exclusive) to a staging
// directory beside dir; the staging directory is renamed to dir when dir
// does not exist, else each file is hard-linked in (which never replaces a
// file) and the links are removed again when one fails. The staging
// directory is removed in every case.
func writeApprovalFiles(dir string, ids []string, raws [][]byte) error {
	if len(ids) != len(raws) || len(ids) == 0 {
		return errors.New("no approvals to write")
	}
	dir = filepath.Clean(dir)
	parent := filepath.Dir(dir)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := filepath.Join(parent, ".approval-stage-"+hex.EncodeToString(nonce[:]))
	defer func() { _ = os.RemoveAll(stage) }()
	for i, id := range ids {
		if err := writeApprovalFile(filepath.Join(stage, id+".json"), raws[i]); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.Rename(stage, dir); err != nil {
			return fmt.Errorf("cannot create %s: %w", logSafe(dir), err)
		}
		return nil
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", logSafe(dir))
	}
	var linked []string
	for _, id := range ids {
		final := filepath.Join(dir, id+".json")
		if err := os.Link(filepath.Join(stage, id+".json"), final); err != nil {
			for _, p := range linked {
				_ = os.Remove(p)
			}
			return fmt.Errorf("cannot create %s: %w; no approval was written", logSafe(final), err)
		}
		linked = append(linked, final)
	}
	return nil
}
