// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signing and checking batch approvals offline. The signer classifies the
// change with the gate's own code, builds the manifest, draws the review
// nonce, prints the summary the gate will render again, asks the owner to
// confirm on the terminal, signs, and runs the gate's offline batch checks
// on the result before it writes anything.

// SignBatchOptions is one batch to sign.
type SignBatchOptions struct {
	Draft    BatchRecord
	Identity string
	Keys     ApprovalKeys
	Key      ed25519.PrivateKey
	Now      time.Time
	// ValidFor is notAfter - decidedAt; zero means MaxBatchValidity.
	ValidFor time.Duration
}

// SignBatch signs a drafted batch and returns the file to commit. It
// refuses a key that is not pinned or has expired, an identity that is not
// a pinned owner and a validity over MaxBatchValidity.
func SignBatch(o SignBatchOptions) ([]byte, BatchRecord, error) {
	if len(o.Key) != ed25519.PrivateKeySize {
		return nil, BatchRecord{}, errors.New("the signing key is not an Ed25519 private key")
	}
	if o.Now.IsZero() {
		return nil, BatchRecord{}, errors.New("no signing time")
	}
	if o.ValidFor == 0 {
		o.ValidFor = MaxBatchValidity
	}
	if o.ValidFor < time.Minute || o.ValidFor > MaxBatchValidity {
		return nil, BatchRecord{}, errors.New("a batch is valid for one minute to 72 hours")
	}
	now := o.Now.UTC().Truncate(time.Second)
	keyID, err := checkBatchSigner(o.Keys, o.Key, o.Identity, now)
	if err != nil {
		return nil, BatchRecord{}, err
	}
	rec := o.Draft
	rec.Identity, rec.Decision = o.Identity, ApprovalDecisionApprove
	rec.DecidedAt = now.Format("2006-01-02T15:04:05Z")
	rec.NotAfter = now.Add(o.ValidFor).Format("2006-01-02T15:04:05Z")
	msg, err := SignedBatchBytes(rec)
	if err != nil {
		return nil, BatchRecord{}, err
	}
	env := BatchEnvelope{Schema: BatchSchema, Record: rec, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(o.Key, msg))}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, BatchRecord{}, err
	}
	return append(raw, '\n'), rec, nil
}

// checkBatchSigner refuses a key that is not pinned or has expired at now and
// an identity that is not a pinned owner, and returns the key id. The signing
// command runs it before it asks for the confirmation, so the owner is never
// asked about a batch that cannot be signed.
func checkBatchSigner(keys ApprovalKeys, key ed25519.PrivateKey, identity string, now time.Time) (string, error) {
	keyID := ApprovalKeyID(key.Public().(ed25519.PublicKey))
	var pinned *ApprovalKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == keyID {
			pinned = &keys.Keys[i]
		}
	}
	if pinned == nil {
		return "", fmt.Errorf("the signing key %s is not pinned in the approval key file", keyID)
	}
	if notAfter, err := time.Parse(time.RFC3339, pinned.NotAfter); err != nil || !now.Before(notAfter) {
		return "", fmt.Errorf("the signing key %s expired at %s", keyID, pinned.NotAfter)
	}
	owner := false
	for _, login := range keys.Owners {
		owner = owner || login == identity
	}
	if !owner {
		return "", fmt.Errorf("%s is not an owner in the approval key file", logSafe(identity))
	}
	return keyID, nil
}

// outsideBatchPaths lists the paths the change touches that a change
// carrying a batch may not: everything but the pack files, their corpus
// attestations, the generated support inventory and the batch file.
func outsideBatchPaths(layout Layout, base, head Tree, batchPath string) ([]string, error) {
	paths, err := ChangedPaths(base, head)
	if err != nil {
		return nil, err
	}
	allowed := batchAllowedPaths(layout, batchPath)
	var outside []string
	for _, p := range paths {
		if !allowed[p] {
			outside = append(outside, p)
		}
	}
	return outside, nil
}

// batchDirHeadroom is how many batch files below maxBatchFiles the signer
// still signs one more. Past it, every read of the directory would soon fail
// closed, so the owner prunes first (a batch file may be removed 14 days
// after it expired, see BatchRetention).
const batchDirHeadroom = 256

// batchDirRoom refuses to add a batch to a directory that is nearly full.
func batchDirRoom(layout Layout, trees ...Tree) error {
	for _, tr := range trees {
		entries, err := os.ReadDir(filepath.Join(tr.Root, filepath.FromSlash(layout.BatchDir)))
		if err != nil {
			continue // no directory yet
		}
		if len(entries) >= maxBatchFiles-batchDirHeadroom {
			return fmt.Errorf("%s holds %d batch files, close to the limit of %d the gate reads; remove the batches that expired more than 14 days ago first", logSafe(tr.Root), len(entries), maxBatchFiles)
		}
	}
	return nil
}

// confirmOnTTY asks on the controlling terminal (standard input carries the
// key) and returns the line typed.
func confirmOnTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("signing a batch needs a terminal to confirm on (/dev/tty)")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(io.LimitReader(tty, 256)).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no confirmation was typed")
	}
	return strings.TrimSpace(line), nil
}

// batchTrees reads the base and head checkouts the batch commands take: each
// must hold every pack file of the layout, so a wrong or empty directory is
// refused instead of being read as a tree with nothing in it.
func batchTrees(layout Layout, baseDir, headDir string) (Tree, Tree, error) {
	base, head := Tree{Root: baseDir}, Tree{Root: headDir}
	for _, spec := range layout.Packs {
		for _, side := range []struct {
			flag string
			tree Tree
		}{{"--base", base}, {"--head", head}} {
			if raw, err := side.tree.Read(spec.Path, MaxFileBytes); err != nil || raw == nil {
				return Tree{}, Tree{}, fmt.Errorf("%s %s holds no readable %s; give a repository checkout (or a tree written by gate export)", side.flag, logSafe(side.tree.Root), spec.Path)
			}
		}
	}
	return base, head, nil
}

func loadKeysFile(path, digest string) (ApprovalKeys, error) {
	raw, err := readBoundedFile(path, maxApprovalBytes*4)
	if err != nil {
		return ApprovalKeys{}, err
	}
	return LoadApprovalKeys(raw, digest)
}

// hasBatchFlag reports whether a command line selects the batch form.
func hasBatchFlag(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]; strings.HasPrefix(a, "-") && name == "batch" {
			return true
		}
	}
	return false
}

func cmdBatchSign(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var batchFlag bool
	var baseDir, headDir, batchID, candidateID, keysPath, keysDigest, identity, output, summaryOut string
	var validFor time.Duration
	var k keyFlags
	f := flag.NewFlagSet("approval sign --batch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolVar(&batchFlag, "batch", false, "sign a batch approval")
	f.StringVar(&baseDir, "base", "", "the base checkout")
	f.StringVar(&headDir, "head", "", "the proposed checkout")
	f.StringVar(&batchID, "batch-id", "", "the batch id, b-YYYYMMDD-N")
	f.StringVar(&candidateID, "candidate-id", "", "a reference for the change, for example its pull request")
	f.StringVar(&keysPath, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&keysDigest, "keys-digest", "", "the pinned digest of the key file")
	f.StringVar(&identity, "identity", "", "the owner's login, as pinned in the key file")
	f.StringVar(&output, "output", "", "the batch file to create (default: in the head's batch directory)")
	f.StringVar(&summaryOut, "summary-out", "", "also write the review summary to this new file")
	f.DurationVar(&validFor, "valid-for", MaxBatchValidity, "notAfter - decidedAt, at most 72h")
	k.register(f)
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if baseDir == "" || headDir == "" || batchID == "" || candidateID == "" || keysPath == "" || keysDigest == "" || identity == "" {
		return 2, usageError{"--base, --head, --batch-id, --candidate-id, --keys, --keys-digest and --identity are required"}
	}
	if !batchIDRE.MatchString(batchID) {
		return 2, errors.New("--batch-id must be b-YYYYMMDD-N")
	}
	if !approvalTokenRE.MatchString(candidateID) {
		return 2, errors.New("--candidate-id may hold letters, digits, '.', '_', ':' and '-' only")
	}
	if validFor < time.Minute || validFor > MaxBatchValidity {
		return 2, errors.New("--valid-for must be between 1m and 72h")
	}
	if layout.BatchDir == "" {
		return 2, errors.New("this layout has no batch directory")
	}
	if output == "" {
		output = filepath.Join(headDir, filepath.FromSlash(layout.BatchDir), batchID+".json")
	} else if filepath.Base(output) != batchID+".json" || filepath.Base(filepath.Dir(output)) != filepath.Base(layout.BatchDir) {
		return 2, fmt.Errorf("--output must end in %s/%s.json, the path the gate reads", filepath.Base(layout.BatchDir), batchID)
	}
	if _, err := os.Lstat(output); err == nil {
		return 2, fmt.Errorf("%s already exists; a batch file is never replaced", output)
	}
	if summaryOut != "" {
		if _, err := os.Lstat(summaryOut); err == nil {
			return 2, fmt.Errorf("%s already exists", summaryOut)
		}
	}
	base, head, err := batchTrees(layout, baseDir, headDir)
	if err != nil {
		return 2, err
	}
	// The gate refuses a batch change that touches anything but the packs,
	// their corpus attestations, the generated inventory and the batch file:
	// say so before a key use, a nonce and a confirmation are spent on it.
	outside, err := outsideBatchPaths(layout, base, head, layout.BatchDir+"/"+batchID+".json")
	if err != nil {
		return 2, err
	}
	if len(outside) > 0 {
		return 2, fmt.Errorf("the change also touches %d files a batch change may not touch%s", len(outside), listDetail(outside))
	}
	if err := batchDirRoom(layout, base, head); err != nil {
		return 2, err
	}
	keys, err := loadKeysFile(keysPath, keysDigest)
	if err != nil {
		return 2, err
	}
	cls, err := Classify(layout, base, head)
	if err != nil {
		return 2, err
	}
	st, err := newBatchState(layout, cls)
	if err != nil {
		return 2, err
	}
	if err := st.readyForBatch(); err != nil {
		return 2, err
	}
	key, err := k.load(env)
	if err != nil {
		return 2, err
	}
	defer wipe(key)
	if env.random == nil || env.confirm == nil {
		return 2, errors.New("no source of randomness or terminal to confirm on")
	}
	// The signer, the key and the validity window are settled and shown
	// before the owner is asked for anything: they are signed too.
	now := env.now().UTC().Truncate(time.Second)
	keyID, err := checkBatchSigner(keys, key, identity, now)
	if err != nil {
		return 2, err
	}
	nonceBytes := make([]byte, batchNonceHexBytes)
	if _, err := io.ReadFull(env.random, nonceBytes); err != nil {
		return 2, errors.New("the review nonce cannot be drawn")
	}
	nonce, err := batchNonce(nonceBytes)
	if err != nil {
		return 2, err
	}
	draft, summary, err := st.draftRecord(batchID, candidateID, nonce)
	if err != nil {
		return 2, err
	}
	fmt.Fprintln(stdout, summary)
	if summaryOut != "" {
		// Created exclusively, never through a symbolic link, like the
		// batch file.
		if err := writeApprovalFile(summaryOut, []byte(summary)); err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "review summary written: %s\n", logSafe(summaryOut))
	}
	notAfter := now.Add(validFor)
	// The prompt goes to the terminal, so it stays in front of the owner
	// whatever happens to standard output.
	prompt := fmt.Sprintf("Signer %s, key %s. Valid %s to %s (%s). %d entries become reviewed knowledge; read in full: sample %s, flagged %s; %d other changes are not approved.\nType the batch id %s to sign, anything else aborts: ",
		logSafe(identity), keyID, now.Format("2006-01-02T15:04:05Z"), notAfter.Format("2006-01-02T15:04:05Z"), validFor, len(draft.Entries),
		indexList(draft.Sample), indexList(st.flaggedIndexes(draft)), othersCount(st, draft), batchID)
	answer, err := env.confirm(prompt)
	if err != nil {
		return 2, err
	}
	if answer != batchID {
		return 2, errors.New("not confirmed; nothing was signed or written")
	}
	raw, rec, err := SignBatch(SignBatchOptions{Draft: draft, Identity: identity, Keys: keys, Key: key, Now: now, ValidFor: validFor})
	if err != nil {
		return 2, err
	}
	if _, err := verifyBatch(raw, batchID+".json", st, keys, now); err != nil {
		return 2, fmt.Errorf("the signed batch does not verify: %w", err)
	}
	used, err := (&baseApprovals{opts: Options{Base: base, Layout: layout}}).refuseBatch(mustDecodeBatch(raw))
	if err != nil {
		return 2, err
	}
	if used != "" {
		return 2, errors.New(used)
	}
	if err := writeApprovalFile(output, raw); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "batch approval written: %s\n", logSafe(output))
	printBatch(stdout, rec, keys, keyIDOf(raw))
	return 0, nil
}

// indexList formats entry numbers for the prompt.
func indexList(idx []int) string {
	if len(idx) == 0 {
		return "none"
	}
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = fmt.Sprintf("#%d", n)
	}
	return strings.Join(parts, " ")
}

func mustDecodeBatch(raw []byte) BatchEnvelope {
	env, _ := decodeBatch(raw)
	return env
}

func keyIDOf(raw []byte) string { return mustDecodeBatch(raw).KeyID }

func printBatch(w io.Writer, rec BatchRecord, keys ApprovalKeys, keyID string) {
	var key ApprovalKey
	for _, k := range keys.Keys {
		if k.KeyID == keyID {
			key = k
		}
	}
	fmt.Fprintf(w, "  batch      %s (candidate %s)\n", rec.BatchID, rec.CandidateID)
	fmt.Fprintf(w, "  entries    %d, sample %v\n", len(rec.Entries), rec.Sample)
	fmt.Fprintf(w, "  identity   %s\n", rec.Identity)
	fmt.Fprintf(w, "  key        %s\n", keyID)
	fmt.Fprintf(w, "  decided    %s, accepted until %s\n", rec.DecidedAt, batchUsableUntil(rec, key))
}

func cmdBatchVerify(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var batchFile, baseDir, headDir, keysPath, keysDigest, now string
	f := flag.NewFlagSet("approval verify --batch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&batchFile, "batch", "", "the batch approval file")
	f.StringVar(&baseDir, "base", "", "the base checkout")
	f.StringVar(&headDir, "head", "", "the proposed checkout")
	f.StringVar(&keysPath, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&keysDigest, "keys-digest", "", "the pinned digest of the key file")
	f.StringVar(&now, "now", "", "the clock, RFC 3339 UTC (default: now)")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if batchFile == "" || baseDir == "" || headDir == "" || keysPath == "" || keysDigest == "" {
		return 2, usageError{"--batch, --base, --head, --keys and --keys-digest are required"}
	}
	at := env.now()
	if now != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, now); err != nil || !strings.HasSuffix(now, "Z") {
			return 2, errors.New("--now must be RFC 3339 UTC")
		}
	}
	if layout.BatchDir == "" {
		return 2, errors.New("this layout has no batch directory")
	}
	base, head, err := batchTrees(layout, baseDir, headDir)
	if err != nil {
		return 2, err
	}
	keys, err := loadKeysFile(keysPath, keysDigest)
	if err != nil {
		return 2, err
	}
	raw, err := readBoundedFile(batchFile, maxBatchBytes+1)
	if err != nil {
		return 2, err
	}
	cls, err := Classify(layout, base, head)
	if err != nil {
		return 2, err
	}
	st, err := newBatchState(layout, cls)
	if err != nil {
		return 2, err
	}
	refused := func(why string) (int, error) {
		fmt.Fprintf(stdout, "batch REFUSED: %s\n", logSafe(why))
		return 1, nil
	}
	name := filepath.Base(batchFile)
	envl, err := verifyBatch(raw, name, st, keys, at)
	if err != nil {
		return refused(err.Error())
	}
	outside, err := outsideBatchPaths(layout, base, head, layout.BatchDir+"/"+name)
	if err != nil {
		return 2, err
	}
	if len(outside) > 0 {
		return refused(fmt.Sprintf("the change also touches %d files a batch change may not touch%s", len(outside), listDetail(outside)))
	}
	used, err := (&baseApprovals{opts: Options{Base: base, Layout: layout}}).refuseBatch(envl)
	if err != nil {
		return refused(err.Error())
	}
	if used != "" {
		return refused(used)
	}
	fmt.Fprintf(stdout, "batch OK: %s\n", logSafe(batchFile))
	printBatch(stdout, envl.Record, keys, envl.KeyID)
	fmt.Fprintln(stdout, "  not checked here (no network): the upstream verification of the entries' citations and the extractor cross-check of line attestations; the gate runs both and refuses the batch if either fails")
	return 0, nil
}
