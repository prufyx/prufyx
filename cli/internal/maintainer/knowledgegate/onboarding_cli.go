// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signing and checking onboarding batches offline. The signer takes the
// proposal's draft (batch id, candidate id, projects with their dry-run
// proofs and claims), computes everything else from the base and head
// checkouts with the gate's own code, runs every offline check (O1 to O5,
// O7), draws the review nonce, prints the summary the gate renders again,
// asks the owner to confirm on the terminal and signs. The dry run (O6) needs
// upstream and is run by the gate only.

// onboardingDraft is the unsigned proposal the signer reads.
type onboardingDraft struct {
	BatchID     string              `json:"batchId"`
	CandidateID string              `json:"candidateId"`
	Projects    []OnboardingProject `json:"projects"`
	// Additions names the kind-new projects whose release-line tag file and
	// additions entry the batch binds (onboarding v3, owner tier only). The
	// signer reads both digests from the head tree and prints them.
	Additions []string `json:"additions,omitempty"`
}

// hasFlag reports whether a command line names the flag.
func hasFlag(args []string, flagName string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]; strings.HasPrefix(a, "-") && name == flagName {
			return true
		}
	}
	return false
}

// prepareOnboarding fills a draft from the trees: the two states, the change
// set, the nonce and the sample, and runs the offline checks. The returned
// record still needs its identity, times and summary digest.
func prepareOnboarding(layout Layout, base, head Tree, draft onboardingDraft, nonce, batchPath string) (OnboardingRecord, *onboardingState, error) {
	cls, err := Classify(layout, base, head)
	if err != nil {
		return OnboardingRecord{}, nil, err
	}
	paths, err := ChangedPaths(base, head)
	if err != nil {
		return OnboardingRecord{}, nil, err
	}
	st, err := newOnboardingState(layout, base, head, cls, paths)
	if err != nil {
		return OnboardingRecord{}, nil, err
	}
	rec := OnboardingRecord{
		Base: st.base.state, Head: st.head.state, BatchID: draft.BatchID, CandidateID: draft.CandidateID,
		ChangeSetDigest: st.changeSetDigest, Nonce: nonce, Projects: draft.Projects,
	}
	if len(draft.Additions) > 0 {
		if rec.adds, err = additionsFromHead(head, draft.Additions); err != nil {
			return OnboardingRecord{}, nil, err
		}
	}
	if rec.Sample, err = recordSample(rec); err != nil {
		return OnboardingRecord{}, nil, err
	}
	if problems := st.check(rec, batchPath); len(problems) > 0 {
		return OnboardingRecord{}, nil, fmt.Errorf("the change is not an onboarding change this batch can admit: %d problems%s", len(problems), listDetail(problems))
	}
	return rec, st, nil
}

func cmdOnboardingSign(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var draftPath, baseDir, headDir, keysPath, keysDigest, identity, output, summaryOut string
	var validFor time.Duration
	var k keyFlags
	var admission admissionFlags
	var supervised supervisedFlags
	f := flag.NewFlagSet("approval sign --onboarding", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&draftPath, "onboarding", "", "the proposal's unsigned draft")
	f.StringVar(&baseDir, "base", "", "the base checkout")
	f.StringVar(&headDir, "head", "", "the proposed checkout")
	f.StringVar(&keysPath, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&keysDigest, "keys-digest", "", "the pinned digest of the key file")
	f.StringVar(&identity, "identity", "", "the owner's login, as pinned in the key file")
	f.StringVar(&output, "output", "", "the batch file to create (default: in the head's onboarding directory)")
	f.StringVar(&summaryOut, "summary-out", "", "also write the review summary to this new file")
	f.DurationVar(&validFor, "valid-for", MaxOnboardingValidity, "notAfter - decidedAt, at most 72h")
	k.register(f)
	admission.register(f)
	supervised.register(f)
	f.StringVar(&admission.expectedKey, "expected-key-id", "", "expected pinned public onboarding-bot key ID (no private-key derivation)")
	f.StringVar(&admission.export, "admission-export", "", "opaque retained plan/manifest/draft SHA256 bindings")
	f.StringVar(&admission.source, "admission-source", "", "pre-key upstream checks: github")
	f.IntVar(&admission.readyFD, "admission-ready-fd", -1, "dedicated supervisor write-only readiness pipe descriptor (not stdout or key stdin)")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	var rawDraft, rawKeys, rawExport []byte
	var err error
	provided := map[string]bool{}
	f.Visit(func(v *flag.Flag) { provided[v.Name] = true })
	if env.supervised == nil {
		for _, name := range []string{"admission-executable-sha256", "admission-draft-sha256", "admission-keys-sha256", "admission-export-sha256", "admission-daily-sha256"} {
			if provided[name] {
				return 2, errors.New("sealed input bindings require sign-supervised")
			}
		}
	}
	if env.supervised != nil {
		for _, name := range []string{"onboarding", "keys", "admission-export", "admission-daily-commits", "admission-ready-fd", "batch"} {
			if provided[name] {
				return 2, errors.New("supervised mode rejects pathname, batch and descriptor overrides")
			}
		}
		if !k.stdin || k.file != "" {
			return 2, errors.New("supervised bot mode requires only --key-stdin")
		}
		rawDraft, rawKeys, rawExport, admission.dailyRaw, err = env.supervised.read(supervised)
		if err != nil {
			return 2, err
		}
		admission.readyFD = 3
	}
	if (draftPath == "" && env.supervised == nil) || baseDir == "" || headDir == "" || (keysPath == "" && env.supervised == nil) || keysDigest == "" || identity == "" {
		return 2, usageError{"--onboarding, --base, --head, --keys, --keys-digest and --identity are required"}
	}
	if validFor < time.Minute || validFor > MaxOnboardingValidity {
		return 2, errors.New("--valid-for must be between 1m and 72h")
	}
	if layout.Onboarding.Dir == "" {
		return 2, errors.New("this layout has no onboarding directory")
	}
	if env.supervised == nil {
		rawDraft, err = readBoundedFile(draftPath, maxOnboardingBytes+1)
		if err != nil {
			return 2, err
		}
	}
	var draft onboardingDraft
	if err := strictDecode([]byte(strings.TrimSuffix(string(rawDraft), "\n")), &draft); err != nil {
		return 2, fmt.Errorf("the draft: %w", err)
	}
	if !onboardingIDRE.MatchString(draft.BatchID) {
		return 2, errors.New("the draft's batchId must be ob-YYYYMMDD-N")
	}
	name := draft.BatchID + ".json"
	if output == "" {
		output = filepath.Join(headDir, filepath.FromSlash(layout.Onboarding.Dir), name)
	} else if filepath.Base(output) != name || filepath.Base(filepath.Dir(output)) != filepath.Base(layout.Onboarding.Dir) {
		return 2, fmt.Errorf("--output must end in %s/%s, the path the gate reads", filepath.Base(layout.Onboarding.Dir), name)
	}
	for _, p := range []string{output, summaryOut} {
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			return 2, fmt.Errorf("%s already exists; it is never replaced", p)
		}
	}
	base, head, err := batchTrees(layout, baseDir, headDir)
	if err != nil {
		return 2, err
	}
	var keys ApprovalKeys
	if env.supervised != nil {
		keys, err = LoadApprovalKeys(rawKeys, keysDigest)
	} else {
		keys, err = loadKeysFile(keysPath, keysDigest)
	}
	if err != nil {
		return 2, err
	}
	var ready *os.File
	if env.supervised != nil && !keys.isBot(identity) {
		return 2, errors.New("supervised inputs are onboarding-bot only; no owner fallback")
	}
	if keys.isBot(identity) {
		if !k.stdin || k.file != "" {
			return 2, errors.New("bot v2 requires --key-stdin and a supervisor that refreshes live controls after admission readiness")
		}
		if admission.expectedKey == "" || (admission.export == "" && rawExport == nil) {
			return 2, errors.New("bot signing requires expected public key and complete v2 admission inputs")
		}
		if env.supervised != nil {
			ready = env.supervised.files[0]
		} else {
			if ready, err = claimOnboardingReadyPipe(admission.readyFD); err != nil {
				return 2, err
			}
			defer ready.Close()
		}
		info, err := ready.Stat()
		if err != nil {
			return 2, err
		}
		channels := []*os.File{os.Stdout, os.Stderr}
		if input, ok := env.stdin.(*os.File); ok {
			channels = append(channels, input)
		}
		for _, channel := range channels {
			other, err := channel.Stat()
			if err != nil {
				return 2, err
			}
			if os.SameFile(info, other) {
				return 2, errors.New("admission control, human output and key input must use separate pipes")
			}
		}
	} else if admission.readyFD != -1 {
		return 2, errors.New("admission readiness is bot-only")
	}
	if env.random == nil || env.confirm == nil {
		return 2, errors.New("no source of randomness or terminal to confirm on")
	}
	now := env.now().UTC().Truncate(time.Second)
	if !keys.isBot(identity) && !keys.isOwner(identity) {
		return 2, errors.New("identity is not pinned")
	}
	inputBase, inputHead := base, head
	var admissionOpts Options
	if keys.isBot(identity) {
		if admissionOpts, err = admission.signOptions(layout, base, head, keysDigest, now, env.onboardingSource); err != nil {
			return 2, err
		}
		if gh, ok := admissionOpts.Source.(*GitHubSource); ok {
			defer gh.Close()
		}
		var cleanup func()
		if base, head, cleanup, err = exportAdmissionTrees(context.Background(), admissionOpts.OnboardingGit); err != nil {
			return 2, err
		}
		defer cleanup()
		if err := equalAdmissionTrees(base, head, inputBase, inputHead); err != nil {
			return 2, err
		}
		// Prepare from owned object exports, never from a caller directory that
		// could change and be restored around a later equivalence check.
		admissionOpts.Base, admissionOpts.Head = base, head
	}
	nonceBytes := make([]byte, batchNonceHexBytes)
	if _, err := io.ReadFull(env.random, nonceBytes); err != nil {
		return 2, errors.New("the review nonce cannot be drawn")
	}
	nonce, err := batchNonce(nonceBytes)
	if err != nil {
		return 2, err
	}
	batchPath := layout.Onboarding.Dir + "/" + name
	rec, st, err := prepareOnboarding(layout, base, head, draft, nonce, batchPath)
	if err != nil {
		return 2, err
	}
	if paths, err := ChangedPaths(base, head); err != nil {
		return 2, err
	} else if why := onboardingModes(Options{Base: base, Head: head}, paths); why != "" {
		return 2, errors.New(why)
	}
	_, baseFiles, err := onboardingFiles(Options{Base: base, Head: head, Layout: layout})
	if err != nil {
		return 2, err
	}
	rec.Identity, rec.Decision = identity, ApprovalDecisionApprove
	rec.DecidedAt = now.Format("2006-01-02T15:04:05Z")
	rec.NotAfter = now.Add(validFor).Format("2006-01-02T15:04:05Z")
	envl := OnboardingEnvelope{Schema: OnboardingSchema, Record: rec}
	if len(rec.adds) > 0 {
		if keys.isBot(identity) {
			return 2, errors.New("onboarding v3 (additions) is owner-only; no bot fallback")
		}
		envl.Schema = OnboardingSchemaV3
	}
	if keys.isBot(identity) {
		raw := rawExport
		if env.supervised == nil {
			var readErr error
			raw, readErr = readBoundedFile(admission.export, maxOnboardingBytes)
			if readErr != nil {
				return 2, readErr
			}
		}
		var export OnboardingExportBinding
		if err := strictDecode(raw, &export); err != nil {
			return 2, err
		}
		if export.DraftDigest != CandidateDigest(rawDraft) {
			return 2, errors.New("draft byte binding differs")
		}
		if envl, err = prepareBotAdmission(context.Background(), admissionOpts, keys, rec, export, admission.expectedKey); err != nil {
			return 2, err
		}
		rec = envl.Record
	} else if admission.expectedKey != "" || admission.export != "" || admission.gitDir != "" {
		return 2, errors.New("v2 admission is bot-only; no owner fallback")
	}
	summary := st.envelopeSummary(envl)
	rec.SummaryDigest = CandidateDigest([]byte(summary))
	envl.Record = rec
	if why := refuseOnboarding(envl, baseFiles); why != "" {
		return 2, errors.New(why)
	}
	fmt.Fprintln(stdout, summary)
	if summaryOut != "" {
		if err := writeApprovalFile(summaryOut, []byte(summary)); err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "review summary written: %s\n", logSafe(summaryOut))
	}
	notAfter := now.Add(validFor)
	prompt := fmt.Sprintf("Signer %s. Valid %s to %s (%s). %d projects enter the catalogue; sample %s. The gate re-runs every project's dry run before it admits the batch.\nType the batch id %s to sign, anything else aborts: ",
		logSafe(identity), now.Format("2006-01-02T15:04:05Z"), notAfter.Format("2006-01-02T15:04:05Z"), validFor, len(rec.Projects), indexList(rec.Sample), draft.BatchID)
	answer, err := env.confirm(prompt)
	if err != nil {
		return 2, err
	}
	if answer != draft.BatchID {
		return 2, errors.New("not confirmed; nothing was signed or written")
	}
	if envl.binding != nil {
		admissionOpts.Now = env.now().UTC().Truncate(time.Second)
		if err := checkBotAdmission(context.Background(), envl, keys, admissionOpts, true); err != nil {
			return 2, err
		}
		if err := equalAdmissionTrees(base, head, inputBase, inputHead); err != nil {
			return 2, err
		}
		if err := writeOnboardingReadiness(ready, envl); err != nil {
			return 2, err
		}
	}
	key, err := k.load(env)
	if err != nil {
		return 2, err
	}
	defer wipe(key)
	keyID, err := checkOnboardingSigner(keys, key, identity, env.now().UTC())
	if err != nil {
		return 2, err
	}
	if envl.binding != nil && keyID != admission.expectedKey {
		return 2, errors.New("private key does not match expected admitted bot key")
	}
	verifiedAt := now
	if envl.binding != nil {
		// Key input may block after readiness. Check the actual local refs,
		// immutable objects, caller snapshots and clock again before signing.
		verifiedAt = env.now().UTC().Truncate(time.Second)
		admissionOpts.Now = verifiedAt
		if err := checkBotAdmission(context.Background(), envl, keys, admissionOpts, true); err != nil {
			return 2, err
		}
		if err := equalAdmissionTrees(base, head, inputBase, inputHead); err != nil {
			return 2, err
		}
	}
	rec.Identity, rec.Decision = identity, ApprovalDecisionApprove
	rec.DecidedAt = now.Format("2006-01-02T15:04:05Z")
	rec.NotAfter = notAfter.Format("2006-01-02T15:04:05Z")
	envl.Record = rec
	msg, err := signedOnboardingEnvelopeBytes(envl)
	if err != nil {
		return 2, err
	}
	envl.KeyID = keyID
	envl.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	raw, err := marshalOnboardingEnvelope(envl)
	if err != nil {
		return 2, err
	}
	raw = append(raw, '\n')
	if err := verifyOnboardingSignature(envl, keys, verifiedAt); err != nil {
		return 2, fmt.Errorf("the signed batch does not verify: %w", err)
	}
	if why := st.checkEnvelopeDigests(envl); why != "" {
		return 2, fmt.Errorf("the signed batch does not verify: %s", why)
	}
	if why := refuseOnboarding(envl, baseFiles); why != "" {
		return 2, errors.New(why)
	}
	if why := botOnboardingLimits(envl, keys, baseFiles, verifiedAt, false); why != "" {
		return 2, errors.New(why)
	}
	if err := writeApprovalFile(output, raw); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "onboarding batch written: %s\n", logSafe(output))
	fmt.Fprintf(stdout, "  batch      %s (candidate %s)\n  projects   %d, sample %v\n  identity   %s\n  key        %s\n  decided    %s, valid until %s\n",
		rec.BatchID, rec.CandidateID, len(rec.Projects), rec.Sample, rec.Identity, keyID, rec.DecidedAt, rec.NotAfter)
	return 0, nil
}

func cmdOnboardingVerify(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var file, baseDir, headDir, keysPath, keysDigest, now string
	var admission admissionFlags
	f := flag.NewFlagSet("approval verify --onboarding", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	admission.register(f)
	f.StringVar(&file, "onboarding", "", "the onboarding batch file")
	f.StringVar(&baseDir, "base", "", "the base checkout")
	f.StringVar(&headDir, "head", "", "the proposed checkout")
	f.StringVar(&keysPath, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&keysDigest, "keys-digest", "", "the pinned digest of the key file")
	f.StringVar(&now, "now", "", "the clock, RFC 3339 UTC (default: now)")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if file == "" || baseDir == "" || headDir == "" || keysPath == "" || keysDigest == "" {
		return 2, usageError{"--onboarding, --base, --head, --keys and --keys-digest are required"}
	}
	at := env.now()
	if now != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, now); err != nil || !strings.HasSuffix(now, "Z") {
			return 2, errors.New("--now must be RFC 3339 UTC")
		}
	}
	if layout.Onboarding.Dir == "" {
		return 2, errors.New("this layout has no onboarding directory")
	}
	base, head, err := batchTrees(layout, baseDir, headDir)
	if err != nil {
		return 2, err
	}
	keys, err := loadKeysFile(keysPath, keysDigest)
	if err != nil {
		return 2, err
	}
	raw, err := readBoundedFile(file, maxOnboardingBytes+1)
	if err != nil {
		return 2, err
	}
	refused := func(why string) (int, error) {
		fmt.Fprintf(stdout, "onboarding batch REFUSED: %s\n", logSafe(why))
		return 1, nil
	}
	envl, err := decodeOnboarding(raw)
	if err != nil {
		return refused(err.Error())
	}
	rec := envl.Record
	if filepath.Base(file) != rec.BatchID+".json" {
		return refused("the file is not named after its batch id")
	}
	if err := verifyOnboardingSignature(envl, keys, at); err != nil {
		return refused(err.Error())
	}
	opts := Options{Base: base, Head: head, Layout: layout}
	_, baseFiles, err := onboardingFiles(opts)
	if err != nil {
		return 2, err
	}
	if why := refuseOnboarding(envl, baseFiles); why != "" {
		return refused(why)
	}
	if why := botOnboardingLimits(envl, keys, baseFiles, at, false); why != "" {
		return refused(why)
	}
	if err := refuseNewBotV1(envl, keys); err != nil {
		return refused(err.Error())
	}
	if envl.binding != nil {
		g, err := admission.context()
		if err != nil {
			return refused(err.Error())
		}
		daily, err := admissionDailyWindow(context.Background(), g, at)
		if err != nil {
			return refused(err.Error())
		}
		count, err := DailyCount(context.Background(), layout, g.GitDir, daily, DefaultBotLogin)
		if err != nil {
			return refused(err.Error())
		}
		opts.Now, opts.ApprovalKeysDigest, opts.OnboardingGit = at, keysDigest, g
		opts.HeadSHA = g.HeadCommit
		opts.BotLogin, opts.MaxLoosening, opts.MaxWithdrawPercent, opts.MaxWithdrawProject = DefaultBotLogin, 200, 5, 20
		opts.MaxDailyLoosening, opts.DailyLoosening, opts.AdmissionRESTBudget = 50, &count, 900
		base, head, cleanup, err := exportAdmissionTrees(context.Background(), g)
		if err != nil {
			return refused(err.Error())
		}
		defer cleanup()
		if err := equalAdmissionTrees(base, head, opts.Base, opts.Head); err != nil {
			return refused(err.Error())
		}
		opts.Base, opts.Head = base, head
		if err := checkBotAdmission(context.Background(), envl, keys, opts, false); err != nil {
			return refused(err.Error())
		}
	}
	base, head = opts.Base, opts.Head
	cls, err := Classify(layout, base, head)
	if err != nil {
		return 2, err
	}
	paths, err := ChangedPaths(base, head)
	if err != nil {
		return 2, err
	}
	st, err := newOnboardingState(layout, base, head, cls, paths)
	if err != nil {
		return refused(err.Error())
	}
	if problems := st.check(rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json"); len(problems) > 0 {
		return refused(fmt.Sprintf("%d problems%s", len(problems), listDetail(problems)))
	}
	if why := onboardingModes(opts, paths); why != "" {
		return refused(why)
	}
	if why := st.checkEnvelopeDigests(envl); why != "" {
		return refused(why)
	}
	fmt.Fprintf(stdout, "onboarding batch OK: %s\n", logSafe(file))
	fmt.Fprintf(stdout, "  batch      %s (candidate %s)\n  projects   %d, sample %v\n  identity   %s\n  decided    %s, valid until %s\n",
		rec.BatchID, rec.CandidateID, len(rec.Projects), rec.Sample, rec.Identity, rec.DecidedAt, rec.NotAfter)
	fmt.Fprintln(stdout, "  not checked here (no network): the dry run of every project against upstream; the gate runs it and refuses the batch if it fails")
	return 0, nil
}
