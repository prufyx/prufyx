// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/sha1" // Legacy changed-line comparison only; SHA256/Git objects bind integrity.
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	OnboardingSchemaV2      = "prufyx.io/knowledge-onboarding-batch/v2"
	onboardingProfileSchema = "prufyx.io/published-gate-admission-profile/v1"
	admissionBaseRef        = "refs/admission/base"
	admissionHeadRef        = "refs/admission/head"
	maxAdmissionChanges     = 256
)

// PublishedGateProfile describes this implementation's existing narrow bot
// authority. It is computed from trusted code and the pinned BASE keyset, never
// loaded as an authorization policy from a proposed file.
type PublishedGateProfile struct {
	Schema             string `json:"schema"`
	Repository         string `json:"repository"`
	BaseCommit         string `json:"baseCommit"`
	BaseTree           string `json:"baseTree"`
	KeysDigest         string `json:"keysDigest"`
	Identity           string `json:"identity"`
	KeyID              string `json:"keyId"`
	KeyNotAfter        string `json:"keyNotAfter"`
	Tier               string `json:"tier"`
	Kind               string `json:"kind"`
	MaxProjects        int    `json:"maxProjects"`
	MaxBatchesWindow   int    `json:"maxBatchesWindow"`
	MaxProjectsWindow  int    `json:"maxProjectsWindow"`
	WindowSeconds      int64  `json:"windowSeconds"`
	MaxValiditySeconds int64  `json:"maxValiditySeconds"`
	KeyMarginSeconds   int64  `json:"keyMarginSeconds"`
	AutomationLogin    string `json:"automationLogin"`
	MaxLoosening       int    `json:"maxLoosening"`
	MaxWithdrawPercent int    `json:"maxWithdrawPercent"`
	MaxWithdrawProject int    `json:"maxWithdrawProject"`
	MaxDailyLoosening  int    `json:"maxDailyLoosening"`
	RESTBudget         int64  `json:"restBudget"`
	PauseRequiredFalse bool   `json:"pauseRequiredFalse"`
}

// OnboardingExportBinding commits opaque retained input identities. These are
// assertions about exact bytes, not public proof of a private producer's work.
type OnboardingExportBinding struct {
	PlanDigest     string `json:"planDigest"`
	ManifestDigest string `json:"manifestDigest"`
	DraftDigest    string `json:"draftDigest"`
	FactsDigest    string `json:"factsDigest"`
	BundleDigest   string `json:"bundleDigest"`
	ExportLineHash string `json:"exportLineHash"`
	PublicLineHash string `json:"publicLineHash"`
}

// OnboardingBlobSide includes explicit absence for added/deleted files.
type OnboardingBlobSide struct {
	Mode   string `json:"mode"`
	Blob   string `json:"blob"`
	Digest string `json:"digest"`
}

type OnboardingGitChange struct {
	Path   string             `json:"path"`
	Status string             `json:"status"`
	Base   OnboardingBlobSide `json:"base"`
	Head   OnboardingBlobSide `json:"head"`
}

type OnboardingAdmissionBinding struct {
	Profile        PublishedGateProfile    `json:"profile"`
	Export         OnboardingExportBinding `json:"export"`
	UnsignedCommit string                  `json:"unsignedCommit"`
	UnsignedTree   string                  `json:"unsignedTree"`
	Changes        []OnboardingGitChange   `json:"changes"`
	ObservedAt     string                  `json:"observedAt"`
	DailyCommits   []DailyCommit           `json:"dailyCommits"`
	DailyCount     int                     `json:"dailyCount"`
	HistoryDigest  string                  `json:"historyDigest"`
}

// Separate v2 types keep every v1 signed byte and domain unchanged.
type OnboardingRecordV2 struct {
	AdmissionBinding OnboardingAdmissionBinding `json:"admissionBinding"`
	OnboardingRecord
}

type OnboardingEnvelopeV2 struct {
	Schema    string             `json:"schema"`
	Record    OnboardingRecordV2 `json:"record"`
	KeyID     string             `json:"keyId"`
	Signature string             `json:"signature"`
}

// OnboardingGitContext is supplied by the trusted fetch/clock/pause boundary.
// Fixed refs must be populated by authenticated fetches, never FETCH_HEAD.
// The public verifier validates all objects and metadata against those refs;
// it cannot authenticate the transport or refresh GitHub variables offline.
type OnboardingGitContext struct {
	GitDir       string
	BaseCommit   string
	HeadCommit   string
	DailyCommits []DailyCommit
	Paused       *bool
	ObservedAt   time.Time
}

func SignedOnboardingV2Bytes(r OnboardingRecordV2) ([]byte, error) {
	if err := r.OnboardingRecord.validate(); err != nil {
		return nil, err
	}
	if err := r.AdmissionBinding.validate(); err != nil {
		return nil, err
	}
	if r.DecidedAt != r.AdmissionBinding.ObservedAt {
		return nil, errors.New("admission observation must equal decision time")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(OnboardingSchemaV2+"\x00"), raw...), nil
}

func signedOnboardingEnvelopeBytes(e OnboardingEnvelope) ([]byte, error) {
	if e.Schema == OnboardingSchemaV3 {
		if e.binding != nil {
			return nil, errors.New("inconsistent onboarding schema/binding")
		}
		return SignedOnboardingV3Bytes(joinV3(e.Record))
	}
	if len(e.Record.adds) != 0 {
		return nil, errors.New("only onboarding v3 carries additions")
	}
	if e.Schema == OnboardingSchemaV2 && e.binding != nil {
		return SignedOnboardingV2Bytes(OnboardingRecordV2{AdmissionBinding: *e.binding, OnboardingRecord: e.Record})
	}
	if e.Schema != OnboardingSchema || e.binding != nil {
		return nil, errors.New("inconsistent onboarding schema/binding")
	}
	return SignedOnboardingBytes(e.Record)
}

func (b OnboardingAdmissionBinding) validate() error {
	if !shaRE.MatchString(b.Profile.BaseCommit) || !shaRE.MatchString(b.Profile.BaseTree) ||
		!shaRE.MatchString(b.UnsignedCommit) || !shaRE.MatchString(b.UnsignedTree) ||
		!validBatchDigest(b.Export.PlanDigest) || !validBatchDigest(b.Export.ManifestDigest) ||
		!validBatchDigest(b.Export.DraftDigest) || !validBatchDigest(b.HistoryDigest) ||
		!validBatchDigest(b.Export.FactsDigest) || !validBatchDigest(b.Export.BundleDigest) ||
		!shaRE.MatchString(b.Export.ExportLineHash) || !shaRE.MatchString(b.Export.PublicLineHash) ||
		len(b.Changes) == 0 || len(b.Changes) > maxAdmissionChanges || b.DailyCommits == nil || len(b.DailyCommits) > MaxDailyCommits {
		return errors.New("onboarding admission binding missing or out of range")
	}
	at, err := time.Parse(time.RFC3339, b.ObservedAt)
	if err != nil || at.Format("2006-01-02T15:04:05Z") != b.ObservedAt {
		return errors.New("invalid admission clock")
	}
	for i, c := range b.Changes {
		if !validOnboardingPath(c.Path) || (i > 0 && b.Changes[i-1].Path >= c.Path) || (c.Status != "A" && c.Status != "M") || c.Head.Mode != "100644" || !shaRE.MatchString(c.Head.Blob) || !validBatchDigest(c.Head.Digest) {
			return errors.New("invalid admission change vector")
		}
		if c.Status == "A" {
			if c.Base != (OnboardingBlobSide{}) {
				return errors.New("added file has a base")
			}
		} else if c.Base.Mode != "100644" || !shaRE.MatchString(c.Base.Blob) || !validBatchDigest(c.Base.Digest) {
			return errors.New("invalid admission base blob")
		}
	}
	for i, c := range b.DailyCommits {
		if !shaRE.MatchString(c.SHA) || c.Parent == nil || !shaRE.MatchString(*c.Parent) || (i > 0 && b.DailyCommits[i-1].SHA >= c.SHA) {
			return errors.New("daily commit observations must be complete, unique and sorted")
		}
	}
	return nil
}

func admissionSample(r OnboardingRecord, b OnboardingAdmissionBinding) ([]int, error) {
	raw, err := json.Marshal(struct {
		Binding OnboardingAdmissionBinding `json:"admissionBinding"`
		Core    onboardingCore             `json:"core"`
	}{b, r.core()})
	if err != nil {
		return nil, err
	}
	return onboardingSampleBytes(raw, OnboardingSchemaV2+"/sample\x00", len(r.Projects))
}

func (st *onboardingState) envelopeSummary(e OnboardingEnvelope) string {
	if e.Schema == OnboardingSchemaV3 {
		return st.summary(e.Record) + additionsSummary(e.Record)
	}
	s := st.summary(e.Record)
	if e.binding != nil {
		s = st.summaryForTier(e.Record, true)
		raw, _ := json.Marshal(e.binding)
		s += "\n## Admission binding (v2)\n\n```json\n" + string(raw) + "\n```\n"
	}
	return s
}

func (st *onboardingState) checkEnvelopeDigests(e OnboardingEnvelope) string {
	if e.Schema == OnboardingSchemaV3 {
		if e.binding != nil || len(e.Record.adds) == 0 {
			return "the v3 binding is inconsistent"
		}
		if e.Record.ChangeSetDigest != st.changeSetDigest {
			return "the change set differs from the one the batch was signed for"
		}
		sample, err := recordSample(e.Record)
		if err != nil {
			return err.Error()
		}
		if !equalInts(sample, e.Record.Sample) {
			return "the sample is not the one drawn from the manifest"
		}
		if CandidateDigest([]byte(st.envelopeSummary(e))) != e.Record.SummaryDigest {
			return "the summary digest does not match the summary of this change"
		}
		return ""
	}
	if e.binding == nil {
		return st.checkDigests(e.Record)
	}
	if e.Record.ChangeSetDigest != st.changeSetDigest {
		return "the change set differs from the one the batch was signed for"
	}
	sample, err := admissionSample(e.Record, *e.binding)
	if err != nil {
		return err.Error()
	}
	if !equalInts(sample, e.Record.Sample) {
		return "the sample differs from the v2 binding"
	}
	if CandidateDigest([]byte(st.envelopeSummary(e))) != e.Record.SummaryDigest {
		return "the summary differs from the v2 binding"
	}
	return ""
}

func admissionGit(ctx context.Context, g *OnboardingGitContext, args ...string) ([]byte, error) {
	if g == nil || g.GitDir == "" {
		return nil, errors.New("onboarding requires authenticated Git context")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, ExportOptions{Git: "git", GitDir: g.GitDir}, append([]string{"--no-replace-objects"}, args...)...)
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil || len(raw) > MaxFileBytes {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("admission Git output bound")
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("admission Git command: %w", err)
	}
	return raw, nil
}

func admissionObject(ctx context.Context, g *OnboardingGitContext, rev string) (string, error) {
	b, err := admissionGit(ctx, g, "rev-parse", "--verify", rev)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if !shaRE.MatchString(s) {
		return "", errors.New("invalid admission object")
	}
	return s, nil
}

func checkAdmissionRefs(ctx context.Context, g *OnboardingGitContext) error {
	if g == nil || !shaRE.MatchString(g.BaseCommit) || !shaRE.MatchString(g.HeadCommit) {
		return errors.New("missing admission commits")
	}
	for _, p := range [][2]string{{admissionBaseRef, g.BaseCommit}, {admissionHeadRef, g.HeadCommit}} {
		s, err := admissionObject(ctx, g, p[0]+"^{commit}")
		if err != nil || s != p[1] {
			return errors.New("admission reference moved or missing")
		}
	}
	_, err := admissionGit(ctx, g, "merge-base", "--is-ancestor", g.BaseCommit, g.HeadCommit)
	return err
}

func admissionChanges(ctx context.Context, g *OnboardingGitContext, head string) ([]OnboardingGitChange, error) {
	raw, err := admissionGit(ctx, g, "diff", "--no-ext-diff", "--no-textconv", "--raw", "-z", "--no-abbrev", "--no-renames", g.BaseCommit, head, "--")
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) == 0 || len(parts[len(parts)-1]) != 0 {
		return nil, errors.New("invalid raw Git diff")
	}
	parts = parts[:len(parts)-1]
	if len(parts) == 0 || len(parts)%2 != 0 || len(parts) > 2*maxAdmissionChanges {
		return nil, errors.New("admission change bound")
	}
	var out []OnboardingGitChange
	for i := 0; i < len(parts); i += 2 {
		m := strings.Fields(strings.TrimPrefix(string(parts[i]), ":"))
		if len(m) != 5 {
			return nil, errors.New("invalid Git change")
		}
		c := OnboardingGitChange{Path: string(parts[i+1]), Status: m[4]}
		if !validOnboardingPath(c.Path) || (c.Status != "A" && c.Status != "M") || m[1] != "100644" {
			return nil, errors.New("onboarding changes only regular added/modified data")
		}
		for j, side := range []*OnboardingBlobSide{&c.Base, &c.Head} {
			if j == 0 && c.Status == "A" {
				continue
			}
			side.Mode, side.Blob = m[j], m[j+2]
			if side.Mode != "100644" || !shaRE.MatchString(side.Blob) {
				return nil, errors.New("invalid Git blob/mode")
			}
			size, err := admissionGit(ctx, g, "cat-file", "-s", side.Blob)
			if err != nil {
				return nil, err
			}
			var n int64
			if _, err := fmt.Sscan(string(size), &n); err != nil || n < 0 || n > MaxFileBytes {
				return nil, errors.New("admission blob size bound")
			}
			blob, err := admissionGit(ctx, g, "cat-file", "blob", side.Blob)
			if err != nil || int64(len(blob)) != n {
				return nil, errors.New("cannot read admission blob")
			}
			side.Digest = CandidateDigest(blob)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func publishedProfile(keys ApprovalKeys, digest, identity, kid, base, tree string, now time.Time) (PublishedGateProfile, error) {
	k := keys.keyByID(kid)
	if k == nil || !k.botTier() || !keys.isBot(identity) || keys.isOwner(identity) {
		return PublishedGateProfile{}, errors.New("expected pinned bot key and identity required")
	}
	active := 0
	for _, candidate := range keys.Keys {
		until, err := time.Parse(time.RFC3339, candidate.NotAfter)
		if candidate.botTier() && err == nil && until.After(now) {
			active++
		}
	}
	until, err := time.Parse(time.RFC3339, k.NotAfter)
	if active != 1 || err != nil || !until.After(now.Add(4*24*time.Hour)) {
		return PublishedGateProfile{}, errors.New("ambiguous or expiring bot key")
	}
	return PublishedGateProfile{Schema: onboardingProfileSchema, Repository: "prufyx/prufyx", BaseCommit: base, BaseTree: tree, KeysDigest: digest, Identity: identity, KeyID: kid, KeyNotAfter: k.NotAfter, Tier: ApprovalTierOnboardingBot, Kind: OnboardingKindNew, MaxProjects: MaxBotOnboardingProjects, MaxBatchesWindow: MaxBotBatchesWeek, MaxProjectsWindow: MaxBotProjectsWeek, WindowSeconds: int64(BotOnboardingWindow / time.Second), MaxValiditySeconds: int64(MaxOnboardingValidity / time.Second), KeyMarginSeconds: 4 * 24 * 3600, AutomationLogin: DefaultBotLogin, MaxLoosening: 200, MaxWithdrawPercent: 5, MaxWithdrawProject: 20, MaxDailyLoosening: 50, RESTBudget: 900, PauseRequiredFalse: true}, nil
}

func canonicalEqual(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func onboardingLineHash(patch []byte) string {
	h := sha1.New()
	for _, line := range bytes.Split(patch, []byte{'\n'}) {
		if len(line) == 0 || (line[0] != '+' && line[0] != '-') {
			continue
		}
		if len(line) > 1 && (line[1] == '+' || line[1] == '-') {
			continue
		}
		_, _ = h.Write(line)
		_, _ = h.Write([]byte{'\n'})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// checkBotAdmission is shared by pre-key preparation and signed gate admission.
// Signature verification is deliberately a separate operation.
func checkBotAdmission(ctx context.Context, e OnboardingEnvelope, keys ApprovalKeys, opts Options, prekey bool) error {
	if e.Schema != OnboardingSchemaV2 || e.binding == nil {
		return errors.New("new bot approvals require onboarding v2")
	}
	b := e.binding
	if err := b.validate(); err != nil {
		return err
	}
	if err := e.Record.validate(); err != nil {
		return err
	}
	if _, err := SignedOnboardingV2Bytes(OnboardingRecordV2{AdmissionBinding: *b, OnboardingRecord: e.Record}); err != nil {
		return err
	}
	expected := keys.keyByID(e.KeyID)
	if expected == nil || !expected.botTier() {
		return errors.New("expected pinned bot-tier key required before admission")
	}
	if err := checkOnboardingTier(*expected, keys, e.Record); err != nil {
		return err
	}
	if e.Record.Decision != ApprovalDecisionApprove {
		return errors.New("admission decision must approve")
	}
	decided, err := time.Parse(time.RFC3339, e.Record.DecidedAt)
	if err != nil || decided.After(opts.Now.Add(approvalClockSkew)) {
		return errors.New("invalid admission decision time")
	}
	until, err := time.Parse(time.RFC3339, e.Record.NotAfter)
	if err != nil || !until.After(opts.Now) || until.Sub(decided) > MaxOnboardingValidity || !until.After(decided) {
		return errors.New("invalid admission validity window")
	}
	g := opts.OnboardingGit
	if err := checkAdmissionRefs(ctx, g); err != nil {
		return err
	}
	baseSnapshot, headSnapshot, cleanup, err := exportAdmissionTrees(ctx, g)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := equalAdmissionTrees(baseSnapshot, headSnapshot, opts.Base, opts.Head); err != nil {
		return err
	}
	opts.Base, opts.Head = baseSnapshot, headSnapshot
	if g.Paused == nil || *g.Paused || opts.BotSignerPaused || g.ObservedAt.IsZero() || g.ObservedAt.After(opts.Now.Add(approvalClockSkew)) || opts.Now.Sub(g.ObservedAt) > 5*time.Minute {
		return errors.New("pause/clock observation missing, stale or paused")
	}
	if opts.Shadow || opts.MaxLoosening != 200 || opts.MaxWithdrawPercent != 5 || opts.MaxWithdrawProject != 20 || opts.MaxDailyLoosening != 50 || opts.BotLogin != DefaultBotLogin || opts.AdmissionRESTBudget != 900 || opts.DailyLoosening == nil {
		return errors.New("published admission guard options missing or changed")
	}
	unsigned := g.HeadCommit
	if !prekey {
		if opts.HeadSHA != g.HeadCommit {
			return errors.New("checked head differs from authenticated approval commit")
		}
		parents, err := admissionGit(ctx, g, "show", "-s", "--format=%P", g.HeadCommit)
		if err != nil || strings.Fields(string(parents)) == nil || len(strings.Fields(string(parents))) != 1 {
			return errors.New("approval must have exactly one parent")
		}
		unsigned = strings.TrimSpace(string(parents))
		added, err := admissionGit(ctx, g, "diff", "--no-ext-diff", "--no-textconv", "--name-status", "--no-renames", unsigned, g.HeadCommit, "--")
		if err != nil || string(added) != "A\t"+opts.Layout.Onboarding.Dir+"/"+e.Record.BatchID+".json\n" {
			return errors.New("approval commit must add only its batch file")
		}
		listing, err := admissionGit(ctx, g, "ls-tree", "-r", "-l", "-z", "--full-tree", g.HeadCommit, "--", opts.Layout.Onboarding.Dir+"/"+e.Record.BatchID+".json")
		if err != nil {
			return err
		}
		entries, err := parseLsTree(listing)
		if err != nil || len(entries) != 1 || entries[0].mode != "100644" {
			return errors.New("approval batch must be a regular non-executable blob")
		}
		raw, err := admissionGit(ctx, g, "show", g.HeadCommit+":"+opts.Layout.Onboarding.Dir+"/"+e.Record.BatchID+".json")
		if err != nil {
			return errors.New("approval blob missing")
		}
		actual, err := decodeOnboarding(raw)
		if err != nil {
			return err
		}
		want, _ := marshalOnboardingEnvelope(e)
		have, _ := marshalOnboardingEnvelope(actual)
		if !bytes.Equal(want, have) {
			return errors.New("verified envelope differs from approval Git blob")
		}
	}
	if unsigned != b.UnsignedCommit || b.Profile.BaseCommit != g.BaseCommit {
		return errors.New("admission commit binding differs")
	}
	merges, err := admissionGit(ctx, g, "rev-list", "--merges", g.BaseCommit+".."+unsigned)
	if err != nil || len(bytes.TrimSpace(merges)) != 0 {
		return errors.New("unsigned candidate contains merge commits")
	}
	baseTree, err := admissionObject(ctx, g, g.BaseCommit+"^{tree}")
	if err != nil {
		return err
	}
	headTree, err := admissionObject(ctx, g, unsigned+"^{tree}")
	if err != nil || headTree != b.UnsignedTree {
		return errors.New("unsigned tree binding differs")
	}
	keyRaw, err := admissionGit(ctx, g, "show", g.BaseCommit+":"+opts.Layout.ApprovalKeysPath)
	if err != nil || pinnedDigest(keyRaw) != opts.ApprovalKeysDigest {
		return errors.New("BASE Git keyset does not match pin")
	}
	actualKeys, err := ParseApprovalKeys(keyRaw)
	if err != nil || !canonicalEqual(actualKeys, keys) {
		return errors.New("BASE keyset differs from admission keys")
	}
	profile, err := publishedProfile(keys, opts.ApprovalKeysDigest, e.Record.Identity, e.KeyID, g.BaseCommit, baseTree, opts.Now)
	if err != nil {
		return err
	}
	if !canonicalEqual(profile, b.Profile) {
		return errors.New("published admission profile differs from trusted code/pins")
	}
	changes, err := admissionChanges(ctx, g, unsigned)
	if err != nil {
		return err
	}
	if !canonicalEqual(changes, b.Changes) {
		return errors.New("complete public path/mode/blob vector differs")
	}
	patch, err := admissionGit(ctx, g, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", g.BaseCommit, unsigned, "--")
	if err != nil {
		return err
	}
	if onboardingLineHash(patch) != b.Export.PublicLineHash {
		return errors.New("public line hash differs")
	}
	for _, c := range changes {
		for _, s := range []struct {
			tr   Tree
			side OnboardingBlobSide
		}{{opts.Base, c.Base}, {opts.Head, c.Head}} {
			if s.side.Blob == "" {
				if s.tr.Exists(c.Path) {
					return errors.New("absent Git side exists in input tree")
				}
				continue
			}
			raw, err := s.tr.Read(c.Path, MaxFileBytes)
			if err != nil || CandidateDigest(raw) != s.side.Digest || s.tr.executable(c.Path) {
				return errors.New("input trees differ from bound Git blobs")
			}
		}
	}
	if err := checkAdmissionDaily(ctx, g, b, opts); err != nil {
		return err
	}
	limits, err := Limits(opts)
	if err != nil {
		return err
	}
	if !limits.Passed() {
		return errors.New("admission limits or withdrawal breaker failed")
	}
	_, baseFiles, err := onboardingFiles(opts)
	if err != nil {
		return err
	}
	for name, raw := range baseFiles {
		historical, err := decodeOnboarding(raw)
		if err != nil {
			return fmt.Errorf("unreadable historical batch %s", logSafe(name))
		}
		if err := historical.Record.validate(); err != nil {
			return errors.New("invalid historical admission record")
		}
		gitRaw, err := admissionGit(ctx, g, "show", g.BaseCommit+":"+opts.Layout.Onboarding.Dir+"/"+name)
		if err != nil || !bytes.Equal(gitRaw, raw) {
			return errors.New("BASE batch history differs from Git")
		}
	}
	history, err := admissionGit(ctx, g, "ls-tree", "--name-only", g.BaseCommit+":"+opts.Layout.Onboarding.Dir)
	if err != nil && len(baseFiles) != 0 {
		return errors.New("cannot authenticate BASE history")
	}
	if len(strings.Fields(string(history))) != len(baseFiles) {
		return errors.New("BASE history incomplete")
	}
	hash, err := domainDigest(OnboardingSchemaV2+"/history\x00", baseFiles)
	if err != nil || hash != b.HistoryDigest {
		return errors.New("BASE history binding differs")
	}
	if err := checkOnboardingTier(*keys.keyByID(e.KeyID), keys, e.Record); err != nil {
		return err
	}
	if why := botOnboardingLimits(e, keys, baseFiles, opts.Now, false); why != "" {
		return errors.New(why)
	}
	if why := refuseOnboarding(e, baseFiles); why != "" {
		return errors.New(why)
	}
	return checkAdmissionRefs(ctx, g)
}

func exportAdmissionTrees(ctx context.Context, g *OnboardingGitContext) (Tree, Tree, func(), error) {
	if err := checkAdmissionRefs(ctx, g); err != nil {
		return Tree{}, Tree{}, nil, err
	}
	dir, err := os.MkdirTemp("", "onboarding-git-trees-")
	if err != nil {
		return Tree{}, Tree{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	for i, commit := range []string{g.BaseCommit, g.HeadCommit} {
		out := filepath.Join(dir, fmt.Sprint(i))
		if err := Export(ctx, ExportOptions{GitDir: g.GitDir, Commit: commit, Out: out}); err != nil {
			cleanup()
			return Tree{}, Tree{}, nil, err
		}
	}
	if err := checkAdmissionRefs(ctx, g); err != nil {
		cleanup()
		return Tree{}, Tree{}, nil, err
	}
	return Tree{Root: filepath.Join(dir, "0")}, Tree{Root: filepath.Join(dir, "1")}, cleanup, nil
}

func equalAdmissionTrees(base, head, inputBase, inputHead Tree) error {
	for _, pair := range [][2]Tree{{base, inputBase}, {head, inputHead}} {
		paths, err := ChangedPaths(pair[0], pair[1])
		if err != nil {
			return err
		}
		if len(paths) != 0 {
			return errors.New("input snapshot differs from complete authenticated Git tree")
		}
	}
	return nil
}

func admissionDailyWindow(ctx context.Context, g *OnboardingGitContext, at time.Time) ([]DailyCommit, error) {
	// Authenticate completeness and parent identities; login observations originate
	// at the trusted API boundary, not from commit author-email strings.
	list, err := admissionGit(ctx, g, "rev-list", "--parents", "--since-as-filter="+at.Add(-24*time.Hour).Format(time.RFC3339), g.BaseCommit)
	if err != nil {
		return nil, err
	}
	lines := strings.FieldsFunc(strings.TrimSpace(string(list)), func(r rune) bool { return r == '\n' })
	if len(lines) > MaxDailyCommits {
		return nil, errors.New("daily history oversized")
	}
	observed := map[string]DailyCommit{}
	for _, c := range g.DailyCommits {
		if _, ok := observed[c.SHA]; ok {
			return nil, errors.New("duplicate observed daily commit")
		}
		observed[c.SHA] = c
	}
	selected := []DailyCommit{}
	for _, line := range lines {
		p := strings.Fields(line)
		if len(p) < 2 {
			return nil, errors.New("daily history has no parent")
		}
		c, ok := observed[p[0]]
		if !ok || c.Parent == nil || *c.Parent != p[1] {
			return nil, errors.New("daily history observation missing or parent mismatch")
		}
		selected = append(selected, c)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].SHA < selected[j].SHA })
	return selected, nil
}

func checkAdmissionDaily(ctx context.Context, g *OnboardingGitContext, b *OnboardingAdmissionBinding, opts Options) error {
	at, err := time.Parse(time.RFC3339, b.ObservedAt)
	if err != nil || at.After(opts.Now.Add(approvalClockSkew)) || opts.Now.Sub(at) > MaxOnboardingValidity {
		return errors.New("admission daily observation stale")
	}
	signedWindow, err := admissionDailyWindow(ctx, g, at)
	if err != nil {
		return err
	}
	if !canonicalEqual(signedWindow, b.DailyCommits) {
		return errors.New("signed daily author observations differ")
	}
	count, err := DailyCount(ctx, opts.Layout, g.GitDir, b.DailyCommits, DefaultBotLogin)
	if err != nil {
		return err
	}
	if count != b.DailyCount {
		return errors.New("signed daily loosening count differs")
	}
	current, err := admissionDailyWindow(ctx, g, opts.Now)
	if err != nil {
		return err
	}
	currentCount, err := DailyCount(ctx, opts.Layout, g.GitDir, current, DefaultBotLogin)
	if err != nil {
		return err
	}
	if opts.DailyLoosening == nil || currentCount != *opts.DailyLoosening {
		return errors.New("current daily loosening count differs")
	}
	cls, err := Classify(opts.Layout, opts.Base, opts.Head)
	if err != nil {
		return err
	}
	_, loose := cls.Counts()
	if loose != 0 && currentCount+loose > 50 {
		return errors.New("daily loosening cap exceeded")
	}
	return nil
}

func refuseNewBotV1(e OnboardingEnvelope, keys ApprovalKeys) error {
	if key := keys.keyByID(e.KeyID); key != nil && key.botTier() && e.Schema != OnboardingSchemaV2 {
		return errors.New("new bot approvals require onboarding v2")
	}
	if e.Schema == OnboardingSchemaV2 {
		if key := keys.keyByID(e.KeyID); key == nil || !key.botTier() {
			return errors.New("onboarding v2 is bot-only")
		}
	}
	return nil
}
