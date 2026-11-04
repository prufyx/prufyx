// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

type admissionFlags struct {
	gitDir, base, head, daily, paused, observed, expectedKey, export, source string
	readyFD                                                                  int
}

func (a *admissionFlags) register(f *flag.FlagSet) {
	f.StringVar(&a.gitDir, "admission-git-dir", "", "authenticated object store with refs/admission/base and refs/admission/head")
	f.StringVar(&a.base, "admission-base", "", "authenticated exact BASE commit")
	f.StringVar(&a.head, "admission-head", "", "authenticated exact proposed commit")
	f.StringVar(&a.daily, "admission-daily-commits", "", "complete authenticated daily commit/author observations")
	f.StringVar(&a.paused, "admission-paused", "", "fresh authenticated pause value, exactly false required")
	f.StringVar(&a.observed, "admission-observed-at", "", "capture time of authenticated job observations, not a live-variable check (RFC3339 UTC)")
}

func (a admissionFlags) context() (*OnboardingGitContext, error) {
	if a.gitDir == "" || a.base == "" || a.head == "" || a.daily == "" || a.observed == "" || a.paused != "false" {
		return nil, errors.New("complete authenticated admission context and pause=false required")
	}
	raw, err := readBoundedFile(a.daily, maxDailyCommitsFile)
	if err != nil {
		return nil, err
	}
	daily, err := ParseDailyCommits(raw)
	if err != nil || daily == nil {
		return nil, errors.New("complete daily history required")
	}
	at, err := time.Parse(time.RFC3339, a.observed)
	if err != nil || at.Format("2006-01-02T15:04:05Z") != a.observed {
		return nil, errors.New("invalid admission observation time")
	}
	paused := false
	return &OnboardingGitContext{GitDir: a.gitDir, BaseCommit: a.base, HeadCommit: a.head, DailyCommits: daily, Paused: &paused, ObservedAt: at}, nil
}

func (a admissionFlags) signOptions(layout Layout, base, head Tree, keysDigest string, now time.Time, fixture Source) (Options, error) {
	g, err := a.context()
	if err != nil {
		return Options{}, err
	}
	daily, err := admissionDailyWindow(context.Background(), g, now)
	if err != nil {
		return Options{}, err
	}
	count, err := DailyCount(context.Background(), layout, g.GitDir, daily, DefaultBotLogin)
	if err != nil {
		return Options{}, err
	}
	opts := Options{Layout: layout, Base: base, Head: head, Now: now, ApprovalKeysDigest: keysDigest, OnboardingGit: g,
		BotLogin: DefaultBotLogin, MaxLoosening: 200, MaxWithdrawPercent: 5, MaxWithdrawProject: 20, MaxDailyLoosening: 50, DailyLoosening: &count, AdmissionRESTBudget: 900}
	if a.source != "github" {
		return Options{}, errors.New("bot pre-key admission requires --admission-source github")
	}
	if fixture != nil {
		opts.Source = fixture
		return opts, nil
	}
	opts.Source, opts.Citations, err = sourceFlag(a.source, 2*time.Minute, os.Getenv)
	if gh, ok := opts.Source.(*GitHubSource); ok {
		gh.MaxRESTRequests = 900
	}
	return opts, err
}

// prepareBotAdmission performs actual offline and upstream admission before a
// private key is loaded. It never substitutes an owner or throwaway signature.
func prepareBotAdmission(ctx context.Context, opts Options, keys ApprovalKeys, rec OnboardingRecord, st *onboardingState, export OnboardingExportBinding, kid string) (OnboardingEnvelope, error) {
	g := opts.OnboardingGit
	if err := checkAdmissionRefs(ctx, g); err != nil {
		return OnboardingEnvelope{}, err
	}
	baseTree, err := admissionObject(ctx, g, g.BaseCommit+"^{tree}")
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	headTree, err := admissionObject(ctx, g, g.HeadCommit+"^{tree}")
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	profile, err := publishedProfile(keys, opts.ApprovalKeysDigest, rec.Identity, kid, g.BaseCommit, baseTree, opts.Now)
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	changes, err := admissionChanges(ctx, g, g.HeadCommit)
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	_, files, err := onboardingFiles(opts)
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	hash, err := domainDigest(OnboardingSchemaV2+"/history\x00", files)
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	daily, err := admissionDailyWindow(ctx, g, opts.Now)
	if err != nil {
		return OnboardingEnvelope{}, err
	}
	sort.Slice(daily, func(i, j int) bool { return daily[i].SHA < daily[j].SHA })
	b := &OnboardingAdmissionBinding{Profile: profile, Export: export, UnsignedCommit: g.HeadCommit, UnsignedTree: headTree, Changes: changes,
		ObservedAt: rec.DecidedAt, DailyCommits: daily, DailyCount: *opts.DailyLoosening, HistoryDigest: hash}
	if rec.Sample, err = admissionSample(rec, *b); err != nil {
		return OnboardingEnvelope{}, err
	}
	e := OnboardingEnvelope{Schema: OnboardingSchemaV2, Record: rec, KeyID: kid, binding: b}
	e.Record.SummaryDigest = CandidateDigest([]byte(st.envelopeSummary(e)))
	if problems := st.check(e.Record, opts.Layout.Onboarding.Dir+"/"+e.Record.BatchID+".json"); len(problems) > 0 {
		return OnboardingEnvelope{}, fmt.Errorf("pre-key onboarding checks: %s", strings.Join(problems, "; "))
	}
	if err := checkBotAdmission(ctx, e, keys, opts, true); err != nil {
		return OnboardingEnvelope{}, err
	}
	if why := st.checkEnvelopeDigests(e); why != "" {
		return OnboardingEnvelope{}, errors.New(why)
	}
	if opts.Source == nil {
		return OnboardingEnvelope{}, errors.New("admission source missing")
	}
	rows := projectsBySlug(st.head.projects)
	index := customresources.NewIndex(st.head.projects)
	for _, p := range e.Record.Projects {
		name := crdversions.TargetFileName(p.Slug)
		target, err := crdversions.LoadTarget(name, st.head.targets[name])
		if err != nil {
			return OnboardingEnvelope{}, err
		}
		if _, err := onboardingDryRun(ctx, opts.Source, opts.Concurrency, target, index, rows[p.Slug], p, opts.Now); err != nil {
			return OnboardingEnvelope{}, fmt.Errorf("pre-key dry run %s: %w", p.Slug, err)
		}
	}
	if err := checkBotAdmission(ctx, e, keys, opts, true); err != nil {
		return OnboardingEnvelope{}, err
	}
	return e, nil
}

func marshalOnboardingEnvelope(e OnboardingEnvelope) ([]byte, error) {
	if e.binding == nil {
		return json.MarshalIndent(e, "", "  ")
	}
	return json.MarshalIndent(OnboardingEnvelopeV2{Schema: e.Schema, Record: OnboardingRecordV2{AdmissionBinding: *e.binding, OnboardingRecord: e.Record}, KeyID: e.KeyID, Signature: e.Signature}, "", "  ")
}
