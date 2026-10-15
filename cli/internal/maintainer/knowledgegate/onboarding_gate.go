// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
)

// onboardingResult is the gate's decision on the onboarding batch a change
// adds.
type onboardingResult struct {
	path   string
	id     string
	ok     bool
	detail string
	// summary is the gate's rendering of the batch's review summary, set
	// once the batch decoded and the trees were read.
	summary string
	// headTable is the head's custom-resource table, which the cncf pack
	// is admitted against once the batch is admitted; headRevision and
	// headRegistry are the pack members it admits.
	headTable                  []byte
	headRevision, headRegistry string
	// restRequests are the dry runs' GitHub REST requests, per project.
	restRequests map[string]int64
}

// admitsMember reports whether the batch admitted a change of a pack member.
func (o *onboardingResult) admitsMember(layout Layout, c *Change) bool {
	if o == nil || !o.ok || c.Pack != layout.Onboarding.Pack {
		return false
	}
	return c.Member == "revision" || c.Member == "registryDigest"
}

// onboardingFiles lists the onboarding files the head adds, by name, and the
// base's files.
func onboardingFiles(opts Options) (added, base map[string][]byte, err error) {
	dir := opts.Layout.Onboarding.Dir
	head, err := opts.Head.Dir(dir, maxOnboardingBytes+1, maxOnboardingFiles)
	if err != nil {
		return nil, nil, err
	}
	if base, err = opts.Base.Dir(dir, maxOnboardingBytes+1, maxOnboardingFiles); err != nil {
		return nil, nil, err
	}
	added = map[string][]byte{}
	for name, raw := range head {
		if _, ok := base[name]; !ok {
			added[name] = raw
		}
	}
	return added, base, nil
}

// runOnboarding decides the onboarding batch a change adds, all or nothing
// (O1 to O8). It returns nil when the change adds none.
func runOnboarding(ctx context.Context, opts Options, cls *Classification, changedPaths []string, loadKeys func() (*ApprovalKeys, error)) *onboardingResult {
	ol := opts.Layout.Onboarding
	if ol.Dir == "" {
		return nil
	}
	res := &onboardingResult{restRequests: map[string]int64{}}
	added, baseFiles, err := onboardingFiles(opts)
	if err != nil {
		res.detail = "O1: the onboarding directory cannot be read: " + logSafe(err.Error())
		return res
	}
	if len(added) == 0 {
		return nil
	}
	fail := func(format string, args ...any) *onboardingResult {
		res.ok, res.detail = false, fmt.Sprintf(format, args...)
		return res
	}
	if len(added) > 1 {
		names := make([]string, 0, len(added))
		for n := range added {
			names = append(names, logSafe(n))
		}
		sort.Strings(names)
		return fail("O1: a change may add one onboarding batch, this one adds %d%s", len(added), listDetail(names))
	}
	var name string
	var raw []byte
	for n, r := range added {
		name, raw = n, r
	}
	res.path = ol.Dir + "/" + name
	if cls.Paused {
		return fail("O8: the kill switch is set: no onboarding batch is admitted")
	}
	env, err := decodeOnboarding(raw)
	if err != nil {
		return fail("O1: %s", logSafe(err.Error()))
	}
	rec := env.Record
	res.id = rec.BatchID
	if name != rec.BatchID+".json" {
		return fail("O1: the file %s is not named after its batch id %s", logSafe(name), logSafe(rec.BatchID))
	}
	keys, err := loadKeys()
	if err != nil {
		return fail("O1: %v", err)
	}
	if err := verifyOnboardingSignature(env, *keys, opts.Now); err != nil {
		return fail("O1: %s", logSafe(err.Error()))
	}
	if why := refuseOnboarding(env, baseFiles); why != "" {
		return fail("O1: %s", why)
	}
	st, err := newOnboardingState(opts.Layout, opts.Base, opts.Head, cls, changedPaths)
	if err != nil {
		return fail("O4: %s", logSafe(err.Error()))
	}
	res.summary = st.summary(rec)
	if problems := st.check(rec, res.path); len(problems) > 0 {
		return fail("%d problems%s", len(problems), listDetail(problems))
	}
	if why := onboardingModes(opts, changedPaths); why != "" {
		return fail("O2: %s", why)
	}
	if why := st.checkDigests(rec); why != "" {
		return fail("O7: %s", why)
	}
	rows := projectsBySlug(st.head.projects)
	for _, p := range rec.Projects {
		file := crdversions.TargetFileName(p.Slug)
		target, err := crdversions.LoadTarget(file, st.head.targets[file])
		if err != nil {
			return fail("O6: %s: %s", logSafe(p.Slug), logSafe(err.Error()))
		}
		used, err := onboardingDryRun(ctx, opts.Source, opts.Concurrency, target, rows[p.Slug], p, opts.Now)
		res.restRequests[p.Slug] = used
		if err != nil {
			return fail("O6: %s: %s", logSafe(p.Slug), err.Error())
		}
	}
	res.ok = true
	res.headTable, res.headRevision, res.headRegistry = st.head.table, st.head.revision, st.head.registryDigest
	res.detail = fmt.Sprintf("onboarding batch %s by %s admits %d projects (sample %d read in full), valid until %s", rec.BatchID, rec.Identity, len(rec.Projects), len(rec.Sample), rec.NotAfter)
	return res
}

// checkDigests runs O7: the change set, the sample and the summary are the
// gate's own.
func (st *onboardingState) checkDigests(rec OnboardingRecord) string {
	if rec.ChangeSetDigest != st.changeSetDigest {
		return "the change set differs from the one the batch was signed for"
	}
	sample, err := onboardingSample(rec.core())
	if err != nil {
		return err.Error()
	}
	if !equalInts(sample, rec.Sample) {
		return "the sample is not the one drawn from the manifest"
	}
	if CandidateDigest([]byte(st.summary(rec))) != rec.SummaryDigest {
		return "the summary digest does not match the summary of this change"
	}
	return ""
}

// onboardingModes refuses an executable bit on, or a change of it on, any
// path an onboarding change touches: they are all data.
func onboardingModes(opts Options, changedPaths []string) string {
	var bad []string
	for _, p := range changedPaths {
		if opts.Head.executable(p) || opts.Base.executable(p) {
			bad = append(bad, logSafe(p))
		}
	}
	if len(bad) > 0 {
		return fmt.Sprintf("%d files with an executable bit%s", len(bad), listDetail(bad))
	}
	return ""
}

// refuseOnboarding says why a batch the head adds may not be used given the
// base's batches, or "": the same batch (id, signature or record) is in the
// base, or a base batch lists one of its projects and was decided at the
// same time or later (decisions per project only move forward).
func refuseOnboarding(head OnboardingEnvelope, baseFiles map[string][]byte) string {
	headAt, err := time.Parse(time.RFC3339, head.Record.DecidedAt)
	if err != nil {
		return "the batch's decidedAt cannot be read"
	}
	names := make([]string, 0, len(baseFiles))
	for n := range baseFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	slugs := map[string]bool{}
	for _, p := range head.Record.Projects {
		slugs[p.Slug] = true
	}
	for _, n := range names {
		env, err := decodeOnboarding(baseFiles[n])
		if err != nil {
			continue // never verifies, so it is no decision
		}
		if sameOnboarding(env, head) {
			return "the onboarding batch is already in the base (" + logSafe(n) + "): a batch admits only the change that adds it"
		}
		at, err := time.Parse(time.RFC3339, env.Record.DecidedAt)
		for _, p := range env.Record.Projects {
			if slugs[p.Slug] && (err != nil || !headAt.After(at)) {
				return fmt.Sprintf("the base batch %s decided about %s at the same time or later: an earlier or concurrent decision cannot replace it", logSafe(n), logSafe(p.Slug))
			}
		}
	}
	return ""
}

// OnboardingRetention is how long an onboarding batch stays in the tree
// after its notAfter: until then it still refuses a replay or an older
// batch for its projects.
const OnboardingRetention = 14 * 24 * time.Hour

// onboardingRecordsCheck is the records rule of the onboarding directory,
// run on every change: a file may be added only as the batch this run
// admitted; a base file is never changed, and removed only
// OnboardingRetention after it expired.
func (r *Report) onboardingRecordsCheck(opts Options, ob *onboardingResult) {
	dir := opts.Layout.Onboarding.Dir
	if dir == "" {
		return
	}
	var bad []string
	touched := false
	for _, p := range r.ChangedPaths {
		if len(p) <= len(dir)+1 || p[:len(dir)+1] != dir+"/" {
			continue
		}
		touched = true
		if why := onboardingPathReason(opts, p, ob); why != "" {
			bad = append(bad, logSafe(p)+": "+why)
		}
	}
	if touched {
		r.add("onboarding-records", len(bad) == 0, "%d onboarding files refused%s", len(bad), listDetail(bad))
	}
}

func onboardingPathReason(opts Options, p string, ob *onboardingResult) string {
	inBase, inHead := opts.Base.Exists(p), opts.Head.Exists(p)
	switch {
	case inBase && inHead:
		return "an onboarding batch file is never changed"
	case inBase:
		raw, err := opts.Base.ReadOptional(p, maxOnboardingBytes+1)
		if err != nil || raw == nil {
			return "an onboarding batch file that cannot be read may not be removed"
		}
		env, err := decodeOnboarding(raw)
		if err != nil {
			return ""
		}
		until, err := time.Parse(time.RFC3339, env.Record.NotAfter)
		if err != nil || opts.Now.Before(until.Add(OnboardingRetention)) {
			return "an onboarding batch may not be removed until 14 days after it expired"
		}
		return ""
	case ob == nil || !ob.ok || ob.path != p:
		return "no onboarding batch admitted in this change is this file"
	}
	return ""
}

// onboardingAdmit admits the cncf pack against the head table the batch
// was admitted with; onboardingAttest regenerates its corpus attestation the
// same way.
func onboardingAdmit(opts Options, ob *onboardingResult) (PackStats, error) {
	ol := opts.Layout.Onboarding
	var spec *PackSpec
	for i := range opts.Layout.Packs {
		if opts.Layout.Packs[i].Name == ol.Pack {
			spec = &opts.Layout.Packs[i]
		}
	}
	if spec == nil {
		return PackStats{}, errors.New("no onboarding pack in the layout")
	}
	files, err := readAll(opts.Head, ol.LandscapePath, ol.PriorityPath, spec.Path)
	if err != nil {
		return PackStats{}, err
	}
	return cncfPackStats(files[0], files[1], files[2], ob.headTable)
}

func onboardingAttest(opts Options, ob *onboardingResult) ([]byte, error) {
	return corpusattest.DocumentFromFilesWithTable(corpusattest.PackCNCF, opts.Head.readUnder(cliDir), ob.headTable)
}
