// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgetargets"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// Defaults.
const (
	ReportSchema        = "prufyx.io/knowledge-gate-report/v1"
	DefaultMaxLoosening = 200
	DefaultBotLogin     = "prufyx-factory[bot]"
	// SizeAlarmPercent is the share of a size cap at which the gate raises
	// an alarm, and fails a change that loosens and grows the pack.
	SizeAlarmPercent = 80
	// Circuit breaker and daily limit defaults.
	DefaultMaxWithdrawPercent = 5
	DefaultMaxWithdrawProject = 20
	DefaultMaxDailyLoosening  = 50
)

// Proofs.
const (
	ProofNoneRequired  = "none-required"
	ProofRederived     = "rederived"
	ProofReattestation = "reattestation"
	ProofApproval      = "approval"
)

// Options configures a gate run.
type Options struct {
	Layout Layout
	// Base is the checkout the change is proposed against; Head the
	// proposed checkout. Nothing in Head is executed.
	Base, Head Tree
	// Source serves pinned upstream bytes for re-derivation. Nil fails
	// every mechanical loosening change.
	Source Source
	// Catalog is the extractor catalog; nil means extractcli.Catalog().
	Catalog     map[string]extractcli.Spec
	Concurrency int
	// Now is the gate's clock; zero means time.Now().
	Now time.Time
	// Author is the change's author login; Sender the login of the
	// account whose action triggered this run; BotLogin the automation's.
	Author, Sender, BotLogin string
	// Owner is the repository owner's login; empty means
	// DefaultOwnerLogin. Only the owner's own change (author and sender)
	// may supersede a reviewed rule.
	Owner string
	// HeadSHA is the head commit the gate checks; Commits the change's
	// commit range (base..head) with authors, committers and signature
	// verification. Both are required for automatic-merge eligibility.
	HeadSHA string
	Commits *CommitList
	// MaxLoosening caps loosening changes; 0 means DefaultMaxLoosening.
	MaxLoosening int
	// TrustRootDigest pins the reattestation trust root read from Base.
	TrustRootDigest string
	// ApprovalKeysDigest pins the owner-approval key file read from Base
	// (sha256 of the file without its trailing newline). Without it no
	// approval is accepted.
	ApprovalKeysDigest string
	// RerunWorklist is the worklist this job's own evidence repin run
	// produced, required to admit a reattestation statement.
	RerunWorklist []byte
	// RederiveAll re-derives every active mechanical rule of the head,
	// changed or not (the scheduled run on the main branch).
	RederiveAll bool
	// MaxWithdrawPercent and MaxWithdrawProject are the withdrawal circuit
	// breakers: a change that withdraws more than this percent of a pack's
	// active rules, or more than this many rules of one project, fails. 0
	// means the defaults.
	MaxWithdrawPercent, MaxWithdrawProject int
	// Shadow computes everything as usual but never makes the change
	// eligible for automatic merging.
	Shadow bool
	// DailyLoosening is the number of loosening changes already merged by
	// the automation in the last day, counted by the caller. Nil means it
	// is unknown: the change is then never eligible for automatic merging.
	DailyLoosening *int
	// MaxDailyLoosening caps DailyLoosening plus this change; 0 means
	// DefaultMaxDailyLoosening.
	MaxDailyLoosening int
	// Citations verifies the sources of every added or changed rule, path
	// policy and line attestation against upstream (see citationCheck).
	// Nil means no upstream is available: a change that cites sources then
	// fails the citations check, it is never skipped.
	Citations CitationChecker
}

// CitationChecker verifies citation items against upstream; the production
// implementation is *rulecheck.CitationVerifier.
type CitationChecker interface {
	VerifyItems(ctx context.Context, items []rulecheck.CitationItem) (rulecheck.CitationReport, error)
}

// Check is one named pass/fail check.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Totals counts changes by class.
type Totals struct {
	Tightening int `json:"tightening"`
	Loosening  int `json:"loosening"`
}

// LimitReport reports the loosening cap.
type LimitReport struct {
	MaxLoosening int  `json:"maxLoosening"`
	Loosening    int  `json:"loosening"`
	OK           bool `json:"ok"`
}

// AutoMerge reports whether the change would be eligible for automatic
// merging. The gate never merges.
type AutoMerge struct {
	Eligible bool     `json:"eligible"`
	Reasons  []string `json:"reasons,omitempty"`
}

// Report is the gate's result.
type Report struct {
	Schema  string      `json:"schema"`
	Result  string      `json:"result"`
	Paused  bool        `json:"paused"`
	Totals  Totals      `json:"totals"`
	Limits  LimitReport `json:"limits"`
	Changes []*Change   `json:"changes"`
	// Supersedes lists the supersede pairs: the removed reviewed rule
	// and the added mechanical rule that replaces it.
	Supersedes []Supersede `json:"supersedes"`
	Checks     []Check     `json:"checks"`
	Alarms     []string    `json:"alarms"`
	// Mode is "enforce" or "shadow".
	Mode          string      `json:"mode"`
	Breakers      []Breaker   `json:"breakers"`
	Daily         DailyReport `json:"daily"`
	ChangedPaths  []string    `json:"changedPaths"`
	ChainsChanged []string    `json:"chainsChanged"`
	AutoMerge     AutoMerge   `json:"autoMerge"`
	Author        string      `json:"author,omitempty"`
	Sender        string      `json:"sender,omitempty"`
	// HeadSHA is the head commit this result is for. A merge must be made
	// with exactly this commit.
	HeadSHA string `json:"headSha,omitempty"`

	// baselineApprovalsUsed names (by approval id) the baseline approval
	// files this change's baseline check admitted entries with.
	baselineApprovalsUsed map[string]bool

	// alarmKinds runs parallel to Alarms.
	alarmKinds []string
	// rederivedUnchanged counts rules re-derived by --rederive-all: every
	// active mechanical rule the change did not already re-derive (see
	// rederiveAll).
	rederivedUnchanged int
}

// Passed reports whether every change was admitted and every check passed.
func (r *Report) Passed() bool { return r.Result == "pass" }

func (c *Change) fail(detail string) {
	c.OK, c.Detail = false, detail
}

func (o *Options) defaults() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	if o.MaxLoosening <= 0 {
		o.MaxLoosening = DefaultMaxLoosening
	}
	if o.MaxWithdrawPercent <= 0 {
		o.MaxWithdrawPercent = DefaultMaxWithdrawPercent
	}
	if o.MaxWithdrawProject <= 0 {
		o.MaxWithdrawProject = DefaultMaxWithdrawProject
	}
	if o.MaxDailyLoosening <= 0 {
		o.MaxDailyLoosening = DefaultMaxDailyLoosening
	}
	if o.BotLogin == "" {
		o.BotLogin = DefaultBotLogin
	}
	if o.Owner == "" {
		o.Owner = DefaultOwnerLogin
	}
	if o.Catalog == nil {
		o.Catalog = extractcli.Catalog()
	}
}

// Limits classifies the change and applies only the loosening cap and the
// kill switch.
func Limits(opts Options) (*Report, error) {
	opts.defaults()
	cls, err := Classify(opts.Layout, opts.Base, opts.Head)
	if err != nil {
		return nil, err
	}
	r := newReport(cls, opts)
	r.limitChecks(cls, opts)
	r.finish(false)
	return r, nil
}

func newReport(cls *Classification, opts Options) *Report {
	t, l := cls.Counts()
	mode := ModeEnforce
	if opts.Shadow {
		mode = ModeShadow
	}
	return &Report{
		Mode: mode, Breakers: []Breaker{}, Schema: ReportSchema, Paused: cls.Paused, Totals: Totals{Tightening: t, Loosening: l},
		Limits:  LimitReport{MaxLoosening: opts.MaxLoosening, Loosening: l, OK: l <= opts.MaxLoosening},
		Changes: cls.Changes, Supersedes: supersedeReport(cls), Checks: []Check{}, Alarms: []string{}, ChangedPaths: []string{}, ChainsChanged: append([]string{}, cls.ChainsChanged...),
		Author: opts.Author, Sender: opts.Sender, HeadSHA: opts.HeadSHA,
	}
}

func (r *Report) add(name string, ok bool, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
}

func (r *Report) limitChecks(cls *Classification, opts Options) {
	r.add("limits", r.Limits.OK, "%d loosening changes, cap %d", r.Limits.Loosening, r.Limits.MaxLoosening)
	if !r.Limits.OK {
		r.alarm(AlarmLooseningCap, "loosening cap exceeded: %d > %d", r.Limits.Loosening, r.Limits.MaxLoosening)
	}
	r.dailyCheck(opts)
	r.breakerChecks(cls, opts)
	if cls.Paused {
		ok := r.Totals.Loosening == 0
		r.add("kill-switch", ok, "the kill switch is set; %d loosening changes", r.Totals.Loosening)
	}
}

// finish sets the result: every check must pass and, when changes is set,
// every change must have been admitted.
func (r *Report) finish(changes bool) {
	pass := true
	for _, c := range r.Checks {
		pass = pass && c.OK
	}
	for _, c := range r.Changes {
		pass = pass && (c.OK || !changes)
	}
	r.Result = "fail"
	if pass {
		r.Result = "pass"
	}
}

// Verify runs the whole gate.
func Verify(ctx context.Context, opts Options) (*Report, error) {
	opts.defaults()
	cls, err := Classify(opts.Layout, opts.Base, opts.Head)
	if err != nil {
		return nil, err
	}
	r := newReport(cls, opts)
	if r.ChangedPaths, err = ChangedPaths(opts.Base, opts.Head); err != nil {
		return nil, err
	}
	// Nothing under cli/ may be a link or a special file: every reader of
	// the head refuses them, and this states it once for the whole tree.
	special, err := opts.Head.SpecialFiles(cliDir)
	if err != nil {
		return nil, err
	}
	r.add("tree", len(special) == 0, "%d links or special files under %s/%s", len(special), cliDir, listDetail(special))

	// Statements appended to a chain are verified whether or not a rule
	// change needs them: the chain is published knowledge too.
	statements := map[string]statementResult{}
	specs := map[string]PackSpec{}
	for _, spec := range opts.Layout.Packs {
		specs[spec.Name] = spec
	}
	for _, name := range cls.ChainsChanged {
		res := verifyStatement(opts.Layout, specs[name], opts.Base, opts.Head, cls.base[name], cls.head[name], opts)
		statements[name] = res
		detail := res.Detail
		if res.OK {
			detail = fmt.Sprintf("statement %s signed by role %s renews %d rules", res.Stem, res.Role, len(res.Renewed))
		}
		r.add("reattestation/"+name, res.OK, "%s", detail)
	}

	var approvalKeys *ApprovalKeys
	var approvalKeysErr error
	keysLoaded := false
	loadKeys := func() (*ApprovalKeys, error) {
		if !keysLoaded {
			keysLoaded = true
			raw, err := opts.Base.Read(opts.Layout.ApprovalKeysPath, maxApprovalBytes*4)
			if err != nil {
				approvalKeysErr = fmt.Errorf("no owner approval key is pinned in the base: %v", err)
			} else if opts.ApprovalKeysDigest == "" {
				approvalKeysErr = errors.New("no owner approval key digest is configured")
			} else if pinnedDigest(raw) != opts.ApprovalKeysDigest {
				approvalKeysErr = errors.New("the owner approval key file in the base does not match the pinned digest")
			} else if k, err := ParseApprovalKeys(raw); err != nil {
				approvalKeysErr = err
			} else {
				approvalKeys = &k
			}
		}
		return approvalKeys, approvalKeysErr
	}

	// The extractor run a reviewed line attestation is cross-checked
	// against, made once per fact family at the gate's clock.
	attesterRuns := map[string]*attesterRun{}
	crossCheck := func(pack string, rec *record) error {
		a := rec.attestation
		if a == nil {
			return errors.New("not a line attestation")
		}
		run := attesterRuns[a.FactFamily]
		if run == nil {
			run = &attesterRun{}
			run.out, run.floor, run.err = runAttester(ctx, opts.Source, opts.Catalog, opts.Concurrency, a.FactFamily, opts.Now)
			attesterRuns[a.FactFamily] = run
		}
		if run.err != nil {
			return run.err
		}
		return crossCheckAttestation(run.out, run.floor, *a, cls.head[pack])
	}

	// The base's approvals, decoded once for every record change.
	approvals := &baseApprovals{opts: opts}

	var mechanical, removals []*Change
	consensusChecks := &consensusRun{}
	defer consensusChecks.close()
	for _, c := range cls.Changes {
		if c.Class == ClassTightening {
			c.OK, c.Proof = true, ProofNoneRequired
			continue
		}
		if cls.Paused {
			c.fail("the kill switch is set: no loosening change is admitted")
			continue
		}
		if c.Member != "" {
			c.fail("only the pack's entries and records may change through this gate; the top-level member " + logSafe(c.Member) + " changed")
			continue
		}
		if c.Section != "" {
			// A record: mechanical ones only by re-derivation, never
			// through a statement or an approval.
			switch {
			case c.rhead != nil && c.rhead.mechanical() && c.Section != sectionAttestations:
				c.fail("no extractor derives path policies: a mechanical path policy cannot be re-derived")
			case c.rhead != nil && c.rhead.mechanical():
				if err := freshRecordDerivation(c.rhead, opts.Now); err != nil {
					c.fail(err.Error())
					continue
				}
				mechanical = append(mechanical, c)
			default:
				admitRecord(c, statements[c.Pack], loadKeys, crossCheck, approvals, opts)
			}
			continue
		}
		if c.head == nil {
			if c.supersededBy != nil {
				// Decided once the added rule has been re-derived.
				removals = append(removals, c)
				continue
			}
			c.fail("a rule may not be removed (it can turn BLOCKED into a scope-complete PASS); withdraw it instead, or replace a reviewed rule through a supersede: an owner change that adds a re-derived mechanical rule with an equal constraint key covering its region")
			continue
		}
		switch c.Basis {
		case constraintengine.BasisMechanical:
			if err := freshDerivation(c.head, opts.Now); err != nil {
				c.fail(err.Error())
				continue
			}
			mechanical = append(mechanical, c)
		case constraintengine.BasisReviewed:
			admitReviewed(c, statements[c.Pack], loadKeys, opts)
		case constraintengine.BasisConsensus:
			c.fail("consensus evidence has no verifier in this gate; not admitted")
			consensusChecks.report(ctx, c, opts)
		case constraintengine.BasisEmpirical:
			// Empirical evidence may pass, so it needs a reproduction proof
			// this gate cannot check yet.
			c.fail("empirical evidence cannot be verified by this gate yet; not admitted")
		case constraintengine.BasisLead:
			c.fail("a lead is never published through this gate")
		default:
			c.fail(fmt.Sprintf("evidence basis %q is not admitted", c.Basis))
		}
	}
	rederive(ctx, opts.Source, opts.Catalog, opts.Concurrency, opts.Layout, mechanical)
	for _, c := range removals {
		admitSupersede(c, opts)
	}
	r.Supersedes = supersedeReport(cls)

	if opts.RederiveAll {
		r.rederiveAll(ctx, cls, mechanical, opts)
	}
	r.packChecks(cls, opts)
	r.generatedChecks(opts)
	r.trustCheck(opts)
	r.modeCheck(opts)
	r.baselineApprovalsUsed = r.baselinesCheck(opts, loadKeys, approvals)
	r.recordCheck(cls, statements, opts)
	r.citationCheck(ctx, cls, opts)
	r.limitChecks(cls, opts)
	r.finish(true)
	r.autoMerge(opts)
	return r, nil
}

func baseCanonical(c *Change) []byte {
	if c.base == nil {
		return nil
	}
	return c.base.Canonical
}

func admitReviewed(c *Change, stmt statementResult, loadKeys func() (*ApprovalKeys, error), opts Options) {
	var reasons []string
	if stmt.OK {
		// The statement verified against exactly this base and head pack
		// (V1 binds the whole next pack), so every change in the pack is
		// its effect; the rule must still be one it renews.
		if stmt.Renewed[c.RuleID] {
			c.OK, c.Proof = true, ProofReattestation
			return
		}
		reasons = append(reasons, "the reattestation statement does not renew this rule")
	} else if stmt.Detail != "" {
		reasons = append(reasons, "reattestation: "+stmt.Detail)
	} else {
		reasons = append(reasons, "no reattestation statement")
	}
	raw, err := opts.Head.ReadOptional(opts.Layout.ApprovalDir+"/"+c.Pack+"/"+c.RuleID+".json", maxApprovalBytes+1)
	switch {
	case err != nil:
		reasons = append(reasons, "approval: "+err.Error())
	case raw == nil:
		reasons = append(reasons, "no owner approval")
	default:
		keys, err := loadKeys()
		if err != nil {
			reasons = append(reasons, err.Error())
		} else if err := VerifyApproval(raw, *keys, c.Pack, c.RuleID, baseCanonical(c), c.head.Canonical, opts.Now); err != nil {
			reasons = append(reasons, err.Error())
		} else {
			c.OK, c.Proof = true, ProofApproval
			return
		}
	}
	c.fail("a reviewed rule may loosen only with a verified reattestation statement or owner approval: " + strings.Join(reasons, "; "))
}

// rederiveAll re-derives every active mechanical head rule the change did
// not already re-derive. A changed rule handed to rederive is skipped whether
// its re-derivation passed or failed: a failure is reported once, on the
// change, and is not counted here. Every other active mechanical rule is
// re-derived and counted, including a changed one that never reached
// rederive: a tightening edit (an earlier validUntil, admitted without
// proof) and a change stopped by the kill switch or a stale derivation. For
// a tightening edit this is the only re-derivation it gets, so it must stay.
func (r *Report) rederiveAll(ctx context.Context, cls *Classification, rederived []*Change, opts Options) {
	done := map[string]bool{}
	for _, c := range rederived {
		done[c.Pack+"\x00"+c.RuleID] = true
	}
	var all []*Change
	for _, spec := range opts.Layout.Packs {
		h := cls.head[spec.Name]
		for _, id := range h.Order {
			e := h.Entries[id]
			if e.effectiveBasis() != constraintengine.BasisMechanical || e.Evidence.State != "active" || done[spec.Name+"\x00"+id] {
				continue
			}
			all = append(all, &Change{Pack: spec.Name, RuleID: id, head: e})
		}
		// Mechanical line attestations, too. They have no state: one in
		// the pack is in force.
		for _, id := range h.RecordOrder {
			rec := h.Records[id]
			if !rec.mechanical() || rec.attestation == nil || done[spec.Name+"\x00"+id] {
				continue
			}
			all = append(all, &Change{Pack: spec.Name, RuleID: id, Section: rec.Section, rhead: rec})
		}
	}
	rederive(ctx, opts.Source, opts.Catalog, opts.Concurrency, opts.Layout, all)
	var failed []string
	attestations := 0
	for _, c := range all {
		if c.rhead != nil {
			attestations++
		}
		if !c.OK {
			failed = append(failed, c.Pack+"/"+c.RuleID+": "+c.Detail)
		}
	}
	r.rederivedUnchanged = len(all)
	records := ""
	if attestations > 0 {
		records = fmt.Sprintf(" (%d of them line attestations)", attestations)
	}
	r.add("rederive-all", len(failed) == 0, "%d mechanical rules re-derived, %d failed%s%s", len(all), len(failed), records, listDetail(failed))
}

func listDetail(items []string) string {
	if len(items) == 0 {
		return ""
	}
	const max = 10
	more := ""
	if len(items) > max {
		more = fmt.Sprintf(" (and %d more)", len(items)-max)
		items = items[:max]
	}
	return ": " + strings.Join(items, "; ") + more
}

func (r *Report) packChecks(cls *Classification, opts Options) {
	loosenedWeeks := map[string]map[string]bool{}
	for _, c := range cls.Changes {
		if c.Class != ClassLoosening || c.head == nil || c.head.Evidence.State != "active" {
			continue
		}
		if c.base != nil && c.base.Evidence.ValidUntil == c.head.Evidence.ValidUntil {
			continue
		}
		until, err := time.Parse(time.RFC3339, c.head.Evidence.ValidUntil)
		if err != nil {
			continue // the admission check rejects it
		}
		if loosenedWeeks[c.Pack] == nil {
			loosenedWeeks[c.Pack] = map[string]bool{}
		}
		loosenedWeeks[c.Pack][evidencereattest.ISOWeek(until)] = true
	}
	loosening := map[string]int{}
	for _, c := range cls.Changes {
		if c.Class == ClassLoosening {
			loosening[c.Pack]++
		}
	}
	for _, spec := range opts.Layout.Packs {
		b, h := cls.base[spec.Name], cls.head[spec.Name]
		if !h.Present {
			r.add("admit/"+spec.Name, !b.Present, "the pack file is missing")
			continue
		}
		stats, err := spec.Admit(opts.Head)
		if err != nil {
			r.add("admit/"+spec.Name, false, "the engine does not admit the pack: %v", err)
		} else {
			r.add("admit/"+spec.Name, true, "%d entries admitted", stats.Entries)
			r.add("registry/"+spec.Name, stats.RegistryFacts <= stats.MaxRegistryFacts, "%d of %d facts", stats.RegistryFacts, stats.MaxRegistryFacts)
			r.sizeCheck(spec, stats, len(b.Raw), len(h.Raw), loosening[spec.Name] > 0)
			if stats.Split {
				r.targetsCheck(spec, stats, len(b.Raw), len(h.Raw), loosening[spec.Name] > 0)
			}
		}
		r.rulecheck(spec, h)
		r.attestationRulecheck(spec, h)
		r.staggerCheck(spec, h, loosenedWeeks[spec.Name])
		r.recordStaggerCheck(cls, spec, b, h, loosenedWeeks[spec.Name])
		r.attestationCheck(spec, opts)
		r.basisCheck(spec, h)
	}
}

func (r *Report) sizeCheck(spec PackSpec, stats PackStats, baseLen, headLen int, loosens bool) {
	pct := 0
	if stats.MaxTargetBytes > 0 {
		pct = stats.TargetBytes * 100 / stats.MaxTargetBytes
	}
	alarm := stats.TargetBytes*100 >= SizeAlarmPercent*stats.MaxTargetBytes
	ok := stats.TargetBytes <= stats.MaxTargetBytes && !(alarm && loosens && headLen > baseLen)
	detail := fmt.Sprintf("target %d of %d bytes (%d percent)", stats.TargetBytes, stats.MaxTargetBytes, pct)
	if alarm {
		r.alarm(AlarmSize, "%s target is at %d percent of its size cap", spec.Name, pct)
		if !ok {
			detail += fmt.Sprintf("; at or above %d percent a change may not loosen and grow the pack", SizeAlarmPercent)
		}
	}
	r.add("size/"+spec.Name, ok, "%s", detail)
}

func (r *Report) rulecheck(spec PackSpec, h *loadedPack) {
	entries := make([]json.RawMessage, 0, len(h.Order))
	for _, id := range h.Order {
		entries = append(entries, h.Entries[id].Raw)
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		r.add("rulecheck/"+spec.Name, false, "%v", err)
		return
	}
	res, err := rulecheck.Validate(raw, rulecheck.Options{AllowRange: true})
	if err != nil {
		r.add("rulecheck/"+spec.Name, false, "%v", err)
		return
	}
	var findings []string
	for _, f := range res.Findings {
		findings = append(findings, fmt.Sprintf("%s %s: %s", f.RuleID, f.Check, f.Message))
	}
	r.add("rulecheck/"+spec.Name, res.Valid && len(findings) == 0, "%d entries, %d findings%s", res.EntryCount, len(findings), listDetail(findings))
}

// staggerCheck applies the V7 cap to every ISO week a loosening change
// moves a lease into: at most StaggerCap(total) rules of the pack may have
// their validUntil in that week.
func (r *Report) staggerCheck(spec PackSpec, h *loadedPack, weeks map[string]bool) {
	if len(weeks) == 0 {
		r.add("stagger/"+spec.Name, true, "no lease moved")
		return
	}
	counts := map[string]int{}
	for _, e := range h.Entries {
		until, err := time.Parse(time.RFC3339, e.Evidence.ValidUntil)
		if err != nil {
			continue
		}
		if w := evidencereattest.ISOWeek(until); weeks[w] {
			counts[w]++
		}
	}
	limit := evidencereattest.StaggerCap(len(h.Entries))
	var over []string
	for w, n := range counts {
		if n > limit {
			over = append(over, fmt.Sprintf("%s holds %d", w, n))
		}
	}
	sort.Strings(over)
	r.add("stagger/"+spec.Name, len(over) == 0, "cap %d rules per ISO week%s", limit, listDetail(over))
}

func (r *Report) attestationCheck(spec PackSpec, opts Options) {
	want, err := spec.Attest(opts.Head)
	if err != nil {
		r.add("attestation/"+spec.Name, false, "cannot regenerate the corpus attestation: %v", err)
		return
	}
	have, err := opts.Head.Read(spec.AttestationPath, MaxFileBytes)
	if err != nil {
		r.add("attestation/"+spec.Name, false, "%v", err)
		return
	}
	r.add("attestation/"+spec.Name, bytes.Equal(want, have), "committed corpus attestation %s regeneration", map[bool]string{true: "matches its", false: "differs from its"}[bytes.Equal(want, have)])
}

// basisCheck enforces, from the engine's own basis flags, that every active
// rule's basis is known, that a consensus rule may only ever block and that a
// lead never takes part in a verdict. It fails if the engine ever lets
// consensus pass or a lead decide.
func (r *Report) basisCheck(spec PackSpec, h *loadedPack) {
	var bad []string
	for _, id := range h.Order {
		e := h.Entries[id]
		if e.Evidence.State != "active" {
			continue
		}
		b := e.effectiveBasis()
		if !constraintengine.KnownBasis(b) || (b == constraintengine.BasisConsensus && !constraintengine.BasisBlockOnly(b)) || (b == constraintengine.BasisLead && !constraintengine.BasisVerdictNeutral(b)) {
			bad = append(bad, id)
		}
	}
	r.add("block-only/"+spec.Name, len(bad) == 0, "%d active rules whose basis is unknown, or that the engine does not evaluate as block-only (consensus) or verdict-neutral (lead)%s", len(bad), listDetail(bad))
}

func (r *Report) generatedChecks(opts Options) {
	for _, g := range opts.Layout.Generated {
		name := "generated/" + g.JSONPath
		wantJSON, wantMD, err := g.Generate(opts.Head)
		if err != nil {
			r.add(name, false, "cannot regenerate: %v", err)
			continue
		}
		haveJSON, err1 := opts.Head.Read(g.JSONPath, MaxFileBytes)
		haveMD, err2 := opts.Head.Read(g.MarkdownPath, MaxFileBytes)
		ok := err1 == nil && err2 == nil && bytes.Equal(wantJSON, haveJSON) && string(haveMD) == wantMD
		r.add(name, ok, "committed output %s its regeneration", map[bool]string{true: "matches", false: "differs from"}[ok])
	}
}

func (r *Report) autoMerge(opts Options) {
	var reasons []string
	if !r.Passed() {
		reasons = append(reasons, "the gate did not pass")
	}
	if opts.Author == "" || opts.Author != opts.BotLogin {
		reasons = append(reasons, fmt.Sprintf("author %q is not the automation account %q", logSafe(opts.Author), logSafe(opts.BotLogin)))
	}
	if opts.Sender != opts.BotLogin {
		reasons = append(reasons, fmt.Sprintf("the run was triggered by %q, not the automation account", logSafe(opts.Sender)))
	}
	reasons = append(reasons, commitReasons(opts)...)
	for _, c := range r.Changes {
		if c.isSupersede() {
			reasons = append(reasons, "the change supersedes a reviewed rule; that is made and merged by the owner, never automatically")
			break
		}
	}
	if len(r.Changes) == 0 && len(r.ChainsChanged) == 0 {
		reasons = append(reasons, "the change holds no knowledge change")
	}
	var outside []string
	for _, p := range r.ChangedPaths {
		if !opts.Layout.autoMergePath(p) {
			outside = append(outside, p)
		}
	}
	if len(outside) > 0 {
		reasons = append(reasons, "the change touches files outside the knowledge files"+listDetail(outside))
	}
	if opts.Shadow {
		reasons = append(reasons, "shadow mode: nothing merges automatically")
	}
	if opts.DailyLoosening == nil {
		reasons = append(reasons, "the number of loosening changes merged by the automation in the last day is unknown")
	}
	r.AutoMerge = AutoMerge{Eligible: len(reasons) == 0, Reasons: reasons}
}

// modeCheck refuses an executable bit on a knowledge file the automation
// may change, and any change of the bit on one: knowledge files are data.
func (r *Report) modeCheck(opts Options) {
	var bad []string
	for _, p := range r.ChangedPaths {
		if !opts.Layout.autoMergePath(p) {
			continue
		}
		if opts.Head.executable(p) || opts.Base.executable(p) {
			bad = append(bad, p)
		}
	}
	r.add("file-modes", len(bad) == 0, "%d knowledge files with an executable bit%s", len(bad), listDetail(bad))
}

// targetsCheck sizes the per-project targets and the index a split pack is
// published as, with the limits of "knowledge-targets check-size": every
// target against the per-target cap and its alarm, and their sum against
// the package bound. Over a cap fails; at or above an alarm raises one and
// fails a change that loosens and grows the pack.
func (r *Report) targetsCheck(spec PackSpec, stats PackStats, baseLen, headLen int, loosens bool) {
	name := "targets/" + spec.Name
	if stats.SplitErr != nil {
		r.add(name, false, "the pack cannot be split into per-project targets: %v", stats.SplitErr)
		return
	}
	limit := knowledgetargets.DefaultLimit()
	var over []string
	largest := knowledgetargets.Target{}
	for _, t := range stats.Targets {
		if t.Bytes > limit.Cap {
			over = append(over, fmt.Sprintf("%s is %d bytes", t.Path, t.Bytes))
		}
		if t.Bytes > largest.Bytes {
			largest = t
		}
	}
	alarmed := knowledgetargets.Alarms(stats.Targets, limit)
	total, totalAlarm := knowledgetargets.TotalAlarmed(stats.Targets, limit)
	for _, t := range alarmed {
		r.alarm(AlarmSize, "%s target %s is at or above %d bytes", spec.Name, t.Path, limit.Alarm)
	}
	if totalAlarm {
		r.alarm(AlarmSize, "%s targets total %d bytes, at or above %d", spec.Name, total, limit.TotalAlarm)
	}
	grows := loosens && headLen > baseLen
	ok := len(over) == 0 && total <= limit.TotalCap && !((len(alarmed) > 0 || totalAlarm) && grows)
	detail := fmt.Sprintf("%d targets, largest %s %d of %d bytes, total %d of %d bytes%s", len(stats.Targets), largest.Path, largest.Bytes, limit.Cap, total, limit.TotalCap, listDetail(over))
	if !ok && len(over) == 0 && total <= limit.TotalCap {
		detail += "; at or above an alarm a change may not loosen and grow the pack"
	}
	r.add(name, ok, "%s", detail)
}
