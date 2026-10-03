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
)

// Proofs.
const (
	ProofNoneRequired  = "none-required"
	ProofRederived     = "rederived"
	ProofReattestation = "reattestation"
	ProofApproval      = "approval"
)

// Evidence bases the gate knows of. Only mechanical and reviewed rules can
// be admitted as loosening changes by this version.
const (
	basisConsensus = "consensus"
	basisEmpirical = "empirical"
)

// blockOnlyBases lists the evidence bases the engine evaluates as
// block-only (a non-match never contributes to a pass). It is empty: no
// engine in this repository can yet evaluate consensus evidence that way,
// so a consensus rule in a pack fails the gate.
var blockOnlyBases = map[string]bool{}

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
	Schema        string      `json:"schema"`
	Result        string      `json:"result"`
	Paused        bool        `json:"paused"`
	Totals        Totals      `json:"totals"`
	Limits        LimitReport `json:"limits"`
	Changes       []*Change   `json:"changes"`
	Checks        []Check     `json:"checks"`
	Alarms        []string    `json:"alarms"`
	ChangedPaths  []string    `json:"changedPaths"`
	ChainsChanged []string    `json:"chainsChanged"`
	AutoMerge     AutoMerge   `json:"autoMerge"`
	Author        string      `json:"author,omitempty"`
	Sender        string      `json:"sender,omitempty"`
	// HeadSHA is the head commit this result is for. A merge must be made
	// with exactly this commit.
	HeadSHA string `json:"headSha,omitempty"`
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
	if o.BotLogin == "" {
		o.BotLogin = DefaultBotLogin
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
	r.limitChecks(cls)
	r.finish(false)
	return r, nil
}

func newReport(cls *Classification, opts Options) *Report {
	t, l := cls.Counts()
	return &Report{
		Schema: ReportSchema, Paused: cls.Paused, Totals: Totals{Tightening: t, Loosening: l},
		Limits:  LimitReport{MaxLoosening: opts.MaxLoosening, Loosening: l, OK: l <= opts.MaxLoosening},
		Changes: cls.Changes, Checks: []Check{}, Alarms: []string{}, ChangedPaths: []string{}, ChainsChanged: append([]string{}, cls.ChainsChanged...),
		Author: opts.Author, Sender: opts.Sender, HeadSHA: opts.HeadSHA,
	}
}

func (r *Report) add(name string, ok bool, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
}

func (r *Report) limitChecks(cls *Classification) {
	r.add("limits", r.Limits.OK, "%d loosening changes, cap %d", r.Limits.Loosening, r.Limits.MaxLoosening)
	if !r.Limits.OK {
		r.Alarms = append(r.Alarms, fmt.Sprintf("loosening cap exceeded: %d > %d", r.Limits.Loosening, r.Limits.MaxLoosening))
	}
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

	var mechanical []*Change
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
			c.fail("only the pack's entries may change through this gate; the top-level member " + logSafe(c.Member) + " changed")
			continue
		}
		if c.head == nil {
			c.fail("a rule may not be removed (it can turn BLOCKED into a scope-complete PASS); withdraw it instead")
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
		case basisConsensus:
			c.fail("consensus evidence may only block, and this gate has no consensus verifier; not admitted")
		case basisEmpirical:
			c.fail("empirical evidence cannot be verified by this gate yet; not admitted")
		default:
			c.fail(fmt.Sprintf("evidence basis %q is not admitted", c.Basis))
		}
	}
	rederive(ctx, opts.Source, opts.Catalog, opts.Concurrency, opts.Layout, mechanical)

	if opts.RederiveAll {
		r.rederiveAll(ctx, cls, opts)
	}
	r.packChecks(cls, opts)
	r.generatedChecks(opts)
	r.trustCheck(opts)
	r.recordCheck(cls, statements, opts)
	r.limitChecks(cls)
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
// not already re-derive.
func (r *Report) rederiveAll(ctx context.Context, cls *Classification, opts Options) {
	done := map[string]bool{}
	for _, c := range cls.Changes {
		if c.Proof == ProofRederived {
			done[c.Pack+"\x00"+c.RuleID] = true
		}
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
	}
	rederive(ctx, opts.Source, opts.Catalog, opts.Concurrency, opts.Layout, all)
	var failed []string
	for _, c := range all {
		if !c.OK {
			failed = append(failed, c.Pack+"/"+c.RuleID+": "+c.Detail)
		}
	}
	r.add("rederive-all", len(failed) == 0, "%d mechanical rules re-derived, %d failed%s", len(all), len(failed), listDetail(failed))
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
		}
		r.rulecheck(spec, h)
		r.staggerCheck(spec, h, loosenedWeeks[spec.Name])
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
		r.Alarms = append(r.Alarms, fmt.Sprintf("%s target is at %d percent of its size cap", spec.Name, pct))
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

// basisCheck enforces that a consensus rule may only ever block: the engine
// must evaluate its basis as block-only, which no engine here does yet.
func (r *Report) basisCheck(spec PackSpec, h *loadedPack) {
	var bad []string
	for _, id := range h.Order {
		e := h.Entries[id]
		if e.effectiveBasis() == basisConsensus && e.Evidence.State == "active" && !blockOnlyBases[basisConsensus] {
			bad = append(bad, id)
		}
	}
	r.add("block-only/"+spec.Name, len(bad) == 0, "%d active consensus rules without block-only evaluation%s", len(bad), listDetail(bad))
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
	r.AutoMerge = AutoMerge{Eligible: len(reasons) == 0, Reasons: reasons}
}
