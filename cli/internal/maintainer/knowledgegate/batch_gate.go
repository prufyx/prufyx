// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// batchResult is the gate's decision on the batch file a change adds.
type batchResult struct {
	// present is true when the change adds a file under the batch
	// directory (or the directory cannot be read): the change's reviewed
	// entries are then decided by the batch alone.
	present bool
	path    string
	id      string
	ok      bool
	detail  string
	entries map[string]bool
}

// admits reports whether the batch admitted the change.
func (b *batchResult) admits(c *Change) bool {
	return b != nil && b.ok && b.entries[batchKey(c.Pack, changeSubject(c), c.RuleID)]
}

// refusal is the detail of a change the batch did not admit.
func (b *batchResult) refusal(c *Change) string {
	if !b.ok {
		return "the change carries a batch approval that is refused: " + b.detail
	}
	return "the change carries a batch approval, and the batch does not list this change"
}

// batchDir is the repository directory of batch files ("" disables them).
func (l Layout) batchDir() string { return l.BatchDir }

// newBatchFiles lists the files the head adds to the batch directory, by
// name. A file the head changes or removes is the knowledge-records
// check's business.
func newBatchFiles(opts Options) (map[string][]byte, error) {
	dir := opts.Layout.batchDir()
	if dir == "" {
		return nil, nil
	}
	head, err := opts.Head.Dir(dir, maxBatchBytes+1, maxBatchFiles)
	if err != nil {
		return nil, err
	}
	base, err := opts.Base.Dir(dir, maxBatchBytes+1, maxBatchFiles)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, raw := range head {
		if _, ok := base[name]; !ok {
			out[name] = raw
		}
	}
	return out, nil
}

// batchAllowedPaths are the only paths a change carrying a batch may
// touch: the pack files, their corpus attestations, the generated outputs
// and the batch file itself.
func batchAllowedPaths(layout Layout, batchPath string) map[string]bool {
	allowed := map[string]bool{batchPath: true}
	for _, spec := range layout.Packs {
		allowed[spec.Path], allowed[spec.AttestationPath] = true, true
	}
	for _, g := range layout.Generated {
		allowed[g.JSONPath], allowed[g.MarkdownPath] = true, true
	}
	return allowed
}

// runBatch decides the batch a change adds, all or nothing: the file and
// its signature (verifyBatch), the change's own contents (no forbidden
// change, only allowed paths), single use against the base, and the
// upstream verification of every entry's citations. The extractor
// cross-check of a line attestation entry runs per entry, in admitRecord.
func runBatch(ctx context.Context, opts Options, cls *Classification, changedPaths []string, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) *batchResult {
	files, err := newBatchFiles(opts)
	res := &batchResult{entries: map[string]bool{}}
	if err != nil {
		res.present, res.detail = true, "the batch directory cannot be read: "+err.Error()
		return res
	}
	if len(files) == 0 {
		return nil
	}
	res.present = true
	if len(files) > 1 {
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, logSafe(n))
		}
		sort.Strings(names)
		res.detail = "a change may add one batch approval, this one adds " + fmt.Sprint(len(files)) + listDetail(names)
		return res
	}
	var name string
	var raw []byte
	for n, r := range files {
		name, raw = n, r
	}
	res.path = opts.Layout.batchDir() + "/" + name
	fail := func(format string, args ...any) *batchResult {
		res.ok, res.detail = false, fmt.Sprintf(format, args...)
		return res
	}
	var outside []string
	allowed := batchAllowedPaths(opts.Layout, res.path)
	for _, p := range changedPaths {
		if !allowed[p] {
			outside = append(outside, logSafe(p))
		}
	}
	if len(outside) > 0 {
		return fail("a change carrying a batch approval may change only the pack files, their corpus attestations, the generated support inventory and the batch file; it also changes %d other files%s", len(outside), listDetail(outside))
	}
	st, err := newBatchState(opts.Layout, cls)
	if err != nil {
		return fail("%v", err)
	}
	keys, err := loadKeys()
	if err != nil {
		return fail("%v", err)
	}
	env, err := verifyBatch(raw, name, st, *keys, opts.Now)
	if err != nil {
		return fail("%s", logSafe(err.Error()))
	}
	res.id = env.Record.BatchID
	used, err := approvals.refuseBatch(env)
	switch {
	case err != nil:
		return fail("%v", err)
	case used != "":
		return fail("%s", used)
	}
	if err := verifyBatchCitations(ctx, opts.Citations, st); err != nil {
		return fail("%v", err)
	}
	for _, e := range env.Record.Entries {
		res.entries[e.key()] = true
	}
	res.ok = true
	res.detail = fmt.Sprintf("batch %s by %s admits %d reviewed entries (sample %d read in full), valid until %s", env.Record.BatchID, env.Record.Identity, len(env.Record.Entries), len(env.Record.Sample), env.Record.NotAfter)
	return res
}

// verifyBatchCitations runs the gate's citation verifier on exactly the
// batch's entries and requires a pass with no finding. Unlike the
// citations check, the offline fixture mode is not enough: a batch is never
// admitted on citations nobody verified.
func verifyBatchCitations(ctx context.Context, checker CitationChecker, st *batchState) error {
	switch checker.(type) {
	case nil:
		return errors.New("no citation verifier is configured (use --source github); a batch is admitted only on verified citations")
	case OfflineCitations, *OfflineCitations:
		return errors.New("offline mode (--source fixture:) verifies no citation; a batch is admitted only on verified citations")
	}
	var items []rulecheck.CitationItem
	for _, it := range st.items {
		c := it.change
		switch {
		case it.entry.Subject == BatchSubjectRule && c.head != nil:
			rule, err := entryRule(c.head.Raw)
			if err != nil {
				return fmt.Errorf("rule %s: %w", logSafe(c.RuleID), err)
			}
			one, err := rulecheck.RuleCitationItems([]json.RawMessage{rule})
			if err != nil {
				return fmt.Errorf("rule %s: %w", logSafe(c.RuleID), err)
			}
			items = append(items, one...)
		case c.rhead != nil && c.rhead.attestation != nil:
			items = append(items, rulecheck.AttestationCitationItem(*c.rhead.attestation))
		default:
			return fmt.Errorf("entry %s has no citations to verify", logSafe(c.RuleID))
		}
	}
	report, err := checker.VerifyItems(ctx, items)
	if err != nil {
		return fmt.Errorf("the batch's citations could not be verified: %v", err)
	}
	if report.Pass && len(report.Findings) == 0 && report.SourcesChecked == 0 {
		// A pass that checked no source proves nothing (fail closed).
		return errors.New("the batch's citations were not verified: the verifier reported a pass without checking a source")
	}
	if !report.Pass || len(report.Findings) > 0 {
		var lines []string
		for _, f := range report.Findings {
			lines = append(lines, fmt.Sprintf("%s source %s [%s]", logSafe(f.RuleID), logSafe(f.SourceID), f.Check))
		}
		return fmt.Errorf("the batch's citations do not verify upstream: %d findings%s", len(report.Findings), listDetail(lines))
	}
	return nil
}

// baseBatch is one decoded batch file of the base.
type baseBatch struct {
	path string
	env  BatchEnvelope
}

// loadBatches reads and decodes every batch file of the base once. A file
// that does not decode is skipped (it can never verify, so it is no
// decision); a directory or entry that cannot be read is an error.
func (b *baseApprovals) loadBatches() ([]baseBatch, error) {
	if b.batchesLoaded {
		return b.batches, b.batchesErr
	}
	b.batchesLoaded = true
	dir := b.opts.Layout.batchDir()
	if dir == "" {
		return nil, nil
	}
	files, err := b.opts.Base.Dir(dir, maxBatchBytes+1, maxBatchFiles)
	if err != nil {
		b.batchesErr = fmt.Errorf("base batch approvals: %v", err)
		return nil, b.batchesErr
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if env, err := decodeBatch(files[name]); err == nil {
			b.batches = append(b.batches, baseBatch{path: dir + "/" + name, env: env})
		}
	}
	return b.batches, nil
}

// refuseBatch says why a batch the head adds may not be used, or "" when
// nothing in the base stands against it:
//
//   - the base holds the same batch: the same batch id, the same signed
//     record or the same signature, however encoded and whatever the file
//     is called; a batch admits only the change that adds it;
//   - for any entry, the base holds a decision about the same pack, subject
//     and id (a per-entry approval file in any approval directory, or an
//     entry of a base batch) made at the same time or later: decisions only
//     move forward.
//
// Unlike per-entry approvals this covers rules too, so a renewal cannot be
// replayed after a rule went back to its earlier state.
func (b *baseApprovals) refuseBatch(head BatchEnvelope) (string, error) {
	batches, err := b.loadBatches()
	if err != nil {
		return "", err
	}
	list, err := b.load()
	if err != nil {
		return "", err
	}
	headAt, err := time.Parse(time.RFC3339, head.Record.DecidedAt)
	if err != nil {
		return "the batch's decidedAt cannot be read", nil
	}
	later := func(at string) bool {
		t, err := time.Parse(time.RFC3339, at)
		return err != nil || !headAt.After(t)
	}
	for _, base := range batches {
		if sameBatch(base.env, head) {
			return "the batch approval is already in the base (" + logSafe(base.path) + "): a batch admits only the change that adds it", nil
		}
	}
	for _, e := range head.Record.Entries {
		for _, base := range batches {
			for _, be := range base.env.Record.Entries {
				if sameDecisionOf(be.Subject, be.Pack, be.ID, e.Subject, e.Pack, e.ID) && later(base.env.Record.DecidedAt) {
					return fmt.Sprintf("the base holds a decision about %s %s/%s made at the same time or later (%s): an earlier or concurrent decision cannot replace it", e.Subject, e.Pack, logSafe(e.ID), logSafe(base.path)), nil
				}
			}
		}
		for _, base := range list {
			r := base.env.Record
			if sameDecisionOf(approvalBatchSubject(r.Subject), r.Pack, r.RuleID, e.Subject, e.Pack, e.ID) && later(r.DecidedAt) {
				return fmt.Sprintf("the base holds an approval for %s %s/%s decided at the same time or later (%s): an earlier or concurrent decision cannot replace it", e.Subject, e.Pack, logSafe(e.ID), logSafe(base.path)), nil
			}
		}
	}
	return "", nil
}

// approvalBatchSubject maps the subject of a per-entry approval ("" for a
// rule) to the subject of a batch entry.
func approvalBatchSubject(subject string) string {
	if subject == "" {
		return BatchSubjectRule
	}
	return subject
}

// sameDecisionOf reports whether two decisions are about the same thing. A
// rule id belongs to its pack, so rules compare by pack and id. A record id
// is a hash of the record's component, family and line only (it does not
// name a pack), so records compare by id alone, whichever pack a decision
// sits in: forward-only is then the same in every direction between
// per-entry approvals and batches.
func sameDecisionOf(aSubject, aPack, aID, bSubject, bPack, bID string) bool {
	if aSubject != bSubject || aID != bID {
		return false
	}
	return aSubject != BatchSubjectRule || aPack == bPack
}

// batchRecordDecision is the base batch entry deciding the same rule (in
// pack) or record (in any pack) as at the same time or after at, for a
// per-entry approval's forward-only check.
func (b *baseApprovals) batchRecordDecision(subject, pack, id string, at time.Time, atErr error) (string, error) {
	batches, err := b.loadBatches()
	if err != nil {
		return "", err
	}
	for _, base := range batches {
		bt, err := time.Parse(time.RFC3339, base.env.Record.DecidedAt)
		for _, e := range base.env.Record.Entries {
			if sameDecisionOf(e.Subject, e.Pack, e.ID, subject, pack, id) && (atErr != nil || err != nil || !at.After(bt)) {
				return "the base holds a batch decision about this " + subject + " made at the same time or later (" + logSafe(base.path) + "): an earlier or concurrent decision cannot replace it", nil
			}
		}
	}
	return "", nil
}

// BatchRetention is how long a batch file stays in the tree after its
// notAfter: a batch is also the "decided at the same time or later" evidence
// that refuses an older per-entry approval (rules and records) and an older
// batch, and such an approval stays usable for MaxApprovalAge from its own
// decidedAt, which is never later than the batch's. Deleting the file any
// earlier would let an owner-signed approval the batch superseded verify
// again. The clock skew is the gate's tolerance for a signer clock ahead.
const BatchRetention = MaxApprovalAge + approvalClockSkew

// batchPathReason is the knowledge-records rule for a file in the batch
// directory: it may be added only as the batch this run admitted; a base
// batch file is never changed, and removed only once nothing it could refuse
// can verify any more: BatchRetention after its notAfter. The directory is
// read with a bound of maxBatchFiles, so the signer refuses to add a batch
// to a directory close to it (see batchDirRoom); pruning is then possible
// well before every read fails closed.
func batchPathReason(opts Options, p string, batch *batchResult) string {
	inBase, inHead := opts.Base.Exists(p), opts.Head.Exists(p)
	switch {
	case inBase && inHead:
		return "a batch approval file is never changed"
	case inBase:
		raw, err := opts.Base.ReadOptional(p, maxBatchBytes+1)
		if err != nil || raw == nil {
			return "a batch approval file that cannot be read may not be removed"
		}
		env, err := decodeBatch(raw)
		if err != nil {
			return ""
		}
		until, err := time.Parse(time.RFC3339, env.Record.NotAfter)
		if err != nil || opts.Now.Before(until.Add(BatchRetention)) {
			return "a batch approval may not be removed until 14 days after it expired: until then it still refuses older approvals of its entries"
		}
		return ""
	case batch == nil || !batch.ok || batch.path != p:
		return "no batch approval admitted in this change is this file"
	}
	return ""
}
