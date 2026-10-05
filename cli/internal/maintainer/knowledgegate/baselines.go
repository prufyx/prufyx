// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

// ApprovalSubjectRepinBaseline marks an owner approval for one entry of the
// owner baseline file (repinbaselines): the owner's choice of the tag a
// repository's citations are compared with when its latest release is
// ambiguous. The approval names the pack "repin-baselines", the entry's
// approval id (owner--repo) as ruleId and the repository as its scope; its
// digests are those of the base entry (or "absent") and of the proposed
// entry, each in canonical JSON.
const ApprovalSubjectRepinBaseline = "repinBaseline"

// maxBaselineFileBytes bounds the baseline file read by the gate.
const maxBaselineFileBytes = repinbaselines.MaxBytes + 1

// baselineEntryCheck is the part of an approval's content that is not a
// digest: the entry must cite the approval (its candidate id), must not be
// decided after the approval, and must be decided strictly after the entry
// it replaces. Signing and the gate both run it.
func baselineEntryCheck(rec ApprovalRecord, head repinbaselines.Entry, base *repinbaselines.Entry) error {
	switch {
	case rec.CandidateID != head.Approval:
		return fmt.Errorf("the entry cites approval %q, the approval's candidate id is %q", logSafe(head.Approval), logSafe(rec.CandidateID))
	case head.DecidedAt > rec.DecidedAt:
		return errors.New("the entry is decided after the approval that admits it")
	case base != nil && head.DecidedAt <= base.DecidedAt:
		return fmt.Errorf("the entry is decided %s, not after the entry it replaces (%s): baseline decisions only move forward", head.DecidedAt, base.DecidedAt)
	}
	return nil
}

// BaselineApprovalSubject reads one repository's base and proposed entries
// from the baseline files of the base and the head (nil: no file), as the
// gate reads them. It refuses a repository the head does not hold and an
// entry the change leaves as it is.
func BaselineApprovalSubject(baseRaw, headRaw []byte, repository string) (ApprovalSubject, error) {
	base, err := repinbaselines.ParseOptional(baseRaw)
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("base: %w", err)
	}
	head, err := repinbaselines.Parse(headRaw)
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("proposed: %w", err)
	}
	h, ok := head.Lookup(repository)
	if !ok {
		return ApprovalSubject{}, fmt.Errorf("the proposed baseline file has no entry for %s", logSafe(repository))
	}
	if h.Repository != repository {
		return ApprovalSubject{}, fmt.Errorf("the entry is spelled %s, not %s; give the repository exactly as the entry spells it", logSafe(h.Repository), logSafe(repository))
	}
	id, err := repinbaselines.ApprovalID(h.Repository)
	if err != nil {
		return ApprovalSubject{}, err
	}
	s := ApprovalSubject{Kind: ApprovalSubjectRepinBaseline, Pack: repinbaselines.ApprovalPack, RuleID: id, Scope: h.Repository, Candidate: h.Canonical(), HeadEntry: &h}
	if b, ok := base.Lookup(repository); ok {
		if bytes.Equal(b.Canonical(), s.Candidate) {
			return ApprovalSubject{}, fmt.Errorf("the entry for %s is the same in the base and the proposed file; there is nothing to approve", logSafe(repository))
		}
		s.Base, s.BaseEntry = b.Canonical(), &b
	}
	return s, nil
}

// verifyBaselineSubject is the verification of one baseline approval file:
// signature, owner, subject, scope, age, digests, then the entry checks.
func verifyBaselineSubject(raw []byte, keys ApprovalKeys, s ApprovalSubject, now time.Time) error {
	if s.HeadEntry == nil {
		return errors.New("approval: no proposed entry")
	}
	if err := VerifyBaselineApproval(raw, keys, s.RuleID, s.Scope, s.Base, s.Candidate, now); err != nil {
		return err
	}
	env, err := decodeApproval(raw)
	if err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	if err := baselineEntryCheck(env.Record, *s.HeadEntry, s.BaseEntry); err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	return nil
}

// baselinesCheck admits a change of the owner baseline file. An entry that
// is new or differs from the base needs an owner approval for exactly that
// entry (subject repinBaseline); the approval is single-use and forward-only
// like a record approval (baseApprovals.refuse). Removing an entry needs
// none: the repository goes back to pending. The automation account may not
// change the file. The returned set names the approval files (by approval
// id) the change used.
func (r *Report) baselinesCheck(opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) map[string]bool {
	used := map[string]bool{}
	path := opts.Layout.BaselinesPath
	if path == "" {
		return used
	}
	baseRaw, err1 := opts.Base.ReadOptional(path, maxBaselineFileBytes)
	headRaw, err2 := opts.Head.ReadOptional(path, maxBaselineFileBytes)
	if err1 == nil && err2 == nil && bytes.Equal(baseRaw, headRaw) {
		return used
	}
	fail := func(format string, args ...any) map[string]bool {
		r.add("repin-baselines", false, format, args...)
		return used
	}
	switch {
	case err1 != nil:
		return fail("the base baseline file cannot be read: %v", err1)
	case err2 != nil:
		return fail("the baseline file cannot be read: %v", err2)
	case botChange(opts):
		return fail("the automation account may not change the owner baseline file")
	}
	base, err := repinbaselines.ParseOptional(baseRaw)
	if err != nil {
		return fail("base: %v", err)
	}
	var head repinbaselines.File
	if headRaw == nil {
		head = repinbaselines.File{Schema: repinbaselines.Schema}
	} else if head, err = repinbaselines.Parse(headRaw); err != nil {
		return fail("%v", logSafe(err.Error()))
	}
	var bad []string
	added, changed, removed := 0, 0, 0
	for _, h := range head.Entries {
		b, had := base.Lookup(h.Repository)
		if had && bytes.Equal(b.Canonical(), h.Canonical()) {
			continue
		}
		if had {
			changed++
		} else {
			added++
		}
		if why := admitBaselineEntry(opts, loadKeys, approvals, h, b, had); why != "" {
			bad = append(bad, h.Repository+" ("+why+")")
		} else if id, err := repinbaselines.ApprovalID(h.Repository); err == nil {
			used[id] = true
		}
	}
	for _, b := range base.Entries {
		if _, ok := head.Lookup(b.Repository); !ok {
			removed++
		}
	}
	sort.Strings(bad)
	r.add("repin-baselines", len(bad) == 0, "%d entries added, %d changed, %d removed%s", added, changed, removed, listDetail(bad))
	return used
}

func admitBaselineEntry(opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals, h, b repinbaselines.Entry, had bool) string {
	id, err := repinbaselines.ApprovalID(h.Repository)
	if err != nil {
		return err.Error()
	}
	approvalPath := opts.Layout.ApprovalDir + "/" + repinbaselines.ApprovalPack + "/" + id + ".json"
	raw, err := opts.Head.ReadOptional(approvalPath, maxApprovalBytes+1)
	if err != nil {
		return "approval: " + err.Error()
	}
	if raw == nil {
		return "no owner approval"
	}
	used, err := approvals.refuse(raw)
	switch {
	case err != nil:
		return "approval: " + err.Error()
	case used != "":
		return used
	}
	keys, err := loadKeys()
	if err != nil {
		return err.Error()
	}
	s := ApprovalSubject{Kind: ApprovalSubjectRepinBaseline, Pack: repinbaselines.ApprovalPack, RuleID: id, Scope: h.Repository, Candidate: h.Canonical(), HeadEntry: &h}
	if had {
		s.Base, s.BaseEntry = b.Canonical(), &b
	}
	if err := verifyBaselineSubject(raw, *keys, s, opts.Now); err != nil {
		return err.Error()
	}
	return ""
}

// baselineApprovalPathReason is approvalPathReason for a file under the
// baseline approvals directory: <owner>--<repo>.json, present in the head
// only when this change's baseline check used it.
func baselineApprovalPathReason(name string, used map[string]bool, inHead bool) string {
	id := strings.TrimSuffix(name, ".json")
	if id == name || !strings.Contains(id, "--") {
		return "not <owner>--<repo>.json"
	}
	if inHead && !used[id] {
		return "no admitted baseline entry uses this approval"
	}
	return ""
}
