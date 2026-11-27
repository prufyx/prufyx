// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// CheckTargetFloor is the name of the check that holds the floors of the CRD
// version targets: a change may not lower minFrom or derivedFrom of a target
// without an owner approval for exactly that floor.
const CheckTargetFloor = "target-floor"

// ApprovalSubjectTargetFloor marks an owner approval for one target's floor
// (its effective minFrom and derivedFrom). The approval names the pack
// TargetFloorApprovalPack, the project slug as ruleId and as scope; its
// digests are those of the canonical floor of the base target and of the
// proposed target.
const ApprovalSubjectTargetFloor = "targetFloor"

// TargetFloorApprovalPack is the approvals directory (under ApprovalDir) of
// target floor approvals: <slug>.json.
const TargetFloorApprovalPack = "target-floors"

var approvalFloorScopeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// floorCanonical is the canonical JSON of a target's floor: the effective
// minFrom and derivedFrom (derivedFrom defaults to minFrom), keys sorted.
func floorCanonical(t crdversions.Target) []byte {
	raw, _ := json.Marshal(struct {
		DerivedFrom string `json:"derivedFrom"`
		MinFrom     string `json:"minFrom"`
		Project     string `json:"project"`
	}{fmt.Sprintf("%d.%d", t.DerivedFrom[0], t.DerivedFrom[1]), fmt.Sprintf("%d.%d", t.MinFrom[0], t.MinFrom[1]), t.Project})
	return raw
}

func lineBefore(a, b [2]int) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

// FloorLowered reports whether head covers more than base by its floor:
// either effective line is lower. A lower derivedFrom adds derived claims as
// a lower minFrom does, so both count.
func FloorLowered(base, head crdversions.Target) bool {
	return lineBefore(head.MinFrom, base.MinFrom) || lineBefore(head.DerivedFrom, base.DerivedFrom)
}

// TargetFloorApprovalSubject builds the approval subject for one project from
// the base and head target files (base nil: the base has no such target).
// It refuses a floor that is not lowered: there is nothing to approve.
func TargetFloorApprovalSubject(baseRaw, headRaw []byte, slug string) (ApprovalSubject, error) {
	name := crdversions.TargetFileName(slug)
	head, err := crdversions.LoadTarget(name, headRaw)
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("proposed: %w", err)
	}
	s := ApprovalSubject{Kind: ApprovalSubjectTargetFloor, Pack: TargetFloorApprovalPack, RuleID: slug, Scope: slug, Candidate: floorCanonical(head)}
	if baseRaw != nil {
		base, err := crdversions.LoadTarget(name, baseRaw)
		if err != nil {
			return ApprovalSubject{}, fmt.Errorf("base: %w", err)
		}
		if !FloorLowered(base, head) {
			return ApprovalSubject{}, fmt.Errorf("the floor of %s is not lowered; there is nothing to approve", logSafe(slug))
		}
		s.Base = floorCanonical(base)
	} else if !lineBefore(head.DerivedFrom, head.MinFrom) {
		return ApprovalSubject{}, fmt.Errorf("a new target without a derivedFrom below its minFrom needs no floor approval")
	}
	return s, nil
}

// targetFloorCheck refuses any change that lowers the effective minFrom or
// derivedFrom of a target unless an owner approval for exactly that floor is
// in the change: signed by a pinned owner, bound to the base floor and the
// proposed floor, single use and forward only (baseApprovals.refuse). The
// author does not matter: the automation account gets no exception, and the
// pause switch holds every lowering. A new target whose derivedFrom is below
// its minFrom is a lowering from an absent base. A floor that is raised, or
// a target that is unchanged, needs nothing here (a raise is narrowing and
// is held by the target guard).
//
// Layouts that name no targets directory publish no target floors; the
// shipped layout always names one. A target of the base or the head that
// cannot be read or parsed fails the check when its bytes differ.
func (r *Report) targetFloorCheck(cls *Classification, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) map[string]bool {
	used := map[string]bool{}
	dir := opts.Layout.Onboarding.TargetsDir
	if dir == "" {
		return used
	}
	fail := func(format string, args ...any) map[string]bool {
		r.add(CheckTargetFloor, false, format, args...)
		return used
	}
	baseT, err := treeTargets(opts.Base, dir)
	if err != nil {
		return fail("the base targets cannot be read: %v", logSafe(err.Error()))
	}
	headT, err := treeTargets(opts.Head, dir)
	if err != nil {
		return fail("the targets of the change cannot be read: %v", logSafe(err.Error()))
	}
	names := make([]string, 0, len(headT))
	for name := range headT {
		names = append(names, name)
	}
	sort.Strings(names)
	var bad []string
	lowered := 0
	for _, name := range names {
		headRaw := headT[name]
		baseRaw, inBase := baseT[name]
		if inBase && bytes.Equal(baseRaw, headRaw) {
			continue
		}
		slug := strings.TrimSuffix(strings.TrimPrefix(name, "target-"), ".json")
		head, err := crdversions.LoadTarget(name, headRaw)
		if err != nil {
			bad = append(bad, slug+" (target: "+logSafe(err.Error())+")")
			continue
		}
		var s ApprovalSubject
		if inBase {
			base, err := crdversions.LoadTarget(name, baseRaw)
			if err != nil {
				bad = append(bad, slug+" (base target: "+logSafe(err.Error())+")")
				continue
			}
			if !FloorLowered(base, head) {
				continue
			}
			s = ApprovalSubject{Kind: ApprovalSubjectTargetFloor, Pack: TargetFloorApprovalPack, RuleID: slug, Scope: slug, Candidate: floorCanonical(head), Base: floorCanonical(base)}
		} else {
			if !lineBefore(head.DerivedFrom, head.MinFrom) {
				continue
			}
			s = ApprovalSubject{Kind: ApprovalSubjectTargetFloor, Pack: TargetFloorApprovalPack, RuleID: slug, Scope: slug, Candidate: floorCanonical(head)}
		}
		lowered++
		if why := admitTargetFloor(cls, opts, loadKeys, approvals, s); why != "" {
			bad = append(bad, slug+" ("+why+")")
		} else {
			used[slug] = true
		}
	}
	sort.Strings(bad)
	r.add(CheckTargetFloor, len(bad) == 0, "%d target floors lowered%s", lowered, listDetail(bad))
	return used
}

func admitTargetFloor(cls *Classification, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals, s ApprovalSubject) string {
	if cls != nil && cls.Paused {
		return "the pause switch is set: no loosening is admitted"
	}
	raw, err := opts.Head.ReadOptional(opts.Layout.ApprovalDir+"/"+TargetFloorApprovalPack+"/"+s.RuleID+".json", maxApprovalBytes+1)
	if err != nil {
		return "approval: " + logSafe(err.Error())
	}
	if raw == nil {
		return "lowers the floor without an owner approval"
	}
	used, err := approvals.refuse(raw)
	switch {
	case err != nil:
		return "approval: " + logSafe(err.Error())
	case used != "":
		return used
	}
	keys, err := loadKeys()
	if err != nil {
		return logSafe(err.Error())
	}
	if err := VerifyApprovalSubject(raw, *keys, s, opts.Now); err != nil {
		return logSafe(err.Error())
	}
	return ""
}

// targetFloorApprovalPathReason is approvalPathReason for a file under the
// target-floors approvals directory: <slug>.json, present in the head only
// when this change's floor check used it.
func targetFloorApprovalPathReason(name string, used map[string]bool, inHead bool) string {
	slug := strings.TrimSuffix(name, ".json")
	if slug == name || !approvalFloorScopeRE.MatchString(slug) {
		return "not <slug>.json"
	}
	if inHead && !used[slug] {
		return "no lowered target floor uses this approval"
	}
	return ""
}
