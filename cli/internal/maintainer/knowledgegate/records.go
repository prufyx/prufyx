// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Records are the line attestations (lineattest.PackMember) and upgrade-path
// policies (upgradepath.PackMember) a rule pack may carry besides its rules.
// The gate diffs them one record at a time, keyed by the record ID evidence
// repin and evidence reattest use (evidencerepin.LineAttestationRecordID,
// evidencerepin.PathPolicyRecordID), never by position.
//
// Classification, from the record diff only:
//
//   - a line attestation removed: tightening (its line becomes a gap again);
//   - a line attestation or path policy whose only change is an earlier
//     validUntil, or (path policy) a withdrawal, or both: tightening;
//   - anything else, including a new record, a renewal, a removed path
//     policy (without a record a path is planned as one direct hop; withdraw
//     it instead) and any change to a record's content: loosening.
//
// A loosening record change is admitted only with a proof the gate checks:
//
//   - basis mechanical: a line attestation re-derived byte-identically by
//     the extractor compiled into this binary, under the derivation-time
//     bound that applies to mechanical rules; no extractor derives path
//     policies, so a mechanical path policy never changes through the gate;
//   - basis reviewed, a renewal: the change appends exactly one verified
//     reattestation statement for the pack that renews this record, and the
//     record differs from the base only in evidence.reviewedAt and
//     evidence.validUntil, set exactly to the statement's attestedAt and the
//     validUntil the statement gives the record;
//   - basis reviewed line attestation, added or changed otherwise: a signed
//     owner approval for exactly this record (subject lineAttestation, its
//     scope, its base state), plus the cross-check against the attesting
//     extractor's own derivation of the line (crossCheckAttestation);
//   - any other reviewed path policy change: not admitted.

// Record sections.
const (
	sectionAttestations = lineattest.PackMember
	sectionPolicies     = upgradepath.PackMember
)

// Approval subjects.
const (
	// ApprovalSubjectLineAttestation marks an owner approval for one line
	// attestation record. A rule approval has no subject.
	ApprovalSubjectLineAttestation = "lineAttestation"
)

// record is one line attestation or path-policy record of a pack, keyed by
// its record ID.
type record struct {
	ID      string
	Section string
	Project string
	// Scope is the record's scope key: "<component> <factFamily> <line>"
	// for a line attestation, the component for a path policy.
	Scope     string
	Raw       json.RawMessage
	Canonical []byte
	generic   map[string]any
	// Basis is the effective basis (absent means reviewed).
	Basis      string
	State      string
	Extractor  *constraintengine.Extractor
	DerivedAt  string
	ReviewedAt string
	ValidUntil string

	attestation *lineattest.LineAttestation
	policy      *upgradepath.Record
}

func (r *record) mechanical() bool { return r.Basis == constraintengine.BasisMechanical }

// attestationScope is the scope key an attestation approval names.
func attestationScope(a lineattest.LineAttestation) string {
	return a.Component + " " + a.FactFamily + " " + a.Line
}

// loadRecords reads the pack's record sections exactly as evidence repin
// and evidence reattest read them (evidencerepin.PackRecords: exact member
// names, strict parse, one record per ID) and indexes them by record ID.
func loadRecords(raw []byte) (map[string]*record, []string, error) {
	records, err := evidencerepin.PackRecords(raw)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]*record{}
	var order []string
	for _, pr := range records {
		r := &record{ID: pr.ID, Project: pr.Project, Raw: pr.Raw}
		doc := append(append([]byte("["), pr.Raw...), ']')
		switch pr.Project {
		case evidencerepin.RecordProjectLineAttestations:
			atts, err := lineattest.Parse(doc)
			if err != nil || len(atts) != 1 {
				return nil, nil, fmt.Errorf("record %s: %v", pr.ID, err)
			}
			a := atts[0]
			if evidencerepin.LineAttestationRecordID(a.Component, a.FactFamily, a.Line) != pr.ID {
				return nil, nil, fmt.Errorf("record %s does not match its scope", pr.ID)
			}
			r.Section, r.Scope, r.attestation = sectionAttestations, attestationScope(a), &a
			r.Basis, r.State = constraintengine.EffectiveBasis(a.Evidence.Basis), upgradepath.StateActive
			r.Extractor, r.DerivedAt, r.ReviewedAt, r.ValidUntil = a.Evidence.Extractor, a.Evidence.DerivedAt, a.Evidence.ReviewedAt, a.Evidence.ValidUntil
		case evidencerepin.RecordProjectPathPolicies:
			policies, err := upgradepath.Parse(doc)
			if err != nil || len(policies) != 1 {
				return nil, nil, fmt.Errorf("record %s: %v", pr.ID, err)
			}
			p := policies[0]
			if evidencerepin.PathPolicyRecordID(p.Component) != pr.ID {
				return nil, nil, fmt.Errorf("record %s does not match its scope", pr.ID)
			}
			r.Section, r.Scope, r.policy = sectionPolicies, p.Component, &p
			r.Basis, r.State = constraintengine.EffectiveBasis(p.Evidence.Basis), p.Evidence.State
			r.Extractor, r.DerivedAt, r.ReviewedAt, r.ValidUntil = p.Evidence.Extractor, p.Evidence.DerivedAt, p.Evidence.ReviewedAt, p.Evidence.ValidUntil
		default:
			return nil, nil, fmt.Errorf("record %s of unknown kind", pr.ID)
		}
		if r.Canonical, err = extract.Canonical(pr.Raw); err != nil {
			return nil, nil, fmt.Errorf("record %s: %w", pr.ID, err)
		}
		if r.generic, err = decodeGeneric(pr.Raw); err != nil {
			return nil, nil, fmt.Errorf("record %s: %w", pr.ID, err)
		}
		if _, dup := out[r.ID]; dup {
			return nil, nil, fmt.Errorf("two records have the ID %s", r.ID)
		}
		out[r.ID] = r
		order = append(order, r.ID)
	}
	return out, order, nil
}

// recordSection reports whether member is a record section the pack's
// records are diffed for.
func recordSection(spec PackSpec, member string) bool {
	return spec.Records && (member == sectionAttestations || member == sectionPolicies)
}

// diffRecords classifies every record of one section that differs between
// base and head, keyed by record ID.
func diffRecords(base, head *loadedPack, section string) []*Change {
	ids := map[string]bool{}
	for id, r := range base.Records {
		if r.Section == section {
			ids[id] = true
		}
	}
	for id, r := range head.Records {
		if r.Section == section {
			ids[id] = true
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	var out []*Change
	for _, id := range sorted {
		b, h := base.Records[id], head.Records[id]
		if b != nil && h != nil && bytes.Equal(b.Canonical, h.Canonical) {
			continue
		}
		c := &Change{Pack: head.Spec.Name, RuleID: id, Section: section, rbase: b, rhead: h}
		switch {
		case b == nil:
			c.Project, c.Basis = h.Project, h.Basis
			c.Class, c.Kinds = ClassLoosening, []string{KindNew}
		case h == nil:
			c.Project, c.Basis = b.Project, b.Basis
			if section == sectionAttestations {
				c.Class, c.Kinds = ClassTightening, []string{KindRemove}
			} else {
				c.Class, c.Kinds = ClassLoosening, []string{KindRemove}
			}
		default:
			c.Project, c.Basis = h.Project, h.Basis
			c.Class, c.Kinds, c.renewal = classifyRecordEdit(b, h)
		}
		out = append(out, c)
	}
	return out
}

// classifyRecordEdit classifies a record present in both packs. It is
// tightening only when the head equals the base except for an earlier
// validUntil and, for a path policy, a withdrawal; renewal is true only
// when the head equals the base except for a later reviewedAt and a later
// validUntil of an active record.
func classifyRecordEdit(b, h *record) (string, []string, bool) {
	var kinds []string
	loosening := false
	if b.State != h.State {
		switch {
		case b.State == upgradepath.StateActive && h.State == upgradepath.StateWithdrawn:
			kinds = append(kinds, KindWithdraw)
		case b.State == upgradepath.StateWithdrawn && h.State == upgradepath.StateActive:
			kinds, loosening = append(kinds, KindReactivate), true
		default:
			kinds, loosening = append(kinds, KindModify), true
		}
	}
	endLater, endEarlier := timeOrder(b.ValidUntil, h.ValidUntil)
	if b.ValidUntil != h.ValidUntil {
		if endEarlier {
			kinds = append(kinds, KindExpire)
		} else {
			kinds, loosening = append(kinds, KindRenew), true
		}
	}
	// Everything but state and validUntil must be canonically identical
	// for the edit to stay tightening.
	if !onlyEvidenceDiffers(b, h, "state", "validUntil") {
		loosening = true
		if !sameAt(b.generic, h.generic, "evidence", "reviewedAt") || !sameAt(b.generic, h.generic, "evidence", "derivedAt") {
			if !containsKind(kinds, KindRenew) {
				kinds = append(kinds, KindRenew)
			}
		}
		if !sameAt(b.generic, h.generic, "evidence", "sources") {
			kinds = append(kinds, KindRepin)
		}
		if !sameAt(b.generic, h.generic, "evidence", "basis") || !sameAt(b.generic, h.generic, "evidence", "extractor") {
			kinds = append(kinds, KindBasis)
		}
		if !onlyEvidenceDiffers(b, h, "state", "validUntil", "reviewedAt", "derivedAt", "sources", "basis", "extractor") {
			kinds = append(kinds, KindModify)
		}
	}
	if !loosening {
		return ClassTightening, kinds, false
	}
	startLater, _ := timeOrder(b.ReviewedAt, h.ReviewedAt)
	renewal := b.State == upgradepath.StateActive && h.State == upgradepath.StateActive && startLater && endLater &&
		onlyEvidenceDiffers(b, h, "reviewedAt", "validUntil")
	if b.attestation != nil && h.attestation != nil {
		// The attestation classifier must agree that this is a renewal.
		changes, err := lineattest.Classify([]lineattest.LineAttestation{*b.attestation}, []lineattest.LineAttestation{*h.attestation})
		renewal = renewal && err == nil && len(changes) == 1 && changes[0].Class == lineattest.Loosening && changes[0].Renewal
	}
	return ClassLoosening, kinds, renewal
}

// onlyEvidenceDiffers reports whether h equals b (canonical JSON) once the
// named evidence members of h are set to b's (or removed when b has none).
func onlyEvidenceDiffers(b, h *record, fields ...string) bool {
	rest := deepCopy(h.generic)
	for _, field := range fields {
		v, ok := lookup(b.generic, "evidence", field)
		if !setOrDelete(rest, v, ok, "evidence", field) {
			return false
		}
	}
	return bytes.Equal(canonicalOf(rest), canonicalOf(b.generic))
}

// timeOrder reports whether b is later or earlier than a; unreadable
// values are neither.
func timeOrder(a, b string) (later, earlier bool) {
	ta, err1 := time.Parse(time.RFC3339, a)
	tb, err2 := time.Parse(time.RFC3339, b)
	if err1 != nil || err2 != nil {
		return false, false
	}
	return tb.After(ta), tb.Before(ta)
}

// renewedValidUntil is the validUntil a statement gives one renewed item:
// its own in an automated statement, the statement's otherwise.
func renewedValidUntil(stmt evidencereattest.Statement, id string) (string, bool) {
	for _, ra := range stmt.Rules {
		if ra.RuleID == id {
			if ra.ValidUntil != "" {
				return ra.ValidUntil, true
			}
			return stmt.ValidUntil, true
		}
	}
	return "", false
}

// admitRecord decides a loosening change of a reviewed record. Mechanical
// record changes go to re-derivation instead (see Verify).
func admitRecord(c *Change, stmt statementResult, loadKeys func() (*ApprovalKeys, error), crossCheck func(pack string, r *record) error, opts Options) {
	h := c.rhead
	if h == nil {
		c.fail("a path policy may not be removed (without it a path is planned as one direct hop); withdraw it instead")
		return
	}
	if h.Basis != constraintengine.BasisReviewed || (c.rbase != nil && c.rbase.mechanical()) {
		c.fail(fmt.Sprintf("evidence basis %q of this record is not admitted here", logSafe(h.Basis)))
		return
	}
	var reasons []string
	switch {
	case !stmt.OK && stmt.Detail != "":
		reasons = append(reasons, "reattestation: "+stmt.Detail)
	case !stmt.OK:
		reasons = append(reasons, "no reattestation statement")
	case !stmt.Renewed[c.RuleID]:
		reasons = append(reasons, "the reattestation statement does not renew this record")
	case !c.renewal:
		reasons = append(reasons, "the record changes more than its evidence.reviewedAt and evidence.validUntil")
	case stmt.Role != evidencereattest.RoleAutomation:
		reasons = append(reasons, "records are renewed only by an automated statement")
	default:
		until, _ := renewedValidUntil(stmt.Statement, c.RuleID)
		if h.ReviewedAt != stmt.Statement.AttestedAt || h.ValidUntil != until {
			reasons = append(reasons, fmt.Sprintf("the record's dates %s..%s are not the statement's %s..%s", logSafe(h.ReviewedAt), logSafe(h.ValidUntil), logSafe(stmt.Statement.AttestedAt), logSafe(until)))
			break
		}
		c.OK, c.Proof = true, ProofReattestation
		return
	}
	if c.Section != sectionAttestations {
		c.fail("a reviewed path policy changes only by renewal through a verified reattestation statement: " + strings.Join(reasons, "; "))
		return
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
			break
		}
		var base []byte
		if c.rbase != nil {
			base = c.rbase.Canonical
		}
		if err := VerifyRecordApproval(raw, *keys, c.Pack, ApprovalSubjectLineAttestation, c.RuleID, h.Scope, base, h.Canonical, opts.Now); err != nil {
			reasons = append(reasons, err.Error())
			break
		}
		if err := crossCheck(c.Pack, h); err != nil {
			reasons = append(reasons, "cross-check with the extractor: "+err.Error())
			break
		}
		c.OK, c.Proof = true, ProofApproval
		return
	}
	c.fail("a reviewed line attestation may change only by renewal through a verified reattestation statement, or with an owner approval and the extractor cross-check: " + strings.Join(reasons, "; "))
}

// freshRecordDerivation applies the derivation-time bound to a loosening
// mechanical record change.
func freshRecordDerivation(r *record, now time.Time) error {
	return freshDerivation(&entry{Evidence: evidenceView{DerivedAt: r.DerivedAt}}, now)
}

// factRef is one fact a rule reads.
type factRef struct{ component, factID string }

// ruleFacts lists the facts a raw rule reads: its condition, its set
// condition and its applicability conditions.
func ruleFacts(rule json.RawMessage) ([]factRef, error) {
	type cond struct {
		Component string `json:"component"`
		FactID    string `json:"factId"`
	}
	var shape struct {
		Condition    *cond  `json:"condition"`
		SetCondition *cond  `json:"setCondition"`
		AppliesWhen  []cond `json:"appliesWhen"`
	}
	if err := json.Unmarshal(rule, &shape); err != nil {
		return nil, err
	}
	conds := append([]cond(nil), shape.AppliesWhen...)
	if shape.Condition != nil {
		conds = append(conds, *shape.Condition)
	}
	if shape.SetCondition != nil {
		conds = append(conds, *shape.SetCondition)
	}
	out := make([]factRef, 0, len(conds))
	for _, c := range conds {
		out = append(out, factRef{c.Component, c.FactID})
	}
	return out, nil
}

// entryRule returns the rule member of a raw pack entry.
func entryRule(raw json.RawMessage) (json.RawMessage, error) {
	var shape struct {
		Rule json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil || len(shape.Rule) == 0 {
		return nil, fmt.Errorf("entry has no rule")
	}
	return shape.Rule, nil
}

// crossCheckAttestation checks a reviewed line attestation against the
// attesting extractor's own run over pinned upstream bytes (out): a person
// may attest a line by approval, but for a line the extractor derives, the
// claim must agree with what the extractor reads upstream.
//
//   - A line before the first line the extractor derives is outside what it
//     can check: the approval alone decides.
//   - Any other line must be one the extractor derived and attested for the
//     attestation's family, and every fact of that family the extractor
//     derives for the line must be read by a rule the attestation lists.
//     So an attestation that leaves out a removal upstream makes is
//     refused, even with an approval.
func crossCheckAttestation(out *extract.Output, a lineattest.LineAttestation, head *loadedPack) error {
	family, ok := lineattest.LookupFamily(a.FactFamily)
	if !ok {
		return fmt.Errorf("unknown fact family %s", logSafe(a.FactFamily))
	}
	var first string
	var pair *extract.PairRecord
	for i := range out.Manifest.Pairs {
		p := &out.Manifest.Pairs[i]
		line, ok := lineattest.LineOf(p.To)
		if !ok {
			continue
		}
		if first == "" || lineattest.LineLess(line, first) {
			first = line
		}
		if line == a.Line {
			pair = p
		}
	}
	if first == "" {
		return fmt.Errorf("the extractor derives no line from the pinned upstream bytes")
	}
	if lineattest.LineLess(a.Line, first) {
		return nil
	}
	if pair == nil {
		return fmt.Errorf("the extractor derives no pair into line %s from the pinned upstream bytes", a.Line)
	}
	if pair.Status != extract.PairDerived || pair.Attestation == nil || pair.Attestation.Status != extract.PairAttested || !containsKind(pair.Attestation.Families, a.FactFamily) {
		reason := pair.Reason
		if pair.Attestation != nil && pair.Attestation.Reason != "" {
			reason = pair.Attestation.Reason
		}
		return fmt.Errorf("the extractor does not attest line %s (%s)", a.Line, logSafe(reason))
	}
	derived := map[string]extract.Entry{}
	for _, e := range out.Entries {
		derived[e.Rule.ID] = e
	}
	read := map[factRef]bool{}
	for _, id := range a.RuleIDs {
		e := head.Entries[id]
		if e == nil {
			return fmt.Errorf("listed rule %s is not in the pack", logSafe(id))
		}
		rule, err := entryRule(e.Raw)
		if err != nil {
			return err
		}
		facts, err := ruleFacts(rule)
		if err != nil {
			return err
		}
		for _, f := range facts {
			read[f] = true
		}
	}
	var missing []string
	for _, id := range pair.Rules {
		e, ok := derived[id]
		if !ok {
			return fmt.Errorf("the extractor's rule %s for line %s is missing from its output", id, a.Line)
		}
		raw, err := json.Marshal(e.Rule)
		if err != nil {
			return err
		}
		facts, err := ruleFacts(raw)
		if err != nil {
			return err
		}
		for _, f := range facts {
			if family.Covers(f.component, f.factID) && !read[f] {
				missing = append(missing, f.factID)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("upstream line %s removes what facts %s describe, and no rule the attestation lists reads them", a.Line, strings.Join(missing, ", "))
	}
	return nil
}

// attestationRulecheck checks the head pack's line attestations against
// its rules with the maintainer rule check (exact rule sets, line-wide
// rules): a rule added to an attested line without the attestation being
// updated fails here as well as in engine admission. It runs only for a
// pack whose head carries a line attestation section.
func (r *Report) attestationRulecheck(spec PackSpec, h *loadedPack) {
	if !spec.Records || !h.Present {
		return
	}
	if _, ok := h.Members[sectionAttestations]; !ok {
		return
	}
	name := "rulecheck/" + spec.Name + "/" + sectionAttestations
	res, err := rulecheck.ValidatePackAttestations(h.Raw, rulecheck.AttestationOptions{})
	if err != nil {
		r.add(name, false, "%v", err)
		return
	}
	var findings []string
	for _, f := range res.Findings {
		findings = append(findings, fmt.Sprintf("%s %s: %s", f.RuleID, f.Check, f.Message))
	}
	r.add(name, res.Valid && len(findings) == 0, "%d line attestations, %d findings%s", res.EntryCount, len(findings), listDetail(findings))
}

// recordStaggerCheck applies the stagger cap to rules and records together,
// as a reattestation statement's own check does: for every ISO week a
// loosening change of a rule or a record moves an active lease into, at
// most StaggerCap(rules + records) items of the pack may have their
// validUntil in that week. The rules-only check (staggerCheck) still
// applies on its own. It runs only for a pack that carries records.
func (r *Report) recordStaggerCheck(cls *Classification, spec PackSpec, b, h *loadedPack, ruleWeeks map[string]bool) {
	if !spec.Records || (len(h.Records) == 0 && len(b.Records) == 0) {
		return
	}
	weeks := map[string]bool{}
	for w := range ruleWeeks {
		weeks[w] = true
	}
	for _, c := range cls.Changes {
		if c.Pack != spec.Name || c.Section == "" || c.Class != ClassLoosening || c.rhead == nil || c.rhead.State != upgradepath.StateActive {
			continue
		}
		if c.rbase != nil && c.rbase.ValidUntil == c.rhead.ValidUntil {
			continue
		}
		until, err := time.Parse(time.RFC3339, c.rhead.ValidUntil)
		if err != nil {
			continue // the record does not parse; loading refused it
		}
		weeks[evidencereattest.ISOWeek(until)] = true
	}
	name := "stagger/" + spec.Name + "/records"
	if len(weeks) == 0 {
		r.add(name, true, "no lease moved")
		return
	}
	counts := map[string]int{}
	count := func(validUntil string) {
		until, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return
		}
		if w := evidencereattest.ISOWeek(until); weeks[w] {
			counts[w]++
		}
	}
	for _, e := range h.Entries {
		count(e.Evidence.ValidUntil)
	}
	for _, rec := range h.Records {
		count(rec.ValidUntil)
	}
	limit := evidencereattest.StaggerCap(len(h.Entries) + len(h.Records))
	var over []string
	for w, n := range counts {
		if n > limit {
			over = append(over, fmt.Sprintf("%s holds %d", w, n))
		}
	}
	sort.Strings(over)
	r.add(name, len(over) == 0, "cap %d rules and records per ISO week%s", limit, listDetail(over))
}
