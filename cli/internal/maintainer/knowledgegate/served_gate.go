// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/servedlists"
)

// A served-API list is admitted only when the gate re-derives it: the
// deriver compiled into this binary (servedlists) runs over the
// specification the record cites, read from the commit the line's release
// tag v<line>.0 points at, and must yield the record byte for byte
// (canonical JSON). That tag-to-commit check is what binds a list to its
// line. A list of any other basis is refused; no approval admits one.
//
// The first introduction of the servedAPIs member into a pack (the base has
// none) also needs an owner approval of subject servedAPIs
// (admitServedIntroduction). Once the member is in the base, lists are
// added, renewed and removed mechanically.

// maxServedUpstreamFailures stops a re-derivation pass after this many
// upstream read failures in a row.
const maxServedUpstreamFailures = 3

// servedPre runs the checks of a served-list change that need no upstream.
func servedPre(c *Change, opts Options) error {
	h := c.rhead
	if !h.mechanical() {
		return fmt.Errorf("a served-API list is admitted only when the gate re-derives it from the pinned upstream specification (evidence basis mechanical); basis %q is not admitted, and no approval admits it", logSafe(h.Basis))
	}
	return freshRecordDerivation(h, opts.Now)
}

// rederiveServed re-derives the served lists of changes and sets OK, Proof
// and Detail on each. The tags are read once; the specifications one by one,
// and the pass stops after maxServedUpstreamFailures upstream errors in a
// row. A refusal about a record's content is final for that record; an
// upstream error is a failure, never a pass.
func rederiveServed(ctx context.Context, src Source, changes []*Change) {
	if len(changes) == 0 {
		return
	}
	failAll := func(why string) {
		for _, c := range changes {
			c.fail("re-derivation failed: " + why)
		}
	}
	if src == nil {
		failAll("no upstream source is configured")
		return
	}
	shipped, err := servedlists.Identity()
	if err != nil {
		failAll(err.Error())
		return
	}
	repo, err := extract.ParseRepo(servedlists.Repo)
	if err != nil {
		failAll(err.Error())
		return
	}
	tags, err := src.Tags(repo)
	if err != nil {
		failAll(fmt.Sprintf("tags of %s: %v", servedlists.Repo, err))
		return
	}
	failures := 0
	for _, c := range changes {
		switch {
		case ctx.Err() != nil:
			c.fail("re-derivation failed: " + ctx.Err().Error())
			continue
		case failures >= maxServedUpstreamFailures:
			c.fail("re-derivation not attempted: upstream reads failed repeatedly in this pass")
			continue
		}
		upstream, err := rederiveServedOne(src, repo, tags, shipped, c)
		switch {
		case err != nil:
			c.fail("re-derivation failed: " + err.Error())
			if upstream {
				failures++
			} else {
				failures = 0
			}
		default:
			failures = 0
			c.OK, c.Proof = true, ProofRederived
		}
	}
}

// rederiveServedOne checks one record. upstream is true when the error is
// the upstream's (a read that failed), not a finding about the record.
func rederiveServedOne(src Source, repo extract.RepoRef, tags []extract.Tag, shipped constraintengine.Extractor, c *Change) (upstream bool, err error) {
	rec := c.rhead.served
	x := rec.Evidence.Extractor
	if x == nil || *x != shipped {
		return false, fmt.Errorf("the list names deriver %s, this gate runs %s %s %s", logSafe(fmt.Sprintf("%+v", x)), shipped.ID, shipped.Version, shipped.CodeDigest)
	}
	if cncfcheck.ServedListNamesRemovedAPI(*rec) {
		return false, errors.New("the list names an API version the removal table marks as removed at or before its line")
	}
	if len(rec.Evidence.Sources) != 1 {
		return false, fmt.Errorf("the list must cite exactly one source, the line's OpenAPI specification; it cites %d", len(rec.Evidence.Sources))
	}
	commit, err := servedlists.ReleaseCommit(tags, rec.Line)
	if err != nil {
		return false, err
	}
	s := rec.Evidence.Sources[0]
	if s.Revision != commit {
		tag, _ := servedlists.ReleaseTag(rec.Line)
		return false, fmt.Errorf("the cited revision %s is not the commit %s of tag %s", logSafe(s.Revision), commit, tag)
	}
	if s.ID != servedlists.SourceID(rec.Line) || s.URL != repo.BlobURL(commit, servedlists.SwaggerPath) {
		return false, fmt.Errorf("the cited source is not %s of %s at %s", servedlists.SwaggerPath, repo.Key, commit)
	}
	data, err := servedlists.ReadSwagger(src, commit)
	if err != nil {
		return true, err
	}
	if got := servedlists.SwaggerDigest(data); got != s.ContentDigest {
		return false, fmt.Errorf("the cited contentDigest %s is not the digest %s of the pinned specification", logSafe(s.ContentDigest), got)
	}
	derivedAt, err1 := time.Parse(time.RFC3339, rec.Evidence.DerivedAt)
	validUntil, err2 := time.Parse(time.RFC3339, rec.Evidence.ValidUntil)
	if err1 != nil || err2 != nil {
		return false, errors.New("derivedAt or validUntil is not a time")
	}
	want, err := servedlists.Assemble(rec.Line, commit, data, derivedAt, validUntil)
	if err != nil {
		return false, err
	}
	canonical, err := extract.Canonical(want)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(canonical, c.rhead.Canonical) {
		return false, fmt.Errorf("the list differs from what deriver %s %s derives from the pinned specification of %s", shipped.ID, shipped.Version, rec.Line)
	}
	return false, nil
}

const (
	// ApprovalSubjectServed is the subject of the owner approval that
	// introduces the servedAPIs member into a pack.
	ApprovalSubjectServed = "servedAPIs"
	// ServedApprovalID is the rule id such an approval names; it is also the
	// approval's file name (<pack>/member.servedAPIs.json). It is never a rule
	// id (rule ids are lower case) or a record ID.
	ServedApprovalID = "member.servedAPIs"
	// ServedApprovalScope is the scope such an approval names.
	ServedApprovalScope = "servedAPIs"
	// ServedIntroductionSchema is the schema of the statement such an
	// approval binds.
	ServedIntroductionSchema = "prufyx.io/served-api-lists-introduction/v1"
)

// ServedIntroduction is the statement an approval of subject servedAPIs binds
// (its canonical JSON is the candidate): the deriver identity, every list of
// the head with the digest of its canonical bytes, and the digests of the
// base and head pack files.
type ServedIntroduction struct {
	Schema         string                     `json:"schema"`
	Deriver        constraintengine.Extractor `json:"deriver"`
	BasePackDigest string                     `json:"basePackDigest"`
	HeadPackDigest string                     `json:"headPackDigest"`
	Lists          []ServedIntroductionList   `json:"lists"`
}

// ServedIntroductionList is one list the statement names.
type ServedIntroductionList struct {
	Component string `json:"component"`
	Line      string `json:"line"`
	RecordID  string `json:"recordId"`
	Digest    string `json:"digest"`
}

// servedIntroductionStatement reads the statement of an introduction of the
// servedAPIs member between a base and a head pack, and its canonical JSON.
func servedIntroductionStatement(base, head *loadedPack) (ServedIntroduction, []byte, error) {
	if base == nil || head == nil || !base.Present || !head.Present {
		return ServedIntroduction{}, nil, errors.New("the pack is missing from the base or the head")
	}
	if _, ok := base.Members[sectionServed]; ok {
		return ServedIntroduction{}, nil, errors.New("the base pack already has the servedAPIs member: lists change mechanically, with no approval")
	}
	if _, ok := head.Members[sectionServed]; !ok {
		return ServedIntroduction{}, nil, errors.New("the head pack has no servedAPIs member")
	}
	x, err := servedlists.Identity()
	if err != nil {
		return ServedIntroduction{}, nil, err
	}
	st := ServedIntroduction{Schema: ServedIntroductionSchema, Deriver: x, BasePackDigest: CandidateDigest(base.Raw), HeadPackDigest: CandidateDigest(head.Raw)}
	for _, id := range head.RecordOrder {
		if rec := head.Records[id]; rec.served != nil {
			st.Lists = append(st.Lists, ServedIntroductionList{Component: rec.served.Component, Line: rec.served.Line, RecordID: id, Digest: CandidateDigest(rec.Canonical)})
		}
	}
	canonical, err := extract.Canonical(st)
	if err != nil {
		return ServedIntroduction{}, nil, err
	}
	return st, canonical, nil
}

// servedApprovalPath is where a change carries the approval of a pack's
// servedAPIs introduction.
func servedApprovalPath(layout Layout, pack string) string {
	return layout.ApprovalDir + "/" + pack + "/" + ServedApprovalID + ".json"
}

// ServedApprovalSubject reads the introduction of the servedAPIs member of a
// pack between a base and a head checkout exactly as the gate reads it, for
// the owner to sign or check an approval of it.
func ServedApprovalSubject(spec PackSpec, base, head Tree) (ApprovalSubject, ServedIntroduction, error) {
	b, err := loadPack(base, spec)
	if err != nil {
		return ApprovalSubject{}, ServedIntroduction{}, err
	}
	h, err := loadPack(head, spec)
	if err != nil {
		return ApprovalSubject{}, ServedIntroduction{}, err
	}
	st, canonical, err := servedIntroductionStatement(b, h)
	if err != nil {
		return ApprovalSubject{}, ServedIntroduction{}, err
	}
	return ApprovalSubject{Kind: ApprovalSubjectServed, Pack: spec.Name, RuleID: ServedApprovalID, Scope: ServedApprovalScope, Candidate: canonical}, st, nil
}

// admitServedIntroduction decides, for every pack whose head holds a
// servedAPIs member the base lacks, whether the introduction is admitted: every
// list change was re-derived (its own proof) and an owner approval of subject
// servedAPIs arrives with the change, verifies under the base's pinned owner
// keys and binds exactly the statement of this change. A change that is not
// admitted fails every list of the pack. With the member in the base nothing
// is decided here: lists change mechanically. It returns the packs it admitted.
func admitServedIntroduction(cls *Classification, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) map[string]bool {
	admitted := map[string]bool{}
	for _, spec := range opts.Layout.Packs {
		base, head := cls.base[spec.Name], cls.head[spec.Name]
		if !spec.Records || base == nil || head == nil || !head.Present {
			continue
		}
		if !base.Present {
			// A pack added with the member has no base to introduce it
			// against: fail closed, the owner approves a later change.
			if _, ok := head.Members[sectionServed]; ok {
				for _, c := range cls.Changes {
					if c.Pack == spec.Name && c.Section == sectionServed {
						c.fail("the servedAPIs member may not be introduced together with the pack; add the pack first, then introduce the member with an owner approval")
					}
				}
			}
			continue
		}
		if _, ok := base.Members[sectionServed]; ok {
			continue
		}
		if _, ok := head.Members[sectionServed]; !ok {
			continue
		}
		var changes []*Change
		allOK := true
		for _, c := range cls.Changes {
			if c.Pack == spec.Name && c.Section == sectionServed {
				changes = append(changes, c)
				allOK = allOK && c.OK
			}
		}
		if len(changes) == 0 || !allOK {
			continue // each refused list carries its own reason
		}
		if err := checkServedIntroduction(spec, base, head, opts, loadKeys, approvals); err != nil {
			for _, c := range changes {
				c.fail("introducing the servedAPIs member needs an owner approval bound to every re-derived list: " + err.Error())
			}
			continue
		}
		admitted[spec.Name] = true
	}
	return admitted
}

func checkServedIntroduction(spec PackSpec, base, head *loadedPack, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) error {
	_, statement, err := servedIntroductionStatement(base, head)
	if err != nil {
		return err
	}
	raw, err := opts.Head.ReadOptional(servedApprovalPath(opts.Layout, spec.Name), maxApprovalBytes+1)
	if err != nil {
		return fmt.Errorf("approval: %v", err)
	}
	if raw == nil {
		return errors.New("no owner approval")
	}
	if why, err := approvals.refuse(raw); err != nil {
		return fmt.Errorf("approval: %v", err)
	} else if why != "" {
		return errors.New(why)
	}
	keys, err := loadKeys()
	if err != nil {
		return err
	}
	return VerifyRecordApproval(raw, *keys, spec.Name, ApprovalSubjectServed, ServedApprovalID, ServedApprovalScope, nil, statement, opts.Now)
}
