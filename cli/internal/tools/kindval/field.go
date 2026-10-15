// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// fieldRun is one crd-field claim within the run of its pair: the object
// built from the From schema, and its result so far.
type fieldRun struct {
	claim  Claim
	object []byte
	res    CRDFieldResult
}

// fieldObjectName is the metadata.name of every object a crd-field claim
// sends.
const fieldObjectName = "kindval-field"

// newFieldRuns starts the results of a pair's crd-field claims.
func newFieldRuns(pair CRDPair) []*fieldRun {
	out := make([]*fieldRun, 0, len(pair.Fields))
	for _, c := range pair.Fields {
		out = append(out, &fieldRun{claim: c, res: CRDFieldResult{ID: c.ID, Pair: pair.ID, Change: c.Subject.Change}})
	}
	return out
}

// failFields records an install failure on every claim not yet decided.
func failFields(runs []*fieldRun, msg string) {
	for _, f := range runs {
		if f.res.Skip == "" && f.res.Error == "" {
			f.res.Error = msg
		}
	}
}

// fieldResults is the recorded results, in claim id order.
func fieldResults(runs []*fieldRun) []CRDFieldResult {
	out := make([]CRDFieldResult, 0, len(runs))
	for _, f := range runs {
		out = append(out, f.res)
	}
	return out
}

// installedScope is the scope of a definition the cluster holds, and
// whether it holds it.
func installedScope(defs []CRDDef, name string) (string, bool) {
	for _, d := range defs {
		if d.Name == name {
			return d.Scope, true
		}
	}
	return "", false
}

// fieldsAtFrom reads each claim's definition from the cluster after From was
// installed, builds the object and sends it: the From schema must accept it.
func fieldsAtFrom(ctx context.Context, k kube, runs []*fieldRun, installed []CRDDef) {
	for _, f := range runs {
		s := f.claim.Subject
		scope, ok := installedScope(installed, s.CRD)
		if !ok {
			f.res.Skip, f.res.Detail = ReasonPathNotInFrom, "the cluster holds no "+s.CRD+" after installing the From release"
			continue
		}
		crd, err := k.getCRDObject(ctx, s.CRD)
		if err != nil {
			f.res.Error = "from schema: " + err.Error()
			continue
		}
		obj, serverPath, reason, detail := buildFieldObject(crd, s, scope)
		f.res.ServerPath = serverPath
		if reason != "" {
			f.res.Skip, f.res.Detail = reason, detail
			continue
		}
		data, err := json.Marshal(obj)
		if err != nil {
			f.res.Skip, f.res.Detail = ReasonObjectNotBuildable, err.Error()
			continue
		}
		sum := sha256.Sum256(data)
		f.object, f.res.ObjectDigest = data, "sha256:"+hex.EncodeToString(sum[:])
		try := k.dryRunCreateStrict(ctx, data)
		f.res.FromAnswer = &try
	}
}

// fieldsAtTo sends every object From accepted again, now that To is
// installed: in place (cross-check only) or fresh (the answer that decides).
// After the fresh install it also reads the state of To's schema at the path.
func fieldsAtTo(ctx context.Context, k kube, runs []*fieldRun, fresh bool, installed []CRDDef) {
	for _, f := range runs {
		if f.object == nil || f.res.FromAnswer == nil || f.res.FromAnswer.Outcome != ServerAccepted || f.res.Error != "" || f.res.Skip != "" {
			continue
		}
		s := f.claim.Subject
		if _, ok := installedScope(installed, s.CRD); fresh && !ok {
			f.res.Skip, f.res.Detail = ReasonOtherRejection, "the To release defines no "+s.CRD+": a wider change than claimed"
			continue
		}
		try := k.dryRunCreateStrict(ctx, f.object)
		if !fresh {
			f.res.ToInPlace = &try
			continue
		}
		f.res.ToAnswer = &try
		crd, err := k.getCRDObject(ctx, s.CRD)
		if err != nil {
			f.res.Error = "to schema: " + err.Error()
			continue
		}
		f.res.ToSchema = schemaAt(crd, s.Version, s.Path)
		if try.Outcome != ServerAccepted {
			f.res.Pattern = matchField(s.Change, f.res.ServerPath, try.Message).Pattern
		}
	}
}

// crdField decides a crd-field claim from the answers its run recorded.
func (e *evaluator) crdField(c Claim, cr *ClaimResult) {
	s := c.Subject
	f, ok := e.fields[c.ID]
	if !ok {
		cr.Detail, cr.Reason = "no run of "+pairID(s.Project, tagOf(s.From), tagOf(s.To))+" decided the claim", ReasonNoRun
		return
	}
	cr.NodeImageDigest = imageDigest(e.fieldImg[c.ID])
	from, to := tagOf(s.From), tagOf(s.To)
	where := s.Path
	if f.ServerPath != "" {
		where = f.ServerPath
	}
	oneLine := func(t *ServerTry) string { return strings.ReplaceAll(t.Message, "\n", " ") }
	undetermined := func(reason, detail string) { cr.Reason, cr.Detail = reason, detail }
	switch {
	case f.Error != "":
		cr.Outcome, cr.Reason, cr.Detail = OutcomeError, ReasonInstallFailed, f.Error
		return
	case f.Skip != "":
		undetermined(f.Skip, f.Detail)
		return
	case f.FromAnswer == nil:
		undetermined(ReasonNotProbed, "no object was sent at "+from)
		return
	case f.FromAnswer.Outcome == ServerError:
		cr.Outcome, cr.Reason, cr.Detail = OutcomeError, ReasonServerNoAnswer, "the API server gave no answer to the object at "+from+": "+oneLine(f.FromAnswer)
		return
	case f.FromAnswer.Outcome != ServerAccepted:
		detail := "the schema at " + from + " refuses the object (" + f.FromAnswer.Outcome + "): " + oneLine(f.FromAnswer)
		if s.Change == ChangeRequiredAdded && matchField(ChangeRequiredAdded, where, f.FromAnswer.Message).Pattern != "" {
			detail = "the field is already required at " + from + ": " + oneLine(f.FromAnswer)
		}
		undetermined(ReasonFromRejected, detail)
		return
	case f.ToAnswer == nil:
		undetermined(ReasonNotProbed, "the object was not sent after "+to+" was installed")
		return
	case f.ToAnswer.Outcome == ServerError:
		cr.Outcome, cr.Reason = OutcomeError, ReasonServerNoAnswer
		cr.Detail = "the API server gave no answer to the object at " + to + ": " + oneLine(f.ToAnswer)
		return
	}
	inPlace := ""
	if f.InPlace == "refused" {
		inPlace = "; the in-place update was refused, decided on the fresh install of " + to
	}
	// The fresh install decides; an in-place dry run without an answer only
	// leaves the decision without its cross-check.
	crossCheck := f.ToInPlace
	if crossCheck != nil && crossCheck.Outcome == ServerError {
		crossCheck = nil
		inPlace += "; the in-place dry run got no answer from the API server (no cross-check): " + oneLine(f.ToInPlace)
	}
	if f.ToAnswer.Outcome == ServerAccepted {
		switch {
		case f.ToSchema == schemaPermissive:
			undetermined(ReasonSchemaPermissive, to+" accepts the object, but its schema at "+s.Path+" preserves unknown fields"+inPlace)
		case f.ToSchema == schemaAbsent:
			// Strict field validation would have refused an undeclared
			// field: it did not run (client-side validation, pruning).
			undetermined(ReasonOtherRejection, "accepted although the path is absent from the schema at "+to+": strict field validation did not decide"+inPlace)
		case crossCheck != nil && crossCheck.Outcome != ServerAccepted:
			undetermined(ReasonOtherRejection, "the fresh install of "+to+" accepts the object, the in-place update refused it: "+oneLine(crossCheck))
		default:
			cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
			cr.Detail = fmt.Sprintf("the CRD schema at %s accepts the object that sets %s, as %s does%s", to, where, from, inPlace)
			e.finding(SeverityMedium, c.ID, "%s %s -> %s: the claim says %s of %s; the CRD schema at %s accepts the object (webhooks and controllers are not checked)", s.Project, from, to, s.Change, where, to)
		}
		return
	}
	m := matchField(s.Change, where, f.ToAnswer.Message)
	switch {
	case s.Change != ChangeFieldRemoved && f.ToSchema == schemaAbsent:
		undetermined(ReasonOtherRejection, "the path is absent from the schema at "+to+" (looks like field-removed): "+oneLine(f.ToAnswer))
		return
	case m.Pattern == "":
		detail := "the schema at " + to + " refuses the object, but not for " + s.Change + " on " + where
		if m.Note != "" {
			detail += " (" + m.Note + ")"
		}
		undetermined(ReasonOtherRejection, detail+": "+oneLine(f.ToAnswer)+inPlace)
		return
	case s.Change == ChangeFieldRemoved && f.ToSchema != schemaAbsent:
		undetermined(ReasonOtherRejection, "the server names "+where+" unknown, but the schema at "+to+" still has it ("+f.ToSchema+")")
		return
	}
	if crossCheck != nil && crossCheck.Outcome != ServerAccepted {
		if p := matchField(s.Change, where, crossCheck.Message).Pattern; p != m.Pattern {
			undetermined(ReasonOtherRejection, "the in-place update and the fresh install of "+to+" refuse the object differently: "+oneLine(crossCheck)+" / "+oneLine(f.ToAnswer))
			return
		}
	}
	cr.Outcome = OutcomeConfirmed
	cr.Detail = fmt.Sprintf("accepted at %s; refused at %s (%s): %s%s", from, to, m.Pattern, oneLine(f.ToAnswer), inPlace)
	if crossCheck != nil && crossCheck.Outcome == ServerAccepted {
		cr.Detail += "; the in-place dry run right after the update was accepted (the server had not yet switched schemas)"
	}
	if len(m.Other) > 0 {
		e.finding(SeverityInfo, c.ID+".also", "%s %s -> %s: besides %s on %s, the schema at %s also refuses: %s", s.Project, from, to, s.Change, where, to, strings.Join(m.Other, "; "))
	}
}

func tagOf(raw json.RawMessage) string {
	r, _ := releaseSubject(raw)
	return r.Tag
}
