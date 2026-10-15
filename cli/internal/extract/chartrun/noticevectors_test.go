// SPDX-License-Identifier: AGPL-3.0-only

package chartrun

import (
	"slices"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

func noticeEntry(op string) Entry {
	e := chartEntry(constraintengine.OperatorRequireSetMember)
	e.Rule.Operator = op
	e.Rule.NextAction = "review the listed values"
	return e
}

// A set notice has its own vector kinds, and the engine agrees with each:
// NOTICE with the listed members, UNKNOWN RULE_NOTICE_NOT_APPLICABLE over a
// complete set that gives it nothing to say, UNKNOWN RULE_SET_FACT_INCOMPLETE
// over an incomplete one.
func TestNoticeVectorsAgreeWithTheEngine(t *testing.T) {
	for _, op := range []string{constraintengine.OperatorNoticeSetMemberPresent, constraintengine.OperatorNoticeSetMemberAbsent} {
		e := noticeEntry(op)
		vs, err := GenerateVectors(e, []string{"z"})
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if err := CheckVectors([]Entry{e}, vs, toyTime); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		kinds := []string{}
		for _, v := range vs {
			kinds = append(kinds, v.Kind)
		}
		if !slices.Equal(kinds, VectorKinds(op)) || !slices.Equal(kinds, []string{VectorNotice, VectorNoNoticeComplete, extract.VectorUnknownIncomplete}) {
			t.Fatalf("%s: kinds %v", op, kinds)
		}
		notice := vs[0].Expect
		if notice.Status != constraintengine.StatusNotice || notice.ReasonCode != "EXAMPLE_CHART" {
			t.Fatalf("%s: notice vector %+v", op, notice)
		}
		if op == constraintengine.OperatorNoticeSetMemberPresent && (!slices.Equal(notice.MatchedMembers, []string{"a.b", "c"}) || notice.MissingMembers != nil) ||
			op == constraintengine.OperatorNoticeSetMemberAbsent && (!slices.Equal(notice.MissingMembers, []string{"a.b", "c"}) || notice.MatchedMembers != nil) {
			t.Fatalf("%s: notice members %+v", op, notice)
		}
		if vs[1].Expect.ReasonCode != constraintengine.ReasonNoticeNotApplicable || vs[2].Expect.ReasonCode != reasonSetIncomplete {
			t.Fatalf("%s: %+v", op, vs)
		}
		// Every expectation is checked.
		for i := range vs {
			bad := append([]Vector(nil), vs...)
			bad[i].Expect.Status = "PASS"
			if err := CheckVectors([]Entry{e}, bad, toyTime); err == nil {
				t.Fatalf("%s: wrong expectation on %s accepted", op, vs[i].Kind)
			}
		}
		// A notice never has verdict kinds, and a missing kind is caught.
		extraKind := vs[1]
		extraKind.Kind, extraKind.Name = extract.VectorPassComplete, e.Rule.ID+"/"+extract.VectorPassComplete
		wrong := append(append([]Vector(nil), vs...), extraKind)
		if err := CheckVectors([]Entry{e}, wrong, toyTime); err == nil {
			t.Fatalf("%s: a verdict kind accepted for a notice", op)
		}
		if err := CheckVectors([]Entry{e}, vs[:2], toyTime); err == nil {
			t.Fatalf("%s: a missing kind accepted", op)
		}
		if _, err := GenerateVectors(e, []string{"c"}); err == nil {
			t.Fatalf("%s: extra member that is listed accepted", op)
		}
	}
	// A verdict rule never has notice kinds.
	e := chartEntry(constraintengine.OperatorRequireSetMember)
	vs, err := GenerateVectors(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	vs = append(vs, Vector{Name: e.Rule.ID + "/" + VectorNotice, RuleID: e.Rule.ID, Kind: VectorNotice, Input: vs[0].Input, Expect: vs[0].Expect})
	if err := CheckVectors([]Entry{e}, vs, toyTime); err == nil {
		t.Fatal("a notice kind accepted for a verdict rule")
	}
}
