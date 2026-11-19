// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

type movedGate struct {
	base, head map[string]any
	statement  evidencereattest.Statement
	ruleID     string
}

var movedNewCommit = strings.Repeat("c", 40)

// newMovedGate takes a real reviewed rule of the shipped pack and moves its
// first source: the head differs from the base in that source's place and in
// the evidence dates, and the statement lists exactly that move.
func newMovedGate(t *testing.T) movedGate {
	t.Helper()
	p := readPack(t, copyKnowledge(t), cncfRulesPath)
	var base map[string]any
	for _, e := range p.entries {
		first := evidenceOf(e)["sources"].([]any)[0].(map[string]any)
		start, _ := intOf(first["startLine"])
		end, _ := intOf(first["endLine"])
		if evidenceOf(e)["state"] == "active" && ruleOf(e)["range"] == nil && evidenceOf(e)["basis"] == nil && end > start {
			base = deepCopy(e).(map[string]any)
			break
		}
	}
	if base == nil {
		t.Fatal("no plain reviewed rule in the shipped pack")
	}
	head := deepCopy(base).(map[string]any)
	src := evidenceOf(base)["sources"].([]any)[0].(map[string]any)
	headSrc := evidenceOf(head)["sources"].([]any)[0].(map[string]any)
	owner, repo, _, path, ok := evidencerepin.ParseCitationURL(src["url"].(string))
	if !ok {
		t.Fatalf("source url %v", src["url"])
	}
	url, _ := evidencerepin.MovedURL(src["url"].(string), owner, repo, movedNewCommit, path)
	oldStart, _ := intOf(src["startLine"])
	oldEnd, _ := intOf(src["endLine"])
	newDigest := "sha256:" + strings.Repeat("9", 64)
	headSrc["revision"], headSrc["url"], headSrc["contentDigest"] = movedNewCommit, url, newDigest
	headSrc["startLine"], headSrc["endLine"] = float64(oldStart+7), float64(oldEnd+7)
	evidenceOf(head)["validUntil"] = shiftTime(t, evidenceOf(head)["validUntil"], 24*3600e9)
	evidenceOf(head)["reviewedAt"] = shiftTime(t, evidenceOf(head)["reviewedAt"], 3600e9)
	id := ruleID(base)
	moved := &evidencereattest.MovedAttestation{
		Path: path, OldStartLine: oldStart, OldEndLine: oldEnd, NewStartLine: oldStart + 7, NewEndLine: oldEnd + 7,
		OldContentDigest: src["contentDigest"].(string), NewContentDigest: newDigest,
	}
	statement := evidencereattest.Statement{
		SignerRole: evidencereattest.RoleHuman,
		Rules: []evidencereattest.RuleAttestation{{RuleID: id, Citations: []evidencereattest.CitationAttestation{{
			SourceID: src["id"].(string), Class: evidencerepin.ClassSpanMoved, ComparedCommit: movedNewCommit, Moved: moved,
		}}}},
	}
	return movedGate{base: base, head: head, statement: statement, ruleID: id}
}

func (m movedGate) change(t *testing.T) *Change {
	t.Helper()
	b, h := entryFrom(t, m.base), entryFrom(t, m.head)
	class, kinds := classifyEdit(b, h)
	return &Change{Pack: "cncf", RuleID: m.ruleID, Project: h.Project, Basis: h.effectiveBasis(), Class: class, Kinds: kinds, base: b, head: h}
}

func (m movedGate) admit(t *testing.T, statement evidencereattest.Statement, ok bool) *Change {
	t.Helper()
	c := m.change(t)
	opts := Options{Head: Tree{Root: t.TempDir()}, Layout: Layout{ApprovalDir: "knowledge/approvals"}, Now: time.Now().UTC()}
	admitReviewed(c, statementResult{OK: true, Renewed: map[string]bool{m.ruleID: true}, Statement: statement, Role: statement.SignerRole}, nil, nil, nil, opts)
	if c.OK != ok {
		t.Fatalf("admitted=%v want %v: %s", c.OK, ok, c.Detail)
	}
	return c
}

func TestGateAdmitsAMovedCitationOnlyAsItsStatementRowStatesIt(t *testing.T) {
	m := newMovedGate(t)
	c := m.admit(t, m.statement, true)
	if c.Proof != ProofReattestation || !containsKind(c.Kinds, KindRepin) || !containsKind(c.Kinds, KindRenew) {
		t.Fatalf("the moved renewal is the reattestation class: %+v", c)
	}
}

func TestGateRefusesAMovedCitationChangeThatIsNotListedInAVerifiedRow(t *testing.T) {
	cases := map[string]func(m *movedGate){
		"no moved row": func(m *movedGate) {
			m.statement.Rules[0].Citations[0].Moved, m.statement.Rules[0].Citations[0].Class = nil, evidencerepin.ClassSpanIdentical
		},
		"row for another source": func(m *movedGate) { m.statement.Rules[0].Citations[0].SourceID = "another-source" },
		"automated statement":    func(m *movedGate) { m.statement.SignerRole = evidencereattest.RoleAutomation },
		"new digest differs from the row": func(m *movedGate) {
			evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("7", 64)
		},
		"new lines differ from the row": func(m *movedGate) {
			evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)["startLine"] = float64(1)
		},
		"smaller span than the row": func(m *movedGate) {
			s := evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)
			s["endLine"] = s["startLine"]
		},
		"url not derived from the commit and path": func(m *movedGate) {
			evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)["url"] = "https://github.com/x/y/blob/" + movedNewCommit + "/z.go"
		},
		"revision not the compared commit": func(m *movedGate) {
			evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)["revision"] = strings.Repeat("d", 40)
		},
		"the source id changes with the move": func(m *movedGate) {
			evidenceOf(m.head)["sources"].([]any)[0].(map[string]any)["id"] = "renamed-source"
		},
		"the description changes with the move": func(m *movedGate) { m.head["description"] = "Other." },
		"the next action changes with the move": func(m *movedGate) { ruleOf(m.head)["nextAction"] = "Do something else." },
		"the basis changes with the move":       func(m *movedGate) { evidenceOf(m.head)["basis"] = "reviewed" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := newMovedGate(t)
			mutate(&m)
			c := m.admit(t, m.statement, false)
			if c.Proof == ProofReattestation {
				t.Error("must not be admitted as a renewal")
			}
		})
	}
}

func TestGateRefusesAListedMoveThePackDoesNotMake(t *testing.T) {
	m := newMovedGate(t)
	m.head = deepCopy(m.base).(map[string]any)
	evidenceOf(m.head)["validUntil"] = shiftTime(t, evidenceOf(m.head)["validUntil"], 24*3600e9)
	m.admit(t, m.statement, false)
}

func TestGatePlainRenewalIsUnchangedByTheMovedCheck(t *testing.T) {
	m := newMovedGate(t)
	m.head = deepCopy(m.base).(map[string]any)
	evidenceOf(m.head)["validUntil"] = shiftTime(t, evidenceOf(m.head)["validUntil"], 24*3600e9)
	plain := evidencereattest.Statement{SignerRole: evidencereattest.RoleAutomation, Rules: []evidencereattest.RuleAttestation{{RuleID: m.ruleID}}}
	m.admit(t, plain, true)
}

func TestGateMovedBlobsPathsAreAppendOnlyAndNamedByDigest(t *testing.T) {
	packs := map[string]bool{"cncf": true}
	good := map[string]statementResult{"cncf": {OK: true}}
	hex := strings.Repeat("ab", 32)
	if why := reattestPathReason("cncf/moved-blobs/"+hex, packs, good, false, true); why != "" {
		t.Fatalf("a new blob named by a hex digest is accepted: %s", why)
	}
	for name, tc := range map[string]struct {
		rest           string
		statements     map[string]statementResult
		inBase, inHead bool
	}{
		"no verified statement": {"cncf/moved-blobs/" + hex, map[string]statementResult{"cncf": {}}, false, true},
		"changed in place":      {"cncf/moved-blobs/" + hex, good, true, true},
		"removed":               {"cncf/moved-blobs/" + hex, good, true, false},
		"not a hex name":        {"cncf/moved-blobs/some-name", good, false, true},
		"upper case name":       {"cncf/moved-blobs/" + strings.ToUpper(hex), good, false, true},
		"nested":                {"cncf/moved-blobs/a/" + hex, good, false, true},
	} {
		if why := reattestPathReason(tc.rest, packs, tc.statements, tc.inBase, tc.inHead); why == "" {
			t.Errorf("%s: must be refused", name)
		}
	}
}
