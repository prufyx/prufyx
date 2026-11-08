// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"errors"
	"sort"
)

// Comparison is the candidate set of two scans of the same repository: the
// union of the deprecated declarations of both sides, each DRAFT unless the
// newer side proves the removal of a field.
type Comparison struct {
	OldCommit  string        `json:"old_commit"`
	NewCommit  string        `json:"new_commit"`
	Candidates []Candidate   `json:"candidates"`
	Ledger     []LedgerEntry `json:"ledger"`
}

// Compare takes the older and the newer scan. The caller is responsible for
// the order of the two commits, and a consumer must bind that order to the
// release tags of the two pinned commits: with the arguments swapped, a real
// removal reads as an addition and never as a removal, but an unbound order
// would let a forged pair choose which side is "newer"; Compare only refuses equal commits and
// different repositories. Both results must come from Scan.
func Compare(older, newer Result) (Comparison, error) {
	if older.syms == nil || newer.syms == nil {
		return Comparison{}, errors.New("envoyproto: Compare needs results produced by Scan")
	}
	if older.Repo != newer.Repo || older.Commit == newer.Commit {
		return Comparison{}, errors.New("envoyproto: Compare needs two different commits of one repository")
	}
	out := Comparison{OldCommit: older.Commit, NewCommit: newer.Commit, Candidates: []Candidate{}}
	var led []LedgerEntry
	complete := true
	if !older.Attestable() {
		led = append(led, LedgerEntry{Code: ReasonSideIncomplete, Item: "older"})
		complete = false
	}
	if !newer.Attestable() {
		led = append(led, LedgerEntry{Code: ReasonSideIncomplete, Item: "newer"})
		complete = false
	}
	type key struct{ m, k string }
	seen := map[key]Candidate{}
	for _, c := range newer.Candidates {
		seen[key{c.Member, c.Kind}] = c
	}
	for _, c := range older.Candidates {
		k := key{c.Member, c.Kind}
		if c.Kind == KindField && complete && removalProven(older, newer, c) {
			c.Status = StatusMechanical
			c.Proof = ProofReservedNumberAndName
			seen[k] = c
			continue
		}
		if _, ok := seen[k]; !ok {
			seen[k] = c
		}
	}
	for _, c := range seen {
		out.Candidates = append(out.Candidates, c)
	}
	sort.Slice(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].Member != out.Candidates[j].Member {
			return out.Candidates[i].Member < out.Candidates[j].Member
		}
		return out.Candidates[i].Kind < out.Candidates[j].Kind
	})
	out.Ledger = ledgerOf(led)
	return out, nil
}

// removalProven is the single place a candidate can become mechanical. The
// old declaration is looked up again from the older scan's own table (the
// candidate's member is only a key), and the newer side must declare the same
// message without the name, with the number not in use, and reserve both.
func removalProven(older, newer Result, c Candidate) bool {
	msgName, fieldName := c.msg, c.field
	if msgName == "" || fieldName == "" {
		return false
	}
	om := older.syms[msgName]
	if om == nil || om.isEnum {
		return false
	}
	of := om.fields[fieldName]
	if of == nil || of.number != c.Number || !(of.deprecated || of.atMinor != "") || of.hidden {
		return false
	}
	nm := newer.syms[msgName]
	if nm == nil || nm.isEnum {
		return false
	}
	if _, still := nm.fields[fieldName]; still {
		return false
	}
	// The newer message must not still accept the removed field's JSON path.
	gone := jsonNames(of)
	for _, nf := range nm.fields {
		for n := range jsonNames(nf) {
			if gone[n] {
				return false
			}
		}
	}
	if _, used := nm.fieldNumber[of.number]; used {
		return false
	}
	if !nm.resNames[fieldName] {
		return false
	}
	for _, r := range nm.resNums {
		if of.number >= r.lo && of.number <= r.hi {
			return true
		}
	}
	return false
}

// jsonNames are the names a field is accepted under by the protobuf JSON
// mapping: the proto name and the json_name (explicit, else lowerCamel of the
// name).
func jsonNames(f *fieldInfo) map[string]bool {
	out := map[string]bool{f.name: true}
	if f.jsonName != "" {
		out[f.jsonName] = true
	} else {
		out[lowerCamel(f.name)] = true
	}
	return out
}

// lowerCamel is protoc's default json_name: underscores are dropped and the
// letter after each is upper-cased.
func lowerCamel(name string) string {
	b := make([]byte, 0, len(name))
	up := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_':
			up = true
		case up && c >= 'a' && c <= 'z':
			b = append(b, c-'a'+'A')
			up = false
		default:
			b = append(b, c)
			up = false
		}
	}
	return string(b)
}
