// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// corpusSHA256 pins the shared vector corpus. The same file, byte for byte,
// is checked by the mirror of this predicate; change both together.
const corpusSHA256 = "f0812b1aff04f132ff9d2164aca996c0d4c82b7484e7a5f6fba95917649332ea"

const corpusPath = "testdata/renewal-remediation-vectors-v1.json"

type vectorCase struct {
	Name      string             `json:"name"`
	AllowList []RemediationPair  `json:"allowList"`
	Published string             `json:"published"`
	Candidate string             `json:"candidate"`
	Want      bool               `json:"want"`
	Record    *RemediationRecord `json:"record"`
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if got := hex.EncodeToString(h[:]); got != corpusSHA256 {
		t.Fatalf("corpus digest %s, pinned %s: update both repositories together", got, corpusSHA256)
	}
	var c struct {
		Version int          `json:"version"`
		Cases   []vectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Version != 1 || len(c.Cases) == 0 {
		t.Fatalf("corpus: version %d, %d cases, %v", c.Version, len(c.Cases), err)
	}
	return c.Cases
}

func TestRemediationVectorCorpus(t *testing.T) {
	cases := loadVectors(t)
	accepted := 0
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
		rec, ok := remediationRenewal(c.AllowList, []byte(c.Published), []byte(c.Candidate))
		if ok != c.Want {
			t.Errorf("%s: admitted = %v, want %v", c.Name, ok, c.Want)
			continue
		}
		if ok {
			accepted++
			if c.Record == nil || !reflect.DeepEqual(rec, *c.Record) {
				t.Errorf("%s: record %+v, want %+v", c.Name, rec, c.Record)
			}
		} else if rec != (RemediationRecord{}) {
			t.Errorf("%s: refused but returned %+v", c.Name, rec)
		}
	}
	if accepted == 0 || accepted > len(cases)/4 {
		t.Fatalf("%d of %d cases admitted: the corpus must be mostly refusals", accepted, len(cases))
	}
}

func TestRemediationAllowListShape(t *testing.T) {
	ids := map[string]bool{}
	hexRE := func(s string) bool {
		b, err := hex.DecodeString(s)
		return err == nil && len(b) == 32 && s == strings.ToLower(s)
	}
	last := ""
	for _, p := range remediationAllowList {
		if ids[p.RuleID] || p.RuleID <= last || !strings.Contains(p.RuleID, ".crd-version-removal.") {
			t.Errorf("entry %q: duplicate, unsorted or not a crd-version-removal rule", p.RuleID)
		}
		ids[p.RuleID], last = true, p.RuleID
		if !hexRE(p.OldSHA256) || !hexRE(p.NewSHA256) || p.OldSHA256 == p.NewSHA256 {
			t.Errorf("entry %q: bad hashes", p.RuleID)
		}
	}
	got := RemediationAllowList()
	if len(got) > 0 {
		got[0].RuleID = "changed"
		if remediationAllowList[0].RuleID == "changed" {
			t.Fatal("RemediationAllowList returns the live slice")
		}
	}
}

// vectorPair returns the first corpus case (an admitted renewal) as the
// published and candidate entries and its allow-list.
func vectorPair(t *testing.T, rename string) (old, nw []byte, allow []RemediationPair) {
	t.Helper()
	c := loadVectors(t)[0]
	if !c.Want {
		t.Fatal("first corpus case must be an admitted renewal")
	}
	id := c.AllowList[0].RuleID
	o, n := c.Published, c.Candidate
	p := c.AllowList[0]
	if rename != "" {
		o, n = strings.ReplaceAll(o, id, rename), strings.ReplaceAll(n, id, rename)
		p.RuleID = rename
	}
	return []byte(o), []byte(n), []RemediationPair{p}
}

func withList(t *testing.T, l []RemediationPair) {
	t.Helper()
	saved := remediationAllowList
	remediationAllowList = l
	t.Cleanup(func() { remediationAllowList = saved })
}

// Each remediation renewal is one renewed rule and one record; other changed
// records in the same run count once each, and nothing is counted twice.
func TestMergeRemediationRenewalCountsOnce(t *testing.T) {
	o1, n1, a1 := vectorPair(t, "")
	o2, n2, a2 := vectorPair(t, "demo.crd-version-removal.gadgets-demo-io.1-0-0-to-2-0-0")
	withList(t, append(a1, a2...))
	plainOld, plainNew := rEntry(nil), rEntry(newer)
	added := rEntry(func(r, e map[string]any) { r["id"] = "r.2" })
	base := mkPack(o1, o2, plainOld)
	run := &Run{Entries: []json.RawMessage{n1, n2, plainNew, added}, renew: true}
	rep := &Report{}
	head, allowed, err := merge(base, run, rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.RenewedRules) != 3 || len(rep.RemediationRenewed) != 2 || len(rep.Added) != 1 || len(allowed) != 1 {
		t.Fatalf("report %+v", rep)
	}
	seen := map[string]int{}
	for _, id := range rep.RenewedRules {
		seen[id]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s renewed %d times", id, n)
		}
	}
	for _, r := range rep.RemediationRenewed {
		if r.Kind != KindRemediationText || r.Before == r.After {
			t.Errorf("record %+v", r)
		}
		if seen[r.RuleID] != 1 {
			t.Errorf("record %s is not in RenewedRules", r.RuleID)
		}
	}
	if len(head.Entries) != 4 {
		t.Fatalf("%d entries", len(head.Entries))
	}
	// A plain renewal is not classified as remediation text.
	for _, r := range rep.RemediationRenewed {
		if r.RuleID == "r.1" {
			t.Fatal("plain renewal classified as remediation-text")
		}
	}
}

func TestMergeRemediationRefusals(t *testing.T) {
	o, n, a := vectorPair(t, "")
	for _, c := range []struct {
		name  string
		list  []RemediationPair
		renew bool
		cand  []byte
	}{
		{"run does not ask to renew", a, false, n},
		{"rule not on the list", nil, true, n},
		{"advice tampered, valid stamps", a, true, []byte(strings.Replace(string(n), "migrate Widget", "ignore Widget", 1))},
	} {
		withList(t, c.list)
		_, _, err := merge(mkPack(o), &Run{Entries: []json.RawMessage{c.cand}, renew: c.renew}, &Report{})
		if !errors.Is(err, ErrCollision) {
			t.Errorf("%s: err = %v, want ErrCollision", c.name, err)
		}
	}
}

// The audit holds the result to the same proof: a changed advice text passes
// only for a listed pair, and a renewed id alone does not excuse it.
func TestAuditRemediationRenewal(t *testing.T) {
	o, n, a := vectorPair(t, "")
	id := a[0].RuleID
	tampered := []byte(strings.Replace(string(n), "migrate Widget", "ignore Widget", 1))
	earlier := []byte(strings.Replace(string(tampered), "2027-02-14T05:00:00Z", "2026-10-20T00:00:00Z", 1))
	for _, c := range []struct {
		name    string
		list    []RemediationPair
		head    []byte
		renewed map[string]bool
		refused bool
	}{
		{"listed pair", a, n, map[string]bool{id: true}, false},
		{"listed pair, id not marked renewed", a, n, nil, true},
		{"pair not listed", nil, n, map[string]bool{id: true}, true},
		{"tampered advice, valid stamps", a, tampered, map[string]bool{id: true}, true},
		{"tampered advice with an earlier expiry", a, earlier, map[string]bool{id: true}, true},
	} {
		withList(t, c.list)
		err := audit(mkPack(o), mkPack(c.head), nil, c.renewed, nil, false)
		if c.refused != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", c.name, err, c.refused)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error type %v", c.name, err)
		}
	}
}
