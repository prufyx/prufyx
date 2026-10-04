// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
)

const cncfRules = "cli/internal/cncfcheck/data/rules.json"

// tree writes a knowledge tree holding one CNCF pack.
func tree(t *testing.T, pack []byte) string {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, filepath.FromSlash(cncfRules))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pack, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func classify(t *testing.T, base, head []byte) knowledgegate.ClassifyOutput {
	t.Helper()
	var out, errb bytes.Buffer
	code := knowledgegate.Main([]string{"classify", "--base", tree(t, base), "--head", tree(t, head), "--json"}, func(string) string { return "" }, &out, &errb)
	if code != 0 {
		t.Fatalf("classify: %d %s", code, errb.String())
	}
	var res knowledgegate.ClassifyOutput
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// Acceptance 1 (gate): for every extractor's run, the gate's classification
// of base -> merged pack is exactly the run's rules as new mechanical rules
// (plus, for an attesting extractor, the attestation member) and nothing
// else; a withdrawal is exactly the withdrawn rules, as tightening.
func TestGateClassifiesExactlyTheRunsChanges(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := runDir(t, c, derivedAt.Add(-24*time.Hour))
			pack := prunedPack(t, "cncf", run)
			base, _ := os.ReadFile(pack)
			if _, err := apply(t, pack, run, false); err != nil {
				t.Fatal(err)
			}
			head, _ := os.ReadFile(pack)
			res := classify(t, base, head)
			// The gate classifies line attestations record by record (section
			// lineAttestations), not as a pack member.
			var gotRules []string
			records := 0
			for _, ch := range res.Changes {
				if ch.Member != "" {
					t.Fatalf("unexpected pack member change %+v", ch)
				}
				if ch.Class != knowledgegate.ClassLoosening || len(ch.Kinds) != 1 || ch.Kinds[0] != knowledgegate.KindNew || ch.Basis != "mechanical" {
					t.Fatalf("change %+v", ch)
				}
				if ch.Section != "" {
					records++
					if ch.Section != "lineAttestations" || !strings.HasPrefix(ch.RuleID, "line-attestation.") || ch.Project != "line-attestations" {
						t.Fatalf("record change %+v", ch)
					}
					continue
				}
				gotRules = append(gotRules, ch.RuleID)
			}
			sort.Strings(gotRules)
			if !equalStrings(gotRules, ruleIDs(t, run)) {
				t.Fatalf("classified rules\n%v\nwant\n%v", gotRules, ruleIDs(t, run))
			}
			wantRecords := 0
			if _, err := os.Stat(filepath.Join(run, "attestations.json")); err == nil {
				var atts []json.RawMessage
				readJSON(t, filepath.Join(run, "attestations.json"), &atts)
				wantRecords = len(atts)
			}
			if records != wantRecords {
				t.Fatalf("classified %d attestation records, the run produced %d", records, wantRecords)
			}

			// Withdraw two rules the extractor stops producing.
			ids := ruleIDs(t, run)
			drop := map[string]bool{ids[0]: true}
			if c.name != "served-apis" { // attestations list every rule of their line
				drop[ids[len(ids)-1]] = true
			}
			later := runDir(t, c, derivedAt)
			trimRun(t, later, drop, false)
			if c.name == "served-apis" {
				trimRun(t, later, nil, true)
			}
			if _, err := apply(t, pack, later, true); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(pack)
			res = classify(t, head, after)
			var got []string
			for _, ch := range res.Changes {
				if ch.Class != knowledgegate.ClassTightening || len(ch.Kinds) != 1 || ch.Kinds[0] != knowledgegate.KindWithdraw {
					t.Fatalf("withdrawal classified as %+v", ch)
				}
				got = append(got, ch.RuleID)
			}
			var want []string
			for id := range drop {
				want = append(want, id)
			}
			sort.Strings(got)
			sort.Strings(want)
			if !equalStrings(got, want) {
				t.Fatalf("classified withdrawals %v, want %v", got, want)
			}
		})
	}
}
