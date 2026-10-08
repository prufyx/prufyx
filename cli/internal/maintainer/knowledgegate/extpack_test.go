// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EXTPACK: a CNCF pack with records splits into the per-project targets it
// is published as (targets/cncf passes), and a change may not carry records
// and trust material together.

// TestGateTargetsCarryRecords: a pack holding line attestations passes
// targets/cncf, and the check sizes the targets with their records.
func TestGateTargetsCarryRecords(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22", "1.25"}, nil)
	r := runGate(t, Options{Base: base, Head: head, Author: "airstand", Sender: "airstand"})
	c, ok := check(r, "targets/cncf")
	if !ok || !c.OK || !strings.Contains(c.Detail, "targets, largest") {
		t.Fatalf("targets/cncf: %+v", c)
	}
	// The reviewed 1.25 attestation has no approval, so that change fails;
	// the split itself is not what refuses it.
	if ch := change(t, r, attestationID("1.25")); ch.OK {
		t.Fatalf("an unapproved reviewed attestation was admitted: %+v", ch)
	}
	if rt, ok := check(r, "records-trust"); !ok || !rt.OK || !strings.Contains(rt.Detail, "1 record changes, 0 trust files changed") {
		t.Fatalf("records-trust: %+v", rt)
	}
}

// TestGateRefusesRecordsWithTrustMaterial: the owner removes a line
// attestation (a tightening record change that needs no proof) and pins new
// approval keys (trust material the owner may change on its own): each
// passes alone, together they fail records-trust.
func TestGateRefusesRecordsWithTrustMaterial(t *testing.T) {
	key := newApprovalKey(t)
	run := func(records, trust bool) *Report {
		t.Helper()
		lines := []string{"1.22", "1.25"}
		headLines := lines
		if records {
			headLines = []string{"1.22"}
		}
		base, head := attestedTrees(t, lines, headLines, nil)
		opts := Options{Base: base, Head: head, Author: "airstand", Sender: "airstand"}
		if trust {
			key.pin(t, head, "airstand")
			raw, err := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(approvalKeys)))
			if err != nil {
				t.Fatal(err)
			}
			opts.ApprovalKeysDigest = pinnedDigest(raw)
		}
		return runGate(t, opts)
	}
	for _, tc := range []struct {
		name           string
		records, trust bool
		ok             bool
	}{
		{"records alone", true, false, true},
		{"trust alone", false, true, true},
		{"records and trust", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(tc.records, tc.trust)
			c, ok := check(r, "records-trust")
			if !ok || c.OK != tc.ok {
				t.Fatalf("records-trust %+v", c)
			}
			if tm, _ := check(r, "trust-material"); !tm.OK {
				t.Fatalf("trust-material must pass on its own here: %+v", tm)
			}
			if r.Passed() != tc.ok {
				t.Fatalf("passed=%v, failed: %v", r.Passed(), failedChecks(r))
			}
			if !tc.ok && !strings.Contains(c.Detail, "split it") {
				t.Fatalf("detail %q", c.Detail)
			}
		})
	}
}
