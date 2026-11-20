// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"testing"
)

func computeCRDDecided(t *testing.T, changelogTarget bool) Report {
	t.Helper()
	atts := []string{crdAttJSON("0.50", "0.49.0", "0.50.0"), crdAttJSON("0.51", "0.50.0", "0.51.0")}
	// No component in the snapshot: the project is attributed by its target.
	snapshot := []byte(fmt.Sprintf(`{"schema":%q,"projects":{"strimzi":{"lines":["0.49","0.50","0.51"],`+
		`"releases":{"0.49":["0.49.0"],"0.50":["0.50.0"],"0.51":["0.51.0"]}}}}`, LinesSchema))
	in := Input{Pack: pack(nil, atts), Lines: snapshot, Now: baselineNow,
		CRDTargetComponents: map[string]string{"strimzi": strimzi}}
	if changelogTarget {
		in.ChangelogTargetComponents = map[string]string{"strimzi": strimzi}
	}
	r, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A change-list target with no listed attestation never removes a decision
// another family already makes: the project keeps its A pairs and counts.
func TestChangelogTargetWithoutAttestationKeepsDecisions(t *testing.T) {
	without := computeCRDDecided(t, false)
	if got := statuses(without.Projects[0]); got != "AA" {
		t.Fatalf("setup: the CRD family decides %q, want AA", got)
	}
	with := computeCRDDecided(t, true)
	if got, want := statuses(with.Projects[0]), statuses(without.Projects[0]); got != want {
		t.Fatalf("statuses with the target %q, without %q", got, want)
	}
	if with.Projects[0].A != without.Projects[0].A || with.Projects[0].Covered != without.Projects[0].Covered {
		t.Fatalf("project counts moved: %+v vs %+v", with.Projects[0], without.Projects[0])
	}
	if with.Fleet != without.Fleet {
		t.Fatalf("fleet totals moved: %+v vs %+v", with.Fleet, without.Fleet)
	}
	for _, p := range with.Projects[0].Pairs {
		if p.Changelog {
			t.Fatalf("a pair with no listed attestation is marked L: %+v", p)
		}
	}
}

// A pair with a listed attestation and no other decision is L, never A or B.
func TestChangelogTargetListedAttestationOnlyIsL(t *testing.T) {
	r := computeListed(t, nil, listedAttJSON(listedComp, "1.9.0", "1.9.1"), map[string]string{"prometheus": listedComp}, nil)
	p := r.Projects[0]
	if !p.Pairs[0].Changelog || p.Pairs[0].Status != StatusG {
		t.Fatalf("pair 1.8->1.9: %+v, want L", p.Pairs[0])
	}
	if p.A != 0 || p.B != 0 || r.Fleet.A != 0 || r.Fleet.B != 0 {
		t.Fatalf("a listed pair counted as A or B: %+v", r.Fleet)
	}
}

// Negative: two different projects claiming one component attribute it to
// neither (fail closed); only one project's two targets count as one claimant.
func TestTargetClaimedByTwoProjectsAttributesNothing(t *testing.T) {
	atts := []string{crdAttJSON("0.50", "0.49.0", "0.50.0"), crdAttJSON("0.51", "0.50.0", "0.51.0")}
	snapshot := []byte(fmt.Sprintf(`{"schema":%q,"projects":{"strimzi":{"lines":["0.49","0.50","0.51"],`+
		`"releases":{"0.49":["0.49.0"],"0.50":["0.50.0"],"0.51":["0.51.0"]}},"other":{"lines":["0.49","0.50","0.51"],`+
		`"releases":{"0.49":["0.49.0"],"0.50":["0.50.0"],"0.51":["0.51.0"]}}}}`, LinesSchema))
	r, err := Compute(Input{Pack: pack(nil, atts), Lines: snapshot, Now: baselineNow,
		CRDTargetComponents:       map[string]string{"strimzi": strimzi},
		ChangelogTargetComponents: map[string]string{"other": strimzi}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Projects {
		if p.A != 0 {
			t.Fatalf("project %s decided %q from a component two projects claim", p.Project, statuses(p))
		}
	}
}
