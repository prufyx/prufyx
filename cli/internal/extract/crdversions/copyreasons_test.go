// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// reasonCases are files next to listed paths that hold Alpha (v1beta1, v1)
// at both releases. outcome and attestable are what the scan decided
// before reasons were recorded; the test pins them.
var reasonCases = []struct {
	name       string
	file       string
	class      string
	reason     string
	status     string
	attestable bool
	copy       bool
}{
	{name: "plain copy", file: crd("Alpha", "v1beta1", "v1"), reason: "v1-same-serving", status: extract.PairDerived, attestable: true, copy: true},
	{name: "multi-doc copy", file: crd("Alpha", "v1beta1", "v1") + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", reason: "v1-same-serving", status: extract.PairDerived, attestable: true, copy: true},
	{name: "multi-doc extra", file: crd("Alpha", "v1beta1", "v1") + "---\n" + crd("Beta", "v1"), class: ClassExtra, reason: "v1-extra", status: extract.PairDerived},
	{name: "multi-doc conflict", file: crd("Alpha", "v1") + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", class: ClassConflict, reason: "v1-conflict", status: extract.PairWithheld},
	{name: "templated copy", file: metallbTemplate(crd("Alpha", "v1beta1", "v1")), class: ClassTemplatedCopy, reason: "templated-same-serving", status: extract.PairDerived, attestable: true},
	{name: "templated unread", file: kueueTemplate(crd("Alpha", "v1beta1", "v1")), class: ClassUnread, reason: ReasonTemplateUnread, status: extract.PairDerived},
	{name: "templated not a copy", file: metallbTemplate(crd("Beta", "v1")), class: ClassUnread, reason: ReasonTemplateNotCopy, status: extract.PairDerived},
	{name: "embedded manifest", file: "manifests: |\n  apiVersion: apiextensions.k8s.io/v1\n  kind: CustomResourceDefinition\n", class: ClassReference, reason: ReasonEmbedded, status: extract.PairDerived},
	{name: "undecodable", file: "kind: CustomResourceDefinition\nspec: [\n", class: ClassUnread, reason: ReasonUndecodable, status: extract.PairDerived},
}

func TestCopyReasonsRecorded(t *testing.T) {
	const path = "deploy/other/alphas.yaml"
	for _, c := range reasonCases {
		t.Run(c.name, func(t *testing.T) {
			p, proof, f := quietPair(t, path, c.file)
			attestable := proof.Completeness != nil && proof.Completeness.Attestable
			if p.Status != c.status || attestable != c.attestable {
				t.Fatalf("outcome changed: %s %q attestable=%v", p.Status, p.Reason, attestable)
			}
			scan := proof.To.Scan
			if c.copy {
				if f != nil || !slices.Contains(scan.Copies, path) {
					t.Fatalf("not a copy: %+v %+v", f, scan.Copies)
				}
				r := copyRecordOf(scan, path)
				if r == nil || r.Reason != c.reason || r.SHA256 == "" || !slices.Equal(r.Definitions, []string{"alphas." + synthGroup}) {
					t.Fatalf("copy record: %+v", r)
				}
				return
			}
			if f == nil || f.Class != c.class || f.Reason != c.reason {
				t.Fatalf("finding: %+v", f)
			}
			if copyRecordOf(scan, path) != nil {
				t.Fatalf("a finding is not a copy record: %+v", scan.CopyRecords)
			}
		})
	}
}

func copyRecordOf(s *ScanRecord, path string) *CopyRecord {
	for i := range s.CopyRecords {
		if s.CopyRecords[i].Path == path {
			return &s.CopyRecords[i]
		}
	}
	return nil
}

// Every file of Copies has exactly one record, in the same order (sorted),
// whatever the order the files are listed in; a declared copy is recorded
// with its location.
func TestCopyRecordsMatchCopies(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	files := map[string]string{"z/a.yaml": alpha, "b/a.yaml": alpha, "m/a.yaml": alpha, "charts/x/templates/a.yaml": metallbTemplate(alpha)}
	copies := Exclusion{Path: "charts/x/templates/", Reason: "Helm chart templates of the listed definitions", Copies: true}
	_, proof := classPair(t, alpha, alpha, files, files, copies)
	scan := proof.To.Scan
	if !slices.IsSorted(scan.Copies) || len(scan.Copies) != 4 || len(scan.CopyRecords) != 4 {
		t.Fatalf("%+v", scan)
	}
	for i, r := range scan.CopyRecords {
		if r.Path != scan.Copies[i] {
			t.Fatalf("record %d is %s, copy is %s", i, r.Path, scan.Copies[i])
		}
	}
	r := copyRecordOf(scan, "charts/x/templates/a.yaml")
	if r == nil || r.Reason != "templated-same-serving" || r.Location != "charts/x/templates/" {
		t.Fatalf("declared templated copy: %+v", r)
	}
}

// The names recorded for one copy are bounded.
func TestCopyRecordNamesBounded(t *testing.T) {
	var docs []string
	for i := 0; i < 20; i++ {
		docs = append(docs, crd(fmt.Sprintf("Kind%02d", i), "v1"))
	}
	all := strings.Join(docs, "---\n")
	_, proof := classPair(t, all, all, map[string]string{"x/all.yaml": all}, map[string]string{"x/all.yaml": all})
	r := copyRecordOf(proof.To.Scan, "x/all.yaml")
	if r == nil || len(r.Definitions) != maxRecordedNames+1 || r.Definitions[maxRecordedNames] != "and 4 more" || !slices.IsSorted(r.Definitions[:maxRecordedNames]) {
		t.Fatalf("%+v", r)
	}
}

// A file that becomes a pre-patch copy leaves Copies and CopyRecords
// together: the records never list a file that is not in Copies.
func TestCopyRecordsNeverOutliveCopies(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	_, proof := classPair(t, alpha, alpha, map[string]string{"x/a.yaml": alpha}, map[string]string{"x/a.yaml": alpha})
	for _, s := range []*ScanRecord{proof.From.Scan, proof.To.Scan} {
		for _, r := range s.CopyRecords {
			if !slices.Contains(s.Copies, r.Path) {
				t.Fatalf("record without copy: %+v", r)
			}
		}
	}
}
