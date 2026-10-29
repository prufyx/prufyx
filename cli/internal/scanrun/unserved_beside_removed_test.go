// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanRemovedAPIBesideAlphaOrUnservedVersion: a document at a version
// removed by the upgrade stays a blocker when another document of the same
// group and kind is an alpha or already unserved version. That document
// keeps its own gap, so the answer is BLOCKED with the finding and the gap,
// never UNKNOWN with no finding. Each removed document alone is unchanged.
func TestScanRemovedAPIBesideAlphaOrUnservedVersion(t *testing.T) {
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	doc := func(api, kind string) string {
		return "apiVersion: " + api + "\nkind: " + kind + "\nmetadata: {name: x}\n---\n"
	}
	cases := []struct {
		name     string
		from, to string
		alone    string
		beside   string
		wantGap  string
	}{
		{"rbac v1beta1 beside v1alpha1", "1.21.0", "1.22.0",
			doc("rbac.authorization.k8s.io/v1beta1", "ClusterRole"),
			doc("rbac.authorization.k8s.io/v1alpha1", "ClusterRole"), "ALPHA_API_NOT_COVERED"},
		{"priorityclass v1beta1 beside v1alpha1", "1.21.0", "1.22.0",
			doc("scheduling.k8s.io/v1beta1", "PriorityClass"),
			doc("scheduling.k8s.io/v1alpha1", "PriorityClass"), "ALPHA_API_NOT_COVERED"},
		{"flowschema v1beta2 beside unserved v1beta1", "1.28.0", "1.29.0",
			doc("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema"),
			doc("flowcontrol.apiserver.k8s.io/v1beta1", "FlowSchema"), "API_VERSION_NOT_SERVED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := func(manifest string) scanreport.Report {
				dir, _ := files(t, map[string]string{"applyset.yaml": manifest})
				var result Result
				inDir(t, dir, func() {
					result = mustScan(t, embedded, args([]string{"."}, "--from", "kubernetes="+tc.from, "--to", "kubernetes="+tc.to)...)
				})
				return result.Report
			}
			alone := scan(tc.alone)
			if alone.Verdict != scanreport.VerdictBlocked || len(alone.Findings) != 1 {
				t.Fatalf("alone: verdict %s findings %+v", alone.Verdict, alone.Findings)
			}
			both := scan(tc.alone + tc.beside)
			if both.Verdict != scanreport.VerdictBlocked || len(both.Findings) != 1 || both.Findings[0].RuleID != alone.Findings[0].RuleID {
				t.Fatalf("beside: verdict %s findings %+v gaps %v", both.Verdict, both.Findings, gapReasons(both))
			}
			if !gapNamed(both, tc.wantGap) {
				t.Fatalf("gap %s lost: %v", tc.wantGap, gapReasons(both))
			}
			// The other document alone is never PASS.
			other := scan(tc.beside)
			if other.Verdict == scanreport.VerdictPass || len(other.Findings) != 0 {
				t.Fatalf("other alone: verdict %s findings %+v", other.Verdict, other.Findings)
			}
		})
	}
}
