// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"bytes"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanStoreRecordsGiveFirstPass (EXTPACK): a knowledge database built
// from a pack that carries a line attestation and a served-API list for
// Kubernetes 1.29, in either layout, gives the scan the same first PASS as
// the embedded pack; the records come from the database, signed and
// verified like its rules. The same database without the records answers
// UNKNOWN with the named gaps, and a removed API is still BLOCKED.
func TestScanStoreRecordsGiveFirstPass(t *testing.T) {
	hop := []string{"--from", "kubernetes=1.28.6", "--to", "kubernetes=1.29.2"}
	for _, layout := range storeLayouts {
		t.Run(layout, func(t *testing.T) {
			embedded := installRecords(t, recordSet{attestation: true, served: true})
			fixture := newStoreFixture(t, layout)
			fixture.importPack(nil, "5")
			store := openAt(t, fixture.store, testNow)
			dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
			inDir(t, dir, func() {
				want := mustScan(t, embedded, args([]string{"applyset.yaml"}, hop...)...)
				got := mustScan(t, store, storeArgs([]string{"applyset.yaml"}, hop...)...)
				if want.Exit != scanreport.ExitPass || got.Exit != scanreport.ExitPass || got.Report.Verdict != scanreport.VerdictPass || len(got.Report.Gaps) != 0 {
					t.Fatalf("exit embedded %d database %d, gaps %v", want.Exit, got.Exit, gapReasons(got.Report))
				}
				if hops := got.Report.Paths[0].Hops; len(hops) != 1 || hops[0].Status != scanreport.HopCovered || hops[0].Attestation == nil {
					t.Fatalf("hops %+v", hops)
				}
				if got.Report.Paths[0].ServedList == nil || got.Report.Paths[0].ServedList.Digest != want.Report.Paths[0].ServedList.Digest {
					t.Fatalf("served list %+v, embedded %+v", got.Report.Paths[0].ServedList, want.Report.Paths[0].ServedList)
				}
				if a, b := withoutProvenance(t, want.Report), withoutProvenance(t, got.Report); !bytes.Equal(a, b) {
					t.Fatalf("reports differ:\nembedded %s\ndatabase %s", a, b)
				}
				if got.Report.Provenance.KnowledgeOrigin != "external_signed_local" || got.Report.Provenance.KnowledgeRevision != "5" {
					t.Fatalf("provenance %+v", got.Report.Provenance)
				}
			})
			// A removal beside the records is still BLOCKED from the database.
			removed := cronjobV1 + "---\napiVersion: flowcontrol.apiserver.k8s.io/v1beta2\nkind: FlowSchema\nmetadata: {name: a}\nspec: {priorityLevelConfiguration: {name: x}}\n"
			dir, _ = files(t, map[string]string{"applyset.yaml": removed})
			inDir(t, dir, func() {
				if result := mustScan(t, store, storeArgs([]string{"applyset.yaml"}, hop...)...); result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) == 0 {
					t.Fatalf("removal from the database: exit %d gaps %v", result.Exit, gapReasons(result.Report))
				}
			})

			// The same database without the records: UNKNOWN, named gaps.
			installRecords(t, recordSet{})
			bare := newStoreFixture(t, layout)
			bare.importPack(nil, "5")
			dir, _ = files(t, map[string]string{"applyset.yaml": cronjobV1})
			inDir(t, dir, func() {
				result := mustScan(t, openAt(t, bare.store, testNow), storeArgs([]string{"applyset.yaml"}, hop...)...)
				if result.Exit != scanreport.ExitUnknown || !hasGap(result.Report, "LINE_NOT_ATTESTED", "") || !hasGap(result.Report, "API_VERSION_NOT_REVIEWED", "") {
					t.Fatalf("database without records: exit %d gaps %v", result.Exit, gapReasons(result.Report))
				}
			})
		})
	}
}
