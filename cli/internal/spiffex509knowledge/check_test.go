// SPDX-License-Identifier: AGPL-3.0-only

package spiffex509knowledge

import (
	"bytes"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/spiffex509svid"
)

func TestEmbeddedReportCanonicalReplayAndPrivacy(t *testing.T) {
	one := "one"
	yes := true
	o := spiffex509svid.Observation{Schema: spiffex509svid.ObservationSchema, URISANCardinality: &one, URISANSchemeIsSPIFFE: &yes, URISANPathIsNonRoot: &yes}
	report, err := EvaluateEmbedded(o, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.Kind != "SPIFFEX509SVIDConformanceReport" || report.Status != "PASS" || report.Purpose != "standards_conformance" || report.Profile.ID != spiffex509svid.ConformanceProfileID || report.Profile.Revision != "1" {
		t.Fatalf("report envelope=%+v", report)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("private-canary.example"), []byte("spiffe://"), []byte("/tmp/")} {
		if bytes.Contains(raw, secret) {
			t.Fatalf("report leaked %q", secret)
		}
	}
	replay, err := ReplayEmbedded(o, raw)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Status != "MATCH" || HistoricalClaimExit(replay) != 0 {
		t.Fatalf("replay=%+v", replay)
	}
}
