// SPDX-License-Identifier: AGPL-3.0-only

package tikvgcpv2

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEmbeddedProfileAndClosedSources(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != "1" || p.Purpose != "planned_operation_preflight" || len(p.NormativeSources) != 3 || len(p.Rules) != 1 {
		t.Fatalf("profile=%+v", p)
	}
	value := true
	claim := Evaluate(p, Observation{Schema: ObservationSchema, Component: Component, TargetVersionClass: CoveredTarget, PlannedGCSFullBackupWithWIF: true, BackupGCPV2Enable: &value}, time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC))
	if claim.Status != "PASS" {
		t.Fatalf("claim=%+v", claim)
	}

	for name, bad := range map[string][]byte{
		"duplicate":         bytes.Replace(EmbeddedProfile(), []byte(`"revision":"1"`), []byte(`"revision":"1","revision":"1"`), 1),
		"case ambiguity":    bytes.Replace(EmbeddedProfile(), []byte(`"revision":"1"`), []byte(`"revision":"1","Revision":"1"`), 1),
		"wrong target repo": bytes.Replace(EmbeddedProfile(), []byte(TiKVRepository), []byte("https://github.com/example/tikv"), 1),
		"wrong docs path":   bytes.Replace(EmbeddedProfile(), []byte("tikv-configuration-file.md"), []byte("other.md"), 1),
		"trailing token":    append(append([]byte{}, EmbeddedProfile()...), 'x'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProfile(bad); err == nil {
				t.Fatal("admitted")
			}
		})
	}

	var document map[string]any
	if err := json.Unmarshal(EmbeddedProfile(), &document); err != nil {
		t.Fatal(err)
	}
	sources := document["normativeSources"].([]any)
	sources[1].(map[string]any)["commit"] = "0123456789abcdef0123456789abcdef01234567"
	raw, _ := json.Marshal(document)
	if _, err := ParseProfile(raw); err == nil {
		t.Fatal("mixed TiKV source commits admitted")
	}
}

func TestProfileEvidenceExpiryIsUnknown(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	value := true
	claim := Evaluate(p, Observation{Schema: ObservationSchema, Component: Component, TargetVersionClass: CoveredTarget, PlannedGCSFullBackupWithWIF: true, BackupGCPV2Enable: &value}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if claim.Status != "UNKNOWN" || claim.ReasonCode != "PROFILE_EVIDENCE_EXPIRED" {
		t.Fatalf("claim=%+v", claim)
	}
}
