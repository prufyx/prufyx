// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func profileAttestation() LineAttestation {
	a := crdAttestation()
	for i, rel := range append(append([]Release{}, a.Releases.From...), a.Releases.To...) {
		for j, id := range []string{"canonical", "ha"} {
			digest := "sha256:" + strings.Repeat(fmt.Sprintf("%x", i*2+j+1), 64)
			file := "config/" + id + ".yaml"
			s := constraintengine.SourceEvidence{ID: fmt.Sprintf("profile-%d-%s", i, id), URL: "https://github.com/strimzi/strimzi-kafka-operator/blob/" + rel.Commit + "/" + file, Revision: rel.Commit, ContentDigest: digest, StartLine: 1, EndLine: 10}
			a.InstallProfiles = append(a.InstallProfiles, InstallProfile{Version: rel.Version, Commit: rel.Commit, ID: id, Artifacts: []InstallArtifact{{Path: file, Digest: digest, Source: s}}, Served: []string{"kafka.strimzi.io/v1beta1/Kafka"}})
		}
	}
	return a
}

func TestInstallProfilesRequireCompletePinnedCensus(t *testing.T) {
	a := profileAttestation()
	if _, err := Parse(encode(t, []LineAttestation{a})); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LineAttestation){
		"missing release": func(a *LineAttestation) { a.InstallProfiles = a.InstallProfiles[2:] },
		"missing profile": func(a *LineAttestation) { a.InstallProfiles = a.InstallProfiles[:len(a.InstallProfiles)-1] },
		"extra release":   func(a *LineAttestation) { a.InstallProfiles[len(a.InstallProfiles)-1].Version = "0.51.1" },
		"foreign commit":  func(a *LineAttestation) { a.InstallProfiles[0].Commit = commit(9) },
		"foreign source": func(a *LineAttestation) {
			a.InstallProfiles[0].Artifacts[0].Source.URL = "https://github.com/example/other/blob/" + commit(1) + "/config/canonical.yaml"
		},
		"modified digest": func(a *LineAttestation) {
			a.InstallProfiles[0].Artifacts[0].Digest = "sha256:" + strings.Repeat("f", 64)
		},
		"foreign member": func(a *LineAttestation) { a.InstallProfiles[0].Served = []string{"argoproj.io/v1alpha1/Application"} },
		"no profiles":    func(a *LineAttestation) { a.InstallProfiles = []InstallProfile{} },
		"path traversal": func(a *LineAttestation) { a.InstallProfiles[0].Artifacts[0].Path = "../config/canonical.yaml" },
		"no artifacts":   func(a *LineAttestation) { a.InstallProfiles[0].Artifacts = nil },
		"unordered profiles": func(a *LineAttestation) {
			a.InstallProfiles[0], a.InstallProfiles[1] = a.InstallProfiles[1], a.InstallProfiles[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := profileAttestation()
			mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid profile census accepted")
			}
		})
	}
}

func TestInstallProfilesStrictShapeAndLegacyRefusal(t *testing.T) {
	raw := string(encode(t, []LineAttestation{profileAttestation()}))
	for _, bad := range []string{
		strings.Replace(raw, `"installProfiles":`, `"InstallProfiles":`, 1),
		strings.Replace(raw, `"artifacts":`, `"Artifacts":`, 1),
		strings.Replace(raw, `"digest":`, `"extra":true,"digest":`, 1),
		strings.Replace(raw, `"source":{`, `"source":null,"x":{`, 1),
		strings.Replace(raw, `"served":[`, `"served":null,"x":[`, 1),
		strings.Replace(raw, `"id":"canonical"`, `"id":"canonical","id":"ha"`, 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("non-exact profile document accepted")
		}
	}
	// This is the previous record grammar, taken from the strict parser.
	// An older client rejects the added field before it could ignore the join.
	var records []any
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		t.Fatal(err)
	}
	legacy := fields("component", "line", "factFamily", "completeness", "ruleIds", "releases?", "evidence")
	if err := object(records[0], legacy, nil); err == nil {
		t.Fatal("legacy parser silently accepted source profiles")
	}
	a := crdAttestation()
	before := string(encode(t, []LineAttestation{a}))
	got, err := Parse([]byte(before))
	if err != nil || string(encode(t, got)) != before || strings.Contains(before, "installProfiles") {
		t.Fatal("legacy record bytes changed")
	}
}

func TestInstallProfilesCopyAndChanges(t *testing.T) {
	a := profileAttestation()
	ix := NewIndex([]LineAttestation{a})
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	got := ix.AttestationsFor(a.Component, a.Line, a.FactFamily, now)[0].Attestation
	got.InstallProfiles[0].Artifacts[0].Path = "changed.yaml"
	got.InstallProfiles[0].Served[0] = "changed"
	again := ix.AttestationsFor(a.Component, a.Line, a.FactFamily, now)[0].Attestation
	if again.InstallProfiles[0].Artifacts[0].Path != a.InstallProfiles[0].Artifacts[0].Path || again.InstallProfiles[0].Served[0] != a.InstallProfiles[0].Served[0] {
		t.Fatal("profile slices escape the index")
	}
	changes, err := Classify([]LineAttestation{a}, []LineAttestation{got})
	if err != nil || len(changes) != 1 || changes[0].Class != Loosening || changes[0].Renewal || len(changes[0].Fields) != 1 || changes[0].Fields[0] != "installProfiles" {
		t.Fatalf("profile change hidden: %+v %v", changes, err)
	}
}
