// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/communityapp/
//
// The ten rules the CRD extractor derives from the frozen Strimzi 0.51.0 and
// 1.0.0 manifests are loaded as synthetic, never published knowledge, and
// the custom-resource mode of check cncf is run end to end against them.

func useStrimziCRDKnowledge(t *testing.T) {
	t.Helper()
	tg, ok := crdversions.TargetFor("strimzi")
	if !ok {
		t.Fatal("no strimzi target")
	}
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	src := extract.FixtureReader{Root: filepath.Join("..", "extract", "crdversions", "testdata", "strimzi")}
	out, err := extract.Run(context.Background(), crdversions.New(tg), src, src, extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 10 {
		t.Fatalf("%d derived rules", len(out.Entries))
	}
	raw, err := extract.Canonical(out.Entries)
	if err != nil {
		t.Fatal(err)
	}
	var entries []cncfcheck.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	// No fact definition is added: the build registers the set.
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
}

func strimziObject(api, kind string) string {
	return "apiVersion: " + api + "\nkind: " + kind + "\nmetadata:\n  name: private-name\n  namespace: private-ns\n"
}

func TestSyntheticCustomResourceCheckWithDerivedStrimziRules(t *testing.T) {
	useStrimziCRDKnowledge(t)
	kafkaRemoved, kafkaServed := strimziObject("kafka.strimzi.io/v1beta2", "Kafka"), strimziObject("kafka.strimzi.io/v1", "Kafka")
	topicServed, topicRemoved := strimziObject("kafka.strimzi.io/v1", "KafkaTopic"), strimziObject("kafka.strimzi.io/v1beta2", "KafkaTopic")
	deployment, certificate := strimziObject("apps/v1", "Deployment"), strimziObject("cert-manager.io/v1", "Certificate")
	for _, tc := range []struct {
		name     string
		docs     []string
		complete bool
		want     int
		blocked  []string
	}{
		{"removed Kafka version blocks", []string{kafkaRemoved, topicServed, deployment}, true, ExitBlocked, []string{"kafka.strimzi.io/v1beta2/Kafka"}},
		{"removed Kafka version blocks without a complete scope", []string{kafkaRemoved, deployment}, false, ExitBlocked, []string{"kafka.strimzi.io/v1beta2/Kafka"}},
		{"removed versions block with an unattributed group", []string{kafkaRemoved, topicRemoved, certificate}, true, ExitBlocked, []string{"kafka.strimzi.io/v1beta2/Kafka", "kafka.strimzi.io/v1beta2/KafkaTopic"}},
		{"served versions pass every rule but the mode never exits 0", []string{kafkaServed, topicServed, deployment}, true, ExitUnknown, nil},
		{"a version neither release serves never passes", []string{strimziObject("kafka.strimzi.io/v1alpha1", "Kafka")}, true, ExitUnknown, nil},
		{"a kind no CRD defines never passes", []string{strimziObject("kafka.strimzi.io/v1beta2", "KAFKA")}, true, ExitUnknown, nil},
		{"served versions stay unknown without a complete scope", []string{kafkaServed, topicServed}, false, ExitUnknown, nil},
		{"served versions stay unknown with an unattributed group", []string{kafkaServed, certificate}, true, ExitUnknown, nil},
		{"templated manifests stay unknown", []string{kafkaRemoved, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n"}, true, ExitUnknown, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "manifests.yaml", []byte(strings.Join(tc.docs, "---\n")), 0o600)
			args := customResourceArgs(path, "--format", "json")
			args[len(args)-3] = "2026-10-05T00:00:00Z" // --now inside the derived rules' validity
			if tc.complete {
				args = append(args, "--custom-resources-complete")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.want || stderr != "" || strings.Contains(stdout, "private-") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			var report cncfcheck.Report
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Check.Claims) != 10 {
				t.Fatalf("%d claims: rules about other evidence must not be evaluated", len(report.Check.Claims))
			}
			var blocked []string
			passed := 0
			for _, claim := range report.Check.Claims {
				if !strings.HasPrefix(claim.RuleID, "strimzi.crd-version-removal.") {
					t.Fatalf("claim of rule %s", claim.RuleID)
				}
				switch claim.Status {
				case "BLOCKED":
					blocked = append(blocked, claim.MatchedMembers...)
				case "PASS":
					passed++
					if partial := !tc.complete || strings.Contains(strings.Join(tc.docs, ""), "cert-manager.io") || strings.Contains(strings.Join(tc.docs, ""), "{{"); partial {
						t.Fatalf("PASS from a partial set: %s", claim.RuleID)
					}
				}
			}
			if tc.name == "served versions pass every rule but the mode never exits 0" && passed != 10 {
				t.Fatalf("%d PASS claims, want 10", passed)
			}
			if strings.Join(blocked, ",") != strings.Join(tc.blocked, ",") {
				t.Fatalf("blocked members %v, want %v", blocked, tc.blocked)
			}
		})
	}
	// Human output names the blocking rule and the fix.
	path := writeCNCFFile(t, "manifests.yaml", []byte(kafkaRemoved), 0o600)
	args := customResourceArgs(path, "--custom-resources-complete")
	args[len(args)-2] = "2026-10-05T00:00:00Z"
	code, stdout, _ := runCNCFCLI(t, args...)
	if code != ExitBlocked || !strings.Contains(stdout, "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0") || !strings.Contains(stdout, "migrate stored Kafka objects to v1 and remove v1beta2 from status.storedVersions, then change apiVersion to kafka.strimzi.io/v1 before upgrading to 1.0.0") {
		t.Fatalf("code=%d %q", code, stdout)
	}
}
