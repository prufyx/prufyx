// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCommunityExampleRunsNativeSyntheticCNCFJourneys(t *testing.T) {
	t.Parallel()

	if _, err := (runtime{}).runEtcdExample(); err != nil {
		t.Fatalf("direct etcd example: %v", err)
	}
	for _, example := range []string{"cncf-coredns-latest", "cncf-envoy-latest", "cncf-etcd", "cncf-kyverno-latest", "cncf-nats-latest", "cncf-opa-latest", "cncf-opentelemetry", "cncf-rook-latest", "knowledge-cert-manager", "knowledge-cncf", "project-ceph-latest"} {
		t.Run(example, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"community-preview", "example", example}, &stdout, &stderr, "test")
			if code != ExitOK || stderr.Len() != 0 {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr.String(), stdout.String())
			}
			if strings.Contains(stdout.String(), "synthetic-private-node") || !json.Valid(stdout.Bytes()) {
				t.Fatalf("private example data crossed output: %s", stdout.String())
			}
			var envelope struct {
				Data communityExampleResult `json:"data"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Data.Example != example || envelope.Data.Aggregate != "UNKNOWN" || envelope.Data.NetworkUsed || envelope.Data.ClusterUsed || envelope.Data.PrivateRetained || envelope.Data.RuntimeObserved || envelope.Data.ProcessExecuted || !envelope.Data.ScopedClaimOnly {
				t.Fatalf("result=%#v", envelope.Data)
			}
			needsClean := example == "cncf-coredns-latest" || example == "cncf-envoy-latest" || example == "cncf-etcd" || example == "cncf-kyverno-latest" || example == "cncf-nats-latest" || example == "cncf-opa-latest" || example == "cncf-opentelemetry" || example == "cncf-rook-latest" || example == "project-ceph-latest"
			wantClean := ExitOK
			if example == "cncf-kyverno-latest" {
				// The hops from 1.14.5 and 1.15.3 cross the custom-resource
				// batch's Kyverno rule once it ships: exit 11 there.
				wantByOrigin := map[string]int{}
				for _, from := range []string{"1.14.5", "1.15.3", "1.16.4", "1.17.2", "1.18.2"} {
					wantByOrigin[from] = passExit(kyvernoLatestBatchRuleIDs(from, "1.19.1"))
					if wantByOrigin[from] != ExitOK {
						wantClean = wantByOrigin[from]
					}
				}
				if !reflect.DeepEqual(envelope.Data.CleanExitsByOrigin, wantByOrigin) {
					t.Fatalf("clean exits by origin %v, want %v", envelope.Data.CleanExitsByOrigin, wantByOrigin)
				}
			} else if envelope.Data.CleanExitsByOrigin != nil {
				t.Fatalf("clean exits by origin on %s: %v", example, envelope.Data.CleanExitsByOrigin)
			}
			if envelope.Data.BlockedExit != ExitBlocked || envelope.Data.UnknownExit != ExitUnknown || (needsClean && envelope.Data.CleanExit != wantClean) {
				t.Fatalf("exit result=%#v", envelope.Data)
			}
		})
	}
}

func TestCommunityExampleRejectsUnknownName(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"community-preview", "example", "unknown"}, &stdout, &stderr, "test"); code != ExitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
