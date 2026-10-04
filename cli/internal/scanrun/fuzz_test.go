// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// FuzzScanArgs: the argument parser never panics, and an accepted command
// line is well formed.
func FuzzScanArgs(f *testing.F) {
	for _, seed := range []string{
		"rendered/\x00--to\x00kubernetes=1.30.4",
		"--to=kubernetes=1.30.4\x00--from\x00kubernetes=1.24.17\x00-\x00--format\x00json",
		"--resource-scope-complete=false\x00--redact\x00--now\x002026-10-04T00:00:00Z",
		"--\x00--to\x00-x",
		"--knowledge-db\x00x",
		"--to\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		request, err := ParseArgs(strings.Split(joined, "\x00"))
		if err != nil {
			if !isUsage(err) || len(err.Error()) > scanreport.MaxText+len("INPUT NOT ACCEPTED: ") {
				t.Fatalf("error %v", err)
			}
			return
		}
		if request.Format != "human" && request.Format != "json" {
			t.Fatalf("format %q", request.Format)
		}
		stdin := 0
		for _, path := range request.Paths {
			if path == "" || strings.IndexByte(path, 0) >= 0 {
				t.Fatalf("path %q", path)
			}
			if path == "-" {
				stdin++
			}
		}
		for _, versions := range []map[string]string{request.From, request.To} {
			for _, version := range versions {
				if !validVersion(version) {
					t.Fatalf("version %q", version)
				}
			}
		}
		if stdin > 1 || (!request.Now.IsZero() && request.Now.Location().String() != "UTC") {
			t.Fatalf("request %+v", request)
		}
	})
}

var fuzzKnowledge struct {
	once      sync.Once
	knowledge Knowledge
}

// FuzzScanWorkspace: arbitrary manifests and declarations never yield a
// pass unless every precondition holds: complete scope declared, target
// apply declared, official upstream distribution, nothing omitted, no gap,
// every hop covered.
func FuzzScanWorkspace(f *testing.F) {
	for _, seed := range []string{
		cronjobV1, cronjobV1beta1,
		"apiVersion: v1\nkind: List\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob}\n",
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ x }}'}\n",
		"apiVersion: flowcontrol.apiserver.k8s.io/v1beta2\nkind: FlowSchema\n",
		"apiVersion: resource.k8s.io/v1alpha3\nkind: DeviceClass\n",
		"apiVersion: prufyx.io/v1alpha1\nkind: ScanConfig\n",
		"replicas: 3\n",
	} {
		f.Add([]byte(seed), uint8(7))
	}
	f.Fuzz(func(t *testing.T, manifest []byte, flags uint8) {
		fuzzKnowledge.once.Do(func() {
			fuzzKnowledge.knowledge = newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
		})
		path := filepath.Join(t.TempDir(), "manifest.yaml")
		if err := os.WriteFile(path, manifest, 0o600); err != nil {
			t.Fatal(err)
		}
		complete, apply := flags&1 != 0, flags&2 != 0
		distribution := []string{"", "official_upstream", "custom_build", "official_upstream"}[(flags>>2)&3]
		command := []string{path, "--now", testNow, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}
		if complete {
			command = append(command, "--resource-scope-complete")
		}
		if apply {
			command = append(command, "--target-api-apply-required")
		}
		if distribution != "" {
			command = append(command, "--distribution", distribution)
		}
		result, err := scan(t, fuzzKnowledge.knowledge, command...)
		if err != nil {
			if !isUsage(err) {
				t.Fatalf("error %v", err)
			}
			return
		}
		checkInvariants(t, result.Report)
		if result.Exit != scanreport.ExitPass {
			return
		}
		for _, omitted := range result.Report.Omitted {
			if omitted.Reason != omittedConfigDocument {
				t.Fatalf("pass with an omitted document: %+v", omitted)
			}
		}
		if !complete || !apply || distribution != "official_upstream" || result.Report.Summary.DocumentsRead == 0 {
			t.Fatalf("pass without its preconditions: complete=%t apply=%t distribution=%q", complete, apply, distribution)
		}
		for _, path := range result.Report.Paths {
			for _, hop := range path.Hops {
				if hop.Status != scanreport.HopCovered || hop.Attestation == nil || hop.Attestation.Freshness != "current" {
					t.Fatalf("pass with hop %+v", hop)
				}
			}
		}
	})
}
