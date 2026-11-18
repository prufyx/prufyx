// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const qaFixture = `{"runId":"x","host":"h","k8sFrom":"1.25.16","k8sTo":"1.26.15","kindVersion":"v","startedAt":"a","finishedAt":"b",
"clusters":[{"kindNodeImage":"kindest/node@sha256:6110314339b3b44d10da7d27881849a87e092124afab5956f2e10ecdb463b025","role":"from"},{"kindNodeImage":"kindest/node@sha256:c79602a44b4056d7e48dc20f7504350f1e87530fe953428b792def00bc1076dd","role":"to"}],
"logs":{},"prufyxBinarySha256":"x","prufyxCommit":"28fc30c183e8c2c9af1d3a483bbec42a27378ba7","prufyxCommitSource":"s",
"checks":[{"app":"podinfo","artifactDigests":{},"assertion":{"command":"scan","ids":[],"verdict":"no path"},"class":"gap","fromVersion":"1.0.0","toVersion":"1.1.0","logDigest":"","logPath":"p","oracle":{"observed":"o","type":"in-place upgrade"},"project":"p","result":"gap"}]}`

func TestQAReportCheckDrift(t *testing.T) {
	res := t.TempDir()
	if err := os.MkdirAll(filepath.Join(res, "r1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(res, "r1", "RESULT.json"), []byte(qaFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	j, md := filepath.Join(outDir, "qa-e2e.json"), filepath.Join(outDir, "qa-e2e.md")
	args := []string{"qa-report", "--results-dir", res, "--out", j, "--md", md}
	var o, e bytes.Buffer
	if err := run(args, &o, &e); err != nil {
		t.Fatal(err)
	}
	if err := run(append(args, "--check"), &o, &e); err != nil {
		t.Fatalf("fresh files flagged: %v", err)
	}
	if err := os.WriteFile(md, []byte("hand edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = run(append(args, "--check"), &o, &e)
	ce, ok := err.(*commandError)
	if !ok || ce.code != 1 {
		t.Fatalf("drift not reported with exit 1: %v", err)
	}
	if err := run([]string{"qa-report", "--results-dir", res}, &o, &e); err == nil {
		t.Error("missing flags accepted")
	}
}
