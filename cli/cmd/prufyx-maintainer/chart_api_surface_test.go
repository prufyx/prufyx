// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/chartapisurface"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

const surfaceEvidence = `{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}`

func surfaceRecord(line, apis string) string {
	return `{"component":"` + servedapis.KubernetesComponent + `","line":"` + line + `","completeness":"` + servedapis.Completeness + `","apis":` + apis + `,"evidence":` + surfaceEvidence + `}`
}

func surfaceArchive(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	files["Chart.yaml"] = "apiVersion: v2\nname: demo\nversion: 1.0.0\n"
	for n, b := range files {
		tw.WriteHeader(&tar.Header{Name: "demo/" + n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
		tw.Write([]byte(b))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestChartAPISurfaceCommand(t *testing.T) {
	dir := t.TempDir()
	chart := filepath.Join(dir, "demo-1.0.0.tgz")
	os.WriteFile(chart, surfaceArchive(t, map[string]string{"templates/pdb.yaml": "apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n"}), 0o644)
	servedFile := filepath.Join(dir, "served.json")
	os.WriteFile(servedFile, []byte("["+surfaceRecord("1.24", `["policy/v1 PodDisruptionBudget","policy/v1beta1 PodDisruptionBudget"]`)+","+surfaceRecord("1.25", `["policy/v1 PodDisruptionBudget"]`)+"]"), 0o644)
	out := filepath.Join(dir, "ledger.json")
	var so, se bytes.Buffer
	if err := run([]string{"chart-api-surface", "--chart", chart, "--out", out, "--served-apis", servedFile, "--lines", "1.24,1.25"}, &so, &se); err != nil {
		t.Fatal(err, se.String())
	}
	raw, _ := os.ReadFile(out)
	var led chartapisurface.Ledger
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&led); err != nil {
		t.Fatal(err)
	}
	if led.Mode != "measurement" || led.Status != "complete" || len(led.ServedChecks) != 2 || led.ServedChecks[0].Result != "would-pass" || led.ServedChecks[1].Result != "would-block" {
		t.Fatalf("%s", raw)
	}
	for _, bad := range []string{`"verdict"`, `"rule"`, `"attest`} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("measurement ledger carries %s", bad)
		}
	}
}

func TestChartAPISurfaceCommandRefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "g.tgz")
	os.WriteFile(good, surfaceArchive(t, map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: ConfigMap\n"}), 0o644)
	junk := filepath.Join(dir, "j.tgz")
	os.WriteFile(junk, []byte("junk"), 0o644)
	out := filepath.Join(dir, "o.json")
	for name, args := range map[string][]string{
		"no args":         {"chart-api-surface"},
		"no out":          {"chart-api-surface", "--chart", good},
		"junk archive":    {"chart-api-surface", "--chart", junk, "--out", out},
		"missing archive": {"chart-api-surface", "--chart", filepath.Join(dir, "none"), "--out", out},
		"served no lines": {"chart-api-surface", "--chart", good, "--out", out, "--served-apis", good},
		"bad line":        {"chart-api-surface", "--chart", good, "--out", out, "--served-apis", good, "--lines", "x"},
		"bad served doc":  {"chart-api-surface", "--chart", good, "--out", out, "--served-apis", good, "--lines", "1.25"},
		"extra arg":       {"chart-api-surface", "--chart", good, "--out", out, "more"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("a ledger was written for refused input")
			}
		})
	}
}

func TestChartAPISurfaceOracleHook(t *testing.T) {
	dir := t.TempDir()
	chart := filepath.Join(dir, "c.tgz")
	os.WriteFile(chart, surfaceArchive(t, map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: ConfigMap\n"}), 0o644)
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755)
		return p
	}
	cases := map[string]struct {
		cmd    string
		status string
		code   string
	}{
		"match":    {script("ok.sh", "printf 'apiVersion: v1\\nkind: ConfigMap\\n'\n"), "complete", ""},
		"mismatch": {script("bad.sh", "printf 'apiVersion: v1\\nkind: Secret\\n'\n"), "withheld", chartapisurface.CodeToolBugOracleMatch},
		"fails":    {script("fail.sh", "exit 3\n"), "withheld", chartapisurface.CodeOracleUnavailable},
		"relative": {"render.sh", "withheld", chartapisurface.CodeOracleUnavailable},
		"missing":  {filepath.Join(dir, "nope"), "withheld", chartapisurface.CodeOracleUnavailable},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, name+".json")
			if err := run([]string{"chart-api-surface", "--chart", chart, "--out", out, "--oracle-cmd", c.cmd}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			var led chartapisurface.Ledger
			raw, _ := os.ReadFile(out)
			if err := json.Unmarshal(raw, &led); err != nil {
				t.Fatal(err)
			}
			if led.Status != c.status {
				t.Fatalf("%s", raw)
			}
			if c.code != "" && !strings.Contains(string(raw), c.code) {
				t.Fatalf("%s", raw)
			}
		})
	}
}
