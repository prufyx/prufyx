// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadChartDeclarationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	doc := `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[{"name":"widget","version":"1.4.2"}]}`
	if err := os.WriteFile(good, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readChartDeclaration(good); err != nil || len(got) != 1 {
		t.Fatalf("good declaration: %v %v", got, err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"charts":[{"name":"widget","version":"1.4.2","values":"x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(doc+strings.Repeat(" ", 70<<10)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"symlink": link, "directory": dir, "missing": filepath.Join(dir, "nope"), "unknown member": bad, "oversize": big} {
		if _, err := readChartDeclaration(path); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCollectorRefusesUnusableDeclarationBeforeAnyRead(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"collect", t.TempDir(), "--kubeconfig", "/nonexistent", "--chart-declaration", "/nonexistent-declaration", "ctx"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "chart declaration") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	code = run(context.Background(), []string{"collect", t.TempDir(), "--chart-declaration", "a", "--chart-declaration", "b", "ctx"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("duplicate declaration option accepted: %d", code)
	}
}
