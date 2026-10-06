// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"os"
	"path/filepath"
	"testing"
)

func outputRootOptions(t *testing.T, root string) Options {
	t.Helper()
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "config")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return Options{OutputRoot: root, Kubeconfig: kubeconfig, Contexts: []string{"private"}, AcknowledgeExecRisk: true, Kubectl: "/bin/false"}
}

func TestValidateOptionsOutputRootRefusesSymlinkAndFile(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	o := outputRootOptions(t, link)
	if err := validateOptions(&o); err == nil {
		t.Fatal("symlinked output root accepted")
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target mode changed to %v", info.Mode().Perm())
	}
	file := filepath.Join(tmp, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	o = outputRootOptions(t, file)
	if err := validateOptions(&o); err == nil {
		t.Fatal("regular-file output root accepted")
	}
}

func TestWritePrivateRefusesExistingAndSymlinkTargets(t *testing.T) {
	tmp := t.TempDir()
	victim := filepath.Join(tmp, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "out.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(link, []byte("x")); err == nil {
		t.Fatal("wrote through symlink")
	}
	if err := writePrivate(victim, []byte("x")); err == nil {
		t.Fatal("overwrote existing file")
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "keep" {
		t.Fatalf("victim modified: %q", raw)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("pre-existing path removed on failure: %v", err)
	}
	fresh := filepath.Join(tmp, "fresh")
	if err := writePrivate(fresh, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}
