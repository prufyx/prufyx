// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// snapshotTree returns every path under dir with its mode and content, so a
// test can prove a failed update left the store byte-identical.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if d.Name() == "clock-floor.json" {
			// The monotonic clock floor records the time of the last check,
			// also after a refusal; it is neither trust state nor selection.
			return nil
		}
		if d.IsDir() {
			out[rel] = "dir " + info.Mode().String()
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = info.Mode().String() + " " + string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An old client (the oldest supported one) offered a package that needs a
// newer capability refuses it with exit 15, names the release page in the
// upgrade advice, and leaves the whole data directory (selection, trust state, packages) byte-identical.
func TestKnowledgeUpdateOldClientNewCapabilityPackage(t *testing.T) {
	old := buildidentity.Version
	buildidentity.Version = "v0.1.0-beta.0"
	t.Cleanup(func() { buildidentity.Version = old })

	build := func(t *testing.T, env defaultUpdateEnv, mutate func(index []byte) []byte) []byte {
		t.Helper()
		index, projects, err := buildEmbeddedForOldClient("5")
		if err != nil {
			t.Fatal(err)
		}
		indexRaw := mutate(index.Bytes)
		if bytes.Equal(indexRaw, index.Bytes) {
			t.Fatal("mutation changed nothing")
		}
		targets := map[string][]byte{index.Path: indexRaw}
		for _, project := range projects {
			targets[project.Path] = project.Bytes
		}
		raw, err := env.repo.Package(knowledgefixture.ProjectsPackage{Version: 2, Targets: targets})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := []struct {
		name   string
		mutate func([]byte) []byte
		reason string
	}{
		{"min client version", func(b []byte) []byte {
			return append(append([]byte(nil), b[:len(b)-1]...), []byte(`,"minClientVersion":"`+cncfcheck.ProviderFactsMinClientVersion+`"}`)...)
		}, "KNOWLEDGE_TOO_NEW_FOR_THIS_CLIENT"},
		{"engine capability", func(b []byte) []byte {
			b = regexp.MustCompile(`"engineCapabilityDigest":"sha256:[0-9a-f]{64}"`).ReplaceAll(b, []byte(`"engineCapabilityDigest":"sha256:`+strings.Repeat("ab", 32)+`"`))
			return regexp.MustCompile(`"baseCapabilityDigest":"sha256:[0-9a-f]{64}"`).ReplaceAll(b, []byte(`"baseCapabilityDigest":"sha256:`+strings.Repeat("cd", 32)+`"`))
		}, "KNOWLEDGE_CAPABILITY_MISMATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDefaultUpdateEnv(t)
			if code, _, stderr := runDefaultUpdate(t, perProjectPackage(t, env.repo, 1, "4")); code != ExitOK {
				t.Fatal(code, stderr)
			}
			before := snapshotTree(t, env.data)
			code, out, _ := runDefaultUpdate(t, build(t, env, tc.mutate))
			if code != ExitKnowledgeTooNew || out.ReasonCode != tc.reason || out.Rejection == nil || out.Rejection.TrustStateAdvanced || out.ImportReceipt != nil {
				t.Fatalf("code=%d out=%+v", code, out)
			}
			if !strings.Contains(out.NextAction, "https://github.com/prufyx/prufyx/releases/latest") {
				t.Fatalf("next action has no release URL: %q", out.NextAction)
			}
			after := snapshotTree(t, env.data)
			if len(before) != len(after) {
				t.Fatalf("data directory changed: %d entries before, %d after", len(before), len(after))
			}
			for k, v := range before {
				if after[k] != v {
					t.Fatalf("data directory changed at %s", k)
				}
			}
		})
	}
}
