// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func recordGitFixture(t *testing.T) (GitSource, Input, *Result) {
	t.Helper()
	dir := t.TempDir()
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	for _, tag := range collapseTags {
		for p, b := range collapseBase().files {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, append(bytes.Clone(b), []byte("# "+tag+"\n")...), 0644); err != nil {
				t.Fatal(err)
			}
		}
		git("add", "-A")
		git("commit", "-q", "-m", tag)
		git("tag", tag)
	}
	source := GitSource{Dir: dir}
	in := collapseInputFor(source, true)
	want, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	return source, in, want
}

func TestRecordDraftReplaysGitAndIsDeterministic(t *testing.T) {
	source, in, want := recordGitFixture(t)
	in.Source = nil // RecordDraft must use its GitSource, not the caller's Source.
	first, err := RecordDraft(in, source, want.A, want.TableRow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RecordDraft(in, source, want.A, want.TableRow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("recording was not deterministic")
	}
	recipe, err := ParseRecipe(first.Recipe)
	if err != nil {
		t.Fatal(err)
	}
	if recipe.Half != "A" || len(recipe.Commits) != len(collapseTags) || recipe.FactBundleDigest != sha256Of(first.FactsBundle) {
		t.Fatal("incorrect recipe binding")
	}
	target, err := decodeDoc(first.Target)
	if err != nil || target.Target.Attest || len(target.Target.Exclude) != 0 {
		t.Fatalf("not half A: %v", err)
	}
	bundle, err := ParseBundle(first.FactsBundle)
	if err != nil {
		t.Fatal(err)
	}
	in.Source = FactSource{B: bundle}
	replay, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	report, err := marshal(replay.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Target, replay.A) || !bytes.Equal(first.TableRow, replay.TableRow) || !bytes.Equal(first.Report, report) || !bytes.Equal(first.Changelog, replay.Changelog) {
		t.Fatal("bundle does not reproduce artifacts")
	}
	corrupt := bytes.Clone(first.FactsBundle)
	corrupt[len(corrupt)/2] ^= 1
	if _, err := ParseBundle(corrupt); err == nil {
		t.Fatal("accepted tampered bundle")
	}
}

func TestRecordDraftRefusesUnsupportedOrMismatch(t *testing.T) {
	source, in, want := recordGitFixture(t)
	for _, tc := range []struct {
		name        string
		edit        func(*Input)
		target, row []byte
	}{
		{"duplicates", func(i *Input) { i.DeriveDuplicates = true }, want.A, want.TableRow},
		{"multi-prefix", func(i *Input) { i.MultiPrefix = true }, want.A, want.TableRow},
		{"infer-paths", func(i *Input) { i.InferInstallPaths = true }, want.A, want.TableRow},
		{"check-copies", func(i *Input) { i.CheckInstallPathCopies = true }, want.A, want.TableRow},
		{"skip-fragments", func(i *Input) { i.SkipPatchFragments = true }, want.A, want.TableRow},
		{"exclusion", func(i *Input) { i.Rules = &Rules{Schema: RulesSchema, Exclusions: []ExclusionRule{{Path: "vendor/"}}} }, want.A, want.TableRow},
		{"target mismatch", func(*Input) {}, []byte("other"), want.TableRow},
		{"row mismatch", func(*Input) {}, want.A, []byte("other")},
		{"missing target", func(*Input) {}, nil, want.TableRow},
		{"missing row", func(*Input) {}, want.A, nil},
		{"typed stop", func(i *Input) { i.Slug = "INVALID" }, want.A, want.TableRow},
		{"missing tag", func(i *Input) { i.Tags = []string{"v9.0.0", "v9.1.0"} }, want.A, want.TableRow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := in
			tc.edit(&input)
			got, err := RecordDraft(input, source, tc.target, tc.row)
			if err == nil || got != nil {
				t.Fatal("accepted unsupported or mismatched draft")
			}
			if tc.name == "typed stop" {
				var stop *StopError
				if !errors.As(err, &stop) {
					t.Fatalf("expected typed stop, got %v", err)
				}
			}
		})
	}
}
