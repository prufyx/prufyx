// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

func metadataTrees(t *testing.T) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	onboardingRepoFiles(t, base)
	onboardingRepoFiles(t, head)
	path := DefaultLayout().Onboarding.TablePath
	raw, err := base.Read(path, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	rows, reserved, err := customresources.LoadTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, customresources.Project{Slug: obSlug, Catalog: customresources.CatalogCNCF, FactProject: obFact, Component: obComp, Groups: []customresources.Group{{Name: obGroup, Source: "https://github.com/" + obOwnerRepo + "/blob/" + obTo + "/" + obCRD}}})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Slug < rows[j].Slug })
	raw, err = customresources.CanonicalTable(rows, reserved)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(head.Root, path), raw)
	writeFile(t, filepath.Join(head.Root, targetPath(DefaultLayout().Onboarding, obSlug)), []byte(obTargetJSON))
	return base, head
}

func TestOnboardingMetadataPreservesPackAndIsIdempotent(t *testing.T) {
	base, head := metadataTrees(t)
	draft, err := prepareOnboardingMetadata(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := base.Read(cncfRulesPath, MaxFileBytes)
	want := bytes.Replace(old, []byte(`"`+draft.oldDigest+`"`), []byte(`"`+draft.newDigest+`"`), 1)
	if !bytes.Equal(want, draft.raw) || draft.path != cncfRulesPath || draft.oldDigest == draft.newDigest {
		t.Fatal("unexpected unsigned pack bytes")
	}
	writeFile(t, filepath.Join(head.Root, cncfRulesPath), draft.raw)
	again, err := prepareOnboardingMetadata(DefaultLayout(), base, head)
	if err != nil || !bytes.Equal(again.raw, draft.raw) {
		t.Fatalf("idempotence: %v", err)
	}
	// Metadata is not a proof-bearing draft or an approval.
	_, _, err = prepareOnboarding(DefaultLayout(), base, head, onboardingDraft{}, "", "cli/knowledge/onboarding/ob-20261003-1.json")
	if err == nil {
		t.Fatal("metadata alone prepared an onboarding approval")
	}
}

func TestOnboardingMetadataTokenSpans(t *testing.T) {
	old, next := CandidateDigest([]byte("old registry")), CandidateDigest([]byte("new registry"))
	for _, key := range []string{`registryDigest`, `registry\u0044igest`} {
		for _, value := range []string{old, strings.Replace(old, "s", `\u0073`, 1)} {
			prefix := "{\n \"nested\":{\"registryDigest\":\"" + old + "\"}, \"" + key + "\" \t : \n "
			suffix := ", \"unknown\": [\"" + old + "\"] }\n\t"
			raw := []byte(prefix + `"` + value + `"` + suffix)
			got, err := replaceRegistryToken(raw, old, next)
			if err != nil || string(got) != prefix+`"`+next+`"`+suffix {
				t.Fatalf("token span %s: %s %v", key, got, err)
			}
		}
	}
	for _, raw := range []string{
		`[]`, `{}`, `{"RegistryDigest":"` + old + `"}`,
		`{"registryDigest":null}`, `{"registryDigest":3}`,
		`{"registryDigest":"wrong"}`, `{"registryDigest":"` + old + `","registryDigest":"` + old + `"}`,
		`{"registryDigest":"` + old + `","RegistryDigest":"` + old + `"}`,
		`{"registryDigest":"` + old + `"} {}`, `{"registryDigest":"` + old + `"`,
	} {
		if _, err := replaceRegistryToken([]byte(raw), old, next); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestOnboardingMetadataRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, Tree, Tree)
	}{
		{"no addition", func(t *testing.T, b, h Tree) {
			rel := DefaultLayout().Onboarding.TablePath
			raw, err := b.Read(rel, MaxFileBytes)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(h.Root, rel), raw)
			if err := os.Remove(filepath.Join(h.Root, targetPath(DefaultLayout().Onboarding, obSlug))); err != nil {
				t.Fatal(err)
			}
		}},
		{"reserved groups edited", func(t *testing.T, b, h Tree) {
			rel := DefaultLayout().Onboarding.TablePath
			raw, _ := h.Read(rel, MaxFileBytes)
			rows, reserved, err := customresources.LoadTable(raw)
			if err != nil || len(reserved) == 0 {
				t.Fatalf("reserved fixture: %v", err)
			}
			raw, err = customresources.CanonicalTable(rows, reserved[1:])
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(h.Root, rel), raw)
		}},
		{"different compiled base registry", func(t *testing.T, b, h Tree) {
			rel := DefaultLayout().Onboarding.TablePath
			raw, _ := h.Read(rel, MaxFileBytes)
			// Even a self-consistent supplied BASE cannot replace the binary's registry.
			writeFile(t, filepath.Join(b.Root, rel), raw)
			digest, err := cncfcheck.TableRegistryDigest(raw)
			if err != nil {
				t.Fatal(err)
			}
			pack, _ := b.Read(cncfRulesPath, MaxFileBytes)
			var members map[string]json.RawMessage
			if err := json.Unmarshal(pack, &members); err != nil {
				t.Fatal(err)
			}
			members["registryDigest"], _ = json.Marshal(digest)
			pack, _ = json.Marshal(members)
			writeFile(t, filepath.Join(b.Root, cncfRulesPath), pack)
		}},
		{"mixed source", func(t *testing.T, b, h Tree) {
			writeFile(t, filepath.Join(h.Root, "cli/unrelated.go"), []byte("package unrelated\n"))
		}},
		{"pack whitespace", func(t *testing.T, b, h Tree) {
			raw, _ := h.Read(cncfRulesPath, MaxFileBytes)
			writeFile(t, filepath.Join(h.Root, cncfRulesPath), append(raw, ' '))
		}},
		{"pack revision", func(t *testing.T, b, h Tree) {
			raw, _ := h.Read(cncfRulesPath, MaxFileBytes)
			var m map[string]json.RawMessage
			_ = json.Unmarshal(raw, &m)
			m["revision"] = json.RawMessage(`"changed"`)
			raw, _ = json.Marshal(m)
			writeFile(t, filepath.Join(h.Root, cncfRulesPath), raw)
		}},
		{"stale base", func(t *testing.T, b, h Tree) {
			raw, _ := b.Read(cncfRulesPath, MaxFileBytes)
			var m map[string]json.RawMessage
			_ = json.Unmarshal(raw, &m)
			m["registryDigest"], _ = json.Marshal(CandidateDigest([]byte("stale")))
			raw, _ = json.Marshal(m)
			writeFile(t, filepath.Join(b.Root, cncfRulesPath), raw)
		}},
		{"executable target", func(t *testing.T, b, h Tree) {
			if err := os.Chmod(filepath.Join(h.Root, targetPath(DefaultLayout().Onboarding, obSlug)), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode only", func(t *testing.T, b, h Tree) {
			writeFile(t, filepath.Join(b.Root, "unrelated"), []byte("same"))
			writeFile(t, filepath.Join(h.Root, "unrelated"), []byte("same"))
			if err := os.Chmod(filepath.Join(h.Root, "unrelated"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink target", func(t *testing.T, b, h Tree) {
			p := filepath.Join(h.Root, targetPath(DefaultLayout().Onboarding, obSlug))
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"existing target overwritten", func(t *testing.T, b, h Tree) {
			p := targetPath(DefaultLayout().Onboarding, obSlug)
			writeFile(t, filepath.Join(b.Root, p), []byte(obTargetJSON))
		}},
		{"old row removed", func(t *testing.T, b, h Tree) {
			p := DefaultLayout().Onboarding.TablePath
			raw, _ := h.Read(p, MaxFileBytes)
			rows, reserved, err := customresources.LoadTable(raw)
			if err != nil {
				t.Fatal(err)
			}
			for i, row := range rows {
				if row.Slug != obSlug {
					rows = append(rows[:i], rows[i+1:]...)
					break
				}
			}
			raw, err = customresources.CanonicalTable(rows, reserved)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(h.Root, p), raw)
		}},
		{"target attests", func(t *testing.T, b, h Tree) {
			raw := strings.Replace(obTargetJSON, `"exclude": []`, `"attest": true, "exclude": []`, 1)
			writeFile(t, filepath.Join(h.Root, targetPath(DefaultLayout().Onboarding, obSlug)), []byte(raw))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, h := metadataTrees(t)
			tc.edit(t, b, h)
			if _, err := prepareOnboardingMetadata(DefaultLayout(), b, h); err == nil {
				t.Fatal("accepted invalid candidate")
			}
		})
	}
}

type metadataBrokenWriter struct{ err error }

func (w metadataBrokenWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

func metadataGitSupported(t *testing.T) {
	t.Helper()
	cmd := gitCommand(context.Background(), ExportOptions{offline: true}, "--version")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("trusted Git lacks --no-lazy-fetch: %s", out)
	}
}

func metadataRepo(t *testing.T) (string, string, string) {
	t.Helper()
	b, h := metadataTrees(t)
	writeFile(t, filepath.Join(b.Root, "unchanged-tool"), []byte("#!/bin/sh\nexit 1\n"))
	if err := os.Chmod(filepath.Join(b.Root, "unchanged-tool"), 0755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, b.Root, "init", "-q")
	gitIn(t, b.Root, "add", "-A")
	gitIn(t, b.Root, "commit", "-qm", "base")
	base := gitIn(t, b.Root, "rev-parse", "HEAD")
	for _, rel := range []string{DefaultLayout().Onboarding.TablePath, targetPath(DefaultLayout().Onboarding, obSlug)} {
		raw, err := h.Read(rel, MaxFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(b.Root, rel), raw)
	}
	gitIn(t, b.Root, "add", "-A")
	gitIn(t, b.Root, "commit", "-qm", "candidate")
	return b.Root, base, gitIn(t, b.Root, "rev-parse", "HEAD")
}

func TestOnboardingMetadataCommand(t *testing.T) {
	metadataGitSupported(t)
	repo, base, head := metadataRepo(t)
	args := []string{"prepare-onboarding-metadata", "--git-dir", filepath.Join(repo, ".git"), "--base", base, "--head", head}
	var out, diag bytes.Buffer
	if code := Main(args, nil, &out, &diag); code != 0 {
		t.Fatalf("%d: %s", code, &diag)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatal("stdout is not one pack JSON")
	}
	for _, w := range []io.Writer{metadataBrokenWriter{}, metadataBrokenWriter{errors.New("broken output")}} {
		if code := Main(args, nil, w, &diag); code == 0 {
			t.Fatal("accepted broken stdout")
		}
	}
	// An unrelated executable can exist unchanged; any mode-only delta refuses.
	gitIn(t, repo, "update-index", "--chmod=+x", DefaultLayout().Onboarding.TablePath)
	gitIn(t, repo, "commit", "-qm", "executable metadata")
	badHead := gitIn(t, repo, "rev-parse", "HEAD")
	badArgs := append([]string(nil), args...)
	badArgs[len(badArgs)-1] = badHead
	out.Reset()
	if code := Main(badArgs, nil, &out, &diag); code == 0 || out.Len() != 0 {
		t.Fatal("executable metadata produced stdout")
	}
	// Resetting the caller's index is unnecessary: the next check uses immutable HEAD.
	gitIn(t, repo, "config", "protocol.ext.allow", "always")
	gitIn(t, repo, "config", "remote.origin.promisor", "true")
	gitIn(t, repo, "config", "remote.origin.url", "ext::sh -c touch${IFS}"+filepath.Join(repo, "transport-ran"))
	blob := gitIn(t, repo, "rev-parse", head+":"+DefaultLayout().Onboarding.TablePath)
	if err := os.Remove(filepath.Join(repo, ".git/objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Main(args, nil, &out, &diag); code == 0 || out.Len() != 0 {
		t.Fatalf("missing promised object: code=%d stdout=%d", code, out.Len())
	}
	if _, err := os.Stat(filepath.Join(repo, "transport-ran")); !os.IsNotExist(err) {
		t.Fatal("transport helper was invoked")
	}
}

func TestOnboardingMetadataOfflineGitBoundary(t *testing.T) {
	cmd := gitCommand(context.Background(), ExportOptions{Git: "untrusted", offline: true}, "cat-file", "-t", strings.Repeat("1", 40))
	if cmd.Path != "/usr/bin/git" || !strings.Contains(strings.Join(cmd.Args, " "), "--no-lazy-fetch") {
		t.Fatal("Git executable/options not pinned")
	}
	for _, want := range []string{"GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=", "GIT_TERMINAL_PROMPT=0"} {
		found := false
		for _, v := range cmd.Env {
			found = found || v == want
		}
		if !found {
			t.Fatalf("missing %s", want)
		}
	}
	if _, err := cmd.Output(); err == nil {
		t.Fatal("missing repository/object unexpectedly accepted")
	}
	// Git without the no-lazy-fetch capability must fail before repository access.
}
