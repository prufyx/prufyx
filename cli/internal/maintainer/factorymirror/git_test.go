// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:] // later entries win, as for exec
		}
	}
	return m
}

func configEntries(env []string) map[string]string {
	m := envMap(env)
	out := map[string]string{}
	for i := 0; ; i++ {
		k, ok := m["GIT_CONFIG_KEY_"+string(rune('0'+i))]
		if !ok {
			break
		}
		out[k] = m["GIT_CONFIG_VALUE_"+string(rune('0'+i))]
	}
	return out
}

func TestExecGitEnvironmentIsLockedDown(t *testing.T) {
	state := t.TempDir()
	inside := filepath.Join(state, "mirror", "github.com", "a", "b.git")
	for _, g := range []ExecGit{{StateDir: state}, {Offline: true, StateDir: state}, {AllowProtocols: "file"}} {
		env := g.env(inside)
		cfg := configEntries(env)
		if cfg["core.hooksPath"] != os.DevNull || cfg["core.fsmonitor"] != "false" {
			t.Fatalf("hooks/fsmonitor not disabled: %v", cfg)
		}
		if got := envMap(env)["GIT_CONFIG_COUNT"]; got != string(rune('0'+len(cfg))) {
			t.Fatalf("GIT_CONFIG_COUNT=%s with %d entries", got, len(cfg))
		}
		for _, v := range cfg {
			if v == "*" {
				t.Fatal("safe.directory must never be a wildcard")
			}
		}
	}
	// Only the repository inside the state directory is trusted.
	if cfg := configEntries(ExecGit{StateDir: state}.env(inside)); cfg["safe.directory"] != inside {
		t.Fatalf("state repository not trusted: %v", cfg)
	}
	for _, dir := range []string{"", state, filepath.Dir(state), filepath.Join(filepath.Dir(state), "other"), filepath.Join(state, "..", "x")} {
		if cfg := configEntries(ExecGit{StateDir: state}.env(dir)); cfg["safe.directory"] != "" {
			t.Fatalf("directory %q outside the state tree is trusted: %v", dir, cfg)
		}
	}
	if cfg := configEntries(ExecGit{}.env(inside)); cfg["safe.directory"] != "" {
		t.Fatalf("no state directory, nothing to trust: %v", cfg)
	}
}

func TestExecGitOfflineEnvironment(t *testing.T) {
	env := envMap(ExecGit{Offline: true, AllowProtocols: "file"}.env(""))
	if env["GIT_NO_LAZY_FETCH"] != "1" || env["GIT_ALLOW_PROTOCOL"] != "none" {
		t.Fatalf("offline environment incomplete: %v", env)
	}
	online := envMap(ExecGit{AllowProtocols: "file"}.env(""))
	if _, ok := online["GIT_NO_LAZY_FETCH"]; ok || online["GIT_ALLOW_PROTOCOL"] != "file" {
		t.Fatalf("online environment wrong: %v", online)
	}
	if envMap(ExecGit{}.env(""))["GIT_ALLOW_PROTOCOL"] != "https" {
		t.Fatal("default protocol must be https")
	}
}

// A hook planted in a mirror (or named by its config) must never run.
func TestPlantedHooksDoNotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks")
	}
	e := newEnv(t, k1)
	c1 := e.remote[k1].commit("one", map[string]string{"f": "1"})
	e.run()
	repoDir := filepath.Join(e.state, filepath.FromSlash(mustRepo(t, k1).RelPath()))
	marker := filepath.Join(t.TempDir(), "hook-ran")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	otherHooks := t.TempDir()
	for _, p := range []string{filepath.Join(repoDir, "hooks"), otherHooks} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"reference-transaction", "post-checkout", "post-fetch", "pre-auto-gc"} {
			if err := os.WriteFile(filepath.Join(p, name), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(repoDir, "config"), append(mustRead(t, filepath.Join(repoDir, "config")), []byte("[core]\n\thooksPath = "+otherHooks+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	// Positive control: plain git does run the planted hook.
	runGit(t, repoDir, "update-ref", "refs/prufyx/control", c1)
	if _, err := os.Stat(marker); err != nil {
		t.Skip("this git does not run the control hook; cannot prove anything")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	for _, g := range []ExecGit{{StateDir: e.state}, {Offline: true, StateDir: e.state}} {
		if _, err := g.Run(context.Background(), repoDir, "update-ref", "refs/prufyx/test", c1); err != nil {
			t.Fatal(err)
		}
	}
	// And through a whole mirror run (fetch, update-ref via preserve).
	e.remote[k1].commit("two", map[string]string{"f": "2"})
	e.remote[k1].tag("v1", false)
	e.opts.Git = ExecGit{AllowProtocols: "file", StateDir: e.state}
	e.run()
	e.remote[k1].commit("three", map[string]string{"f": "3"})
	e.remote[k1].tag("v1", false)
	e.run()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a planted hook ran")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGitErrorUnwraps(t *testing.T) {
	_, err := ExecGit{}.Run(context.Background(), t.TempDir(), "rev-parse", "HEAD")
	var ge *GitError
	if !errors.As(err, &ge) {
		t.Fatalf("%v", err)
	}
}
