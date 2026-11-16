// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/targetdraft"
)

// The argument vector of the verifier's binding (same shape as its own).
func runnerGoodArgv() []string {
	return []string{"git",
		"-c", "protocol.version=2", "-c", "http.followRedirects=false", "-c", "credential.helper=",
		"-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=20", "-c", "core.askPass=",
		"ls-remote", "--tags", "--", "https://github.com/o/r.git", "refs/tags/v1", "refs/tags/v1^{}"}
}

func TestRunnerArgvShape(t *testing.T) {
	t.Parallel()
	if !runnerArgvOK(runnerGoodArgv()) {
		t.Fatal("the verifier's own argument vector is refused")
	}
	cp := func() []string { return append([]string(nil), runnerGoodArgv()...) }
	bad := map[string][]string{
		"empty":         nil,
		"not git":       append([]string{"sh"}, runnerGoodArgv()[1:]...),
		"fetch":         append(append(cp()[:13:13], "fetch"), cp()[14:]...),
		"other host":    append(cp()[:16:16], append([]string{"https://example.invalid/o/r.git"}, cp()[17:]...)...),
		"http":          append(cp()[:16:16], append([]string{"http://github.com/o/r.git"}, cp()[17:]...)...),
		"file url":      append(cp()[:16:16], append([]string{"file:///etc"}, cp()[17:]...)...),
		"no separator":  append(cp()[:15:15], cp()[16:]...),
		"head pattern":  append(cp(), "HEAD"),
		"option inject": append(cp(), "--upload-pack=x"),
		"other config":  append([]string{"git", "-c", "core.sshCommand=x"}, cp()[1:]...),
		"alias":         append([]string{"git", "-c", "alias.x=!id", "x"}, cp()[1:]...),
		"config no key": append([]string{"git", "-c", "="}, cp()[1:]...),
		"only config":   {"git", "-c", "protocol.version=2", "ls-remote", "--tags"},
	}
	for name, argv := range bad {
		if runnerArgvOK(argv) {
			t.Fatalf("%s: accepted %v", name, argv)
		}
	}
	res := admissionRunner{}.Run(context.Background(), targetdraft.ExecSpec{Argv: []string{"git", "config", "--list"}})
	if res.Err == nil || res.Exit != 0 || len(res.Stdout) != 0 {
		t.Fatalf("a refused vector ran: %+v", res)
	}
}

// The child's environment is the spec's plus HOME, never the gate's own, even
// when the gate process holds credentials.
func TestRunnerChildEnvIsFixed(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "WEB_APPROVAL_KEYS_DIGEST", "SSH_AUTH_SOCK", "GIT_ASKPASS", "HTTPS_PROXY"} {
		t.Setenv(k, "secret-"+k)
	}
	spec := targetdraft.ExecSpec{Argv: runnerGoodArgv(), Env: []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ASKPASS=/bin/false", "HOME=/attacker"}}
	env := runnerChildEnv(spec, "/tmp/h")
	want := append(append([]string(nil), spec.Env[:8]...), "HOME=/tmp/h")
	if strings.Join(env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("env %v want %v", env, want)
	}
	for _, e := range env {
		if strings.Contains(strings.ToLower(e), "token") || strings.Contains(e, "secret-") || strings.HasPrefix(e, "SSH_") || strings.Contains(e, "PROXY") {
			t.Fatalf("credential-like variable in the child env: %s", e)
		}
	}
	// A real child, in an empty directory, sees exactly that environment.
	git := ""
	for _, c := range runnerGitPaths {
		if _, err := os.Stat(c); err == nil {
			git = c
			break
		}
	}
	if git == "" {
		t.Skip("git is not installed")
	}
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Skip("no env command")
	}
	home := t.TempDir()
	res := runnerExec(context.Background(), git, []string{"-c", "alias.dump=!/usr/bin/env", "dump"}, runnerChildEnv(spec, home), home)
	if res.Err != nil || res.Exit != 0 || res.TimedOut {
		t.Fatalf("child: %+v", res)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("unexpected line %q", l)
		}
		got[k] = v
	}
	// Variables the shell or git itself adds, nothing else (as in the
	// verifier's own environment test).
	extra := map[string]bool{"PWD": true, "OLDPWD": true, "SHLVL": true, "_": true, "GIT_EXEC_PATH": true, "GIT_CONFIG_PARAMETERS": true, "GIT_PREFIX": true, "TEXTDOMAINDIR": true}
	exp := map[string]string{}
	for _, e := range want {
		k, v, _ := strings.Cut(e, "=")
		exp[k] = v
	}
	exp["HOME"] = home
	for k, v := range got {
		ev, ok := exp[k]
		switch {
		case !ok && extra[k]:
		case !ok:
			t.Fatalf("variable %q is not in the fixed environment", k)
		case k == "PATH":
			// git puts its exec dir in front of the PATH it was given.
			if v != ev && !strings.HasSuffix(v, "git-core:"+ev) {
				t.Fatalf("PATH %q", v)
			}
		case v != ev:
			t.Fatalf("%s=%q want %q", k, v, ev)
		}
	}
	for k := range exp {
		if _, ok := got[k]; !ok {
			t.Fatalf("fixed variable %s missing in the child", k)
		}
	}
}

func TestRunnerExecBounds(t *testing.T) {
	t.Parallel()
	sh := "/bin/sh"
	if _, err := os.Stat(sh); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	// Output over the cap stays over the cap.
	res := runnerExec(context.Background(), sh, []string{"-c", "head -c 100000 /dev/zero"}, []string{"PATH=/usr/bin:/bin"}, dir)
	if res.Err != nil || len(res.Stdout) != runnerMaxOutput+1 {
		t.Fatalf("stdout %d err %v", len(res.Stdout), res.Err)
	}
	// A timeout is reported as such and kills the child.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	res = runnerExec(ctx, sh, []string{"-c", "sleep 30"}, []string{"PATH=/usr/bin:/bin"}, dir)
	if !res.TimedOut || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout %+v after %v", res, time.Since(start))
	}
	// A non-zero exit is an exit, not an error.
	res = runnerExec(context.Background(), sh, []string{"-c", "exit 3"}, []string{"PATH=/usr/bin:/bin"}, dir)
	if res.Err != nil || res.Exit != 3 {
		t.Fatalf("exit %+v", res)
	}
	// A missing binary is an error.
	if res := runnerExec(context.Background(), "/nonexistent/git", nil, nil, dir); res.Err == nil {
		t.Fatal("missing binary ran")
	}
	_ = exec.ErrNotFound
}
