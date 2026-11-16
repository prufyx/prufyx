// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// secretEnv sets token-like variables, and a PATH that starts with a directory
// holding a fake git, in the PARENT process. None of it may reach the child.
func secretEnv(t *testing.T) (marker string) {
	t.Helper()
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "APP_TOKEN", "GIT_ASKPASS_TOKEN", "HTTPS_PROXY", "GIT_CONFIG_COUNT", "GIT_SSH_COMMAND"} {
		t.Setenv(k, "secret-"+k)
	}
	dir := t.TempDir()
	marker = filepath.Join(dir, "fake-git-ran")
	script := "#!/bin/sh\necho ran > '" + marker + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// The prepared command carries exactly the fixed environment plus HOME, never
// the parent's: a nil Env would inherit it, and an App token set in the parent
// would reach the git child.
func TestPrepareCmdNeverInheritsTheParentEnvironment(t *testing.T) {
	secretEnv(t)
	spec := ExecSpec{Argv: bindingArgv("owner/name", []string{"v1.0.0"}), Env: bindingEnv()}
	cmd := exec.CommandContext(context.Background(), "/usr/bin/git", spec.Argv[1:]...)
	prepareCmd(cmd, runnerEnv(spec, "/empty/home"), "/empty/home")
	if cmd.Env == nil {
		t.Fatal("nil Env inherits the whole parent environment")
	}
	want := append(append([]string(nil), bindingEnv()...), "HOME=/empty/home")
	if strings.Join(cmd.Env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("env %q, want exactly %q", cmd.Env, want)
	}
	for _, e := range cmd.Env {
		low := strings.ToLower(e)
		if strings.Contains(low, "token") || strings.Contains(low, "secret") || strings.HasPrefix(e, "GH_") || strings.HasPrefix(e, "GITHUB_") || strings.HasPrefix(e, "ACTIONS_") {
			t.Fatalf("a token-like variable in the child environment: %q", e)
		}
	}
	if cmd.Dir != "/empty/home" || cmd.Path != "/usr/bin/git" {
		t.Fatalf("dir %q path %q", cmd.Dir, cmd.Path)
	}
	if got := bindingEnv(); !strings.Contains(strings.Join(got, "\n"), "PATH="+bindingPath) {
		t.Fatalf("the child PATH is the fixed one: %q", got)
	}
}

// The argv is a function of the validated repo and the tags only: it names the
// constant host, carries no credential and no variable-controlled part.
func TestBindingArgvIsFixedAndTokenFree(t *testing.T) {
	secretEnv(t)
	a := bindingArgv("owner/name", []string{"v1.0.0", "v1.1.0"})
	want := []string{"git", "-c", "protocol.version=2", "-c", "http.followRedirects=false", "-c", "credential.helper=",
		"-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=20", "-c", "core.askPass=",
		"ls-remote", "--tags", "--", "https://github.com/owner/name.git",
		"refs/tags/v1.0.0", "refs/tags/v1.0.0^{}", "refs/tags/v1.1.0", "refs/tags/v1.1.0^{}"}
	if strings.Join(a, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv %q", a)
	}
	for _, x := range a {
		if strings.Contains(strings.ToLower(x), "token") || strings.Contains(x, "secret") || strings.Contains(x, "@") {
			t.Fatalf("argv element %q", x)
		}
	}
}

// The real runner, run for real on a harmless local command (no network), sees
// none of the parent's token variables, is not redirected by a PATH-injected
// helper, and runs in an empty temporary directory that is also HOME.
func TestExecRunnerChildSeesOnlyTheFixedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix runner")
	}
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		if _, err2 := os.Stat("/usr/local/bin/git"); err2 != nil {
			if _, err3 := os.Stat("/bin/git"); err3 != nil {
				t.Skip("no git binary")
			}
		}
	}
	marker := secretEnv(t)
	t.Setenv("HOME", "/parent-home-must-not-leak")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// An alias that dumps the environment and the directory the child runs
	// in; git itself runs it (no network, no repository).
	spec := ExecSpec{Argv: []string{"git", "-c", "alias.dump=!env; echo PWD_IS=$(pwd -P)", "dump"}, Env: bindingEnv()}
	res := execRunner{}.Run(ctx, spec)
	if res.Err != nil || res.Exit != 0 || res.TimedOut {
		t.Fatalf("%+v %s", res, res.Stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a PATH-injected git ran: the runner must use an absolute git path")
	}
	out := string(res.Stdout)
	for _, bad := range []string{"secret-", "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "APP_TOKEN", "parent-home", "HTTPS_PROXY", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT"} {
		if strings.Contains(out, bad) {
			t.Fatalf("the child saw %q:\n%s", bad, out)
		}
	}
	allowed := map[string]bool{"HOME": true, "PWD": true, "OLDPWD": true, "SHLVL": true, "_": true, "PWD_IS": true,
		"GIT_EXEC_PATH": true, "GIT_CONFIG_PARAMETERS": true, "GIT_PREFIX": true, "TEXTDOMAINDIR": true}
	for _, e := range bindingEnv() {
		allowed[strings.SplitN(e, "=", 2)[0]] = true
	}
	var seen []string
	home := ""
	pwd := ""
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			t.Fatalf("unexpected line %q", ln)
		}
		seen = append(seen, k)
		if !allowed[k] {
			t.Fatalf("variable %q is not in the fixed environment:\n%s", k, out)
		}
		switch k {
		case "HOME":
			home = v
		case "PWD_IS":
			pwd = v
		case "PATH":
			// git itself puts its exec dir in front of the PATH it was given.
			if v != bindingPath && !strings.HasSuffix(v, ":"+bindingPath) {
				t.Fatalf("PATH %q", v)
			}
		}
	}
	sort.Strings(seen)
	if home == "" || !strings.Contains(home, "prufyx-binding-") || home == os.Getenv("HOME") {
		t.Fatalf("HOME %q is not the empty temporary directory", home)
	}
	if pwd != home && pwd != strings.TrimPrefix(home, "/private") {
		t.Fatalf("cwd %q is not HOME %q", pwd, home)
	}
	if _, err := os.Stat(home); err == nil {
		t.Fatal("the empty temporary directory must be removed after the run")
	}
}
