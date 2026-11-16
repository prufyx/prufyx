// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
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

// replaceAt returns a copy of the good vector with element i replaced.
func replaceAt(i int, v string) []string {
	a := append([]string(nil), runnerGoodArgv()...)
	a[i] = v
	return a
}

// The runner accepts the one exact vector of the verifier (keys, values, order,
// subcommand, URL shape and tag-pair patterns), and nothing near it.
func TestRunnerArgvExactShape(t *testing.T) {
	t.Parallel()
	good := runnerGoodArgv()
	// Indices of the good vector: 2,4,6,8,10,12 are the -c values, 13 ls-remote,
	// 14 --tags, 15 --, 16 the URL, 17 and 18 the tag pair.
	ins := func(i int, v ...string) []string {
		return append(append(append([]string(nil), good[:i]...), v...), good[i:]...)
	}
	del := func(i, n int) []string { return append(append([]string(nil), good[:i]...), good[i+n:]...) }
	swap := func(i, j int) []string {
		a := append([]string(nil), good...)
		a[i], a[j] = a[j], a[i]
		return a
	}
	bad := map[string][]string{
		"helper command":      replaceAt(6, "credential.helper=!x"),
		"helper plain":        replaceAt(6, "credential.helper=store"),
		"askpass program":     replaceAt(12, "core.askPass=x"),
		"askpass path":        replaceAt(12, "core.askPass=/bin/true"),
		"protocol value":      replaceAt(2, "protocol.version=0"),
		"redirects value":     replaceAt(4, "http.followRedirects=true"),
		"speed value":         replaceAt(8, "http.lowSpeedLimit=1"),
		"time value":          replaceAt(10, "http.lowSpeedTime=0"),
		"key case":            replaceAt(12, "core.askpass="),
		"key without value":   replaceAt(12, "core.askPass"),
		"extra config":        ins(13, "-c", "core.sshCommand=x"),
		"extra config first":  ins(1, "-c", "core.sshCommand=x"),
		"duplicate config":    ins(13, "-c", "core.askPass="),
		"missing config":      del(11, 2),
		"missing first":       del(1, 2),
		"reordered configs":   swap(2, 4),
		"reordered pairs":     swap(8, 10),
		"flag and value swap": swap(1, 2),
		"other subcommand":    replaceAt(13, "fetch"),
		"remote subcommand":   replaceAt(13, "remote"),
		"no tags option":      del(14, 1),
		"other option":        replaceAt(14, "--heads"),
		"extra option":        ins(15, "--exit-code"),
		"no separator":        del(15, 1),
		"url not dot git":     replaceAt(16, "https://github.com/o/r"),
		"url extra segment":   replaceAt(16, "https://github.com/o/r/x.git"),
		"url userinfo":        replaceAt(16, "https://u:p@github.com/o/r.git"),
		"url port":            replaceAt(16, "https://github.com:444/o/r.git"),
		"url query":           replaceAt(16, "https://github.com/o/r.git?x=1"),
		"url dotdot":          replaceAt(16, "https://github.com/o/..r.git"),
		"url parent":          replaceAt(16, "https://github.com/../r.git"),
		"url name dot":        replaceAt(16, "https://github.com/o/r..git"),
		"url double dot git":  replaceAt(16, "https://github.com/o/r.git.git"),
		"url uppercase host":  replaceAt(16, "https://GitHub.com/o/r.git"),
		"url local path":      replaceAt(16, "/tmp/upstream"),
		"url space":           replaceAt(16, "https://github.com/o/r .git"),
		"url newline":         replaceAt(16, "https://github.com/o/r\n.git"),
		"no tag pair":         good[:17],
		"one pattern only":    good[:18],
		"peeled only":         del(17, 1),
		"pair mismatch":       replaceAt(18, "refs/tags/v2^{}"),
		"unpeeled twice":      replaceAt(18, "refs/tags/v1"),
		"pattern glob":        append(append([]string(nil), good[:17]...), "refs/tags/*", "refs/tags/*^{}"),
		"pattern branch":      append(append([]string(nil), good[:17]...), "refs/heads/v1", "refs/heads/v1^{}"),
		"pattern dash":        append(append([]string(nil), good[:17]...), "refs/tags/-x", "refs/tags/-x^{}"),
		"extra argument":      append(append([]string(nil), good...), "x"),
		"extra pair half":     append(append([]string(nil), good...), "refs/tags/v2"),
		"empty tag":           append(append([]string(nil), good[:17]...), "refs/tags/", "refs/tags/^{}"),
		"git path":            replaceAt(0, "/usr/bin/git"),
		"empty":               nil,
	}
	for name, argv := range bad {
		if runnerArgvOK(argv) {
			t.Errorf("%s: accepted %v", name, argv)
		}
	}
	// Positives of the same shape: more tags, other owner and name spellings.
	two := append(append([]string(nil), good...), "refs/tags/v1.1.0-rc.1+b2", "refs/tags/v1.1.0-rc.1+b2^{}")
	two = append(append([]string(nil), two[:16]...), append([]string{"https://github.com/Some-Org/repo_name.v2.git"}, two[17:]...)...)
	if !runnerArgvOK(two) || !runnerArgvOK(good) {
		t.Fatal("a vector of the exact shape is refused")
	}
	// And the real entry refuses every one of them without running git.
	for name, argv := range bad {
		if res := (admissionRunner{}).Run(context.Background(), targetdraft.ExecSpec{Argv: argv}); res.Err == nil || len(res.Stdout) != 0 {
			t.Errorf("%s: Run did not refuse: %+v", name, res)
		}
	}
}

// The non-unix variant refuses to run a command (fail closed); checked on the
// source here because this build is unix, and by compiling and running the
// variant's own test on a platform it applies to.
func TestRunnerOtherVariantRefuses(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("onboarding_admission_runner_other.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "onboarding_admission_runner_other.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "runnerKillGroup" {
			continue
		}
		found = true
		if fd.Type.Results == nil || len(fd.Type.Results.List) != 1 || len(fd.Body.List) != 1 {
			t.Fatalf("runnerKillGroup shape")
		}
		ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Fatal("runnerKillGroup does not return an error at once")
		}
		call, ok := ret.Results[0].(*ast.CallExpr)
		sel, ok2 := call.Fun.(*ast.SelectorExpr)
		if !ok || !ok2 || sel.Sel.Name != "New" {
			t.Fatal("runnerKillGroup does not return errors.New(...)")
		}
	}
	if !found {
		t.Fatal("no runnerKillGroup in the non-unix variant")
	}
	if !strings.Contains(string(raw), "//go:build !darwin && !linux") {
		t.Fatal("variant build tag changed")
	}
	// The unix variant is the one that returns nil, and it sets a group.
	unix, err := os.ReadFile("onboarding_admission_runner_unix.go")
	if err != nil || !strings.Contains(string(unix), "Setpgid: true") || !strings.Contains(string(unix), "return nil") {
		t.Fatalf("unix variant: %v", err)
	}
}
