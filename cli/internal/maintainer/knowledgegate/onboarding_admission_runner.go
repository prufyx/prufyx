// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/targetdraft"
)

// The upstream runner of the onboarding admission seam. The verifier builds
// the exact argument vector and environment (one ls-remote of one fixed host,
// a cleared environment without any credential variable); this runner refuses
// any other command shape and adds nothing from the gate's own environment:
// the gate process holds credentials, the child never sees one.

const (
	runnerMaxOutput = 64 << 10
	runnerMaxStderr = 16 << 10
	runnerWaitDelay = 2 * time.Second
	runnerHost      = "https://github.com/"
)

var runnerGitPaths = []string{"/usr/bin/git", "/usr/local/bin/git", "/bin/git"}

// runnerPrefix is the one fixed head of the verifier's argument vector: git,
// the six `-c key=value` pairs with their exact values and order, and the
// ls-remote subcommand with its options. It mirrors the verifier's builder
// (targetdraft bindingArgv); a change there needs the same change here, and
// until then the runner refuses (fail closed).
var runnerPrefix = []string{"git",
	"-c", "protocol.version=2",
	"-c", "http.followRedirects=false",
	"-c", "credential.helper=",
	"-c", "http.lowSpeedLimit=1000",
	"-c", "http.lowSpeedTime=20",
	"-c", "core.askPass=",
	"ls-remote", "--tags", "--"}

var (
	runnerURLRE = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*\.git$`)
	runnerTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
)

type admissionRunner struct{}

func newAdmissionRunner() targetdraft.LsRemoteRunner { return admissionRunner{} }

// runnerArgvOK accepts exactly one shape: runnerPrefix, one repository URL of
// the fixed host, then for every tag the pair "refs/tags/T" and
// "refs/tags/T^{}" (at least one pair). Nothing else is accepted: no extra,
// missing, reordered or re-valued -c setting, no other subcommand or option,
// no other URL form, no other pattern.
func runnerArgvOK(argv []string) bool {
	n := len(runnerPrefix)
	if len(argv) < n+3 || (len(argv)-n-1)%2 != 0 {
		return false
	}
	for i, want := range runnerPrefix {
		if argv[i] != want {
			return false
		}
	}
	url := argv[n]
	if !runnerURLRE.MatchString(url) || strings.Contains(url, "..") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(url, runnerHost), ".git")
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, ".git") {
		return false
	}
	pats := argv[n+1:]
	for i := 0; i < len(pats); i += 2 {
		tag, ok := strings.CutPrefix(pats[i], "refs/tags/")
		if !ok || !runnerTagRE.MatchString(tag) || pats[i+1] != pats[i]+"^{}" {
			return false
		}
	}
	return true
}

// runnerChildEnv is the spec environment plus HOME, nothing else; the gate's
// own environment is never inherited.
func runnerChildEnv(spec targetdraft.ExecSpec, home string) []string {
	env := make([]string, 0, len(spec.Env)+1)
	for _, e := range spec.Env {
		if !strings.HasPrefix(e, "HOME=") {
			env = append(env, e)
		}
	}
	return append(env, "HOME="+home)
}

func (admissionRunner) Run(ctx context.Context, spec targetdraft.ExecSpec) targetdraft.ExecResult {
	if !runnerArgvOK(spec.Argv) {
		return targetdraft.ExecResult{Err: errors.New("refused argv")}
	}
	gitBin := ""
	for _, c := range runnerGitPaths {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			gitBin = c
			break
		}
	}
	if gitBin == "" {
		return targetdraft.ExecResult{Err: errors.New("git binary not found")}
	}
	home, err := os.MkdirTemp("", "prufyx-admission-")
	if err != nil {
		return targetdraft.ExecResult{Err: err}
	}
	defer os.RemoveAll(home)
	return runnerExec(ctx, gitBin, spec.Argv[1:], runnerChildEnv(spec, home), home)
}

type runnerBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *runnerBuffer) Write(p []byte) (int, error) {
	if room := c.limit + 1 - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// runnerExec runs one prepared command with an exact environment in an empty
// directory, capped output and a bounded wait after a kill. Output over the cap
// stays over the cap (limit+1 bytes), so it is never read as a short answer.
func runnerExec(ctx context.Context, bin string, args, env []string, dir string) targetdraft.ExecResult {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env, cmd.Dir = env, dir
	so, se := &runnerBuffer{limit: runnerMaxOutput}, &runnerBuffer{limit: runnerMaxStderr}
	cmd.Stdout, cmd.Stderr = so, se
	cmd.WaitDelay = runnerWaitDelay
	// No group kill, no command: the child never starts.
	if err := runnerKillGroup(cmd); err != nil {
		return targetdraft.ExecResult{Err: err}
	}
	runErr := cmd.Run()
	res := targetdraft.ExecResult{Stdout: so.buf.Bytes(), Stderr: se.buf.Bytes()}
	if ctx.Err() != nil {
		res.TimedOut = true
		return res
	}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &ee):
		res.Exit = ee.ExitCode()
		if res.Exit == 0 {
			res.Exit = -1
		}
	default:
		res.Err = runErr
	}
	return res
}
