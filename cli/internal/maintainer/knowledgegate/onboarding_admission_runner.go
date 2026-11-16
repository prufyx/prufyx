// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
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

// runnerConfigKeys are the only `-c` settings the verifier's argument vector
// may carry.
var runnerConfigKeys = map[string]bool{
	"protocol.version": true, "http.followRedirects": true, "credential.helper": true,
	"http.lowSpeedLimit": true, "http.lowSpeedTime": true, "core.askPass": true,
}

type admissionRunner struct{}

func newAdmissionRunner() targetdraft.LsRemoteRunner { return admissionRunner{} }

// runnerArgvOK accepts exactly the verifier's shape: git, "-c key=value"
// pairs of the fixed keys, then "ls-remote --tags -- <https://github.com/...>"
// and exact refs/tags patterns.
func runnerArgvOK(argv []string) bool {
	if len(argv) < 6 || argv[0] != "git" {
		return false
	}
	i := 1
	for i+1 < len(argv) && argv[i] == "-c" {
		key, _, ok := strings.Cut(argv[i+1], "=")
		if !ok || !runnerConfigKeys[key] {
			return false
		}
		i += 2
	}
	rest := argv[i:]
	if len(rest) < 4 || rest[0] != "ls-remote" || rest[1] != "--tags" || rest[2] != "--" || !strings.HasPrefix(rest[3], runnerHost) {
		return false
	}
	for _, p := range rest[4:] {
		if !strings.HasPrefix(p, "refs/tags/") || strings.HasPrefix(p, "-") {
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
	runnerKillGroup(cmd)
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
