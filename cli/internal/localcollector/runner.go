// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

const maxKubectlOutput = 16 << 20

type CommandResult struct {
	Stdout []byte
	Class  string
	Exit   int
}

type Runner interface {
	Run(context.Context, []string, []string, time.Duration) (CommandResult, error)
}

type ExecRunner struct{ Binary string }

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func (r ExecRunner) Run(parent context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.Command(r.Binary, argv...)
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Env = env
	cmd.Stdin = nil
	configureProcessGroup(cmd)
	stdout := &cappedBuffer{limit: maxKubectlOutput}
	stderr := &cappedBuffer{limit: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return CommandResult{Class: "generic_api_read_failure", Exit: 125}, fmt.Errorf("start kubectl: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
		// A leader can exit successfully while a descendant keeps the inherited
		// output pipes open. Wait reports ErrWaitDelay after closing those pipes,
		// but does not terminate the descendant. Always clean the original group
		// before returning this bounded-runner failure.
		if errors.Is(err, exec.ErrWaitDelay) {
			killProcessGroup(cmd)
		}
	case <-ctx.Done():
		terminateProcessGroup(cmd)
		grace := time.NewTimer(250 * time.Millisecond)
		waited := false
		select {
		case <-done:
			waited = true
		case <-grace.C:
		}
		if !grace.Stop() {
			select {
			case <-grace.C:
			default:
			}
		}
		// Always kill the original process group after grace. The leader can
		// exit on TERM while a descendant retains output pipes or ignores TERM.
		killProcessGroup(cmd)
		if !waited {
			select {
			case <-done:
			case <-time.After(cmd.WaitDelay + 250*time.Millisecond):
			}
		}
		return CommandResult{Class: "transport_timeout_unreachable", Exit: 124}, ctx.Err()
	}
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		} else {
			exit = 125
		}
	}
	if stdout.overflow {
		return CommandResult{Class: "generic_api_read_failure", Exit: 125}, errors.New("kubectl output exceeded limit")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return CommandResult{Class: "generic_api_read_failure", Exit: 125}, fmt.Errorf("kubectl output pipes did not close: %w", err)
	}
	return CommandResult{Stdout: append([]byte(nil), stdout.Bytes()...), Class: ClassifyKubectlStderr(stderr.Bytes()), Exit: exit}, nil
}

var _ io.Writer = (*cappedBuffer)(nil)
