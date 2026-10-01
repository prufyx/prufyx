// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecRunnerSuccessAndRedaction(t *testing.T) {
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "success" {
		_, _ = os.Stdout.WriteString(`{"ok":true}`)
		_, _ = os.Stderr.WriteString("private diagnostic that must not escape")
		os.Exit(0)
	}
	runner := ExecRunner{Binary: os.Args[0]}
	result, err := runner.Run(context.Background(), []string{"-test.run=TestExecRunnerSuccessAndRedaction"}, []string{"PRUFYX_COLLECTOR_HELPER=success"}, 10*time.Second)
	if err != nil || result.Exit != 0 || string(result.Stdout) != `{"ok":true}` {
		t.Fatalf("unexpected result: %#v, %v", result, err)
	}
	if strings.Contains(string(result.Stdout), "private") {
		t.Fatal("stderr escaped into retained output")
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	runner := ExecRunner{Binary: os.Args[0]}
	started := time.Now()
	result, err := runner.Run(context.Background(), []string{"-test.run=TestExecRunnerTimeout"}, []string{"PRUFYX_COLLECTOR_HELPER=sleep"}, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || result.Exit != 124 || result.Class != "transport_timeout_unreachable" {
		t.Fatalf("timeout result = %#v, %v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout cleanup took %s", elapsed)
	}
}

func TestExecRunnerKillsChildAfterLeaderTermExit(t *testing.T) {
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "descendant" {
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("PRUFYX_CHILD_PID_FILE"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			os.Exit(91)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "leader" {
		child := exec.Command(os.Args[0], "-test.run=^TestExecRunnerKillsChildAfterLeaderTermExit$")
		child.Env = []string{}
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "PRUFYX_COLLECTOR_HELPER=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "PRUFYX_COLLECTOR_HELPER=descendant")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(90)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	pidFile := t.TempDir() + "/child.pid"
	runner := ExecRunner{Binary: os.Args[0]}
	_, err := runner.Run(context.Background(), []string{"-test.run=^TestExecRunnerKillsChildAfterLeaderTermExit$"}, []string{"PRUFYX_COLLECTOR_HELPER=leader", "PRUFYX_CHILD_PID_FILE=" + pidFile}, 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runner error=%v", err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if descendantTerminated(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("descendant %d remains live after timeout cleanup", pid)
}

func TestExecRunnerKillsDescendantAfterLeaderExitAndWaitDelay(t *testing.T) {
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "wait-delay-descendant" {
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("PRUFYX_CHILD_PID_FILE"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			os.Exit(91)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if os.Getenv("PRUFYX_COLLECTOR_HELPER") == "wait-delay-leader" {
		child := exec.Command(os.Args[0], "-test.run=^TestExecRunnerKillsDescendantAfterLeaderExitAndWaitDelay$")
		child.Env = []string{}
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "PRUFYX_COLLECTOR_HELPER=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "PRUFYX_COLLECTOR_HELPER=wait-delay-descendant")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(90)
		}
		os.Exit(0)
	}
	pidFile := t.TempDir() + "/child.pid"
	runner := ExecRunner{Binary: os.Args[0]}
	result, err := runner.Run(context.Background(), []string{"-test.run=^TestExecRunnerKillsDescendantAfterLeaderExitAndWaitDelay$"}, []string{"PRUFYX_COLLECTOR_HELPER=wait-delay-leader", "PRUFYX_CHILD_PID_FILE=" + pidFile}, 10*time.Second)
	if !errors.Is(err, exec.ErrWaitDelay) || result.Exit != 125 {
		t.Fatalf("wait-delay result=%#v error=%v", result, err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if descendantTerminated(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("descendant %d remains live after wait-delay cleanup", pid)
}

// descendantTerminated treats an unreaped Linux zombie as terminated. kill(pid,
// 0) reports zombies as existing even though SIGKILL already stopped execution;
// accepting only ESRCH makes the process-group cleanup contract flaky under a
// container init that reaps asynchronously.
func descendantTerminated(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}
	close := strings.LastIndexByte(string(raw), ')')
	if close < 0 {
		return false
	}
	fields := strings.Fields(string(raw[close+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

func TestCappedBuffer(t *testing.T) {
	t.Parallel()
	b := &cappedBuffer{limit: 3}
	if n, err := b.Write([]byte("private")); err != nil || n != 7 || b.String() != "pri" || !b.overflow {
		t.Fatalf("bounded write = %d, %v, %q, overflow=%v", n, err, b.String(), b.overflow)
	}
}
