// SPDX-License-Identifier: AGPL-3.0-only

// Package offlineboundary runs explicit Linux-only network-isolation probes for
// an already-built Community binary. It does not build the binary, create
// inputs, or infer test scenarios. Callers supply every command argv and must
// provide a Go positive-control command that opens a local socket.
package offlineboundary

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var (
	ErrUnsupportedPlatform = errors.New("offline boundary requires Linux")
	ErrInvalidConfig       = errors.New("offline boundary configuration is invalid")
)

type Scenario struct {
	Name          string
	Argv          []string
	ExpectedExit  int
	ExpectNetwork bool
}

type Config struct {
	Binary          string
	PositiveControl []string
	WorkDir         string
	Scenarios       []Scenario
	UID             int
	GID             int
}

type Result struct {
	Name            string
	ExitCode        int
	NetworkObserved bool
	Stdout          string
	Stderr          string
}

// Requirements are deliberately explicit: a skipped or unavailable harness is
// not evidence of offline behavior on macOS, Windows, a host without sudo
// namespace creation, or a host without strace and setpriv.
func Requirements() []string {
	return []string{"linux", "sudo -n", "unshare", "setpriv", "strace", "an explicit non-root uid/gid", "a Go socket positive-control binary"}
}

func Run(ctx context.Context, config Config) ([]Result, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupportedPlatform
	}
	if err := validate(config); err != nil {
		return nil, err
	}
	if err := requireTools(); err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(config.Scenarios)+1)
	positive, err := trace(ctx, config, "positive-control", config.PositiveControl)
	if err != nil {
		return nil, err
	}
	if positive.ExitCode != 0 || !positive.NetworkObserved {
		return nil, fmt.Errorf("network positive-control did not produce a network syscall")
	}
	results = append(results, positive)
	for _, scenario := range config.Scenarios {
		if scenario.Name == "" || len(scenario.Argv) == 0 {
			return nil, ErrInvalidConfig
		}
		result, err := trace(ctx, config, scenario.Name, append([]string{config.Binary}, scenario.Argv...))
		if err != nil {
			return nil, err
		}
		if result.ExitCode != scenario.ExpectedExit {
			return nil, fmt.Errorf("scenario %q exit=%d want=%d", scenario.Name, result.ExitCode, scenario.ExpectedExit)
		}
		if result.NetworkObserved != scenario.ExpectNetwork {
			return nil, fmt.Errorf("scenario %q network observation=%t want=%t", scenario.Name, result.NetworkObserved, scenario.ExpectNetwork)
		}
		results = append(results, result)
	}
	return results, nil
}

func validate(config Config) error {
	if !filepath.IsAbs(config.Binary) || !filepath.IsAbs(config.WorkDir) || config.UID <= 0 || config.GID <= 0 || len(config.PositiveControl) == 0 || len(config.Scenarios) == 0 {
		return ErrInvalidConfig
	}
	info, err := os.Lstat(config.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidConfig
	}

	info, err = os.Lstat(config.WorkDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return ErrInvalidConfig
	}
	for _, scenario := range config.Scenarios {
		if len(scenario.Argv) == 0 || safeName(scenario.Name) != nil {
			return ErrInvalidConfig
		}
	}
	return nil
}

func requireTools() error {
	for _, tool := range []string{"sudo", "unshare", "setpriv", "strace"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("offline boundary prerequisite %s: %w", tool, err)
		}
	}
	return nil
}

func trace(ctx context.Context, config Config, name string, argv []string) (Result, error) {
	if err := safeName(name); err != nil {
		return Result{}, err
	}
	traceDir, err := newTraceDir(config.WorkDir, name)
	if err != nil {
		return Result{}, fmt.Errorf("prepare isolated %s trace: %w", name, err)
	}
	defer os.RemoveAll(traceDir)
	prefix := filepath.Join(traceDir, "trace")
	args := []string{"-n", "unshare", "--net", "--", "setpriv", "--reuid", strconv.Itoa(config.UID), "--regid", strconv.Itoa(config.GID), "--clear-groups", "--", "strace", "-ff", "-o", prefix, "-e", "trace=%network", "--"}
	args = append(args, argv...)
	command := exec.CommandContext(ctx, "sudo", args...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	result := Result{Name: name, Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return Result{}, fmt.Errorf("run isolated %s: %w", name, err)
		}
		result.ExitCode = exitError.ExitCode()
	}
	if strings.Contains(result.Stderr, "sudo:") {
		return Result{}, fmt.Errorf("run isolated %s: sudo diagnostic", name)
	}
	files, err := traceFiles(traceDir)
	if err != nil || len(files) == 0 {
		return Result{}, fmt.Errorf("read isolated %s trace", name)
	}
	observed := false
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read isolated trace: %w", err)
		}
		if strings.Contains(string(raw), "socket(") || strings.Contains(string(raw), "connect(") || strings.Contains(string(raw), "sendto(") || strings.Contains(string(raw), "sendmsg(") {
			observed = true
		}
	}
	result.NetworkObserved = observed
	return result, nil
}

func safeName(value string) error {
	if value == "" || len(value) > 80 {
		return ErrInvalidConfig
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return ErrInvalidConfig
		}
	}
	return nil
}

// newTraceDir creates a fresh private directory per trace so stale, planted or
// prefix-colliding files in WorkDir can never be read as trace evidence.
func newTraceDir(workDir, name string) (string, error) {
	dir, err := os.MkdirTemp(workDir, "strace-"+name+"-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// traceFiles lists the regular trace files in dir and refuses anything else
// (symlinks, directories, devices).
func traceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("unsafe trace entry %q", entry.Name())
		}
		files = append(files, path)
	}
	return files, nil
}
