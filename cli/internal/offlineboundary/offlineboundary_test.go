// SPDX-License-Identifier: AGPL-3.0-only

package offlineboundary

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateRejectsUnsafeBoundaryInputs(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(work, "prufyx")
	if err := os.WriteFile(binary, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	base := Config{Binary: binary, WorkDir: work, PositiveControl: []string{"/bin/true"}, Scenarios: []Scenario{{Name: "help", Argv: []string{"--help"}}}, UID: 1000, GID: 1000}
	if err := validate(base); err != nil {
		t.Fatalf("validate base: %v", err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Binary = "relative" },
		func(c *Config) { c.UID = 0 },
		func(c *Config) { c.WorkDir = filepath.Join(work, "missing") },
		func(c *Config) { c.Scenarios[0].Name = "path/escape" },
	} {
		copy := base
		copy.Scenarios = append([]Scenario(nil), base.Scenarios...)
		mutate(&copy)
		if err := validate(copy); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}

func TestRunRequiresLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux execution is covered only with explicit isolated prerequisites")
	}
	if _, err := Run(t.Context(), Config{}); err != ErrUnsupportedPlatform {
		t.Fatalf("err=%v", err)
	}
}

type integrationScenarioFile struct {
	Scenarios []Scenario `json:"scenarios"`
}

// TestOfflineBoundaryLinuxIntegration is deliberately opt-in. A release runner
// must supply a private 0600 scenario file and the separately-built Go socket
// positive-control. Missing prerequisites skip; they never become an offline
// PASS on a non-Linux development host.
func TestOfflineBoundaryLinuxIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("PRUFYX_OFFLINE_BOUNDARY_ENABLE") != "1" {
		t.Skip("requires explicit Linux boundary execution")
	}
	binary, positive, scenarioPath := os.Getenv("PRUFYX_OFFLINE_BOUNDARY_BINARY"), os.Getenv("PRUFYX_OFFLINE_BOUNDARY_POSITIVE_CONTROL"), os.Getenv("PRUFYX_OFFLINE_BOUNDARY_SCENARIO_FILE")
	if binary == "" || positive == "" || scenarioPath == "" {
		t.Fatal("explicit Linux boundary inputs are required")
	}
	info, err := os.Lstat(scenarioPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("scenario file must be a private regular file")
	}
	raw, err := os.ReadFile(scenarioPath)
	if err != nil {
		t.Fatal(err)
	}
	var scenarios integrationScenarioFile
	if err := json.Unmarshal(raw, &scenarios); err != nil || len(scenarios.Scenarios) == 0 {
		t.Fatal("invalid scenario file")
	}
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	results, err := Run(t.Context(), Config{Binary: binary, PositiveControl: []string{positive, "positive-control"}, WorkDir: work, Scenarios: scenarios.Scenarios, UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatal("offline boundary execution failed")
	}
	if len(results) != len(scenarios.Scenarios)+1 || !results[0].NetworkObserved {
		t.Fatal("incomplete boundary results")
	}
}
