// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

var locationsMember = regexp.MustCompile(`,"locations":\[[^\]]*\]`)

// withoutLocations removes the additive locations members of a check report.
func withoutLocations(raw []byte) []byte { return locationsMember.ReplaceAll(raw, nil) }

const locationsApplySet = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: default\n---\napiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\n---\napiVersion: v1\nkind: List\nitems:\n- apiVersion: batch/v1beta1\n  kind: CronJob\n  metadata:\n    name: weekly\n"

func locationsArgs(path string, extra ...string) []string {
	args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", "1.24.0", "--to", "1.25.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", humanReportNow}
	return append(args, extra...)
}

func writeLocationsInput(t *testing.T) string {
	t.Helper()
	return writeCNCFFile(t, "applyset.yaml", []byte(locationsApplySet), 0o600)
}

type locatedReport struct {
	Check struct {
		Claims []struct {
			RuleID    string                `json:"ruleId"`
			Status    string                `json:"status"`
			Locations []scanreport.Location `json:"locations"`
		} `json:"claims"`
	} `json:"check"`
}

func TestCheckJSONCarriesObjectLocationsAdditively(t *testing.T) {
	t.Parallel()
	path := writeLocationsInput(t)
	code, stdout, _ := runCNCFCLI(t, locationsArgs(path, "--format", "json")...)
	if code != ExitBlocked {
		t.Fatalf("code=%d", code)
	}
	var report locatedReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, claim := range report.Check.Claims {
		if claim.Status != "BLOCKED" {
			if len(claim.Locations) != 0 {
				t.Fatalf("%s %s lists locations", claim.RuleID, claim.Status)
			}
			continue
		}
		blocked++
		want := []scanreport.Location{
			{File: path, Document: 1, Item: -1, Line: 7, Kind: "CronJob", Namespace: "default", Name: "nightly-report"},
			{File: path, Document: 2, Item: 0, Line: 16, Kind: "CronJob", Name: "weekly"},
		}
		if len(claim.Locations) != len(want) || claim.Locations[0] != want[0] || claim.Locations[1] != want[1] {
			t.Fatalf("locations %+v, want %+v", claim.Locations, want)
		}
	}
	if blocked != 1 {
		t.Fatalf("blocked claims %d", blocked)
	}
	// The same run without the locations members is valid JSON that holds
	// every other byte of the report.
	if stripped := withoutLocations([]byte(stdout)); !json.Valid(stripped) || strings.Contains(string(stripped), `"locations"`) {
		t.Fatalf("stripped report: %s", stripped)
	}
}

func TestCheckHumanListsObjectLocations(t *testing.T) {
	t.Parallel()
	path := writeLocationsInput(t)
	code, stdout, _ := runCNCFCLI(t, locationsArgs(path)...)
	if code != ExitBlocked {
		t.Fatalf("code=%d", code)
	}
	for _, line := range []string{path + ":7  CronJob default/nightly-report", path + ":16  CronJob weekly"} {
		if !strings.Contains(stdout, "    "+line+"\n") {
			t.Fatalf("missing %q in:\n%s", line, stdout)
		}
	}
}

func TestCheckRedactReplacesLocationsWithDigests(t *testing.T) {
	t.Parallel()
	path := writeLocationsInput(t)
	for _, format := range []string{"json", "human"} {
		code, stdout, _ := runCNCFCLI(t, locationsArgs(path, "--format", format, "--redact")...)
		if code != ExitBlocked {
			t.Fatalf("%s code=%d", format, code)
		}
		for _, secret := range []string{path, "nightly-report", "weekly", "default/"} {
			if strings.Contains(stdout, secret) {
				t.Fatalf("%s output leaks %q:\n%s", format, secret, stdout)
			}
		}
		if !strings.Contains(stdout, scanreport.RedactValue(path)[:19]) {
			t.Fatalf("%s output has no file digest:\n%s", format, stdout)
		}
	}
}

func TestCheckLocationsAreOutsideTheHashedInput(t *testing.T) {
	t.Parallel()
	path := writeLocationsInput(t)
	other := writeCNCFFile(t, "Chart.yaml", []byte(locationsApplySet), 0o600)
	var digests []string
	for _, p := range []string{path, other} {
		_, stdout, _ := runCNCFCLI(t, locationsArgs(p, "--format", "json")...)
		var report struct {
			Check struct {
				InputDigest string `json:"inputDigest"`
			} `json:"check"`
		}
		if err := json.Unmarshal([]byte(stdout), &report); err != nil || report.Check.InputDigest == "" {
			t.Fatalf("%v %s", err, stdout)
		}
		digests = append(digests, report.Check.InputDigest)
	}
	if digests[0] != digests[1] {
		t.Fatalf("input digest depends on the file name: %v", digests)
	}
}

func TestCheckRedactIsRefusedWhereNothingIsLocated(t *testing.T) {
	t.Parallel()
	path := writeLocationsInput(t)
	for name, args := range map[string][]string{
		"generic input":  {"check", "cncf", "--input", path, "--from", "1.24.0", "--to", "1.25.0", "--redact"},
		"other project":  {"check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.13.0", "--to", "0.14.0", "--redact"},
		"external store": append(locationsArgs(path, "--redact"), "--knowledge-db", filepath.Join(t.TempDir(), "store")),
	} {
		if code, _, _ := runCNCFCLI(t, args...); code != ExitUsage {
			t.Fatalf("%s: code=%d", name, code)
		}
	}
}

func TestCheckPassCarriesNoLocations(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "applyset.yaml", []byte("apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: ok\n"), 0o600)
	code, stdout, _ := runCNCFCLI(t, locationsArgs(path, "--format", "json")...)
	if code == ExitBlocked || strings.Contains(stdout, `"locations"`) {
		t.Fatalf("code=%d %s", code, stdout)
	}
	_ = os.Remove(path)
}

func TestSpliceClaimLocationsFailsClosed(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"check":{"claims":[{"ruleId":"a.b","status":"BLOCKED"}]}}`)
	got, err := spliceClaimLocations(raw, map[string][]scanreport.Location{"a.b": {{File: "f", Item: -1}}})
	if err != nil || !json.Valid(got) || string(withoutLocations(got)) != string(raw) {
		t.Fatalf("%v %s", err, got)
	}
	if _, err := spliceClaimLocations(raw, map[string][]scanreport.Location{"other": {{File: "f"}}}); err == nil {
		t.Fatal("locations for an unknown claim were accepted")
	}
	if _, err := spliceClaimLocations([]byte(`not json`), map[string][]scanreport.Location{"a": {{}}}); err == nil {
		t.Fatal("bad report accepted")
	}
}
