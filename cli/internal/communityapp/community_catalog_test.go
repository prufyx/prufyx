// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// With the shipped knowledge a community project answers exactly as before
// the community knowledge step on every route that names it.
func TestCommunityProjectWithoutDataAnswersAsBefore(t *testing.T) {
	t.Parallel()
	sourceRules := shippedSourceRuleProjects(t)
	path := writeCNCFFile(t, "manifests.yaml", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"), 0o600)
	for _, p := range customresources.CommunityProjects() {
		args := []string{"check", "cncf", "--project", p.Slug, "--custom-resources", path, "--from", "1.0.0", "--to", "1.1.0", "--now", "2026-10-04T00:00:00Z"}
		code, stdout, stderr := runCNCFCLI(t, args...)
		want := fmt.Sprintf("prufyx: %s (%s) is in the %s: check cncf does not check its custom-resource versions yet; see docs/custom-resources.md\n", p.Slug, p.Upstream.Name, customresources.CommunityLabel)
		has, err := cncfcheck.CommunityProjectHasData(p.Slug)
		if err != nil {
			t.Fatal(err)
		}
		if has {
			// Shipped data makes the project checkable: it no longer gets
			// the "not checked yet" answer.
			// The checkable path answers PASS or UNKNOWN for this input; a usage
			// error or a crash must fail.
			if (code != ExitOK && code != ExitUnknown) || !strings.Contains(stdout, p.Slug) || strings.Contains(stderr, "does not check its custom-resource versions yet") {
				t.Fatalf("%s has shipped data: code=%d stdout=%q stderr=%q", p.Slug, code, stdout, stderr)
			}
		} else if code != ExitUsage || stdout != "" || stderr != want {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q, want %q", p.Slug, code, stdout, stderr, want)
		}
		// Listing routes know the project as nothing: it is not a catalogue
		// project and has no rule.
		for _, command := range [][]string{{"catalog", "cncf", "--project", p.Slug}, {"catalog", "checks", "--project", p.Slug}} {
			code, stdout, stderr := runCNCFCLI(t, command...)
			if sourceRules[p.Slug] && command[1] == "checks" {
				// A project that is also a community source-rule project
				// lists its embedded rules there, and nowhere else.
				if code != ExitOK || stderr != "" || !strings.Contains(stdout, "embedded source-rule identities: ") || !strings.Contains(stdout, p.Slug+" "+p.Slug+".") {
					t.Fatalf("%v: source-rule project: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
				}
				continue
			}
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, fmt.Sprintf("unknown project %q", p.Slug)) {
				t.Fatalf("%v: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
			}
		}
	}
	// The CNCF catalogue lists no community project.
	code, stdout, _ := runCNCFCLI(t, "catalog", "cncf", "--format", "json")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	for _, p := range customresources.CommunityProjects() {
		if strings.Contains(stdout, `"slug":"`+p.Slug+`"`) {
			t.Fatalf("the CNCF catalogue lists %s", p.Slug)
		}
	}
}

// shippedSourceRuleProjects reads the project of every embedded community
// source-rule entry straight from the shipped pack, independent of the code
// under test.
func shippedSourceRuleProjects(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../projectcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Project string `json:"project"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	projects := map[string]bool{}
	for _, e := range pack.Entries {
		projects[e.Project] = true
	}
	return projects
}
