// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func TestKubernetesDeclarationActionNamesTheFlag(t *testing.T) {
	cases := []struct {
		name         string
		reason       cncfprepare.Reason
		apply        bool
		distribution string
		want         []string
		absent       []string
	}{
		{"scope", cncfprepare.ReasonKubernetesScopeIncomplete, true, "official_upstream", []string{"--resource-scope-complete", "complete apply set"}, nil},
		{"apply and distribution", cncfprepare.ReasonKubernetesTargetGuard, false, "", []string{"--target-api-apply-required", "--distribution official_upstream", "then run again"}, nil},
		{"apply only", cncfprepare.ReasonKubernetesTargetGuard, false, "official_upstream", []string{"--target-api-apply-required"}, []string{"--distribution"}},
		{"distribution only", cncfprepare.ReasonKubernetesTargetGuard, true, "", []string{"--distribution official_upstream"}, []string{"--target-api-apply-required"}},
		{"custom build", cncfprepare.ReasonKubernetesTargetGuard, true, "custom_build", []string{"only the official_upstream distribution is evaluated"}, []string{"run again"}},
		{"pagination", cncfprepare.ReasonKubernetesPagination, true, "official_upstream", []string{"paginated", "every page"}, nil},
		{"templated", cncfprepare.ReasonKubernetesTemplated, true, "official_upstream", []string{"helm template"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kubernetesDeclarationAction(tc.reason, tc.apply, tc.distribution)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("action %q lacks %q", got, want)
				}
			}
			for _, banned := range append(tc.absent, "inspect local", "pkg:", "gvk_present") {
				if strings.Contains(got, banned) {
					t.Errorf("action %q contains %q", got, banned)
				}
			}
		})
	}
	if got := kubernetesDeclarationAction(cncfprepare.ReasonKubernetesRemovedGVKAbsent, true, "official_upstream"); got != "" {
		t.Fatalf("an unrelated reason gets an action: %q", got)
	}
}

func TestWithKubernetesDeclarationActionsOnlyTouchesUnavailableClaims(t *testing.T) {
	claims := []constraintengine.Claim{
		{Status: "UNKNOWN", ReasonCode: reasonFactUnavailable, NextAction: "engine text"},
		{Status: "BLOCKED", ReasonCode: "REVIEWED_SOURCE_CONSTRAINT", NextAction: "migrate"},
		{Status: "UNKNOWN", ReasonCode: "RULE_TRANSITION_NOT_REVIEWED", NextAction: "no rule"},
	}
	out := withKubernetesDeclarationActions(claims, "declared action")
	if out[0].NextAction != "declared action" || out[1].NextAction != "migrate" || out[2].NextAction != "no rule" {
		t.Fatalf("out=%+v", out)
	}
	if claims[0].NextAction != "engine text" {
		t.Fatal("the report's own claims were modified")
	}
	if same := withKubernetesDeclarationActions(claims, ""); &same[0] != &claims[0] {
		t.Fatal("no action must leave the claims alone")
	}
}

// The quickstart promises that dropping a declaration flag makes the CLI say
// why in the next action field: it must name the flag, not a package URL or a
// fact identifier.
func TestKubernetesNativeUnknownNamesTheMissingFlag(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "applyset.json", []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"nightly-report","namespace":"default"}}]}`), 0o600)
	base := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", "1.24.0", "--to", "1.25.0", "--now", "2026-09-24T00:00:00Z", "--format", "human"}
	for _, test := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"no scope declaration", []string{"--distribution", "official_upstream", "--target-api-apply-required"}, "add --resource-scope-complete"},
		{"no apply declaration", []string{"--distribution", "official_upstream", "--resource-scope-complete"}, "add --target-api-apply-required"},
		{"no distribution", []string{"--target-api-apply-required", "--resource-scope-complete"}, "add --distribution official_upstream"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), base...), test.flags...)...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "next action: ") || !strings.Contains(stdout, test.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, banned := range []string{"inspect local", "pkg:github", "gvk_present", "mark missing"} {
				if strings.Contains(stdout, banned) {
					t.Fatalf("output contains %q: %s", banned, stdout)
				}
			}
		})
	}
	complete := append(append([]string(nil), base...), "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete")
	if code, stdout, _ := runCNCFCLI(t, complete...); code != ExitBlocked || strings.Contains(stdout, "add --") {
		t.Fatalf("declared run code=%d stdout=%q", code, stdout)
	}
}
