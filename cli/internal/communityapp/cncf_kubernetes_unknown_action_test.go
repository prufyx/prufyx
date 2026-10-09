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
		scope        bool
		apply        bool
		distribution string
		want         []string
		absent       []string
	}{
		{"scope", cncfprepare.ReasonKubernetesScopeIncomplete, false, true, "official_upstream", []string{"--resource-scope-complete", "complete apply set"}, []string{"--distribution", "--target-api-apply-required"}},
		{"nothing declared names every declaration", cncfprepare.ReasonKubernetesScopeIncomplete, false, false, "", []string{"--resource-scope-complete", "--target-api-apply-required", "--distribution official_upstream", "then run again"}, nil},
		{"target guard with nothing declared names scope too", cncfprepare.ReasonKubernetesTargetGuard, false, false, "", []string{"--resource-scope-complete", "--target-api-apply-required", "--distribution official_upstream"}, nil},
		{"apply and distribution", cncfprepare.ReasonKubernetesTargetGuard, true, false, "", []string{"--target-api-apply-required", "--distribution official_upstream", "then run again"}, nil},
		{"apply only", cncfprepare.ReasonKubernetesTargetGuard, true, false, "official_upstream", []string{"--target-api-apply-required"}, []string{"--distribution"}},
		{"distribution only", cncfprepare.ReasonKubernetesTargetGuard, true, true, "", []string{"--distribution official_upstream"}, []string{"--target-api-apply-required"}},
		{"custom build", cncfprepare.ReasonKubernetesTargetGuard, true, true, "custom_build", []string{"only the official_upstream distribution is evaluated"}, []string{"run again"}},
		{"pagination", cncfprepare.ReasonKubernetesPagination, true, true, "official_upstream", []string{"paginated", "every page"}, nil},
		{"templated", cncfprepare.ReasonKubernetesTemplated, true, true, "official_upstream", []string{"helm template"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kubernetesDeclarationAction(tc.reason, tc.scope, tc.apply, tc.distribution)
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
	if got := kubernetesDeclarationAction(cncfprepare.ReasonKubernetesRemovedGVKAbsent, true, true, "official_upstream"); got != "" {
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

func TestWriteCitedSourcesOnlyForStaleOrWithdrawn(t *testing.T) {
	claim := constraintengine.Claim{ReasonCode: "RULE_EVIDENCE_STALE", Sources: []constraintengine.SourceEvidence{{URL: "https://example.test/doc", StartLine: 3, EndLine: 5, Revision: "r1", ContentDigest: "sha256:x"}}}
	var out strings.Builder
	writeCitedSources(&out, claim)
	if !strings.Contains(out.String(), "pinned source: https://example.test/doc lines 3-5") {
		t.Fatalf("stale claim prints no source: %q", out.String())
	}
	out.Reset()
	claim.ReasonCode = "RULE_FACT_UNAVAILABLE"
	writeCitedSources(&out, claim)
	if out.Len() != 0 {
		t.Fatalf("other reason prints a source: %q", out.String())
	}
}
