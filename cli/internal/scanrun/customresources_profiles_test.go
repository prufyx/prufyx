// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

func TestLineReviewInstallProfileTargetBinding(t *testing.T) {
	const component = "pkg:github/argoproj/argo-cd"
	const beta = "argoproj.io/v1beta1/Application"
	const alpha = "argoproj.io/v1alpha2/Application"
	decode := func(raw string) intake.Workspace {
		t.Helper()
		w, err := intake.Decode("input.yaml", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	crd := func(name string) intake.Workspace {
		return decode("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + name + "\nspec:\n  group: argoproj.io\n")
	}
	canonical := crd("applications.argoproj.io")
	second := crd("appprojects.argoproj.io")
	ha := crd("applications-ha.argoproj.io")
	artifact := func(path, commit string, w intake.Workspace) lineattest.InstallArtifact {
		digest := w.Documents[0].Source.Digest
		return lineattest.InstallArtifact{Path: path, Digest: digest, Source: constraintengine.SourceEvidence{ID: "crd-source", URL: "https://github.com/argoproj/argo-cd/blob/" + commit + "/" + path, Revision: commit, ContentDigest: digest, StartLine: 1, EndLine: 2}}
	}
	att := crdLineAttestation(constraintengine.BasisReviewed)
	att.Component = component
	att.InstallProfiles = []lineattest.InstallProfile{}
	releases := append(append([]lineattest.Release{}, att.Releases.From...), att.Releases.To...)
	for _, rel := range releases {
		att.InstallProfiles = append(att.InstallProfiles,
			lineattest.InstallProfile{Version: rel.Version, Commit: rel.Commit, ID: "canonical", Artifacts: []lineattest.InstallArtifact{artifact("crds/application.yaml", rel.Commit, canonical), artifact("crds/project.yaml", rel.Commit, second)}, Served: []string{beta}},
			lineattest.InstallProfile{Version: rel.Version, Commit: rel.Commit, ID: "ha", Artifacts: []lineattest.InstallArtifact{artifact("crds/ha.yaml", rel.Commit, ha)}, Served: []string{alpha}},
		)
	}
	if err := att.Validate(); err != nil {
		t.Fatal(err)
	}
	both := intake.Workspace{Documents: append(append([]intake.Document{}, canonical.Documents...), second.Documents...)}
	mixed := intake.Workspace{Documents: append(append([]intake.Document{}, canonical.Documents...), ha.Documents...)}
	private := crd("applications.argoproj.io\n  labels:\n    note: private-value-marker")
	privateTarget := intake.Workspace{Documents: append(append([]intake.Document{}, private.Documents...), second.Documents...)}
	cases := []struct {
		name      string
		workspace intake.Workspace
		target    string
		alter     func(*lineattest.LineAttestation)
		pass      bool
		detail    string
		member    string
	}{
		{name: "canonical target", workspace: both, target: "0.51.0", pass: true},
		{name: "ha target does not serve beta", workspace: ha, target: "0.51.0"},
		{name: "ha target serves alpha", workspace: ha, target: "0.51.0", member: alpha, pass: true},
		{name: "missing target artifacts", workspace: intake.Workspace{}, target: "0.51.0"},
		{name: "partial target", workspace: canonical, target: "0.51.0"},
		{name: "mixed profiles", workspace: mixed, target: "0.51.0"},
		{name: "unlisted target", workspace: privateTarget, target: "0.51.0"},
		{name: "unlisted release", workspace: both, target: "0.51.1", detail: "did not read release"},
		{name: "stale evidence", workspace: both, target: "0.51.0", detail: "is not current", alter: func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-01T00:00:00Z" }},
		{name: "foreign artifact source", workspace: both, target: "0.51.0", alter: func(a *lineattest.LineAttestation) {
			a.InstallProfiles[len(a.InstallProfiles)-2].Artifacts[0].Source.URL = "https://github.com/example/other/blob/" + a.InstallProfiles[len(a.InstallProfiles)-2].Commit + "/crds/application.yaml"
		}},
		{name: "missing profile census", workspace: both, target: "0.51.0", alter: func(a *lineattest.LineAttestation) { a.InstallProfiles = []lineattest.InstallProfile{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := att
			a.InstallProfiles = lineattest.CopyInstallProfiles(att.InstallProfiles)
			if tc.alter != nil {
				tc.alter(&a)
			}
			k := newAttestedCRD(t, &a)
			report := &scanreport.Report{}
			r := &customResourceRun{knowledge: k, now: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), report: report, workspace: tc.workspace, slug: "argo-cd", component: component, policy: cncfcheck.DefaultTrustPolicy(), byID: map[string]cncfcheck.ScanRule{}}
			member := tc.member
			if member == "" {
				member = beta
			}
			prepared := cncfprepare.CustomResourceScan{Prepared: cncfprepare.Prepared{Reason: cncfprepare.ReasonCustomResourcesComplete}, Members: map[string][]intake.Source{member: {{Display: "consumer.yaml"}}}}
			var hop scanreport.Hop
			f := r.lineReview(upgradepath.Hop{}, scanreport.HopRef{From: "0.50.1", To: tc.target}, "0.50.1", tc.target, prepared, map[string]bool{}, map[string]bool{}, map[string]bool{}, &hop)
			if tc.pass {
				if f == nil || f.Status != scanreport.FamilyPass {
					t.Fatalf("expected scoped pass: family=%+v gaps=%+v", f, report.Gaps)
				}
				return
			}
			if f != nil || len(report.Gaps) == 0 {
				t.Fatalf("expected unknown: family=%+v gaps=%+v", f, report.Gaps)
			}
			detail := tc.detail
			if detail == "" {
				detail = "target CRDs or consumed versions"
			}
			if !hasComponentGap(*report, "argo-cd", scanreport.ReasonLineNotAttested, detail) {
				t.Fatalf("missing profile diagnostic: %+v", report.Gaps)
			}
			for _, g := range report.Gaps {
				for _, forbidden := range []string{"private-value-marker", private.Documents[0].Source.Digest} {
					if strings.Contains(g.Detail, forbidden) || strings.Contains(g.Action, forbidden) {
						t.Fatalf("private data in diagnostic: %+v", g)
					}
				}
			}
		})
	}
}
