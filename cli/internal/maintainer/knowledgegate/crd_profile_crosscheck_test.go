// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestCrossCheckReviewedCRDInstallProfiles(t *testing.T) {
	root := t.TempDir()
	repo, err := extract.ParseRepo("github.com/argoproj/argo-cd")
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{"v1.0.0": strings.Repeat("1", 40), "v1.0.1": strings.Repeat("2", 40), "v1.1.0": strings.Repeat("3", 40)}
	write := func(p string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	tagJSON, err := json.Marshal(tags)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, repo.Key, "tags.json"), tagJSON)
	crd := func(versions string) string {
		return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: applications.argoproj.io\nspec:\n  group: argoproj.io\n  names:\n    kind: Application\n    plural: applications\n  scope: Namespaced\n  versions:\n" + versions
	}
	version := func(v string, storage bool) string {
		s := "false"
		if storage {
			s = "true"
		}
		return "  - name: " + v + "\n    served: true\n    storage: " + s + "\n    schema:\n      openAPIV3Schema:\n        type: object\n"
	}
	for _, commit := range tags {
		dir := filepath.Join(root, repo.Key, "commits", commit)
		write(filepath.Join(dir, "deploy/canonical/application.yaml"), []byte(crd(version("v1alpha2", false)+version("v1beta1", true))))
		write(filepath.Join(dir, "deploy/ha/application.yaml"), []byte(crd(version("v1alpha2", true))))
	}
	match := regexp.MustCompile(`^[^.][^/]*\.ya?ml$`)
	guard := regexp.MustCompile(`(?i)crd`)
	tg := crdversions.Target{Project: "argo-cd", Name: "Argo CD", Repo: "github.com/argoproj/argo-cd", Component: argoComponent, FactProject: "argo_cd", TagPrefixes: []string{"v"}, MinFrom: [2]int{1, 0}, Attest: true, ProfileAttestation: true, DeclaredChannel: "canonical", Paths: []crdversions.PathSpec{{Path: "deploy/canonical", Dir: true, Match: match, Guard: guard}}, Channels: []crdversions.Channel{{Name: "ha", Paths: []crdversions.PathSpec{{Path: "deploy/ha", Dir: true, Match: match, Guard: guard}}}}}
	src := extract.FixtureReader{Root: root}
	ex := crdversions.New(tg)
	out, err := extract.Run(context.Background(), ex, crdversions.ReleaseTags(ex, src), src, extract.Options{Repo: repo, DerivedAt: gateNow.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Attestations) != 1 || len(out.Attestations[0].InstallProfiles) != 6 || len(out.Attestations[0].RuleIDs) != 0 {
		t.Fatalf("expected quiet multi-profile derivation: %+v", out.Attestations)
	}
	derived := out.Attestations[0]
	reviewed := derived
	reviewed.Evidence.Basis = "reviewed"
	reviewed.Evidence.Extractor = nil
	reviewed.Evidence.DerivedAt = ""
	reviewed.Evidence.ReviewedAt = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
	reviewed.Evidence.ValidUntil = gateNow.Add(50 * 24 * time.Hour).Format(time.RFC3339)
	clone := func() lineattest.LineAttestation {
		a := reviewed
		a.InstallProfiles = lineattest.CopyInstallProfiles(reviewed.InstallProfiles)
		r := *reviewed.Releases
		r.From = append([]lineattest.Release{}, r.From...)
		r.To = append([]lineattest.Release{}, r.To...)
		a.Releases = &r
		return a
	}
	cases := []struct {
		name   string
		mutate func(*lineattest.LineAttestation)
		accept bool
	}{
		{name: "unchanged", accept: true},
		{name: "complete release subset", accept: true, mutate: func(a *lineattest.LineAttestation) {
			a.Releases.From = a.Releases.From[:1]
			a.InstallProfiles = append(a.InstallProfiles[:2], a.InstallProfiles[4:]...)
		}},
		{name: "stripped profiles", mutate: func(a *lineattest.LineAttestation) { a.InstallProfiles = nil }},
		{name: "changed served", mutate: func(a *lineattest.LineAttestation) {
			a.InstallProfiles[5].Served = []string{"argoproj.io/v1beta1/Application"}
		}},
		{name: "added served", mutate: func(a *lineattest.LineAttestation) {
			a.InstallProfiles[5].Served = append(a.InstallProfiles[5].Served, "argoproj.io/v1beta1/Application")
		}},
		{name: "changed artifact", mutate: func(a *lineattest.LineAttestation) {
			f := &a.InstallProfiles[5].Artifacts[0]
			f.Digest = "sha256:" + strings.Repeat("f", 64)
			f.Source.ContentDigest = f.Digest
		}},
		{name: "changed provenance", mutate: func(a *lineattest.LineAttestation) { a.InstallProfiles[5].Artifacts[0].Source.ID = "other-source" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := clone()
			if tc.mutate != nil {
				tc.mutate(&a)
			}
			if err := a.Validate(); err != nil {
				t.Fatalf("test input must be valid: %v", err)
			}
			err := crossCheckAttestation(out, "", a, &loadedPack{})
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%v, error=%v", tc.accept, err)
			}
		})
	}
}
