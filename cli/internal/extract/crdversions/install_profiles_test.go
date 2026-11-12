// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestInstallProfilesRetainSeparateServingRelations(t *testing.T) {
	tg := channelTarget()
	tg.Attest, tg.ProfileAttestation = true, true
	canonical := strings.ReplaceAll(crd("Application", "v1alpha1", "v1beta1"), synthGroup, "argoproj.io")
	ha := strings.ReplaceAll(crd("Application", "v1alpha1"), synthGroup, "argoproj.io")
	world := func(tag string) release {
		r := channelWorld(map[string]string{"a.yaml": canonical}, map[string]string{"a.yaml": ha})
		r.tag = tag
		return r
	}
	s := newSynth(world("v1.0.0"), world("v1.1.0"))
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	out, err := extract.Run(context.Background(), New(tg), ReleaseTags(New(tg), s), s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	a := attestationFor(t, out, "1.1")
	if a == nil || len(a.InstallProfiles) != 4 || a.Validate() != nil || len(a.RuleIDs) != 0 {
		t.Fatalf("missing source-profile census: %+v", a)
	}
	for _, p := range a.InstallProfiles {
		want := 2
		if p.ID == "experimental" {
			want = 1
		}
		if len(p.Served) != want || len(p.Artifacts) != 1 || p.Artifacts[0].Source.Revision != p.Commit || p.Artifacts[0].Source.ContentDigest != p.Artifacts[0].Digest {
			t.Fatalf("profile serving sets merged or unbound: %+v", p)
		}
	}
	for name, mutate := range map[string]func(*extract.AttestationCandidate){
		"unread path": func(c *extract.AttestationCandidate) { c.InstallProfiles[0].Artifacts[0].Path = "unread.yaml" },
		"wrong digest": func(c *extract.AttestationCandidate) {
			c.InstallProfiles[0].Artifacts[0].Digest = "sha256:" + strings.Repeat("f", 64)
		},
		"wrong release":   func(c *extract.AttestationCandidate) { c.InstallProfiles[0].Commit = commitOf("v9.9.9") },
		"omitted profile": func(c *extract.AttestationCandidate) { c.InstallProfiles = c.InstallProfiles[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			x := tampering{New(tg), mutate}
			if _, err := extract.Run(context.Background(), x, ReleaseTags(New(tg), s), s, extract.Options{Repo: repo, DerivedAt: derivedAt}); err == nil {
				t.Fatal("unproved profile artifact stamped")
			}
		})
	}
	// A conflicting source outside the declared channels still blocks the
	// source proof. Profiles never relax the existing whole-tree guard.
	s = newSynth(world("v1.0.0"), world("v1.1.0"))
	for _, tag := range s.tags {
		s.files[tag.Commit+":other/crd.yaml"] = []byte(strings.ReplaceAll(crd("Application", "v1"), synthGroup, "argoproj.io"))
	}
	out, err = extract.Run(context.Background(), New(tg), ReleaseTags(New(tg), s), s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	if len(out.Attestations) != 0 {
		t.Fatal("profile declaration hid conflicting source")
	}
}
