// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha1" //nolint:gosec // Git fixture object identities.
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// staticPositiveReader gives the existing fixture real Git blob identities.
type staticPositiveReader struct{ synthRepo }

func (r staticPositiveReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	entries, err := r.synthRepo.List(repo, commit, dir)
	for i := range entries {
		e := &entries[i]
		if e.Type == "tree" {
			e.Mode = "040000"
			continue
		}
		data, readErr := r.Read(repo, commit, e.Path)
		if readErr != nil {
			return nil, readErr
		}
		h := sha1.New() //nolint:gosec // Git fixture object identities.
		fmt.Fprintf(h, "blob %d%c", len(data), 0)
		h.Write(data)
		e.SHA = hex.EncodeToString(h.Sum(nil))
	}
	return entries, err
}

// This regression exercises the production scanner and rule emitter, not
// merely the helper recognizer. Its expected scan fails on the old reader.
func TestStaticHelperPreservesLiteralCRDClaims(t *testing.T) {
	const helper = "charts/widgets/templates/_helpers.tpl"
	const body = `{{/* CustomResourceDefinition guard; never a manifest. */}}
{{ define "widgets.check" }}
{{ if .Values.enabled }}{{ fail "CustomResourceDefinition is unavailable" }}{{ else }}
{{ if not .Values.disabled }}{{ fail "CustomResourceDefinition is unavailable" }}{{ end }}
{{ end }}
{{ end }}
`
	run := func(withHelper bool) *extract.Output {
		t.Helper()
		files := func(versions ...string) map[string]string {
			m := map[string]string{
				"deploy/crds/widgets.yaml":              crd("Widget", versions...),
				"charts/widgets/Chart.yaml":             "apiVersion: v2\nname: widgets\nversion: 1.0.0\n",
				"charts/widgets/templates/widgets.yaml": crd("Widget", versions...),
			}
			if withHelper {
				m[helper] = body
			}
			return m
		}
		rd := staticPositiveReader{newSynth(release{"v1.0.0", files("v1alpha1", "v1")}, release{"v1.1.0", files("v1")})}
		tg := synthTarget()
		repo, err := extract.ParseRepo(tg.Repo)
		must(t, err)
		x := New(tg).WithIndex(syntheticOwnership(tg, synthGroup))
		out, err := extract.Run(context.Background(), x, ReleaseTags(x, rd), rd, extract.Options{Repo: repo, DerivedAt: derivedAt})
		must(t, err)
		return out
	}
	plain, with := run(false), run(true)
	p, proof := pairOf(t, with, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Scan {
		t.Fatalf("literal definition was not completely read: %+v %+v", p, proof.Completeness)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		found := false
		for _, f := range inv.Scan.Findings {
			if f.Path == helper {
				found = f.Class == ClassNoDefinition && f.Reason == ReasonNoDefinition && f.SHA256 == shaOf(body)
			}
		}
		if !found {
			t.Fatalf("missing source-bound helper proof: %+v", inv.Scan.Findings)
		}
	}
	if !reflect.DeepEqual(plain.Entries, with.Entries) {
		t.Fatal("helper changed literal CRD facts or their citations")
	}
	t.Log("literal CRD rule count=1; helper scan clean; claims and citations unchanged")
}
