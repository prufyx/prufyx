// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"path"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// literalKustomizationProof returns the sole file that can use the reviewed
// exception. Every other source reference to its directory refuses the file.
func (x *Extractor) literalKustomizationProof(r extract.PinnedReader, repo extract.RepoRef, commit, tag string, blobs []extract.TreeEntry) (map[string]bool, error) {
	d := x.target.LiteralKustomization
	if d == nil {
		return nil, nil
	}
	entries := map[string]extract.TreeEntry{}
	for _, b := range blobs {
		entries[b.Path] = b
	}
	for _, p := range []string{d.Path, d.Makefile, d.Default} {
		b, ok := entries[p]
		if !ok || b.Mode == "120000" || b.Type != "blob" {
			return nil, nil
		}
	}
	data, err := r.Read(repo, commit, d.Path)
	if err != nil {
		return nil, fmt.Errorf("literal Kustomization reading %s at %s: %w", d.Path, commit, err)
	}
	makefile, err := r.Read(repo, commit, d.Makefile)
	if err != nil {
		return nil, fmt.Errorf("literal Kustomization reading %s at %s: %w", d.Makefile, commit, err)
	}
	def, err := r.Read(repo, commit, d.Default)
	if err != nil {
		return nil, fmt.Errorf("literal Kustomization reading %s at %s: %w", d.Default, commit, err)
	}
	refs, err := literalKustomizationReferrers(r, repo, commit, blobs, path.Dir(d.Path), d.Default)
	if err != nil {
		return nil, err
	}
	ctx := literalKustomizationContext{Project: x.target.Project, Repo: x.target.Repo, Tag: tag, Commit: commit, Path: d.Path, MakefileSHA256: sha256Hex(makefile), DefaultSHA256: sha256Hex(def), Referrers: refs}
	if !literalKustomizationAllowed(ctx, data) {
		return nil, nil
	}
	return map[string]bool{d.Path: true}, nil
}

func literalKustomizationReferrers(r extract.PinnedReader, repo extract.RepoRef, commit string, blobs []extract.TreeEntry, directory, allowed string) ([]literalKustomizationReferrer, error) {
	var refs []literalKustomizationReferrer
	for _, b := range blobs {
		if b.Mode == "120000" || surfaceKindOf(b.Path) != surfRefs {
			continue
		}
		data, err := r.Read(repo, commit, b.Path)
		if err != nil {
			return nil, fmt.Errorf("literal Kustomization reading referrer %s at %s: %w", b.Path, commit, err)
		}
		tokens, why := refTokens(data)
		if why != "" {
			return nil, nil
		}
		base := path.Dir(b.Path)
		if base == "." {
			base = ""
		}
		for _, token := range tokens {
			ref := path.Join(base, token)
			if ref != directory {
				continue
			}
			kind := "kustomize"
			if path.Base(b.Path) == "Chart.yaml" || path.Base(b.Path) == "requirements.yaml" {
				kind = "helm"
			}
			refs = append(refs, literalKustomizationReferrer{Path: b.Path, Kind: kind})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })
	if len(refs) != 1 || refs[0] != (literalKustomizationReferrer{Path: allowed, Kind: "kustomize"}) {
		return nil, nil
	}
	return refs, nil
}
