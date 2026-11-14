// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"path"
	"sort"
	"strings"

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
	refs, err := literalKustomizationReferrers(r, repo, commit, blobs, d.Path, d.Default)
	if err != nil {
		return nil, err
	}
	ctx := literalKustomizationContext{Project: x.target.Project, Repo: x.target.Repo, Tag: tag, Commit: commit, Path: d.Path, MakefileSHA256: sha256Hex(makefile), DefaultSHA256: sha256Hex(def), Referrers: refs}
	if !literalKustomizationAllowed(ctx, data) {
		return nil, nil
	}
	return map[string]bool{d.Path: true}, nil
}

func literalKustomizationReferrers(r extract.PinnedReader, repo extract.RepoRef, commit string, blobs []extract.TreeEntry, source, allowed string) ([]literalKustomizationReferrer, error) {
	var refs []literalKustomizationReferrer
	directory := path.Dir(source)
	excluded := Exclusion{Path: directory + "/"}
	for _, b := range blobs {
		if b.Path == source {
			continue
		}
		kind := surfaceKindOf(b.Path)
		if kind == surfNone && strings.HasSuffix(b.Path, ".go") && !strings.HasSuffix(b.Path, "_test.go") {
			kind = surfGo
		}
		if kind == surfNone {
			continue
		}
		if b.Mode == "120000" || b.Type != "blob" {
			return nil, nil
		}
		data, err := r.Read(repo, commit, b.Path)
		if err != nil {
			return nil, fmt.Errorf("literal Kustomization reading referrer %s at %s: %w", b.Path, commit, err)
		}
		info := summarizeSurface(kind, data)
		if info.unread != "" {
			return nil, nil
		}
		base := path.Dir(b.Path)
		if base == "." {
			base = ""
		}
		switch kind {
		case surfRefs:
			for _, token := range info.tokens {
				ref := path.Join(base, token)
				if !hitsPath(excluded, ref) {
					continue
				}
				if b.Path != allowed || ref != directory {
					return nil, nil
				}
				kind := "kustomize"
				if path.Base(b.Path) == "Chart.yaml" || path.Base(b.Path) == "requirements.yaml" {
					kind = "helm"
				}
				refs = append(refs, literalKustomizationReferrer{Path: b.Path, Kind: kind})
			}
		case surfMake:
			if _, ok := makeHit(excluded, info.lines); ok {
				return nil, nil
			}
		case surfDoc, surfShell:
			if _, ok := docHit(excluded, info.lines); ok {
				return nil, nil
			}
		case surfBuild:
			if _, ok := linesHit(excluded, base, true, info.lines); ok {
				return nil, nil
			}
		case surfNix:
			if _, ok := linesHit(excluded, base, false, info.lines); ok {
				return nil, nil
			}
		case surfGo:
			for _, pattern := range info.embeds {
				for _, candidate := range blobs {
					if hitsPath(excluded, candidate.Path) && embedMatches(path.Join(base, pattern), base, candidate.Path) {
						return nil, nil
					}
				}
			}
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })
	if len(refs) != 1 || refs[0] != (literalKustomizationReferrer{Path: allowed, Kind: "kustomize"}) {
		return nil, nil
	}
	return refs, nil
}
