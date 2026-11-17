// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// RecordedDraft is an untrusted local draft, not proof that tags belong to an
// upstream repository. An independent upstream binding is still required.
type RecordedDraft struct {
	Recipe      []byte
	Rules       []byte
	FactsBundle []byte
	Target      []byte
	Report      []byte
	TableRow    []byte
	Changelog   []byte
}

// RecordDraft records and replays a recipe-v1 half A against a local GitSource.
// It returns no artifacts unless the generated target and row exactly match
// both caller-supplied expected byte strings. It never writes files or fetches.
func RecordDraft(in Input, source GitSource, expectedTarget, expectedRow []byte) (*RecordedDraft, error) {
	if len(expectedTarget) == 0 || len(expectedRow) == 0 {
		return nil, errors.New("expected target and table row are required")
	}
	if in.MultiPrefix || in.InferInstallPaths || in.CheckInstallPathCopies {
		return nil, errors.New("input uses options unsupported by recipe v1")
	}
	var rulesRaw []byte
	if in.Rules != nil {
		if len(in.Rules.Exclusions) != 0 || in.Rules.checkCopies {
			return nil, errors.New("rules contain unsupported exclusions or options")
		}
		var err error
		rulesRaw, err = canonicalJSON(in.Rules)
		if err != nil {
			return nil, err
		}
		in.Rules, err = ParseRules(rulesRaw)
		if err != nil {
			return nil, err
		}
	}
	rec := &RecordingSource{Inner: source}
	in.Source = rec
	result, err := Generate(in)
	if err != nil {
		return nil, err
	}
	target, err := decodeDoc(result.A)
	if err != nil || target.Target.Attest || len(target.Target.Exclude) != 0 {
		return nil, errors.New("generated target is not exclusion-free half A")
	}
	if !bytes.Equal(result.A, expectedTarget) || !bytes.Equal(result.TableRow, expectedRow) {
		return nil, errors.New("generated target or table row differs from expected bytes")
	}
	tags := append(append([]string(nil), in.Tags...), in.RangeCheckTags...)
	sort.Strings(tags)
	var commits []recipeCommit
	for _, tag := range tags {
		if len(commits) != 0 && commits[len(commits)-1].Tag == tag {
			continue
		}
		commit, ok := rec.commits[tag]
		if !ok {
			_, commit, err = rec.Open(tag)
			if err != nil {
				return nil, err
			}
		}
		commits = append(commits, recipeCommit{Tag: tag, Commit: commit})
	}
	bundleRaw, err := rec.BundleFromGit(source)
	if err != nil {
		return nil, err
	}
	bundle, err := ParseBundle(bundleRaw)
	if err != nil {
		return nil, err
	}
	if len(bundle.Tags()) != len(commits) {
		return nil, errors.New("recorded bundle has unexpected tags")
	}
	for _, c := range commits {
		if got, ok := bundle.Commit(c.Tag); !ok || got != c.Commit {
			return nil, errors.New("recorded bundle commit mismatch")
		}
	}
	recipe := Recipe{Schema: RecipeSchema, Slug: in.Slug, Name: in.Name, Repo: in.Repo, Catalog: in.Catalog, Component: in.Component, FactProject: in.FactProject, Tags: append([]string(nil), in.Tags...), RangeCheckTags: append([]string(nil), in.RangeCheckTags...), StrictWindow: in.StrictWindow, CollapseDirectories: in.CollapseDirectories, Half: "A", Exclude: []string{}, Commits: commits, FactBundleDigest: sha256Of(bundleRaw)}
	if in.Rules != nil {
		recipe.Rules = "rules.json"
	}
	recipeRaw, err := canonicalJSON(recipe)
	if err != nil {
		return nil, err
	}
	if _, err := ParseRecipe(recipeRaw); err != nil {
		return nil, fmt.Errorf("recipe: %w", err)
	}
	report, err := marshal(result.Report)
	if err != nil {
		return nil, err
	}
	in.Source = FactSource{B: bundle}
	replay, err := Generate(in)
	if err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	replayReport, err := marshal(replay.Report)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(result.A, replay.A) || !bytes.Equal(result.B, replay.B) || !bytes.Equal(result.TableRow, replay.TableRow) || !bytes.Equal(result.Changelog, replay.Changelog) || !bytes.Equal(report, replayReport) {
		return nil, errors.New("recorded facts do not reproduce draft")
	}
	return &RecordedDraft{Recipe: recipeRaw, Rules: rulesRaw, FactsBundle: bundleRaw, Target: result.A, Report: report, TableRow: result.TableRow, Changelog: result.Changelog}, nil
}
