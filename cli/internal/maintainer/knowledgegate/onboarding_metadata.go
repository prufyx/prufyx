// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

type metadataDraft struct {
	path, oldDigest, newDigest string
	raw                        []byte
}

func cmdOnboardingMetadata(args []string, layout Layout, stdout io.Writer) (int, error) {
	var gitDir, baseSHA, headSHA string
	f := flag.NewFlagSet("gate prepare-onboarding-metadata", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&gitDir, "git-dir", "", "local repository holding complete objects")
	f.StringVar(&baseSHA, "base", "", "operational base commit containing this command")
	f.StringVar(&headSHA, "head", "", "unsigned table/target-only candidate commit")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if gitDir == "" || !shaRE.MatchString(baseSHA) || !shaRE.MatchString(headSHA) {
		return 2, errors.New("--git-dir and full --base/--head commit IDs are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o := ExportOptions{GitDir: gitDir, offline: true}
	// Resolve actual commits, not tags or tree IDs. No missing object may fetch.
	for _, sha := range []string{baseSHA, headSHA} {
		typ, err := gitOutput(ctx, o, "cat-file", "-t", sha)
		if err != nil || string(bytes.TrimSpace(typ)) != "commit" {
			return 2, fmt.Errorf("%s is not an available local commit (Git with --no-lazy-fetch support is required)", sha)
		}
	}
	if _, err := gitOutput(ctx, o, "merge-base", "--is-ancestor", baseSHA, headSHA); err != nil {
		return 2, fmt.Errorf("BASE must be an ancestor of HEAD: %w", err)
	}
	parent, err := os.MkdirTemp("", "prufyx-onboarding-metadata-")
	if err != nil {
		return 2, err
	}
	defer os.RemoveAll(parent)
	// Complete exports under a private parent preserve whole-change comparison.
	for i, sha := range []string{baseSHA, headSHA} {
		o.Commit, o.Out = sha, filepath.Join(parent, []string{"base", "head"}[i])
		if err := Export(ctx, o); err != nil {
			return 2, err
		}
	}
	draft, err := prepareOnboardingMetadata(layout, Tree{Root: filepath.Join(parent, "base")}, Tree{Root: filepath.Join(parent, "head")})
	if err != nil {
		return 2, err
	}
	n, err := stdout.Write(draft.raw)
	if err == nil && n != len(draft.raw) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 2, err
	}
	return 0, nil
}

// prepareOnboardingMetadata prepares bytes only; it grants no admission.
// Trees are complete immutable exports owned by the caller, never checkouts.
func prepareOnboardingMetadata(layout Layout, base, head Tree) (metadataDraft, error) {
	var out metadataDraft
	if layout.Onboarding != defaultOnboardingLayout() {
		return out, errors.New("unsupported onboarding layout")
	}
	paths, err := ChangedPaths(base, head)
	if err != nil {
		return out, err
	}
	if why := onboardingModes(Options{Base: base, Head: head}, paths); why != "" {
		return out, errors.New(why)
	}
	cls, err := Classify(layout, base, head)
	if err != nil {
		return out, err
	}
	st, err := newOnboardingState(layout, base, head, cls, paths)
	if err != nil {
		return out, err
	}
	compiled, err := constraintengine.NewCompiledRegistry(cncfcheck.CompiledFactDefinitions())
	if err != nil {
		return out, err
	}
	if st.base.state.RegistryDigest != compiled.Digest() || st.base.registryDigest != st.base.state.RegistryDigest {
		return out, errors.New("BASE table, pack and trusted binary registry must agree")
	}
	if !reflect.DeepEqual(st.base.reserved, st.head.reserved) {
		return out, errors.New("reserved groups must remain unchanged")
	}
	baseRows, headRows := projectsBySlug(st.base.projects), projectsBySlug(st.head.projects)
	for slug, row := range baseRows {
		if !reflect.DeepEqual(row, headRows[slug]) {
			return out, errors.New("existing table rows must remain unchanged")
		}
	}
	allowed := map[string]bool{layout.Onboarding.TablePath: true, cncfRulesPath: true}
	groupOwners := map[string][]groupListing{}
	for _, row := range st.head.projects {
		for _, group := range row.Groups {
			groupOwners[group.Name] = append(groupOwners[group.Name], groupListing{slug: row.Slug, kinds: group.Kinds})
		}
	}
	added := 0
	for slug, row := range headRows {
		if _, exists := baseRows[slug]; exists {
			continue
		}
		added++
		rel := targetPath(layout.Onboarding, slug)
		allowed[rel] = true
		if base.Exists(rel) {
			return out, errors.New("a new row's target must be absent in BASE")
		}
		raw, err := head.Read(rel, MaxFileBytes)
		if err != nil {
			return out, err
		}
		// Reuse structural onboarding checks without constructing proof or claims.
		p := OnboardingProject{Slug: slug, Kind: OnboardingKindNew, Catalog: string(row.Catalog), Facts: []string{row.FactID()}, Artifacts: []OnboardingArtifact{{Path: rel, Digest: CandidateDigest(raw)}}}
		for _, group := range row.Groups {
			p.Groups = append(p.Groups, group.Name)
		}
		if problems := st.checkProject(p, baseRows, headRows, groupOwners); len(problems) != 0 {
			return out, fmt.Errorf("new project structure: %s", problems[0])
		}
	}
	if added == 0 || added > MaxOnboardingProjects || st.base.state.RegistryDigest == st.head.state.RegistryDigest {
		return out, errors.New("a bounded registry-changing table addition is required")
	}
	for _, rel := range paths {
		if !allowed[rel] {
			return out, fmt.Errorf("outside metadata preparation scope: %s", logSafe(rel))
		}
		if _, err := head.Read(rel, MaxFileBytes); err != nil {
			return out, err
		}
	}
	// Also reject executable fixed inputs even when their mode did not change.
	for _, rel := range []string{layout.Onboarding.TablePath, cncfRulesPath} {
		if base.executable(rel) || head.executable(rel) {
			return out, errors.New("metadata inputs must be non-executable regular files")
		}
	}
	baseRaw, err := base.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		return out, err
	}
	want, err := replaceRegistryToken(baseRaw, st.base.state.RegistryDigest, st.head.state.RegistryDigest)
	if err != nil {
		return out, err
	}
	headRaw, err := head.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(headRaw, baseRaw) && !bytes.Equal(headRaw, want) {
		return out, errors.New("HEAD pack must equal BASE or its exact computed registry token replacement")
	}
	landscape, err := base.Read(layout.Onboarding.LandscapePath, MaxFileBytes)
	if err != nil {
		return out, err
	}
	priority, err := base.Read(layout.Onboarding.PriorityPath, MaxFileBytes)
	if err != nil {
		return out, err
	}
	if _, err := cncfcheck.CheckPackFilesWithTable(landscape, priority, want, st.head.table); err != nil {
		return out, fmt.Errorf("prepared pack does not load against the proposed table: %w", err)
	}
	return metadataDraft{path: cncfRulesPath, oldDigest: st.base.state.RegistryDigest, newDigest: st.head.state.RegistryDigest, raw: want}, nil
}

// replaceRegistryToken preserves every byte outside the top-level string value.
func replaceRegistryToken(raw []byte, oldDigest, newDigest string) ([]byte, error) {
	if err := strictjson.Check(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("pack must be one JSON object")
	}
	start, end := -1, -1
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		before := int(d.InputOffset())
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if name, _ := key.(string); name == registryMember {
			var got string
			if json.Unmarshal(value, &got) != nil || got != oldDigest || !approvalDigestRE.MatchString(got) {
				return nil, errors.New("invalid BASE registryDigest string")
			}
			// Decode starts after ':' and whitespace. RawMessage is exactly
			// the value, so its length identifies the opening quote precisely.
			end = int(d.InputOffset())
			start = end - len(value)
			if start <= before || raw[start] != '"' || raw[end-1] != '"' {
				return nil, errors.New("invalid registryDigest token span")
			}
		}
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF || start < 0 {
		return nil, errors.New("one exact top-level registryDigest member is required")
	}
	if !approvalDigestRE.MatchString(newDigest) {
		return nil, errors.New("invalid computed registry digest")
	}
	replacement, _ := json.Marshal(newDigest)
	out := append([]byte{}, raw[:start]...)
	out = append(out, replacement...)
	out = append(out, raw[end:]...)
	return out, nil
}
