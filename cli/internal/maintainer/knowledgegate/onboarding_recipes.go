// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"errors"
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/maintainer/docstables"
)

// The recipe directory allowance of the onboarding path allow-list (O2).
//
// An onboarding change that the admission seam judges carries the recipe
// directory of its project (the files the upstream verification reads). The
// allow-list admits exactly those fixed file names below
// target-recipes/<slug>/, and only when all of these hold:
//   - the compiled layout enables the onboarding admission AND the run-time
//     lock is set (either one off: nothing here runs, the allow-list is the
//     one it always was);
//   - the change is the pull-request-target admission context with the
//     authenticated git objects, whose exported trees equal the trees the
//     gate checks;
//   - the batch lists exactly one project and the slug is that project's,
//     never one read from the head tree or the change;
//   - the base tree has no recipe directory of that slug at all (a new
//     project), and the file is an ADDED plain regular file (mode 100644) in
//     the raw diff, read by the same parser the admission uses: any other
//     entry anywhere in that diff (a link, an executable, a delete, a
//     rename, a modification, an unreadable object) removes the allowance
//     altogether.
//
// This step takes its own git diff, between the two immutable commits, with
// the references checked before it and after it; the admission seam takes a
// separate diff of the same commits later, under the same checks. The gate
// then fails the change unless that seam ran and passed (admitOnboarding).
//
// Every failure returns nil, which is the allow-list without recipe files.

// recipeSlugRE is the slug form of the recipe directory: lower case letters,
// digits and single hyphens between them, at most 63 bytes (the verifier's
// own two forms together). Go's $ is the end of the text: no trailing newline.
var recipeSlugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// recipeSlug is the one slug of a batch that may have a recipe directory.
func recipeSlug(rec OnboardingRecord) (string, bool) {
	if len(rec.Projects) != 1 {
		return "", false
	}
	slug := rec.Projects[0].Slug
	if !recipeSlugRE.MatchString(slug) || !admitSlugRE.MatchString(slug) {
		return "", false
	}
	return slug, true
}

// recipePaths are the exact recipe files of a slug (no pattern, no
// subdirectory).
func recipePaths(slug string) []string {
	out := make([]string, 0, len(seamRecipeFiles))
	for _, n := range seamRecipeFiles {
		out = append(out, recipesRoot+slug+"/"+n)
	}
	return out
}

// recipeDiffHook runs between the diff and the second reference check. It is
// nil outside tests.
var recipeDiffHook func(g *OnboardingGitContext)

// onboardingRecipeAllowance returns the recipe files of the batch's one new
// project that the change adds as plain files, or nil.
func onboardingRecipeAllowance(ctx context.Context, opts Options, rec OnboardingRecord) map[string]bool {
	if !opts.Layout.OnboardingAdmission.Enabled || !opts.OnboardingAdmissionInProcess {
		return nil
	}
	if opts.AdmissionEvent != AdmissionEventPullRequestTarget {
		return nil
	}
	g := opts.OnboardingGit
	if g == nil || g.HeadCommit != opts.HeadSHA || !shaRE.MatchString(g.BaseCommit) || !shaRE.MatchString(g.HeadCommit) || g.BaseCommit == g.HeadCommit {
		return nil
	}
	slug, ok := recipeSlug(rec)
	if !ok {
		return nil
	}
	if checkAdmissionRefs(ctx, g) != nil {
		return nil
	}
	// The git objects must be the trees the gate checks, and the base must
	// not know the project's recipe directory: a new project only.
	base, head, cleanup, err := exportAdmissionTrees(ctx, g)
	if err != nil {
		return nil
	}
	defer cleanup()
	if equalAdmissionTrees(base, head, opts.Base, opts.Head) != nil {
		return nil
	}
	if d, err := base.openDir(recipesRoot + slug); err == nil {
		d.Close()
		return nil
	} else if !errors.Is(err, ErrMissing) {
		return nil
	}
	raw, err := admissionRawDiff(ctx, g, g.HeadCommit)
	if err != nil || len(raw) == 0 {
		return nil
	}
	changes, err := parseAdmissionRaw(ctx, g, raw)
	if err != nil || len(changes) == 0 {
		return nil
	}
	if recipeDiffHook != nil {
		recipeDiffHook(g)
	}
	// The objects must still be the authenticated ones after the reads.
	if checkAdmissionRefs(ctx, g) != nil {
		return nil
	}
	want := map[string]bool{}
	for _, p := range recipePaths(slug) {
		want[p] = true
	}
	out := map[string]bool{}
	for _, c := range changes {
		if !want[c.Path] || c.Status != "A" || c.Head.Mode != "100644" {
			continue
		}
		out[c.Path] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recipeAllowedPaths are the recipe files the allow-list admits for rec: the
// exact files of the batch's one slug that the gate found plain, and only
// those.
func (st *onboardingState) recipeAllowedPaths(rec OnboardingRecord) map[string]bool {
	if st.recipeFiles == nil {
		return nil
	}
	slug, ok := recipeSlug(rec)
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, p := range recipePaths(slug) {
		if st.recipeFiles[p] {
			out[p] = true
		}
	}
	return out
}

// defaultOnboardingAdmission is the compiled admission configuration: the
// exact files an admitted onboarding change may touch, all named, none a
// directory or a pattern. It is OFF (Enabled false); the compiled layout and
// the run-time lock are the only two ways to turn the admission on.
//
//   - StaticPaths are the files that do not depend on the project: the table,
//     the pack file and its corpus attestation, the generated support
//     inventory, the two generated documentation tables, and the README and
//     source preview files whose generated blocks an onboarding regenerates.
//     They are the verifier's Optional set as well (the table is the
//     verifier's own table path), so the gate and the verifier read one list.
//   - ProjectPaths are the six recipe files of the batch's one slug.
//   - TargetPath is the slug's target file.
//
// {slug} is replaced only by the slug of the signed batch, at run time.
func defaultOnboardingAdmission() OnboardingAdmissionConfig {
	ol := defaultOnboardingLayout()
	cfg := OnboardingAdmissionConfig{
		StaticPaths: []string{
			ol.TablePath,
			cncfRulesPath,
			cncfAttestPath,
			inventoryJSON,
			inventoryMD,
			ol.DocsDir + "/" + docstables.CRDTargetsPath,
			ol.DocsDir + "/" + docstables.CustomResourcesPath,
			readmePath,
			PreviewPath,
		},
		TargetPath: ol.TargetsDir + "/target-{slug}.json",
	}
	for _, n := range seamRecipeFiles {
		cfg.ProjectPaths = append(cfg.ProjectPaths, recipesRoot+"{slug}/"+n)
	}
	return cfg
}
