// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every non-test file that special-cases an engine "not reviewed" reason must
// have a decision for the boundary-covered reason. A file in coverDecided
// handles it (it names IsBoundaryCovered or ReasonBoundaryCoveredByExact); a
// file in coverNotApplicable builds its own claims and never sees an engine
// claim of a covered rule. A new site that special-cases the reasons without
// either fails here, so the default stays fail-closed (undecided).
var (
	coverDecided = map[string]bool{
		"cncfcheck/chain.go":                true,
		"communityapp/cncf_chain.go":        true,
		"communityapp/cncf_quiet_output.go": true,
		"humanreport/report.go":             true,
		"scanrun/reasons.go":                true,
	}
	coverNotApplicable = map[string]string{
		"communityapp/cncf_tuf_raw.go":        "raw route builds its own claim",
		"communityapp/cncf_kubeflow_raw.go":   "raw route builds its own claim",
		"communityapp/cncf_intoto_raw.go":     "raw route builds its own claim",
		"communityapp/cncf_knative_raw.go":    "raw route builds its own claim",
		"communityapp/cncf_cubefs_raw.go":     "raw route builds its own claim",
		"communityapp/cncf_crio_raw.go":       "raw route builds its own claim",
		"communityapp/cncf_formats_raw.go":    "raw route builds its own claim",
		"communityapp/cncf_buildpacks_raw.go": "raw route builds its own claim",
		"scanrun/kubernetes.go":               "notice exclusions only: a notice never has a covering rule",
		"onecommand/onecommand.go":            "catalog/display; keeps the conservative boundary answer until the pack migration (no engine claim)",
		"checkroutemetadata/catalog.go":       "catalog/display; keeps the conservative boundary answer until the pack migration",
		"projectcheck/projectcheck.go":        "catalog selection; keeps the conservative boundary answer until the pack migration",
		"cncfcheck/pack.go":                   "rule selection keeps the boundary rule so the engine decides",
	}
	coverNeedles = []string{"RULE_TRANSITION_NOT_REVIEWED", "ReasonReleaseBoundaryNotReviewed", "reasonTransitionNotReviewed", "ReasonTransitionNotReviewed", "CrossesUnreviewed"}
)

func TestBoundaryCoverEveryNotReviewedSiteHasADecision(t *testing.T) {
	root := filepath.Join("..")
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, filepath.Join("..", "constraintengine")) {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		special := false
		for _, needle := range coverNeedles {
			special = special || strings.Contains(text, needle)
		}
		if !special {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		seen[rel] = true
		switch {
		case coverDecided[rel]:
			if !strings.Contains(text, "IsBoundaryCovered") && !strings.Contains(text, "ReasonBoundaryCoveredByExact") {
				t.Errorf("%s special-cases not-reviewed reasons but does not decide the covered reason", rel)
			}
		case coverNotApplicable[rel] != "":
		default:
			t.Errorf("%s special-cases not-reviewed reasons and has no decision for the boundary-covered reason (add it to coverDecided or coverNotApplicable)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range coverDecided {
		if !seen[rel] {
			t.Errorf("%s is listed as deciding but no longer special-cases the reasons", rel)
		}
	}
}
