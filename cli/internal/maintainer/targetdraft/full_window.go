// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// FullWindowSelector carries externally supplied selector evidence. The caller
// must independently authenticate the complete upstream tag enumeration; this
// generator proves consistency only for the supplied bounded window. Tags
// must already be in ascending numeric order; they are never silently sorted.
type FullWindowSelector struct {
	Policy       string
	Prefix       string
	LinesBack    int
	MinFrom      string
	Newest       string
	LaterTag     string
	TagSetSHA256 string
	Commits      map[string]string
}

// GenerateFullWindow is a dormant local draft generator. It does not establish
// upstream completeness, tag authenticity, eligibility, or merge authority.
func GenerateFullWindow(in Input, selector FullWindowSelector) (*Result, error) {
	if !in.StrictWindow || in.MultiPrefix || in.DeriveDuplicates || in.InferInstallPaths || in.CheckInstallPathCopies || in.SkipPatchFragments || len(in.RangeCheckTags) != 0 {
		return nil, fullWindowError("unsupported full-window options")
	}
	if in.Rules != nil && (len(in.Rules.Exclusions) != 0 || len(in.Rules.InstallSurface) != 0 || len(in.Rules.InstallPaths) != 0 || len(in.Rules.PathFilter) != 0 || in.Rules.deriveStrict || in.Rules.checkCopies) {
		return nil, fullWindowError("full-window rules require provenance only")
	}
	if in.Catalog == "community" && (in.Rules == nil || in.Rules.Upstream == nil) {
		return nil, fullWindowError("community provenance required")
	}
	if (in.Catalog == "" || in.Catalog == "cncf") && in.Rules != nil {
		return nil, fullWindowError("CNCF full-window rules are unsupported")
	}
	return generate(in, &selector)
}

func fullWindowError(detail string) error {
	return &StopError{Stops: []Stop{stop(StopBadInput, "full-window", detail)}}
}

func fullWindowTags(names []string, selector FullWindowSelector) ([]parsedTag, string, []Stop) {
	fail := func(message string) ([]parsedTag, string, []Stop) {
		return nil, "", []Stop{stop(StopBadInput, "full-window", message)}
	}
	if selector.Policy != "singleton-final/v1" || selector.LinesBack != 5 || !crdversions.ValidTagPrefix(selector.Prefix) || selector.MinFrom == "" || selector.Newest == "" || selector.LaterTag == "" || !strings.HasPrefix(selector.TagSetSHA256, "sha256:") || !sha256HexRE.MatchString(strings.TrimPrefix(selector.TagSetSHA256, "sha256:")) {
		return fail("invalid selector")
	}
	if len(names) < 2 || len(names) > MaxBundleTags || len(selector.Commits) != len(names) {
		return fail("invalid full-window size")
	}
	out := make([]parsedTag, 0, len(names))
	prevMajor, prevMinor, prevPatch := -1, -1, -1
	lines := 0
	later := ""
	newestLine := ""
	for _, name := range names {
		m := tagRE.FindStringSubmatch(name)
		if m == nil || m[1] != selector.Prefix || !tagNameRE.MatchString(name) || !sha1HexRE.MatchString(selector.Commits[name]) {
			return fail("invalid full-window tag or commit")
		}
		major, e1 := strconv.Atoi(m[2])
		minor, e2 := strconv.Atoi(m[3])
		patch, e3 := strconv.Atoi(m[4])
		if e1 != nil || e2 != nil || e3 != nil || major < prevMajor || (major == prevMajor && minor < prevMinor) || (major == prevMajor && minor == prevMinor && patch <= prevPatch) {
			return fail("full-window tags must be unique and numerically ordered")
		}
		line := fmt.Sprintf("%d.%d", major, minor)
		if line != newestLine {
			lines++
			newestLine = line
			later = name
		}
		out = append(out, parsedTag{Tag: name, Prefix: m[1], Major: major, Minor: minor})
		prevMajor, prevMinor, prevPatch = major, minor, patch
	}
	if lines > selector.LinesBack+1 {
		return fail("full window has too many release lines")
	}
	if lines < 2 || selector.MinFrom != fmt.Sprintf("%d.%d", out[0].Major, out[0].Minor) || selector.Newest != names[len(names)-1] || selector.LaterTag != later {
		return fail("selector does not match full window")
	}
	return out, selector.Prefix, nil
}

func fullWindowCitation(window []*tagResult, selector FullWindowSelector) (*tagResult, error) {
	if len(window) < 2 {
		return nil, fullWindowError("full window is incomplete")
	}
	var later *tagResult
	var reference map[string]bool
	for i, r := range window {
		if r.commit != selector.Commits[r.tag] || !sha1HexRE.MatchString(r.commit) || len(r.stops) != 0 {
			return nil, fullWindowError("tag source or scan mismatch")
		}
		kinds := map[string]bool{}
		for _, v := range r.included {
			for _, c := range v.CRDs {
				kinds[c.Group+"\x00"+c.Kind] = true
			}
		}
		if len(kinds) == 0 {
			return nil, fullWindowError("empty group set")
		}
		if i == 0 {
			reference = kinds
		} else {
			if len(kinds) != len(reference) {
				return nil, fullWindowError("group kinds differ across tags")
			}
			for k := range kinds {
				if !reference[k] {
					return nil, fullWindowError("group kinds differ across tags")
				}
			}
		}
		if r.tag == selector.LaterTag {
			later = r
		}
	}
	if later == nil {
		return nil, fullWindowError("later tag was not read")
	}
	// With more than one file per group, the factory's metadata-name tie-break
	// cannot be reconstructed from the generator's current parsed facts.
	sources := map[string]string{}
	for _, v := range later.included {
		for _, c := range v.CRDs {
			if previous, ok := sources[c.Group]; ok && previous != v.Path {
				return nil, fullWindowError("ambiguous later group citation")
			}
			sources[c.Group] = v.Path
		}
	}
	return later, nil
}
