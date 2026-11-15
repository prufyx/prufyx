// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// PrefixWindow is the proven window of one tag prefix of a multi-prefix run:
// the window tags of that prefix, oldest first, and the API groups they read.
type PrefixWindow struct {
	Prefix string   `json:"prefix"`
	Tags   []string `json:"tags"`
	Groups []string `json:"groups"`
}

// minPrefixWindow is the smallest window a prefix may hold: one pair needs two
// release lines.
const minPrefixWindow = 2

// parseTagsMulti reads the tags of a multi-prefix run. It accepts exactly two
// valid, disjoint prefixes, every tag matching exactly one of them by the
// extractor's own final-tag grammar, at least minPrefixWindow tags per prefix,
// and the two prefixes occupying consecutive runs of release lines (one
// switch-over, no interleaving). The returned prefixes are ordered newest tag
// first, the order of the target's tagPrefixes list. Anything else is a typed
// stop; no prefix is ever guessed or dropped.
func parseTagsMulti(in []string) ([]parsedTag, []string, []Stop) {
	out, stops := parseTagList(in)
	if len(stops) > 0 {
		return nil, nil, stops
	}
	sortTags(out)
	count := map[string]int{}
	for _, t := range out {
		count[t.Prefix]++
	}
	var prefs []string
	for p := range count {
		prefs = append(prefs, p)
	}
	sort.Strings(prefs)
	if len(prefs) != 2 {
		return nil, nil, []Stop{stop(StopMultiPrefixAmbiguous, "", fmt.Sprintf("a multi-prefix run needs tags of exactly two prefixes, got %d", len(prefs)))}
	}
	for _, p := range prefs {
		if !crdversions.ValidTagPrefix(p) {
			return nil, nil, []Stop{stop(StopTagPrefixUnsupported, p, "")}
		}
	}
	a, b := prefs[0], prefs[1]
	if (a != "" && strings.HasPrefix(b, a)) || (b != "" && strings.HasPrefix(a, b)) {
		return nil, nil, []Stop{stop(StopMultiPrefixAmbiguous, a+" "+b, "one prefix is the start of the other")}
	}
	var st []Stop
	for _, t := range out {
		n := 0
		for _, p := range prefs {
			if _, _, ok := crdversions.ReadFinalTag(p, 4, t.Tag); ok {
				n++
			}
		}
		if n != 1 {
			st = append(st, stop(StopMultiPrefixAmbiguous, t.Tag, fmt.Sprintf("the tag is a final release of %d of the two prefixes, not exactly one", n)))
		}
	}
	if len(st) > 0 {
		return nil, nil, sortStops(st)
	}
	for _, p := range prefs {
		if count[p] < minPrefixWindow {
			st = append(st, stop(StopMultiPrefixShort, p, fmt.Sprintf("%d tag(s); each prefix needs at least %d", count[p], minPrefixWindow)))
		}
	}
	if len(st) > 0 {
		return nil, nil, sortStops(st)
	}
	switches := 0
	for i := 1; i < len(out); i++ {
		if out[i].Prefix != out[i-1].Prefix {
			switches++
		}
	}
	if switches != 1 {
		return nil, nil, []Stop{stop(StopMultiPrefixAmbiguous, "", fmt.Sprintf("the two prefixes interleave in version order (%d switch-overs); one switch-over is the only accepted shape", switches))}
	}
	newest := out[len(out)-1].Prefix
	other := a
	if newest == a {
		other = b
	}
	return out, []string{newest, other}, nil
}

// checkPrefixWindows proves, after the window is known, that every prefix
// still holds its own window of at least minPrefixWindow tags and that every
// prefix reads the same set of API groups. A prefix whose older tags were
// withheld by the window, or that reads another group set, is a typed stop:
// two different release lines are never merged into one claim.
func checkPrefixWindows(prefixes []string, tags []parsedTag, window []*tagResult) ([]PrefixWindow, []Stop) {
	if len(tags) != len(window) {
		return nil, []Stop{stop(StopBadInput, "", "internal: prefix window and tag window differ")}
	}
	byPrefix := map[string]*PrefixWindow{}
	sets := map[string]map[string]bool{}
	for _, p := range prefixes {
		byPrefix[p] = &PrefixWindow{Prefix: p, Tags: []string{}, Groups: []string{}}
		sets[p] = map[string]bool{}
	}
	for i, t := range tags {
		pw, ok := byPrefix[t.Prefix]
		if !ok {
			return nil, []Stop{stop(StopMultiPrefixAmbiguous, t.Tag, "the window tag has a prefix outside the run's prefixes")}
		}
		pw.Tags = append(pw.Tags, t.Tag)
		for _, inc := range window[i].included {
			for _, c := range inc.CRDs {
				sets[t.Prefix][c.Group] = true
			}
		}
	}
	var stops []Stop
	var out []PrefixWindow
	for _, p := range prefixes {
		pw := byPrefix[p]
		for g := range sets[p] {
			pw.Groups = append(pw.Groups, g)
		}
		sort.Strings(pw.Groups)
		if len(pw.Tags) < minPrefixWindow {
			stops = append(stops, stop(StopMultiPrefixShort, p, fmt.Sprintf("only %d tag(s) of this prefix are in the window; the other tags were withheld", len(pw.Tags))))
		}
		out = append(out, *pw)
	}
	if len(stops) > 0 {
		return nil, stops
	}
	if g0, g1 := strings.Join(out[0].Groups, ","), strings.Join(out[1].Groups, ","); g0 != g1 {
		return nil, []Stop{stop(StopMultiPrefixGroups, out[1].Prefix, fmt.Sprintf("prefix %q reads groups [%s], prefix %q reads [%s]", out[0].Prefix, g0, out[1].Prefix, g1))}
	}
	return out, nil
}
