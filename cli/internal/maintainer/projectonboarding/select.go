// SPDX-License-Identifier: AGPL-3.0-only

package projectonboarding

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrWindowCap means the bounded release-list read ended before the list did
// and before enough versions were collected to fill the requested window.
var ErrWindowCap = errors.New("release list cap reached before enough versions")

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

type version struct {
	core [3]uint64
	pre  []string
}

// parseVersion reads a semantic version out of tag after dropping the request
// prefix and one leading "v". Anything else is reported as not a version.
func parseVersion(tag, prefix string) (version, bool) {
	text := strings.TrimPrefix(strings.TrimPrefix(tag, prefix), "v")
	m := semverRE.FindStringSubmatch(text)
	if m == nil {
		return version{}, false
	}
	var v version
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return version{}, false
		}
		v.core[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		for _, id := range v.pre {
			if isNumeric(id) && len(id) > 1 && id[0] == '0' {
				return version{}, false
			}
		}
	}
	return v, true
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// compareVersion follows semver precedence (build metadata ignored).
func compareVersion(a, b version) int {
	for i := 0; i < 3; i++ {
		if a.core[i] != b.core[i] {
			if a.core[i] < b.core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xn, yn := isNumeric(x), isNumeric(y)
		switch {
		case xn && yn:
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
		case xn:
			return -1
		case yn:
			return 1
		}
		if x < y {
			return -1
		}
		return 1
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

type choice struct {
	release githubRelease
	page    int
	ver     version
}

// selectByVersion picks the r.limit newest eligible releases by version, not
// by list order, from every page read. Selection order is newest first. The
// result depends only on the page bytes, so sync and offline verification
// agree.
func selectByVersion(pages [][]githubRelease, r request) (chosen []choice, skippedNonSemver, candidates int, truncated bool, err error) {
	seenIDs, seenTags := map[int64]bool{}, map[string]bool{}
	all := []choice{}
	for pageIndex, page := range pages {
		if pageIndex < len(pages)-1 && len(page) != releasePageSize {
			return nil, 0, 0, false, ErrRejected
		}
		candidates += len(page)
		for _, rel := range page {
			if *rel.Draft || *rel.Prerelease || rel.ID < 1 || !tagRE.MatchString(rel.Tag) || (r.prefix != "" && !strings.HasPrefix(rel.Tag, r.prefix)) || !validTimestamp(rel.Published) {
				continue
			}
			if seenIDs[rel.ID] || seenTags[rel.Tag] {
				return nil, 0, 0, false, ErrRejected
			}
			seenIDs[rel.ID], seenTags[rel.Tag] = true, true
			v, ok := parseVersion(rel.Tag, r.prefix)
			if !ok {
				skippedNonSemver++
				continue
			}
			all = append(all, choice{rel, pageIndex, v})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if c := compareVersion(all[i].ver, all[j].ver); c != 0 {
			return c > 0
		}
		return all[i].release.Tag > all[j].release.Tag
	})
	if len(all) > r.limit {
		all = all[:r.limit]
	}
	if n := len(pages); n > maxReleasePages || n > 0 && len(pages[n-1]) > releasePageSize {
		return nil, 0, 0, false, ErrRejected
	} else if n == maxReleasePages && len(pages[n-1]) == releasePageSize {
		truncated = true
	}
	if truncated && len(all) < r.limit {
		return nil, 0, 0, false, ErrWindowCap
	}
	return all, skippedNonSemver, candidates, truncated, nil
}
