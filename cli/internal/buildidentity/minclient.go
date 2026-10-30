// SPDX-License-Identifier: AGPL-3.0-only

package buildidentity

import (
	"strconv"
	"strings"
)

// MeetsMinimum reports whether this build is at least min, a semantic
// version with an optional leading "v" (vMAJOR.MINOR.PATCH[-pre.N]). A
// development build accepts every minimum. A minimum that is not a semantic
// version is not met: a build cannot show it satisfies what it cannot read.
func MeetsMinimum(min string) bool {
	return meetsMinimum(Version, min)
}

func meetsMinimum(have, min string) bool {
	if have == DevelopmentVersion {
		return true
	}
	if !ValidVersion(min) || !ValidVersion(have) {
		return false
	}
	return compareSemver(have, min) >= 0
}

type semver struct {
	core [3]uint64
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var out semver
	if i := strings.IndexByte(v, '-'); i >= 0 {
		out.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return out, false
		}
		out.core[i] = n
	}
	return out, true
}

// compareSemver follows semver 2.0 precedence; build metadata is ignored.
func compareSemver(a, b string) int {
	x, okx := parseSemver(a)
	y, oky := parseSemver(b)
	if !okx || !oky {
		return -1
	}
	for i := range x.core {
		if x.core[i] != y.core[i] {
			if x.core[i] < y.core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0
	case len(x.pre) == 0:
		return 1
	case len(y.pre) == 0:
		return -1
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		xn, xerr := strconv.ParseUint(x.pre[i], 10, 64)
		yn, yerr := strconv.ParseUint(y.pre[i], 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x.pre[i], y.pre[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(x.pre) < len(y.pre):
		return -1
	case len(x.pre) > len(y.pre):
		return 1
	}
	return 0
}
