// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import "sort"

// closest returns up to limit candidates nearest to name by edit distance,
// ties broken lexically. The order is deterministic.
func closest(name string, candidates []string, limit int) []string {
	type scored struct {
		value    string
		distance int
	}
	scoredList := make([]scored, 0, len(candidates))
	for _, candidate := range candidates {
		scoredList = append(scoredList, scored{candidate, editDistance(name, candidate)})
	}
	sort.Slice(scoredList, func(i, j int) bool {
		if scoredList[i].distance != scoredList[j].distance {
			return scoredList[i].distance < scoredList[j].distance
		}
		return scoredList[i].value < scoredList[j].value
	})
	out := make([]string, 0, limit)
	for index := 0; index < len(scoredList) && index < limit; index++ {
		out = append(out, scoredList[index].value)
	}
	return out
}

// editDistance is the Levenshtein distance over bytes.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}
