// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"sort"
	"strings"
)

// ValueAt returns the value at a key path of a decoded values document
// and whether every key on the path exists. A null value exists here; the
// callers decide what null means (Helm drops null keys when it merges).
func ValueAt(values any, path []string) (any, bool) {
	cur := values
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// ValuePaths lists every key path of the document whose value is not
// null, through mappings only (a list is a leaf), in path order.
func ValuePaths(values any) [][]string {
	var out [][]string
	var visit func(v any, path []string)
	visit = func(v any, path []string) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if m[k] == nil {
				continue
			}
			p := AppendPath(path, k)
			out = append(out, p)
			visit(m[k], p)
		}
	}
	visit(values, nil)
	return out
}

// AppendPath returns a new path: path followed by k.
func AppendPath(path []string, k string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = k
	return out
}

// DisplayPath renders a key path for people: keys joined by ".", the root
// as "(root)". A key holding a "." makes it ambiguous, so it is never a set
// member; see Member.
func DisplayPath(path []string) string {
	if len(path) == 0 {
		return "(root)"
	}
	return strings.Join(path, ".")
}
