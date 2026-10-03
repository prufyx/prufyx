// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"encoding/json"
	"regexp"
	"strings"
)

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func asStr(v any) string {
	s, _ := v.(string)
	return s
}

// scalar reads a string, or a number written without quotes, as text.
func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	}
	return "", false
}

func get(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

var pinned = regexp.MustCompile(`^=?v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// isPinned reports an exact version or a digest. A range, a wildcard, a
// partial version, an empty value and a template are not pinned.
func isPinned(version string) bool {
	return len(version) <= MaxFieldBytes && (pinned.MatchString(version) || digestRe.MatchString(version))
}

// splitImage separates an image reference into name, tag and digest.
func splitImage(ref string) (image, tag, digest string, ok bool) {
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") {
		return "", "", "", false
	}
	rest := ref
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest, digest = rest[:i], rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 && i > strings.LastIndexByte(rest, '/') {
		rest, tag = rest[:i], rest[i+1:]
	}
	if rest == "" {
		return "", "", "", false
	}
	return rest, tag, digest, true
}

func fits(values ...string) bool {
	for _, v := range values {
		if len(v) > MaxFieldBytes {
			return false
		}
	}
	return true
}
