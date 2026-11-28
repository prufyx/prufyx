// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"
	"unicode"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// location is a parsed source URL.
type location struct{ repo, commit, path string }

// parseSourceURL accepts exactly the two pinned github.com file forms:
//
//	https://github.com/<owner>/<repo>/blob/<40 hex>/<path>
//	https://raw.githubusercontent.com/<owner>/<repo>/<40 hex>/<path>
//
// A query, fragment, percent escape, backslash, space, control character,
// empty segment or dot segment is refused.
func parseSourceURL(raw string) (location, bool) {
	if strings.ContainsAny(raw, "?#%\\") || strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	}) >= 0 {
		return location{}, false
	}
	rest, blob := strings.CutPrefix(raw, "https://github.com/")
	if !blob {
		var ok bool
		if rest, ok = strings.CutPrefix(raw, "https://raw.githubusercontent.com/"); !ok {
			return location{}, false
		}
	}
	parts := strings.Split(rest, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return location{}, false
		}
	}
	if blob {
		if len(parts) < 5 || parts[2] != "blob" {
			return location{}, false
		}
		parts = append(parts[:2], parts[3:]...)
	}
	if len(parts) < 4 || !nameRE.MatchString(parts[0]) || !nameRE.MatchString(parts[1]) || !commitRE.MatchString(parts[2]) {
		return location{}, false
	}
	return location{repo: parts[0] + "/" + parts[1], commit: parts[2], path: strings.Join(parts[3:], "/")}, true
}

var noteExtensions = map[string]bool{".md": true, ".markdown": true, ".mdx": true, ".rst": true, ".adoc": true, ".txt": true}

var noteNames = map[string]bool{"changes": true, "news": true, "history": true, "changelog": true, "release-notes": true, "release_notes": true, "releasenotes": true}

var noteDirectories = map[string]bool{"changelog": true, "changelogs": true, "release-notes": true, "release_notes": true, "releasenotes": true}

var (
	versionedNoteRE = regexp.MustCompile(`^(changelog|release-notes|release_notes)[-_.]v?[0-9]+(\.[0-9]+)*$`)
	versionStemRE   = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*$`)
)

// isReleaseNotes is the closed classification of changelog and release note
// files. It needs a text extension and either a closed file name (optionally
// followed by a version) or a version as the name of a file directly in a
// notes directory. Everything else counts as code, including any file without
// an extension and any other file in a notes directory.
func isReleaseNotes(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	ext := path.Ext(base)
	// "changelog-1.24" has no text extension; ".24" is part of the name.
	if !noteExtensions[ext] {
		return false
	}
	stem := strings.TrimSuffix(base, ext)
	if noteNames[stem] || versionedNoteRE.MatchString(stem) {
		return true
	}
	return noteDirectories[path.Base(path.Dir(lower))] && versionStemRE.MatchString(stem)
}

// splitLines splits after every newline and keeps it. A final line without a
// newline is its own line and differs from the same text with one.
func splitLines(data []byte) [][]byte {
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// occurrences returns the 1-based start lines at which the whole-line
// sequence span occurs, byte exact, overlapping occurrences included.
func occurrences(data []byte, span [][]byte) []int {
	lines := splitLines(data)
	var found []int
	for i := 0; i+len(span) <= len(lines); i++ {
		match := true
		for j := range span {
			if !bytes.Equal(lines[i+j], span[j]) {
				match = false
				break
			}
		}
		if match {
			found = append(found, i+1)
		}
	}
	return found
}
