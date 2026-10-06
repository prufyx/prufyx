// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// unsafeRune is a rune that must never reach a terminal, a log or a
// Markdown document as itself: control characters (C0, DEL and C1, which
// carry terminal escape sequences and carriage returns), format characters
// (bidirectional controls, zero-width and tag characters), the Unicode line
// and paragraph separators, and the surrogate range.
func unsafeRune(r rune) bool {
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || (r >= 0xD800 && r <= 0xDFFF)
}

// Sanitize makes a string that came from the scanned input or from
// knowledge text safe to print. Each unsafe rune is replaced by a visible
// escape, "\xNN" below U+0100 and "\uXXXX" or "\UXXXXXXXX" above, and each
// byte that is not valid UTF-8 by "\xNN". Backslash is left alone, so the
// function is idempotent, and printable text is returned byte for byte.
func Sanitize(text string) string {
	clean := true
	for _, r := range text {
		if unsafeRune(r) || r == utf8.RuneError {
			clean = false
			break
		}
	}
	if clean {
		return text
	}
	var out strings.Builder
	for index := 0; index < len(text); {
		r, size := utf8.DecodeRuneInString(text[index:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&out, "\\x%02x", text[index])
		case unsafeRune(r):
			switch {
			case r < 0x100:
				fmt.Fprintf(&out, "\\x%02x", r)
			case r < 0x10000:
				fmt.Fprintf(&out, "\\u%04x", r)
			default:
				fmt.Fprintf(&out, "\\U%08x", r)
			}
		default:
			out.WriteString(text[index : index+size])
		}
		index += size
	}
	return out.String()
}

// sanitizeArgs sanitizes the string arguments of a format call. The format
// itself is catalog text and is never passed through it.
func sanitizeArgs(args []any) []any {
	out := make([]any, len(args))
	for i, arg := range args {
		switch value := arg.(type) {
		case string:
			out[i] = Sanitize(value)
		case error:
			out[i] = Sanitize(value.Error())
		default:
			out[i] = arg
		}
	}
	return out
}

// escapeJSON rewrites the runes that Sanitize would escape, which the JSON
// encoder leaves raw (DEL, C1, format characters), as \u escapes. They only
// occur inside strings, and the decoded value is unchanged.
func escapeJSON(raw []byte) []byte {
	clean := true
	for _, r := range string(raw) {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return raw
	}
	var out strings.Builder
	for _, r := range string(raw) {
		switch {
		case r == '\n' || !unsafeRune(r):
			out.WriteRune(r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(&out, "\\u%04x\\u%04x", 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&out, "\\u%04x", r)
		}
	}
	return []byte(out.String())
}
