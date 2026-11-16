package crdversions

import (
	"path"
	"regexp"
	"strings"
)

// ReasonFailMessage is the reason of a Helm partial that names the kind
// only inside fail messages.
const ReasonFailMessage = "source-fail-message"

// strLit is an interpreted string without a newline and with only the
// escapes \\ \" \n \r \t, or a raw string. Any other backslash escape is
// not accepted.
const strLit = "(?:\"(?:[^\"\\\\\n]|\\\\[\\\\\"nrt])*\"|`[^`]*`)"

const ws = "[ \t\r\n]+"

var (
	failRE   = regexp.MustCompile("^fail" + ws + strLit + "$")
	defineRE = regexp.MustCompile("^define" + ws + strLit + "$")
	hasRE    = regexp.MustCompile("^(?:if|else" + ws + "if)" + ws + `\.Capabilities\.APIVersions\.Has` + ws + strLit + "$")
	plainRE  = regexp.MustCompile("^(?:end|else)$")
)

// failOnlyPartial reports whether the bytes of a template partial are made
// only of actions from a closed list and name the kind only inside
// `fail "<literal>"`. It is a function of the bytes: a failed check, or any
// template syntax that is not plainly well formed, gives false (the file
// stays unsupported).
//
//  1. Every action is well formed: it closes, holds no "{{", and a string
//     literal in it holds no "}}" and does not run over a line (an
//     interpreted one) or past the end of the file.
//  2. Every action is one of: a comment that does not hold the kind name;
//     `define <literal>`; `end`; `else`; `if` or `else if` of exactly
//     `.Capabilities.APIVersions.Has <literal>`; `fail <literal>`. Any other
//     action (print, printf, cat, tpl, include, variable, pipe, call,
//     parenthesis) refuses the file, so the kind name cannot be built by an
//     action.
//  3. All the text outside the actions, joined without the actions, holds
//     neither the kind name nor apiextensions.k8s.io, in any case.
//  4. The kind name stands only in the literal of a `fail` action, and at
//     least one such action holds it.
//
// Interpreted literals accept only the escapes \\ \" \n \r \t.
func failOnlyPartial(data []byte) bool {
	if len(data) > MaxFileBytes {
		return false
	}
	s := string(data)
	seen := false
	var outside strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			outside.WriteString(s)
			return checkOutside(outside.String()) && seen
		}
		outside.WriteString(s[:i])
		body, comment, rest, ok := readAction(s[i+2:])
		if !ok {
			return false
		}
		s = rest
		trimmed := strings.Trim(body, " \t\r\n")
		switch {
		case comment:
			if holdsKind(body) {
				return false
			}
		case failRE.MatchString(trimmed):
			if holdsKind(trimmed) {
				seen = true
			}
		case holdsKind(trimmed):
			return false
		case defineRE.MatchString(trimmed), hasRE.MatchString(trimmed), plainRE.MatchString(trimmed):
		default:
			return false
		}
	}
}

func checkOutside(t string) bool {
	l := strings.ToLower(t)
	return !strings.Contains(l, "customresourcedefinition") && !strings.Contains(l, "apiextensions.k8s.io")
}

func holdsKind(body string) bool {
	return strings.Contains(strings.ToLower(body), "customresourcedefinition")
}

// readAction reads one action after its opening "{{". It returns the body
// without trim markers, whether it is a comment, the text after the closing
// "}}", and false when the action is not well formed.
func readAction(s string) (body string, comment bool, rest string, ok bool) {
	// Opening trim marker: "-" and a space.
	if len(s) >= 2 && s[0] == '-' && strings.ContainsRune(" \t\r\n", rune(s[1])) {
		s = s[1:]
	}
	// A comment runs to "*/", then an optional trim marker and "}}".
	if t := strings.TrimLeft(s, " \t\r\n"); strings.HasPrefix(t, "/*") {
		end := strings.Index(t[2:], "*/")
		if end < 0 {
			return "", false, "", false
		}
		text := t[2 : 2+end]
		after := t[2+end+2:]
		if strings.Contains(text, "{{") {
			return "", false, "", false
		}
		after = strings.TrimLeft(after, " \t\r\n")
		if strings.HasPrefix(after, "-}}") {
			// The marker needs the space before it, trimmed above: accept
			// only when whitespace stood there.
			if len(t[2+end+2:]) == len(after) {
				return "", false, "", false
			}
			return text, true, after[3:], true
		}
		if strings.HasPrefix(after, "}}") && len(t[2+end+2:]) == len(after) {
			return text, true, after[2:], true
		}
		return "", false, "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\n' {
					return "", false, "", false
				}
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return "", false, "", false
			}
			if strings.Contains(s[i:j+1], "{{") || strings.Contains(s[i:j+1], "}}") {
				return "", false, "", false
			}
			b.WriteString(s[i : j+1])
			i = j + 1
		case c == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				return "", false, "", false
			}
			lit := s[i : i+j+2]
			if strings.Contains(lit, "{{") || strings.Contains(lit, "}}") {
				return "", false, "", false
			}
			b.WriteString(lit)
			i += j + 2
		case c == '\'':
			j := i + 1
			for ; j < len(s) && s[j] != '\'' && s[j] != '\n'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) || s[j] != '\'' {
				return "", false, "", false
			}
			b.WriteString(s[i : j+1])
			i = j + 1
		case strings.HasPrefix(s[i:], "{{"):
			return "", false, "", false
		case strings.HasPrefix(s[i:], "}}"):
			out := b.String()
			// A closing trim marker is "-" after whitespace.
			if n := len(out); n >= 2 && out[n-1] == '-' && strings.ContainsRune(" \t\r\n", rune(out[n-2])) {
				out = out[:n-1]
			}
			return out, false, s[i+2:], true
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", false, "", false
}

// failPartialPlace reports whether the path and place allow the fail-message
// rule: a "_*.tpl" file directly under a chart's templates directory (the
// chart file beside it is checked by the caller), in the open tree, under a
// default-excluded directory or under a void entry. Under a reviewed
// exclusion the finding keeps its class.
func failPartialPlace(p string, at place) bool {
	if at.kind == locReviewed {
		return false
	}
	base := path.Base(p)
	return strings.HasPrefix(base, "_") && strings.HasSuffix(base, ".tpl") && path.Base(path.Dir(p)) == "templates"
}
