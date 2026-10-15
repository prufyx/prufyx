// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"strings"
)

// MaxMemberBytes bounds an encoded member: the set-member bound of the
// constraint engine.
const MaxMemberBytes = 128

// EscapedPrefix starts every member in the escaped form. No member in the
// plain form contains "..", and every member in the escaped form does.
const EscapedPrefix = "k.."

// separator separates the keys of a member in the escaped form.
const separator = ".."

const hexDigits = "0123456789ABCDEF"

// Member renders a key path as a set member, in one of two forms:
//
//   - plain: when every key is non-empty over [A-Za-z0-9_/-] and the first
//     key starts with a letter or digit, the keys joined by ".";
//   - escaped: otherwise, "k.." followed by the keys joined by "..", each
//     key with every byte outside [A-Za-z0-9/-] written as "_" and two
//     upper-case hex digits ("_" itself is "_5F", "." is "_2E").
//
// Both forms are inside the engine's set-member grammar, and the same path
// always gives the same member. ok is false for the root (an empty path),
// an empty key, or a member over MaxMemberBytes bytes; no member names
// such a path.
func Member(path []string) (member string, ok bool) {
	if len(path) == 0 {
		return "", false
	}
	for _, k := range path {
		// No values file can hold an empty key or one with a NUL byte (the
		// decoder refuses both), so such a key never becomes a member.
		if k == "" || strings.IndexByte(k, 0) >= 0 {
			return "", false
		}
	}
	if plainPath(path) {
		m := strings.Join(path, ".")
		if len(m) > MaxMemberBytes {
			return "", false
		}
		return m, true
	}
	var b strings.Builder
	b.WriteString(EscapedPrefix)
	for i, k := range path {
		if i > 0 {
			b.WriteString(separator)
		}
		for j := 0; j < len(k); j++ {
			c := k[j]
			if escapedLiteral(c) {
				b.WriteByte(c)
				continue
			}
			b.WriteByte('_')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
		if b.Len() > MaxMemberBytes {
			return "", false
		}
	}
	return b.String(), true
}

// Path reads a member back into its key path. It accepts only canonical
// members, those Member returns: ok is false for anything else, including
// the escaped form of a path the plain form can express, lower-case or
// truncated escapes, an escape of a byte the escaped form writes as
// itself, and empty keys.
func Path(member string) (path []string, ok bool) {
	path, ok = parse(member)
	if !ok {
		return nil, false
	}
	if again, ok := Member(path); !ok || again != member {
		return nil, false
	}
	return path, true
}

// Canonical reports whether member is exactly what Member renders for some
// key path. A rule member that is not canonical could never equal a member
// a values reader produces for the same path.
func Canonical(member string) bool {
	_, ok := Path(member)
	return ok
}

// parse reads either form without checking that it is canonical.
func parse(member string) ([]string, bool) {
	if member == "" || len(member) > MaxMemberBytes {
		return nil, false
	}
	if !strings.HasPrefix(member, EscapedPrefix) {
		if strings.Contains(member, separator) {
			return nil, false
		}
		path := strings.Split(member, ".")
		if !plainPath(path) {
			return nil, false
		}
		return path, true
	}
	segs := strings.Split(member[len(EscapedPrefix):], separator)
	path := make([]string, 0, len(segs))
	for _, seg := range segs {
		if seg == "" {
			return nil, false
		}
		var key []byte
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			switch {
			case escapedLiteral(c):
				key = append(key, c)
			case c == '_' && j+2 < len(seg):
				hi, lo := hexValue(seg[j+1]), hexValue(seg[j+2])
				if hi < 0 || lo < 0 {
					return nil, false
				}
				key = append(key, byte(hi<<4|lo))
				j += 2
			default:
				return nil, false
			}
		}
		path = append(path, string(key))
	}
	return path, true
}

// plainPath reports whether the plain form can express path.
func plainPath(path []string) bool {
	if len(path) == 0 || path[0] == "" || !alnum(path[0][0]) {
		return false
	}
	for _, k := range path {
		if k == "" {
			return false
		}
		for j := 0; j < len(k); j++ {
			if c := k[j]; !escapedLiteral(c) && c != '_' {
				return false
			}
		}
	}
	return true
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// escapedLiteral reports a byte the escaped form writes as itself.
func escapedLiteral(c byte) bool { return alnum(c) || c == '/' || c == '-' }

// hexValue is the value of an upper-case hex digit, -1 for any other byte.
func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
