// SPDX-License-Identifier: AGPL-3.0-only

// Package membercode is the one encoder of set-fact members. Extractors and
// collectors that name the same thing (a CRD field, an enum value, a command
// line flag, a config key) must produce the same member bytes, because the
// rule engine matches members exactly: a second encoder that drifts would
// turn a removed setting into a missed match. Every encoding is therefore
// defined here and nowhere else.
//
// A member is a public identifier of at most constraintengine.MaxSetMemberBytes
// bytes over [A-Za-z0-9._/-]. Encodings:
//
//	field       group/Kind/seg/seg/...
//	enum value  group/Kind/seg/seg/.../value
//	flag        flag
//	config key  seg.seg.seg
//
// An array item segment is "_item_" and a map value segment is "_any_". A
// real property with either of those names, a name that holds the separator,
// a name outside the charset or a member that is too long is refused with a
// typed error; the caller withholds the item instead of emitting a lossy
// member.
package membercode

import (
	"embed"
	"errors"
	"io/fs"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

//go:embed *.go
var source embed.FS

// Source is this package's own Go source, so that an extractor can fold the
// encoder into its code digest.
func Source() fs.FS { return source }

// Reserved segment names.
const (
	ItemSegment = "_item_"
	AnySegment  = "_any_"
)

// Errors a caller maps to withhold reasons.
var (
	ErrCharset   = errors.New("member contains a character outside the member charset")
	ErrTooLong   = errors.New("member is too long")
	ErrAmbiguous = errors.New("member would be ambiguous")
)

// SegKind says what a path segment is.
type SegKind uint8

// Segment kinds.
const (
	Prop SegKind = iota // a named property
	Item                // array item
	Any                 // additionalProperties value
)

// Seg is one path segment. Name is used for Prop only.
type Seg struct {
	Kind SegKind
	Name string
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// checkName validates one name that is joined with sep.
func checkName(s string, sep byte) error {
	if s == "" {
		return ErrCharset
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == sep {
			continue
		}
		if !isNameByte(c) && c != '/' {
			return ErrCharset
		}
	}
	if strings.IndexByte(s, sep) >= 0 || strings.IndexByte(s, '/') >= 0 {
		return ErrAmbiguous
	}
	return nil
}

func segText(s Seg, sep byte) (string, error) {
	switch s.Kind {
	case Item:
		return ItemSegment, nil
	case Any:
		return AnySegment, nil
	case Prop:
		if err := checkName(s.Name, sep); err != nil {
			return "", err
		}
		if s.Name == ItemSegment || s.Name == AnySegment {
			return "", ErrAmbiguous
		}
		return s.Name, nil
	}
	return "", ErrCharset
}

func finish(m string) (string, error) {
	if len(m) > constraintengine.MaxSetMemberBytes {
		return "", ErrTooLong
	}
	if !constraintengine.ValidSetMember(m) {
		return "", ErrCharset
	}
	return m, nil
}

func join(sep byte, head []string, path []Seg, tail ...string) (string, error) {
	parts := append([]string(nil), head...)
	for _, s := range path {
		t, err := segText(s, sep)
		if err != nil {
			return "", err
		}
		parts = append(parts, t)
	}
	parts = append(parts, tail...)
	return finish(strings.Join(parts, string(sep)))
}

func gk(group, kind string) ([]string, error) {
	if err := checkName(group, '/'); err != nil {
		return nil, err
	}
	if err := checkName(kind, '/'); err != nil {
		return nil, err
	}
	return []string{group, kind}, nil
}

// Field encodes a CRD field path. The path must hold at least one segment.
func Field(group, kind string, path []Seg) (string, error) {
	if len(path) == 0 {
		return "", ErrCharset
	}
	head, err := gk(group, kind)
	if err != nil {
		return "", err
	}
	return join('/', head, path)
}

// Enum encodes one enum value of a CRD field path.
func Enum(group, kind string, path []Seg, value string) (string, error) {
	if len(path) == 0 {
		return "", ErrCharset
	}
	head, err := gk(group, kind)
	if err != nil {
		return "", err
	}
	if err := checkName(value, '/'); err != nil {
		return "", err
	}
	return join('/', head, path, value)
}

// Flag encodes a command line flag name (without leading dashes). Flags are
// matched by long name only: there is no subcommand form.
func Flag(flag string) (string, error) {
	if err := checkName(flag, '/'); err != nil {
		return "", err
	}
	return finish(flag)
}

// ConfigKey encodes a config key path, dot separated. A name that holds a dot
// is ambiguous and refused.
func ConfigKey(path []Seg) (string, error) {
	if len(path) == 0 {
		return "", ErrCharset
	}
	return join('.', nil, path)
}

func decodeSeg(t string) Seg {
	switch t {
	case ItemSegment:
		return Seg{Kind: Item}
	case AnySegment:
		return Seg{Kind: Any}
	}
	return Seg{Kind: Prop, Name: t}
}

// DecodeField inverts Field. ok is false for any string Field cannot produce.
func DecodeField(member string) (group, kind string, path []Seg, ok bool) {
	parts := strings.Split(member, "/")
	if len(parts) < 3 {
		return "", "", nil, false
	}
	for _, p := range parts[2:] {
		path = append(path, decodeSeg(p))
	}
	back, err := Field(parts[0], parts[1], path)
	if err != nil || back != member {
		return "", "", nil, false
	}
	return parts[0], parts[1], path, true
}

// DecodeEnum inverts Enum.
func DecodeEnum(member string) (group, kind string, path []Seg, value string, ok bool) {
	parts := strings.Split(member, "/")
	if len(parts) < 4 {
		return "", "", nil, "", false
	}
	value = parts[len(parts)-1]
	for _, p := range parts[2 : len(parts)-1] {
		path = append(path, decodeSeg(p))
	}
	back, err := Enum(parts[0], parts[1], path, value)
	if err != nil || back != member {
		return "", "", nil, "", false
	}
	return parts[0], parts[1], path, value, true
}
