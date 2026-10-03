// SPDX-License-Identifier: AGPL-3.0-only

// Package strictjson checks that a JSON document has exactly one reading.
//
// Go's struct decoding matches object member names without regard to letter
// case (Unicode simple case folding) and keeps the last of repeated members,
// while a decode into a map keeps every spelling. A document with members
// "rule" and "Rule", or with "rule" twice, therefore means different things to
// different readers. Check refuses such documents, at every depth, so every
// reader that runs after it sees the same values.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrAmbiguous reports a document that is not plain, unambiguous JSON.
var ErrAmbiguous = errors.New("ambiguous JSON")

// DefaultMaxDepth bounds nesting.
const DefaultMaxDepth = 64

// Check returns nil when raw is one JSON value, valid UTF-8, nested at most
// DefaultMaxDepth deep, in which no object holds two members whose names are
// equal or equal under Unicode simple case folding.
func Check(raw []byte) error {
	return CheckDepth(raw, DefaultMaxDepth)
}

// CheckDepth is Check with a caller-supplied nesting bound.
func CheckDepth(raw []byte, maxDepth int) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: not valid UTF-8", ErrAmbiguous)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walk(dec, 0, maxDepth, "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the JSON value", ErrAmbiguous)
	}
	return nil
}

// FoldKey maps a member name to a key equal for exactly the names Go's
// encoding/json treats as the same member: each rune is replaced by the
// smallest rune of its simple case folding orbit.
func FoldKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		b.WriteRune(least)
	}
	return b.String()
}

func walk(dec *json.Decoder, depth, maxDepth int, at string) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nested deeper than %d at %s", ErrAmbiguous, maxDepth, at)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAmbiguous, err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrAmbiguous, err)
			}
			name, ok := tok.(string)
			if !ok {
				return fmt.Errorf("%w: member name is not a string at %s", ErrAmbiguous, at)
			}
			key := FoldKey(name)
			if prior, dup := seen[key]; dup {
				if prior == name {
					return fmt.Errorf("%w: member %q repeated at %s", ErrAmbiguous, name, at)
				}
				return fmt.Errorf("%w: members %q and %q differ only in letter case at %s", ErrAmbiguous, prior, name, at)
			}
			seen[key] = name
			if err := walk(dec, depth+1, maxDepth, at+"."+name); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walk(dec, depth+1, maxDepth, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrAmbiguous, err)
	}
	return nil
}

// Decode checks raw with Check and then decodes it into v, refusing
// members v does not declare and any data after the value.
func Decode(raw []byte, v any) error {
	if err := Check(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the JSON value", ErrAmbiguous)
	}
	return nil
}
