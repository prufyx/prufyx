// SPDX-License-Identifier: AGPL-3.0-only
package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

type node struct {
	start, end int
	value      any
	object     map[string]*node
	array      []*node
}

// parse retains token spans; no unknown value is decoded and re-encoded.
func parse(raw []byte) (*node, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (*node, error)
	read = func(depth int) (*node, error) {
		if depth > 64 {
			return nil, errors.New("JSON nesting limit")
		}
		start := int(d.InputOffset())
		for start < len(raw) && bytes.ContainsRune([]byte(" \r\n\t,:"), rune(raw[start])) {
			start++
		}
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		n := &node{start: start, value: t}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				n.object = map[string]*node{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					s, ok := k.(string)
					if !ok {
						return nil, errors.New("nonstring member")
					}
					if _, ok = n.object[s]; ok {
						return nil, errors.New("duplicate JSON member")
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					n.object[s] = v
				}
			case '[':
				n.array = []*node{}
				for d.More() {
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					n.array = append(n.array, v)
				}
			default:
				return nil, errors.New("unexpected delimiter")
			}
			if _, e = d.Token(); e != nil {
				return nil, e
			}
		}
		n.end = int(d.InputOffset())
		return n, nil
	}
	n, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return n, nil
}
func member(n *node, k string) (*node, error) {
	if n == nil || n.object == nil {
		return nil, errors.New("expected object")
	}
	v, ok := n.object[k]
	if !ok {
		return nil, errors.New("missing " + k)
	}
	return v, nil
}
func text(n *node) (string, error) {
	if n == nil {
		return "", errors.New("missing string")
	}
	s, ok := n.value.(string)
	if !ok || s == "" {
		return "", errors.New("expected nonempty string")
	}
	return s, nil
}
