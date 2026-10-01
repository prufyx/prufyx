// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"unicode/utf8"
)

var ErrRejected = errors.New("contribution input rejected")

func safeRead(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || linkCount(info) != 1 || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrRejected
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRejected
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maximum+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(data)) > maximum || after.Size() != info.Size() || !os.SameFile(info, after) {
		return nil, ErrRejected
	}
	return data, nil
}

func decode(raw []byte, maximum int64) (any, error) {
	if len(raw) == 0 || int64(len(raw)) > maximum || !json.Valid(raw) {
		return nil, ErrRejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeValue(dec, 0)
	if err != nil {
		return nil, ErrRejected
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, ErrRejected
	}
	return value, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrRejected
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok || len(key) == 0 || len(key) > 64 {
					return nil, ErrRejected
				}
				if _, dup := m[key]; dup {
					return nil, ErrRejected
				}
				v, e := decodeValue(dec, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
				if len(m) > 16 {
					return nil, ErrRejected
				}
			}
			_, err = dec.Token()
			return m, err
		case '[':
			a := []any{}
			for dec.More() {
				v, e := decodeValue(dec, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
				if len(a) > 512 {
					return nil, ErrRejected
				}
			}
			_, err = dec.Token()
			return a, err
		}
	case string:
		if len(t) == 0 || len(t) > 1200 {
			return nil, ErrRejected
		}
		return t, nil
	case json.Number:
		if bytes.ContainsAny([]byte(t.String()), ".eE") || len(t.String()) > 12 {
			return nil, ErrRejected
		}
		return t, nil
	case bool, nil:
		return t, nil
	}
	return nil, ErrRejected
}

func canonical(value any, newline bool) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, ErrRejected
	}
	b, err := escapeNonASCII(out.Bytes())
	if err != nil {
		return nil, ErrRejected
	}
	if !newline {
		b = bytes.TrimSuffix(b, []byte{'\n'})
	}
	return b, nil
}

func escapeNonASCII(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, ErrRejected
	}
	const hexadecimal = "0123456789abcdef"
	out := make([]byte, 0, len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		raw = raw[size:]
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
			continue
		}
		appendCodeUnit := func(value rune) {
			out = append(out, '\\', 'u', hexadecimal[(value>>12)&0xf], hexadecimal[(value>>8)&0xf], hexadecimal[(value>>4)&0xf], hexadecimal[value&0xf])
		}
		if r <= 0xffff {
			appendCodeUnit(r)
			continue
		}
		r -= 0x10000
		appendCodeUnit(0xd800 + (r >> 10))
		appendCodeUnit(0xdc00 + (r & 0x3ff))
	}
	return out, nil
}
func linkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func object(v any, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, ErrRejected
	}
	for _, k := range keys {
		if _, ok = m[k]; !ok {
			return nil, ErrRejected
		}
	}
	return m, nil
}
func stringField(m map[string]any, key string, max int) (string, error) {
	s, ok := m[key].(string)
	if !ok || !validPlainText(s, max) {
		return "", ErrRejected
	}
	return s, nil
}

func validPlainText(s string, maximum int) bool {
	if s == "" || utf8.RuneCountInString(s) > maximum {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == 0x7f || r < 0x20 || r >= 0xd800 && r <= 0xdfff {
			return false
		}
	}
	return true
}
