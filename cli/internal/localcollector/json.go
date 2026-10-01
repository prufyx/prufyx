// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxJSONDepth = 64
	maxJSONNodes = 250_000
)

var errInvalidJSON = errors.New("strict JSON rejected")

// DecodeStrict rejects duplicate object members, trailing values and excessive
// nesting before any API response is passed to a projection stage.
func DecodeStrict(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	nodes := 0
	value, err := decodeValue(dec, 0, &nodes)
	if err != nil {
		return nil, errInvalidJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalidJSON
	}
	return value, nil
}

func decodeValue(dec *json.Decoder, depth int, nodes *int) (any, error) {
	if depth > maxJSONDepth || *nodes >= maxJSONNodes {
		return nil, errInvalidJSON
	}
	(*nodes)++
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		out := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errInvalidJSON
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("%w: duplicate member", errInvalidJSON)
			}
			value, err := decodeValue(dec, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errInvalidJSON
		}
		return out, nil
	case '[':
		out := make([]any, 0)
		for dec.More() {
			value, err := decodeValue(dec, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errInvalidJSON
		}
		return out, nil
	default:
		return nil, errInvalidJSON
	}
}
