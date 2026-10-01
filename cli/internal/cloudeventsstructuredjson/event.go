// SPDX-License-Identifier: AGPL-3.0-only

package cloudeventsstructuredjson

import (
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"
)

var (
	ErrEventInput = errors.New("CloudEvents event input failed admission")
)

const ObservationSchema = "prufyx.io/cloudevents-structured-json-observation/v1"

type Observation struct {
	Schema                          string  `json:"schema"`
	RootAdmission                   string  `json:"rootAdmission"`
	EditionAdmission                *string `json:"editionAdmission,omitempty"`
	IDIsNonemptyValidString         *bool   `json:"idIsNonemptyValidString,omitempty"`
	SourceAdmission                 *string `json:"sourceAdmission,omitempty"`
	TypeIsNonemptyValidString       *bool   `json:"typeIsNonemptyValidString,omitempty"`
	DataAndDataBase64NotBothPresent *bool   `json:"dataAndDataBase64NotBothPresent,omitempty"`
}

type selectedValue struct {
	present  bool
	kind     byte
	text     string
	repaired bool
}

type eventScan struct {
	rootObject bool
	duplicate  bool
	selected   map[string]selectedValue
}

type jsonScanner struct {
	raw     []byte
	pos     int
	tokens  int
	members int
}

func Observe(raw []byte) (Observation, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || !json.Valid(raw) {
		return Observation{}, ErrEventInput
	}
	s := &jsonScanner{raw: raw}
	skipSpace := func() { s.space() }
	skipSpace()
	result, err := s.scanRoot()
	if err != nil {
		return Observation{}, ErrEventInput
	}
	s.space()
	if s.pos != len(raw) {
		return Observation{}, ErrEventInput
	}
	o := Observation{Schema: ObservationSchema, RootAdmission: "unsupported_root_shape"}
	if !result.rootObject {
		return o, nil
	}
	if result.duplicate {
		o.RootAdmission = "duplicate_decoded_root_name"
		return o, nil
	}
	o.RootAdmission = "admitted_root_object"
	edition := "missing_or_invalid"
	if v := result.selected["specversion"]; v.present && v.kind == 's' && validCloudEventsString(v) {
		if v.text == "1.0" {
			edition = "valid_1_0"
		} else {
			edition = "other_valid_edition"
		}
	}
	o.EditionAdmission = &edition
	if edition != "valid_1_0" {
		return o, nil
	}
	idOK := false
	if v := result.selected["id"]; v.present && v.kind == 's' {
		idOK = validCloudEventsString(v)
	}
	o.IDIsNonemptyValidString = &idOK
	if !idOK {
		return o, nil
	}
	source := "missing_or_invalid"
	if v := result.selected["source"]; v.present && v.kind == 's' && v.text != "" {
		if v.repaired {
			source = "repair_detected"
		} else {
			source = "admitted_nonempty_json_string"
		}
	}
	o.SourceAdmission = &source
	if source != "admitted_nonempty_json_string" {
		return o, nil
	}
	typeOK := false
	if v := result.selected["type"]; v.present && v.kind == 's' {
		typeOK = validCloudEventsString(v)
	}
	o.TypeIsNonemptyValidString = &typeOK
	if !typeOK {
		return o, nil
	}
	notBoth := !(result.selected["data"].present && result.selected["data_base64"].present)
	o.DataAndDataBase64NotBothPresent = &notBoth
	return o, nil
}

func validCloudEventsString(v selectedValue) bool {
	if v.text == "" || v.repaired {
		return false
	}
	for _, r := range v.text {
		if r <= 0x1f || r >= 0x7f && r <= 0x9f || r >= 0xfdd0 && r <= 0xfdef || r&0xffff == 0xfffe || r&0xffff == 0xffff {
			return false
		}
	}
	return true
}

func (s *jsonScanner) scanRoot() (eventScan, error) {
	s.space()
	if s.pos >= len(s.raw) {
		return eventScan{}, ErrEventInput
	}
	if s.raw[s.pos] != '{' {
		if _, err := s.value(0); err != nil {
			return eventScan{}, err
		}
		return eventScan{}, nil
	}
	s.pos++
	s.tokens++
	result := eventScan{rootObject: true, selected: map[string]selectedValue{}}
	seen := map[string]bool{}
	s.space()
	if s.take('}') {
		return result, nil
	}
	for {
		key, _, err := s.stringToken()
		if err != nil || len(key) > 16384 {
			return eventScan{}, ErrEventInput
		}
		s.members++
		if s.members > 100000 {
			return eventScan{}, ErrEventInput
		}
		if seen[key] {
			result.duplicate = true
		}
		seen[key] = true
		s.space()
		if !s.take(':') {
			return eventScan{}, ErrEventInput
		}
		value, err := s.value(1)
		if err != nil {
			return eventScan{}, err
		}
		if key == "specversion" || key == "id" || key == "source" || key == "type" || key == "data" || key == "data_base64" {
			value.present = true
			result.selected[key] = value
		}
		s.space()
		if s.take('}') {
			return result, nil
		}
		if !s.take(',') {
			return eventScan{}, ErrEventInput
		}
	}
}

func (s *jsonScanner) value(depth int) (selectedValue, error) {
	if depth > 24 || s.tokens > 100000 {
		return selectedValue{}, ErrEventInput
	}
	s.space()
	if s.pos >= len(s.raw) {
		return selectedValue{}, ErrEventInput
	}
	s.tokens++
	switch s.raw[s.pos] {
	case '"':
		text, repaired, err := s.stringToken()
		return selectedValue{kind: 's', text: text, repaired: repaired}, err
	case '{':
		return selectedValue{kind: 'o'}, s.object(depth + 1)
	case '[':
		return selectedValue{kind: 'a'}, s.array(depth + 1)
	case 'n':
		if s.literal("null") {
			return selectedValue{kind: 'n'}, nil
		}
	case 't':
		if s.literal("true") {
			return selectedValue{kind: 'b'}, nil
		}
	case 'f':
		if s.literal("false") {
			return selectedValue{kind: 'b'}, nil
		}
	default:
		start := s.pos
		for s.pos < len(s.raw) && !isJSONTerminator(s.raw[s.pos]) {
			s.pos++
		}
		if s.pos > start {
			return selectedValue{kind: '#'}, nil
		}
	}
	return selectedValue{}, ErrEventInput
}

func (s *jsonScanner) object(depth int) error {
	s.pos++
	s.space()
	if s.take('}') {
		return nil
	}
	for {
		key, _, err := s.stringToken()
		if err != nil || len(key) > 16384 {
			return ErrEventInput
		}
		s.members++
		if s.members > 100000 {
			return ErrEventInput
		}
		s.space()
		if !s.take(':') {
			return ErrEventInput
		}
		if _, err = s.value(depth); err != nil {
			return err
		}
		s.space()
		if s.take('}') {
			return nil
		}
		if !s.take(',') {
			return ErrEventInput
		}
	}
}

func (s *jsonScanner) array(depth int) error {
	s.pos++
	s.space()
	if s.take(']') {
		return nil
	}
	for {
		if _, err := s.value(depth); err != nil {
			return err
		}
		s.space()
		if s.take(']') {
			return nil
		}
		if !s.take(',') {
			return ErrEventInput
		}
	}
}

func (s *jsonScanner) stringToken() (string, bool, error) {
	s.space()
	if s.pos >= len(s.raw) || s.raw[s.pos] != '"' {
		return "", false, ErrEventInput
	}
	start := s.pos
	s.pos++
	repaired := false
	for s.pos < len(s.raw) {
		c := s.raw[s.pos]
		if c == '"' {
			s.pos++
			var text string
			err := json.Unmarshal(s.raw[start:s.pos], &text)
			if err != nil || !utf8.ValidString(text) {
				return "", false, ErrEventInput
			}
			return text, repaired, nil
		}
		if c == '\\' {
			if s.pos+1 >= len(s.raw) {
				return "", false, ErrEventInput
			}
			if s.raw[s.pos+1] != 'u' {
				s.pos += 2
				continue
			}
			if s.pos+6 > len(s.raw) {
				return "", false, ErrEventInput
			}
			v, err := strconv.ParseUint(string(s.raw[s.pos+2:s.pos+6]), 16, 16)
			if err != nil {
				return "", false, ErrEventInput
			}
			if v >= 0xd800 && v <= 0xdbff {
				if s.pos+12 <= len(s.raw) && s.raw[s.pos+6] == '\\' && s.raw[s.pos+7] == 'u' {
					low, lowErr := strconv.ParseUint(string(s.raw[s.pos+8:s.pos+12]), 16, 16)
					if lowErr == nil && low >= 0xdc00 && low <= 0xdfff {
						s.pos += 12
						continue
					}
				}
				repaired = true
			} else if v >= 0xdc00 && v <= 0xdfff {
				repaired = true
			}
			s.pos += 6
			continue
		}
		s.pos++
	}
	return "", false, ErrEventInput
}

func (s *jsonScanner) literal(v string) bool {
	if len(s.raw)-s.pos < len(v) || string(s.raw[s.pos:s.pos+len(v)]) != v {
		return false
	}
	s.pos += len(v)
	return true
}
func (s *jsonScanner) take(c byte) bool {
	s.space()
	if s.pos < len(s.raw) && s.raw[s.pos] == c {
		s.pos++
		return true
	}
	return false
}
func (s *jsonScanner) space() {
	for s.pos < len(s.raw) && (s.raw[s.pos] == ' ' || s.raw[s.pos] == '\n' || s.raw[s.pos] == '\r' || s.raw[s.pos] == '\t') {
		s.pos++
	}
}
func isJSONTerminator(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' || c == ']' || c == '}'
}

func MarshalObservation(o Observation) ([]byte, error) {
	if o.Schema != ObservationSchema {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}
func ObservationDigest(o Observation) (string, error) {
	raw, err := MarshalObservation(o)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}
