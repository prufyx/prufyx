// SPDX-License-Identifier: AGPL-3.0-only

package distribution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Exact shape. Each object level names its members; a trailing "?" marks an
// optional one. An optional string member, when present, must not be empty,
// so every section has one written form.
var (
	sectionFields       = fieldSet("records", "applicability")
	recordFields        = fieldSet("distribution", "controlPlane", "kubernetesMapping?", "evidence")
	mappingFields       = fieldSet("line", "kubernetes")
	applicabilityFields = fieldSet("distribution", "family", "status", "reason?", "evidence")
	evidenceFields      = fieldSet("state", "basis?", "extractor?", "derivedAt?", "reviewedAt", "validUntil", "sources")
	extractorFields     = fieldSet("id", "version", "codeDigest")
	sourceFields        = fieldSet("id", "url", "revision", "contentDigest", "startLine", "endLine")
)

func fieldSet(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		if len(n) > 0 && n[len(n)-1] == '?' {
			out[n[:len(n)-1]] = false
		} else {
			out[n] = true
		}
	}
	return out
}

// checkShape checks every object against its exact member names
// (encoding/json would match names case-insensitively), required members,
// nulls and empty optional strings. Repeated members and case variants were
// already refused by strictjson.Check.
func checkShape(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	err := object(doc, sectionFields, func(name string, v any) error {
		items, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s must be an array", name)
		}
		for i, item := range items {
			var err error
			if name == "records" {
				err = object(item, recordFields, func(name string, v any) error {
					switch name {
					case "evidence":
						return evidence(v)
					case "kubernetesMapping":
						return arrayOf(v, mappingFields)
					}
					return nil
				})
			} else {
				err = object(item, applicabilityFields, func(name string, v any) error {
					if name == "evidence" {
						return evidence(v)
					}
					return nil
				})
			}
			if err != nil {
				return fmt.Errorf("%s %d: %v", name, i, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func evidence(v any) error {
	return object(v, evidenceFields, func(name string, v any) error {
		switch name {
		case "extractor":
			return object(v, extractorFields, nil)
		case "sources":
			return arrayOf(v, sourceFields)
		}
		return nil
	})
}

func arrayOf(v any, fields map[string]bool) error {
	items, ok := v.([]any)
	if !ok {
		return fmt.Errorf("expected an array")
	}
	for _, item := range items {
		if err := object(item, fields, nil); err != nil {
			return err
		}
	}
	return nil
}

func object(v any, want map[string]bool, inner func(string, any) error) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("expected an object")
	}
	for name, required := range want {
		if _, ok := m[name]; required && !ok {
			return fmt.Errorf("member %q is required", name)
		}
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		required, known := want[name]
		if !known {
			return fmt.Errorf("unknown member %q", name)
		}
		if m[name] == nil {
			return fmt.Errorf("member %q is null", name)
		}
		if s, isString := m[name].(string); !required && isString && s == "" {
			return fmt.Errorf("optional member %q is empty; leave it out instead", name)
		}
		if inner != nil {
			if err := inner(name, m[name]); err != nil {
				return err
			}
		}
	}
	return nil
}
