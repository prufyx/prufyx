// SPDX-License-Identifier: AGPL-3.0-only

package cloudeventsstructuredjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestObserveStagedOutcomes(t *testing.T) {
	cases := []struct {
		name, raw, root, edition, source string
		id, typ, dataOK                  *bool
		err                              bool
	}{
		{"pass", `{"specversion":"1.0","id":"a","source":"/x","type":"t"}`, "admitted_root_object", "valid_1_0", "admitted_nonempty_json_string", ptr(true), ptr(true), ptr(true), false},
		{"non-object", `[]`, "unsupported_root_shape", "", "", nil, nil, nil, false},
		{"duplicate", `{"id":"a","id":"b"}`, "duplicate_decoded_root_name", "", "", nil, nil, nil, false},
		{"other edition", `{"specversion":"0.3"}`, "admitted_root_object", "other_valid_edition", "", nil, nil, nil, false},
		{"missing edition", `{"id":"a"}`, "admitted_root_object", "missing_or_invalid", "", nil, nil, nil, false},
		{"missing id", `{"specversion":"1.0"}`, "admitted_root_object", "valid_1_0", "", ptr(false), nil, nil, false},
		{"missing source", `{"specversion":"1.0","id":"a"}`, "admitted_root_object", "valid_1_0", "missing_or_invalid", ptr(true), nil, nil, false},
		{"missing type", `{"specversion":"1.0","id":"a","source":"x"}`, "admitted_root_object", "valid_1_0", "admitted_nonempty_json_string", ptr(true), ptr(false), nil, false},
		{"both data", `{"specversion":"1.0","id":"a","source":"x","type":"t","data":null,"data_base64":""}`, "admitted_root_object", "valid_1_0", "admitted_nonempty_json_string", ptr(true), ptr(true), ptr(false), false},
		{"malformed", `{`, "", "", "", nil, nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Observe([]byte(tc.raw))
			if tc.err {
				if !errors.Is(err, ErrEventInput) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.RootAdmission != tc.root || deref(o.EditionAdmission) != tc.edition || deref(o.SourceAdmission) != tc.source || !sameBool(o.IDIsNonemptyValidString, tc.id) || !sameBool(o.TypeIsNonemptyValidString, tc.typ) || !sameBool(o.DataAndDataBase64NotBothPresent, tc.dataOK) {
				t.Fatalf("observation=%+v", o)
			}
		})
	}
}

func TestObserveJSONStringsAndRepair(t *testing.T) {
	cases := []struct{ name, raw, reason string }{
		{"escaped slash", `{"specversion":"1.0","id":"a","source":"https:\/\/example.invalid\/x","type":"t"}`, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"valid pair", `{"specversion":"1.0","id":"\uD83D\uDE00","source":"x","type":"t"}`, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"literal replacement", `{"specversion":"1.0","id":"a","source":"�","type":"t"}`, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"escaped replacement", `{"specversion":"1.0","id":"a","source":"\uFFFD","type":"t"}`, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"unpaired source", `{"specversion":"1.0","id":"a","source":"\uD800","type":"t"}`, "SOURCE_REPAIR_DETECTED"},
		{"unpaired edition", `{"specversion":"\uD800","id":"a","source":"x","type":"t"}`, "SPECVERSION_REQUIRED_VALID_STRING"},
		{"unpaired id", `{"specversion":"1.0","id":"\uD800","source":"x","type":"t"}`, "ID_REQUIRED_VALID_STRING"},
		{"unpaired type", `{"specversion":"1.0","id":"a","source":"x","type":"\uD800"}`, "TYPE_REQUIRED_VALID_STRING"},
		{"escaped literal backslash", `{"specversion":"1.0","id":"a","source":"\\uD800","type":"t"}`, "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
	}
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Observe([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := Evaluate(p, o, at).ReasonCode; got != tc.reason {
				t.Fatalf("reason=%s observation=%+v", got, o)
			}
		})
	}
}

func TestObserveCanonicalPrivacyAndEquivalence(t *testing.T) {
	a, _ := Observe([]byte(`{"specversion":"1.0","id":"a","source":"x","type":"t","data":{"secret":"alpha-private"},"Extension":"canary"}`))
	b, _ := Observe([]byte(`{"type":"t","source":"x","id":"b","specversion":"1.0","data":{"secret":"beta-private"},"other":[1,2]}`))
	ar, _ := MarshalObservation(a)
	br, _ := MarshalObservation(b)
	if string(ar) != string(br) {
		t.Fatalf("canonical observations differ\n%s\n%s", ar, br)
	}
	for _, secret := range []string{"alpha-private", "beta-private", "canary", "Extension", "other"} {
		if strings.Contains(string(ar), secret) || strings.Contains(string(br), secret) {
			t.Fatalf("leaked %q", secret)
		}
	}
	if !json.Valid(ar) {
		t.Fatal("invalid canonical JSON")
	}
}

func TestObserveDecodedRootNamesAndOpaqueNestedData(t *testing.T) {
	cases := []struct {
		name, raw, root, reason string
	}{
		{"escaped duplicate", `{"id":"a","\u0069d":"b"}`, "duplicate_decoded_root_name", "DUPLICATE_DECODED_ROOT_NAME"},
		{"case distinct", `{"specversion":"1.0","id":"a","Id":"ignored","source":"x","type":"t"}`, "admitted_root_object", "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"nested duplicate opaque", `{"specversion":"1.0","id":"a","source":"x","type":"t","data":{"same":1,"same":2}}`, "admitted_root_object", "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS"},
		{"control id", `{"specversion":"1.0","id":"\u0001","source":"x","type":"t"}`, "admitted_root_object", "ID_REQUIRED_VALID_STRING"},
		{"noncharacter type", `{"specversion":"1.0","id":"a","source":"x","type":"\uFDD0"}`, "admitted_root_object", "TYPE_REQUIRED_VALID_STRING"},
	}
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Observe([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if o.RootAdmission != tc.root {
				t.Fatalf("root=%s", o.RootAdmission)
			}
			if got := Evaluate(p, o, at).ReasonCode; got != tc.reason {
				t.Fatalf("reason=%s observation=%+v", got, o)
			}
		})
	}
}

func ptr(v bool) *bool { return &v }
func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func sameBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
