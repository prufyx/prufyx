// SPDX-License-Identifier: AGPL-3.0-only

package kamajipredicate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func resource(list string) []byte {
	return []byte(`{"apiVersion":"kamaji.clastix.io/v1alpha1","kind":"TenantControlPlane","metadata":{"name":"private-resource"},"spec":{"networkProfile":{"podCidrs":` + list + `}}}`)
}

var selected = Selection{Index: 0, Explicit: true, Complete: true}

func TestDeclaredMultiplicityAndFamilies(t *testing.T) {
	for i, tc := range []struct {
		list  string
		value bool
	}{
		{`["10.0.0.0/16","10.1.0.0/16"]`, true},
		{`["10.0.0.0/16","10.0.0.0/16"]`, true},
		{`["2001:db8::/64","2001:db9::/64"]`, true},
		{`["10.0.0.0/16","2001:db8::/64"]`, false},
		{`["2001:db8::/64","10.0.0.0/16"]`, false},
		{`["10.0.0.0/16"]`, false},
		{`["2001:db8::/64"]`, false},
	} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			got, err := Produce(resource(tc.list), selected)
			if err != nil || got.State != "DECLARED" || got.BoolValue == nil || *got.BoolValue != tc.value {
				t.Fatalf("result=%+v err=%v", got, err)
			}
			b, _ := json.Marshal(got)
			for _, forbidden := range []string{"private-resource", "10.0.", "2001:", "networkProfile", "TenantControlPlane"} {
				if strings.Contains(string(b), forbidden) {
					t.Fatal("output retains raw input")
				}
			}
		})
	}
}

func TestUnsupportedInputRemainsUnknown(t *testing.T) {
	for i, list := range []string{`null`, `[]`, `[1]`, `["bad"]`, `["10.0.0.1/16"]`, `["::ffff:192.0.2.0/120"]`, `["2001:0DB8::/64"]`, `["10.0.0.0/16","10.1.0.0/16","10.2.0.0/16"]`, `"10.0.0.0/16"`, `[" 10.0.0.0/16"]`} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) { assertUnknown(t, resource(list), selected) })
	}
	for _, raw := range []string{`{}`, `{"kind":"List","items":[]}`, `{"apiVersion":"kamaji.clastix.io/v1alpha1","kind":"Other"}`, `{"apiVersion":"kamaji.clastix.io/v1alpha1","kind":"TenantControlPlane","spec":{}}`, `null`} {
		assertUnknown(t, []byte(raw), selected)
	}
	for _, s := range []Selection{{}, {Index: 0, Explicit: true}, {Index: -1, Explicit: true, Complete: true}, {Index: 1, Explicit: true, Complete: true}} {
		assertUnknown(t, resource(`["10.0.0.0/16"]`), s)
	}
}

func assertUnknown(t *testing.T, raw []byte, s Selection) {
	t.Helper()
	got, err := Produce(raw, s)
	if err != nil || got.State != "UNKNOWN" || got.BoolValue != nil {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestExplicitSelectionAndWrappers(t *testing.T) {
	a, b := resource(`["10.0.0.0/16"]`), resource(`["10.0.0.0/16","10.0.0.0/16"]`)
	raw := append(append(append([]byte("["), a...), ','), b...)
	raw = append(raw, ']')
	assertUnknown(t, raw, Selection{Complete: true})
	got, err := Produce(raw, Selection{Index: 1, Explicit: true, Complete: true})
	if err != nil || got.BoolValue == nil || !*got.BoolValue {
		t.Fatal(got, err)
	}
	assertUnknown(t, []byte(`{"resources":[`+string(a)+`]}`), selected)
	wrapped := strings.Replace(string(a), `"spec":`, `"items":[],"spec":`, 1)
	assertUnknown(t, []byte(wrapped), selected)
}

func TestAmbiguousAndBoundedJSONRefusesWithoutLeaks(t *testing.T) {
	valid := string(resource(`["10.0.0.0/16"]`))
	cases := []string{
		strings.Replace(valid, `"podCidrs":`, `"podCidrs":[],"podCidrs":`, 1),
		strings.Replace(valid, `"podCidrs":`, `"PodCidrs":[],"podCidrs":`, 1),
		strings.Replace(valid, `"name":`, `"Name":"other","name":`, 1),
		valid + valid, `{`, strings.Repeat(" ", MaxInputBytes) + valid,
		`{"deep":` + strings.Repeat("[", 25) + `0` + strings.Repeat("]", 25) + `}`,
		`{"many":[` + strings.Repeat("0,", 1024) + `0]}`,
	}
	for i, raw := range cases {
		got, err := Produce([]byte(raw), selected)
		if !errors.Is(err, ErrInvalid) || got.BoolValue != nil || err.Error() != ErrInvalid.Error() {
			t.Fatalf("case %d result=%+v err=%v", i, got, err)
		}
	}
}
