// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// fill sets every exported field of v to a non-zero value, slices and
// pointers included, so that a shallow copy anywhere shows up as sharing.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("a")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(v.Index(0))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i))
			}
		}
	}
}

// scribble overwrites every string, bool and number reachable through v.
func scribble(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString("MUTATED")
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(!v.Bool())
		}
	case reflect.Int, reflect.Int64:
		if v.CanSet() {
			v.SetInt(v.Int() + 7)
		}
	case reflect.Ptr:
		if !v.IsNil() {
			scribble(v.Elem())
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			scribble(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			scribble(v.Field(i))
		}
	}
}

// Every value an index accessor returns is the caller's own: scribbling over
// it, however deep, leaves the next answer of the same accessor unchanged.
func TestIndexAccessorsReturnIndependentValues(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]func() any{}

	var att lineattest.LineAttestation
	fill(reflect.ValueOf(&att).Elem())
	li := lineattest.NewIndex([]lineattest.LineAttestation{att})
	cases["lineattest.AttestationsFor"] = func() any { return li.AttestationsFor("a", "a", "a", now) }

	var up upgradepath.Record
	fill(reflect.ValueOf(&up).Elem())
	ui := upgradepath.NewIndex([]upgradepath.Record{up})
	cases["upgradepath.Lookup"] = func() any { return ui.Lookup("a", now) }

	var sa servedapis.Record
	fill(reflect.ValueOf(&sa).Elem())
	si := servedapis.NewIndex([]servedapis.Record{sa})
	cases["servedapis.For"] = func() any { s, _ := si.For("a", "a", now); return s }

	var section distribution.Section
	fill(reflect.ValueOf(&section).Elem())
	di := distribution.NewIndex(section)
	cases["distribution.Record"] = func() any { r, _, _ := di.Record("a", now); return r }
	cases["distribution.ApplicabilityFor"] = func() any { return di.ApplicabilityFor("a", "a", now) }
	cases["distribution.OpenShiftMinor"] = func() any { return di.OpenShiftMinor("a", now) }

	for name, call := range cases {
		first := call()
		reference, err := json.Marshal(first) // a snapshot, not an alias of the memory under test
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(first, reflect.Zero(reflect.TypeOf(first)).Interface()) {
			t.Fatalf("%s: fixture produced a zero answer", name)
		}
		v := reflect.New(reflect.TypeOf(first)).Elem()
		v.Set(reflect.ValueOf(first))
		scribble(v)
		if got, _ := json.Marshal(call()); string(got) != string(reference) {
			t.Errorf("%s: mutating a returned value changed the index", name)
		}
	}
}
