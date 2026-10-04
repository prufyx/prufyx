// SPDX-License-Identifier: AGPL-3.0-only

package k8sversion

import (
	"errors"
	"reflect"
	"testing"
)

// The mappings below are synthetic (minor 99); they are not release data.

func TestOpenShiftInjectedTable(t *testing.T) {
	table := OpenShiftMap{99: 99}
	v, err := ParseWith("4.99.3", "openshift", table)
	if err != nil {
		t.Fatal(err)
	}
	if v.Distribution != OpenShift || v.Raw != "4.99.3" || v.Upstream.Major != 1 || v.Upstream.Minor != 99 || v.Upstream.PatchKnown || v.Upstream.Patch != 0 || v.Upstream.String() != "1.99" || v.Confidence != ConfidenceMapped {
		t.Fatalf("ParseWith with a table: %+v", v)
	}
	// A minor the table does not hold is unknown.
	if _, err := ParseWith("4.98.1", "openshift", table); !errors.Is(err, ErrUnknownOpenShift) {
		t.Fatalf("minor outside the table: %v", err)
	}
	// An empty (non-nil) table knows nothing.
	if _, err := ParseWith("4.99.3", "openshift", OpenShiftMap{}); !errors.Is(err, ErrUnknownOpenShift) {
		t.Fatalf("empty table: %v", err)
	}
	// A value outside the version bounds is never used.
	for _, bad := range []int{-1, maxNumber + 1} {
		if _, err := ParseWith("4.99", "openshift", OpenShiftMap{99: bad}); !errors.Is(err, ErrUnknownOpenShift) {
			t.Fatalf("table value %d: %v", bad, err)
		}
	}
	// Malformed strings stay malformed whatever the table says.
	for _, raw := range []string{"4", "4.x", "5.99", "4.099", "4.99.3.1", "4.99-rc"} {
		if _, err := ParseWith(raw, "openshift", table); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", raw, err)
		}
	}
	// Parse never reads an injected table: without the compiled-in entry the
	// same string is unknown.
	if _, err := Parse("4.99.3", "openshift"); !errors.Is(err, ErrUnknownOpenShift) {
		t.Fatalf("Parse read an injected table: %v", err)
	}
	// Without a table, ParseWith equals Parse, also for the compiled-in
	// mapping.
	openshiftToKubernetes[99] = [2]int{1, 77}
	defer delete(openshiftToKubernetes, 99)
	for _, c := range [][2]string{{"4.99.3", "openshift"}, {"4.98", "openshift"}, {"v1.29.3-eks-adc7111", ""}, {"1.29.3", "aks"}, {"1.29.3", "eks"}, {"bad", ""}} {
		want, wantErr := Parse(c[0], c[1])
		got, gotErr := ParseWith(c[0], c[1], nil)
		if !reflect.DeepEqual(want, got) || (wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
			t.Fatalf("%q/%q: ParseWith(nil) = %+v %v, Parse = %+v %v", c[0], c[1], got, gotErr, want, wantErr)
		}
	}
	// With a table, the table alone decides an OpenShift minor.
	v, err = ParseWith("4.99.3", "openshift", table)
	if err != nil || v.Upstream.Minor != 99 {
		t.Fatalf("table did not decide: %+v %v", v, err)
	}
	// Other formats ignore the table.
	for _, c := range [][2]string{{"v1.29.3-eks-adc7111", ""}, {"1.29.3", "aks"}, {"1.29.3", "eks"}} {
		want, wantErr := Parse(c[0], c[1])
		got, gotErr := ParseWith(c[0], c[1], table)
		if !reflect.DeepEqual(want, got) || (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%q/%q: table changed a non-OpenShift result", c[0], c[1])
		}
	}
}

func TestKnown(t *testing.T) {
	for id := range known {
		if !Known(string(id)) {
			t.Fatalf("%s not known", id)
		}
	}
	for _, id := range []string{"", "EKS", "upstream", "minikube", "openshift "} {
		if Known(id) {
			t.Fatalf("%q known", id)
		}
	}
}

func FuzzParseWithNilTableEqualsParse(f *testing.F) {
	for _, s := range []string{"v1.29.3", "4.16.3", "1.29.3-gke.1093000", ""} {
		f.Add(s, "")
		f.Add(s, "openshift")
	}
	f.Fuzz(func(t *testing.T, raw, decl string) {
		want, wantErr := Parse(raw, decl)
		got, gotErr := ParseWith(raw, decl, nil)
		if !reflect.DeepEqual(want, got) || (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%q/%q differ", raw, decl)
		}
	})
}
