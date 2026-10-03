// SPDX-License-Identifier: AGPL-3.0-only

package k8sversion

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAccepted(t *testing.T) {
	cases := []struct {
		raw, decl string
		dist      Distribution
		up        string
		conf      Confidence
	}{
		{"v1.29.3", "", OfficialUpstream, "1.29.3", ConfidenceExact},
		{"1.29.3", "", OfficialUpstream, "1.29.3", ConfidenceExact},
		{"v1.29.3", "official_upstream", OfficialUpstream, "1.29.3", ConfidenceDeclared},
		{"v1.29.3", "kubeadm", Kubeadm, "1.29.3", ConfidenceDeclared},
		{"v1.29.3", "talos", Talos, "1.29.3", ConfidenceDeclared},
		{"1.29.4", "aks", AKS, "1.29.4", ConfidenceDeclared},
		{"v1.29.3-eks-adc7111", "", EKS, "1.29.3", ConfidenceExact},
		{"v1.29.3-eks-adc7111", "eks", EKS, "1.29.3", ConfidenceExact},
		{"1.29.3-gke.1093000", "", GKE, "1.29.3", ConfidenceExact},
		{"v1.29.4+k3s1", "", K3s, "1.29.4", ConfidenceExact},
		{"v1.29.4+rke2r1", "rke2", RKE2, "1.29.4", ConfidenceExact},
		{"v1.30.0+k3s12", "k3s", K3s, "1.30.0", ConfidenceExact},
	}
	for _, c := range cases {
		v, err := Parse(c.raw, c.decl)
		if err != nil {
			t.Errorf("%q/%q: %v", c.raw, c.decl, err)
			continue
		}
		if v.Distribution != c.dist || v.Upstream.String() != c.up || v.Confidence != c.conf || v.Raw != c.raw {
			t.Errorf("%q/%q: got %+v", c.raw, c.decl, v)
		}
	}
}

func TestParseRejected(t *testing.T) {
	cases := []struct {
		raw, decl string
		want      error
	}{
		{"", "", ErrMalformed},
		{"v1.29.3-eks", "", ErrMalformed},
		{"v1.29.3-eks-", "", ErrMalformed},
		{"v1.29.3-eks-ADC7111", "", ErrMalformed},
		{"v1.29.3-eks-adc711", "", ErrMalformed},
		{"1.29.3-eks-adc7111", "", ErrMalformed},
		{"v1.29.3-gke.1093000", "", ErrMalformed},
		{"1.29.3-gke.", "", ErrMalformed},
		{"1.29.3-gke.0", "", ErrMalformed},
		{"1.29.3-gke.01", "", ErrMalformed},
		{"v1.29.4+k3s", "", ErrMalformed},
		{"v1.29.4+k3s0", "", ErrMalformed},
		{"v1.29.4+k3s01", "", ErrMalformed},
		{"1.29.4+k3s1", "", ErrMalformed},
		{"v1.29.4+rke2", "", ErrMalformed},
		{"v1.29.4+rke2r", "", ErrMalformed},
		{"v1.29.4+rke2r1x", "", ErrMalformed},
		{"v1.29.4+rke2r1+k3s1", "", ErrMalformed},
		{"v01.29.3", "", ErrMalformed},
		{"v1.029.3", "", ErrMalformed},
		{"v1.29.03", "", ErrMalformed},
		{"v1.29", "", ErrMalformed},
		{"v1.29.3.4", "", ErrMalformed},
		{"v1.29.3-rc.1", "", ErrMalformed},
		{"v1.29.3+meta", "", ErrMalformed},
		{"v2.29.3", "", ErrMalformed},
		{"v1.29.99999999999999999999", "", ErrMalformed},
		{"v1.29.1000000", "", ErrMalformed},
		{"v1.-1.3", "", ErrMalformed},
		{"v1.+1.3", "", ErrMalformed},
		{" v1.29.3", "", ErrMalformed},
		{"v1.29.3\n", "", ErrMalformed},
		{"vv1.29.3", "", ErrMalformed},
		{"v1.29.3-eks-adc7111-eks-adc7111", "", ErrMalformed},
		{strings.Repeat("1", 500), "", ErrMalformed},
		{"v1.29.3", "bogus", ErrUnknownDistribution},
		{"v1.29.3", "EKS", ErrUnknownDistribution},
		{"v1.29.3", "eks", ErrDistributionMismatch},
		{"v1.29.3", "gke", ErrDistributionMismatch},
		{"v1.29.3", "k3s", ErrDistributionMismatch},
		{"v1.29.3-eks-adc7111", "gke", ErrDistributionMismatch},
		{"v1.29.4+k3s1", "rke2", ErrDistributionMismatch},
		{"v1.29.4+k3s1", "kubeadm", ErrDistributionMismatch},
		{"v1.29.4", "aks", ErrMalformed},
		{"4.16.3", "", ErrMalformed}, // upstream major must be 1; openshift needs a declaration
	}
	for _, c := range cases {
		_, err := Parse(c.raw, c.decl)
		if !errors.Is(err, c.want) {
			t.Errorf("%q/%q: got %v, want %v", c.raw, c.decl, err, c.want)
		}
	}
}

func TestOpenShiftUnknownWhenTableEmpty(t *testing.T) {
	for _, raw := range []string{"4.16", "4.16.3", "v4.16.3"} {
		_, err := Parse(raw, "openshift")
		if !errors.Is(err, ErrUnknownOpenShift) {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{"4", "4.x", "5.1", "4.016", "4.16.3.1", "1.29.3", "4.16-rc"} {
		_, err := Parse(raw, "openshift")
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func TestOpenShiftMappingMechanism(t *testing.T) {
	// Synthetic entry to exercise the lookup; NOT real release data.
	openshiftToKubernetes[99] = [2]int{1, 77}
	defer delete(openshiftToKubernetes, 99)
	v, err := Parse("4.99.2", "openshift")
	if err != nil {
		t.Fatal(err)
	}
	if v.Distribution != OpenShift || v.Upstream.String() != "1.77" || v.Upstream.PatchKnown || v.Confidence != ConfidenceMapped {
		t.Errorf("%+v", v)
	}
	if _, err := Parse("4.98", "openshift"); !errors.Is(err, ErrUnknownOpenShift) {
		t.Errorf("%v", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"v1.29.3", "v1.29.3-eks-adc7111", "1.29.3-gke.1093000", "v1.29.4+k3s1", "v1.29.4+rke2r1", "4.16.3", "", "+k3s", "-eks-"} {
		f.Add(s, "")
		f.Add(s, "openshift")
	}
	f.Fuzz(func(t *testing.T, raw, decl string) {
		v, err := Parse(raw, decl)
		if err != nil {
			return
		}
		if v.Raw != raw || !known[v.Distribution] || v.Upstream.Major != 1 || v.Upstream.Minor > maxNumber || v.Upstream.Patch > maxNumber {
			t.Fatalf("bad result %+v for %q", v, raw)
		}
		if len(raw) > maxRawLen {
			t.Fatalf("accepted oversize input")
		}
	})
}
