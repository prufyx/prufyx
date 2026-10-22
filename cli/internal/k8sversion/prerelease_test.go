// SPDX-License-Identifier: AGPL-3.0-only

package k8sversion

import (
	"errors"
	"testing"
)

func TestParsePreReleaseAccepted(t *testing.T) {
	cases := []struct {
		raw, decl, up, line string
		stage               Stage
		n                   int
	}{
		{"1.38.0-alpha.1", "", "1.38.0-alpha.1", "1.38", StageAlpha, 1},
		{"v1.38.0-alpha.2", "", "1.38.0-alpha.2", "1.38", StageAlpha, 2},
		{"1.38.0-beta.0", "official_upstream", "1.38.0-beta.0", "1.38", StageBeta, 0},
		{"v1.38.0-rc.10", "", "1.38.0-rc.10", "1.38", StageRC, 10},
	}
	for _, c := range cases {
		v, err := Parse(c.raw, c.decl)
		if err != nil {
			t.Errorf("%q/%q: %v", c.raw, c.decl, err)
			continue
		}
		u := v.Upstream
		if v.Distribution != OfficialUpstream || !u.PreRelease() || u.Pre != c.stage || u.PreN != c.n || u.Line() != c.line || u.String() != c.up {
			t.Errorf("%q/%q: got %+v", c.raw, c.decl, v)
		}
		// String round-trips through the bare parser.
		back, ok := ParsePreRelease(u.String())
		if !ok || back != u {
			t.Errorf("%q: round trip gave %+v, %v", c.raw, back, ok)
		}
	}
}

func TestParsePreReleaseRejected(t *testing.T) {
	cases := []struct{ raw, decl string }{
		{"1.38.0-alpha", ""},
		{"1.38.0-alpha.", ""},
		{"1.38.0-alpha.01", ""},
		{"1.38.0-alpha.1.2", ""},
		{"1.38.0-alpha.-1", ""},
		{"1.38.0-Alpha.1", ""},
		{"1.38.0-nightly.1", ""},
		{"1.38.0-alpha.1234567", ""},
		{"1.38.1-alpha.1", ""},
		{"1.38-alpha.1", ""},
		{"1.38.0-alpha.1+x", ""},
		{"1.38.0+x", ""},
		{"1.38.0-alpha.1-x", ""},
		{"1.38.0--alpha.1", ""},
		{"1.38.0-", ""},
		{"2.38.0-alpha.1", ""},
		{"1.38.0-alpha.1", "kubeadm"},
		{"1.38.0-alpha.1", "aks"},
		{"v1.38.0-alpha.1-eks-adc7111", ""},
		{"v1.38.0-alpha.1+k3s1", ""},
		{"v1.38.0-alpha.1+rke2r1", "rke2"},
		{"1.38.0-alpha.1-gke.5", ""},
	}
	for _, c := range cases {
		if v, err := Parse(c.raw, c.decl); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDistributionMismatch) {
			t.Errorf("%q/%q: got %+v, %v", c.raw, c.decl, v, err)
		}
	}
	for _, raw := range []string{"1.38.0", "v1.38.0-alpha.1", "1.38.0-alpha", "1.38.1-rc.1", ""} {
		if v, ok := ParsePreRelease(raw); ok {
			t.Errorf("ParsePreRelease(%q) = %+v, want refused", raw, v)
		}
	}
}

func TestCompare(t *testing.T) {
	// Ascending SemVer 2.0 order; every pair must agree.
	order := []string{
		"1.37.9", "1.38.0-alpha.1", "1.38.0-alpha.2", "1.38.0-alpha.10",
		"1.38.0-beta.0", "1.38.0-beta.1", "1.38.0-rc.0", "1.38.0-rc.1",
		"1.38.0", "1.38.1", "1.39.0-alpha.1", "1.39.0",
	}
	parse := func(s string) Semver {
		v, err := Parse(s, "")
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		return v.Upstream
	}
	for i, a := range order {
		for j, b := range order {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(parse(a), parse(b)); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestLine(t *testing.T) {
	for raw, want := range map[string]string{"1.29.3": "1.29", "1.38.0": "1.38", "1.38.0-alpha.2": "1.38", "v1.38.0-rc.1": "1.38"} {
		v, err := Parse(raw, "")
		if err != nil || v.Upstream.Line() != want {
			t.Errorf("%q: line %q, %v; want %q", raw, v.Upstream.Line(), err, want)
		}
	}
}
