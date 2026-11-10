// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestIsPreviousLine(t *testing.T) {
	const calver = "pkg:github/example/calendar"
	defer lineattest.SetCalverComponentsForTest(calver)()
	for _, c := range []struct {
		component, from, to string
		want                bool
	}{
		{"pkg:github/example/ordinary", "1.27", "1.28", true},
		{"pkg:github/example/ordinary", "25.12", "26.1", false},
		{"pkg:github/example/ordinary", "26.0", "26.1", true},
		{"pkg:github/example/ordinary", "1.0", "1.0", false},
		{calver, "25.12", "26.1", true},
		{calver, "26.0", "26.1", false},
		{calver, "26.1", "26.2", true},
		{calver, "26.1", "26.3", false},
	} {
		if got := isPreviousLine(c.component, c.from, c.to); got != c.want {
			t.Errorf("isPreviousLine(%q, %q, %q) = %v, want %v", c.component, c.from, c.to, got, c.want)
		}
	}
}

// A published-line component's hop is decided by the line the attestation
// carries: 25.10.x -> 26.3.0 is applied, 25.10.x -> 26.6.0 and 26.1.x -> 26.3.0
// are refused as a hop shape.
func TestPublishedLineHopFromTheAttestation(t *testing.T) {
	const comp = "pkg:github/example/published"
	defer lineattest.SetPublishedLineComponentsForTest(comp)()
	rel := func(v string) lineattest.Release {
		return lineattest.Release{Version: v, Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}
	a := lineattest.LineAttestation{Component: comp, Line: "26.3", Releases: &lineattest.Releases{
		From: []lineattest.Release{rel("25.10.1"), rel("25.10.2")}, To: []lineattest.Release{rel("26.3.0")}}}
	decide := func(from, to string) bool { return isPreviousLine(comp, from, to) && a.HopFrom(from) }
	if !decide("25.10", "26.3") {
		t.Error("25.10.x -> 26.3.0 must be applied")
	}
	for _, c := range [][2]string{{"26.1", "26.3"}, {"25.8", "26.3"}, {"26.3", "26.3"}, {"26.6", "26.3"}} {
		if decide(c[0], c[1]) {
			t.Errorf("%s -> %s must be refused", c[0], c[1])
		}
	}
	// 25.10 -> 26.6: the attestation of 26.6 carries 25.10, which has the
	// published hop shape; that no published line lies between is asserted by
	// the extractor and the knowledge gate (the live tags), and the scan finds
	// no attestation of 26.6 whose releases.from are 26.3 releases to apply.
	// An attestation of 26.3 is not an attestation for the line 26.6.
	if a.Line == "26.6" {
		t.Fatal("setup")
	}
	// Unregistered component and era: unchanged.
	if isPreviousLine("pkg:github/example/ordinary", "25.10", "26.3") {
		t.Error("an unregistered component keeps M.(m-1)")
	}
	if isPreviousLine(comp, "0.38", "25.0") || isPreviousLine(comp, "0.34", "0.36") {
		t.Error("cross-era and skipped semver minors are no hops")
	}
}
