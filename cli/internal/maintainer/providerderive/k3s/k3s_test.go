// SPDX-License-Identifier: AGPL-3.0-only

package k3s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

var seq int

// mk builds a valid synthetic excerpt input for tag with body lines.
func mk(t *testing.T, tag, pre, draft string, body ...string) providerderive.Input {
	t.Helper()
	seq++
	id := fmt.Sprintf("k3s-rel-%03d", seq)
	src := "https://github.com/k3s-io/k3s/releases/tag/" + tag
	lines := []string{providerexcerpt.FileMagic,
		"source: " + src, "fetchedAt: 2026-11-07T09:47:36Z", "anchor: release-body",
		"licence: " + providerexcerpt.LicencePermissive, "form: " + providerexcerpt.FormVerbatim,
		"pageSha256: sha256:" + strings.Repeat("a", 64), "---",
		"tag: " + tag, "prerelease: " + pre, "draft: " + draft}
	lines = append(lines, body...)
	data := []byte(strings.Join(lines, "\n") + "\n")
	sum := sha256.Sum256(data)
	return providerderive.Input{
		Entry: providerexcerpt.Entry{
			ID: id, Provider: Provider, Path: Provider + "/" + id + ".txt", SourceURL: src,
			FetchedAt: "2026-11-07T09:47:36Z", SHA256: "sha256:" + hex.EncodeToString(sum[:]),
			Anchor: "release-body", Licence: providerexcerpt.LicencePermissive, Form: providerexcerpt.FormVerbatim,
		},
		Data: data,
	}
}

func ga(t *testing.T, tag, k8s string) providerderive.Input {
	return mk(t, tag, "false", "false", "<!-- "+tag+" -->", "This release updates Kubernetes to "+k8s+", and fixes a number of issues.", "", "## Changes since v1.0.0+k3s1:")
}

func rc(t *testing.T, tag string) providerderive.Input {
	return mk(t, tag, "true", "false", "## What's Changed", "* synthetic change")
}

func isDrift(t *testing.T, in []providerderive.Input) {
	t.Helper()
	res, err := Derive(in)
	var de *providerderive.DriftError
	if !errors.As(err, &de) || !errors.Is(err, providerderive.ErrDrift) {
		t.Fatalf("want drift error, got %v", err)
	}
	if len(res.Rows) != 0 || len(res.Unknown) != 0 {
		t.Fatalf("partial output on drift: %+v", res)
	}
}

func TestGoldenDeterministicOrderIndependent(t *testing.T) {
	build := func() []providerderive.Input {
		return []providerderive.Input{
			ga(t, "v1.37.2+k3s1", "v1.37.2"), rc(t, "v1.37.2-rc2+k3s1"), ga(t, "v1.34.13+k3s1", "v1.34.13"),
			ga(t, "v1.36.6+k3s1", "v1.36.6"), rc(t, "v1.37.2-rc1+k3s1"), ga(t, "v1.34.9+k3s2", "v1.34.9"),
			ga(t, "v1.34.10+k3s1", "v1.34.10"),
			mk(t, "v1.37.3-weird+k3s1", "false", "false"),
		}
	}
	a := build()
	b := build()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	ra, err := Derive(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Derive(b)
	if err != nil {
		t.Fatal(err)
	}
	// Excerpt ids differ per build; compare the mapping columns only.
	norm := func(r providerderive.Result) string {
		var s []string
		for _, x := range r.Rows {
			s = append(s, x.Distribution+" "+x.ProviderVersion+" -> "+x.Kubernetes)
			if x.NonProduction {
				t.Fatal("k3s row marked non-production")
			}
		}
		for _, u := range r.Unknown {
			s = append(s, "unknown "+u.Tag+" "+u.Reason)
		}
		return strings.Join(s, "\n")
	}
	want := `k3s v1.34.9+k3s2 -> v1.34.9
k3s v1.34.10+k3s1 -> v1.34.10
k3s v1.34.13+k3s1 -> v1.34.13
k3s v1.36.6+k3s1 -> v1.36.6
k3s v1.37.2+k3s1 -> v1.37.2
unknown v1.37.2-rc1+k3s1 prerelease
unknown v1.37.2-rc2+k3s1 prerelease
unknown v1.37.3-weird+k3s1 unknown_suffix`
	if norm(ra) != want || norm(rb) != want {
		t.Fatalf("got\n%s\nreverse\n%s", norm(ra), norm(rb))
	}
	if _, err := json.Marshal(ra); err != nil {
		t.Fatal(err)
	}
}

func TestMutatedTags(t *testing.T) {
	for _, tag := range []string{"v1.37.2+k3s", "v1.37.2+k3s1-rc1", "V1.37.2+k3s1", "v1.37.02+k3s1", "v1.37.2.1+k3s1", "v1.37.2+k3s0", "v1.37+k3s1", "v1.37.2", "k3s-v1.37.2"} {
		isDrift(t, []providerderive.Input{ga(t, tag, "v1.37.2")})
	}
}

func TestMissingFields(t *testing.T) {
	// header fields absent or malformed
	in := ga(t, "v1.37.2+k3s1", "v1.37.2")
	bad := []providerderive.Input{
		mk(t, "v1.37.2+k3s1", "maybe", "false", "x"),
		mk(t, "v1.37.2+k3s1", "false", "", "x"),
	}
	for _, b := range bad {
		isDrift(t, []providerderive.Input{b})
	}
	_ = in
	// GA body without the sentence: UNKNOWN, no row, no error.
	res, err := Derive([]providerderive.Input{mk(t, "v1.37.2+k3s1", "false", "false", "<!-- v1.37.2+k3s1 -->", "no sentence here")})
	if err != nil || len(res.Rows) != 0 || len(res.Unknown) != 1 || res.Unknown[0].Reason != providerderive.ReasonNoMapping {
		t.Fatalf("%+v %v", res, err)
	}
	// wrong provider / wrong repo / tampered bytes
	x := ga(t, "v1.37.2+k3s1", "v1.37.2")
	x.Entry.Provider = "kind"
	isDrift(t, []providerderive.Input{x})
	y := ga(t, "v1.37.2+k3s1", "v1.37.2")
	y.Entry.SourceURL = "https://github.com/other/k3s/releases/tag/v1.37.2+k3s1"
	isDrift(t, []providerderive.Input{y})
	z := ga(t, "v1.37.2+k3s1", "v1.37.2")
	z.Data = append([]byte(nil), z.Data...)
	z.Data[len(z.Data)-3] ^= 1
	isDrift(t, []providerderive.Input{z})
}

func TestUnparsableBodies(t *testing.T) {
	isDrift(t, []providerderive.Input{ga(t, "v1.37.2+k3s1", "v1.37.1")}) // sentence != tag
	isDrift(t, []providerderive.Input{mk(t, "v1.37.2+k3s1", "false", "false",
		"This release updates Kubernetes to v1.37.2, and fixes a number of issues.",
		"This release updates Kubernetes to v1.37.2, and fixes a number of issues.")})
	isDrift(t, []providerderive.Input{mk(t, "v1.37.2+k3s1", "false", "false",
		"This release updates Kubernetes to v1.37.2 and v1.37.1, and fixes a number of issues.")})
	isDrift(t, []providerderive.Input{mk(t, "v1.37.2+k3s1", "false", "false",
		"This release updates Kubernetes to v1.37, and fixes a number of issues.")})
	// conflict: two excerpts, one provider version, different upstream
	a := mk(t, "v1.37.2+k3s1", "false", "false", "This release updates Kubernetes to v1.37.2, and fixes a number of issues.")
	b := mk(t, "v1.37.2+k3s1", "false", "false", "This release updates Kubernetes to v1.37.2, and fixes a number of issues.", "extra")
	if r, err := Derive([]providerderive.Input{a, b}); err != nil || len(r.Rows) != 1 {
		t.Fatalf("identical duplicate must dedupe: %v %v", r, err)
	}
	dup := a
	isDrift(t, []providerderive.Input{a, dup}) // duplicate manifest id
}

func TestNoNetworkNoPartial(t *testing.T) {
	// a good row next to a drifting one yields nothing
	isDrift(t, []providerderive.Input{ga(t, "v1.37.2+k3s1", "v1.37.2"), ga(t, "v1.36.6+k3s1", "v1.36.7")})
	// empty input is an empty, valid result
	r, err := Derive(nil)
	if err != nil || len(r.Rows) != 0 {
		t.Fatal(r, err)
	}
}

func TestPrereleaseNeverMaps(t *testing.T) {
	for _, tag := range []string{"v1.37.2-rc1+k3s1", "v1.37.2-rc5+k3s1", "v1.37.2-alpha1+k3s1", "v1.37.2-beta1+k3s1"} {
		// even a body that carries a GA-style sentence must not map
		in := mk(t, tag, "true", "false", "This release updates Kubernetes to v1.37.2, and fixes a number of issues.")
		r, err := Derive([]providerderive.Input{in})
		if err != nil || len(r.Rows) != 0 || len(r.Unknown) != 1 || r.Unknown[0].Reason != providerderive.ReasonPrerelease {
			t.Fatalf("%s: %+v %v", tag, r, err)
		}
	}
	for _, f := range [][2]string{{"true", "false"}, {"false", "true"}} {
		in := mk(t, "v1.37.2+k3s1", f[0], f[1], "This release updates Kubernetes to v1.37.2, and fixes a number of issues.")
		r, err := Derive([]providerderive.Input{in})
		if err != nil || len(r.Rows) != 0 || len(r.Unknown) != 1 || r.Unknown[0].Reason != providerderive.ReasonFlagged {
			t.Fatalf("%v: %+v %v", f, r, err)
		}
	}
}
