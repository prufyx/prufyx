// SPDX-License-Identifier: AGPL-3.0-only

package kind

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

var seq int

func mk(t *testing.T, tag, pre, draft string, body ...string) providerderive.Input {
	t.Helper()
	seq++
	id := fmt.Sprintf("kind-rel-%03d", seq)
	src := "https://github.com/kubernetes-sigs/kind/releases/tag/" + tag
	lines := []string{providerexcerpt.FileMagic,
		"source: " + src, "fetchedAt: 2026-11-07T09:47:37Z", "anchor: release-body",
		"licence: " + providerexcerpt.LicencePermissive, "form: " + providerexcerpt.FormVerbatim,
		"pageSha256: sha256:" + strings.Repeat("b", 64), "---",
		"tag: " + tag, "prerelease: " + pre, "draft: " + draft}
	lines = append(lines, body...)
	data := []byte(strings.Join(lines, "\n") + "\n")
	sum := sha256.Sum256(data)
	return providerderive.Input{
		Entry: providerexcerpt.Entry{
			ID: id, Provider: Provider, Path: Provider + "/" + id + ".txt", SourceURL: src,
			FetchedAt: "2026-11-07T09:47:37Z", SHA256: "sha256:" + hex.EncodeToString(sum[:]),
			Anchor: "release-body", Licence: providerexcerpt.LicencePermissive, Form: providerexcerpt.FormVerbatim,
		},
		Data: data,
	}
}

func d(ver, digest string) string {
	return "The default node image is now  `kindest/node:" + ver + "@sha256:" + digest + "`"
}

func h(c string) string { return strings.Repeat(c, 64) }

func bullets(style string, vers ...string) []string {
	out := []string{"Images pre-built for this release:"}
	for i, v := range vers {
		out = append(out, fmt.Sprintf("%s %s: `kindest/node:%s@sha256:%s`", style, v, v, h(string(rune('a'+i)))))
	}
	return out
}

func rel(t *testing.T, tag, ver, digest string) providerderive.Input {
	return mk(t, tag, "false", "false", "Synthetic release notes.", "", d(ver, digest))
}

func isDrift(t *testing.T, in ...providerderive.Input) {
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

func TestGolden(t *testing.T) {
	list := append([]string{"Synthetic.", "", d("v1.37.0", h("a")), ""}, bullets("*", "v1.37.0", "v1.36.4")...)
	dash := append([]string{"Synthetic.", "", d("v1.35.0", h("c")), ""}, bullets("-", "v1.34.1", "v1.35.0")...)
	// second bullet (index 1) has digest h("b"); make v1.35.0 consistent
	dash[len(dash)-1] = "- v1.35.0: `kindest/node:v1.35.0@sha256:" + h("c") + "`"
	in := []providerderive.Input{
		mk(t, "v0.33.0", "false", "false", list...),
		rel(t, "v0.29.0", "v1.33.1", h("d")),
		mk(t, "v0.31.0", "false", "false", dash...),
		rel(t, "v0.27.0", "v1.32.2", h("e")),
		rel(t, "v0.28.0", "v1.33.1", h("f")),
		mk(t, "v0.26.0", "false", "false", "Images pre-built for this release:", "- v1.32.0: `kindest/node:v1.32.0`"),
		rel(t, "v0.9.0", "v1.33.1", h("0")), // before v0.27: never mapped even if a sentence exists
		mk(t, "v0.34.0-alpha.0", "true", "false", d("v1.38.0", h("1"))),
		mk(t, "v0.34.0-beta.1", "false", "false", d("v1.38.0", h("1"))),
		mk(t, "v0.34.0-weird", "false", "false", d("v1.38.0", h("1"))),
		mk(t, "v0.30.0", "false", "false", "No image statement."),
	}
	got, err := Derive(in)
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, r := range got.Rows {
		if !r.NonProduction || r.Distribution != "kind" || !strings.HasPrefix(r.NodeImage, "kindest/node:"+r.Kubernetes+"@sha256:") {
			t.Fatalf("bad row %+v", r)
		}
		s = append(s, r.ProviderVersion+"->"+r.Kubernetes)
	}
	for _, u := range got.Unknown {
		s = append(s, "?"+u.Tag+":"+u.Reason)
	}
	want := "v0.27.0->v1.32.2 v0.28.0->v1.33.1 v0.29.0->v1.33.1 v0.31.0->v1.35.0 v0.33.0->v1.37.0 " +
		"?v0.26.0:release_before_first_mapped ?v0.30.0:no_mapping_statement ?v0.34.0-alpha.0:prerelease " +
		"?v0.34.0-beta.1:prerelease ?v0.34.0-weird:unknown_suffix ?v0.9.0:release_before_first_mapped"
	if strings.Join(s, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(s, " "), want)
	}
}

func TestCRLFAndBulletStyles(t *testing.T) {
	body := []string{"Notes.\r", d("v1.37.0", h("a")) + "\r", "\r"}
	for _, l := range bullets("*", "v1.37.0") {
		body = append(body, l+"\r")
	}
	hd, rest, err := providerderive.ParseBody(Provider, "x", append([]string{"tag: v0.33.0\r", "prerelease: false\r", "draft: false\r"}, body...))
	if err != nil || hd.Tag != "v0.33.0" {
		t.Fatal(hd, err)
	}
	k, img, ok, err := mapping("x", rest)
	if err != nil || !ok || k != "v1.37.0" || !strings.HasSuffix(img, h("a")) {
		t.Fatal(k, img, ok, err)
	}
	// single-space variant of the sentence is tolerated too
	one := "The default node image is now `kindest/node:v1.37.0@sha256:" + h("a") + "`"
	if _, _, ok, err := mapping("x", []string{one}); err != nil || !ok {
		t.Fatal(ok, err)
	}
}

func TestMutatedImages(t *testing.T) {
	for _, line := range []string{
		"The default node image is now  `kindest/node:v1.37.0@sha256:" + strings.Repeat("a", 63) + "`",
		"The default node image is now  `kindest/node:v1.37.0`",
		"The default node image is now  `kindest/node:v1.37.0@sha256:" + strings.Repeat("A", 64) + "`",
		"The default node image is now  `kindest/node:v1.37.0@sha256:" + strings.Repeat("g", 64) + "`",
		"The default node image is now  `kindest/node:v1.37@sha256:" + h("a") + "`",
	} {
		isDrift(t, mk(t, "v0.33.0", "false", "false", line))
	}
}

func TestMissingStatementIsUnknown(t *testing.T) {
	for _, body := range [][]string{
		{"Notes only."},
		{"Images pre-built for this release:"},
		{"Images pre-built for this release:", "", "No bullets follow."},
	} {
		r, err := Derive([]providerderive.Input{mk(t, "v0.33.0", "false", "false", body...)})
		if err != nil || len(r.Rows) != 0 || len(r.Unknown) != 1 || r.Unknown[0].Reason != providerderive.ReasonNoMapping {
			t.Fatalf("%v: %+v %v", body, r, err)
		}
	}
}

func TestUnparsableLists(t *testing.T) {
	l := bullets("*", "v1.37.0")
	// plus bullet, numbered bullet
	isDrift(t, mk(t, "v0.33.0", "false", "false", append([]string{d("v1.37.0", h("a"))}, "Images pre-built for this release:", "+ v1.37.0: `kindest/node:v1.37.0@sha256:"+h("a")+"`")...))
	isDrift(t, mk(t, "v0.33.0", "false", "false", append([]string{d("v1.37.0", h("a"))}, "Images pre-built for this release:", "1. v1.37.0: `kindest/node:v1.37.0@sha256:"+h("a")+"`")...))
	// label differs from image tag
	isDrift(t, mk(t, "v0.33.0", "false", "false", d("v1.37.0", h("a")), "Images pre-built for this release:", "* v1.36.4: `kindest/node:v1.36.5@sha256:"+h("b")+"`"))
	// two default sentences
	isDrift(t, mk(t, "v0.33.0", "false", "false", d("v1.37.0", h("a")), d("v1.36.0", h("b"))))
	// default digest differs from the list entry of the same version
	isDrift(t, mk(t, "v0.33.0", "false", "false", append([]string{d("v1.37.0", h("f"))}, l...)...))
	// duplicate list version
	isDrift(t, mk(t, "v0.33.0", "false", "false", d("v1.37.0", h("a")), "Images pre-built for this release:", l[1], l[1]))
}

func TestGrammarAndFlags(t *testing.T) {
	for _, tag := range []string{"kind-v0.33", "0.33.0", "v0.33", "V0.33.0", "v0.033.0", "v0.33.0.1", "v0.33.0+x"} {
		isDrift(t, rel(t, tag, "v1.37.0", h("a")))
	}
	for _, f := range [][2]string{{"true", "false"}, {"false", "true"}} {
		r, err := Derive([]providerderive.Input{mk(t, "v0.33.0", f[0], f[1], d("v1.37.0", h("a")))})
		if err != nil || len(r.Rows) != 0 || r.Unknown[0].Reason != providerderive.ReasonFlagged {
			t.Fatalf("%v %+v %v", f, r, err)
		}
	}
	x := rel(t, "v0.33.0", "v1.37.0", h("a"))
	x.Entry.Provider = "k3s"
	isDrift(t, x)
	y := rel(t, "v0.33.0", "v1.37.0", h("a"))
	y.Entry.SourceURL = "https://github.com/k3s-io/k3s/releases/tag/v0.33.0"
	isDrift(t, y)
}

func TestConflictAndNoPartial(t *testing.T) {
	a := rel(t, "v0.33.0", "v1.37.0", h("a"))
	b := rel(t, "v0.33.0", "v1.37.0", h("b"))
	isDrift(t, a, b) // same provider version, different image
	c := rel(t, "v0.33.0", "v1.36.1", h("a"))
	isDrift(t, a, c) // different upstream
	isDrift(t, a, rel(t, "v0.32.0", "v1.36.1", h("c")), mk(t, "v0.31.0", "false", "false", d("v1.35.0", "zz")))
}
