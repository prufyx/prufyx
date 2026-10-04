// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// The fixtures under testdata/lsremote are recorded "git ls-remote
// https://github.com/<owner>/<repo>.git" output, trimmed to the lines a
// test needs. Lines are kept verbatim.
func recordedListing(t *testing.T, name string) RefListing {
	t.Helper()
	listing, err := ParseLsRemote(recordedRaw(t, name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return listing
}

func recordedRaw(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "lsremote", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const (
	goTag1214Commit   = "ed817f1c4055a559a94afffecbb91c78e4f39942"
	goTag12113Commit  = "8bba868de983dd7bf55fcd121495ba8d6e2734e7"
	goTag1266Commit   = "1ea5a71ad8ceb7b9f16b4b6f8ea4739a4327dd6e"
	goTag1268Commit   = "c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e"
	goTag1205Commit   = "e827d41c0a2ea392c117a790cdfed0022e419424"
	k8sV1332Object    = "d43821f9491a55bd544f7c7e894fc97f1eebedd0"
	k8sV1332Commit    = "a57b6f7709f6c2722b92f07b8b4c48210a51fc40"
	k8sV13313Commit   = "c029d48d28322ad0369aabdcf8b656fd3195cd30"
	k8sRelease137Head = "8aaeb4e53d1a489570afe94ef5258554de68897a"
	k8sV1380Alpha1    = "039223d3e2a1c6f5b1422c95fb396ff8c31d2619"
	longhornV190      = "8bb4d023b6d85475471091d3eedea02a7411bc5c"
	longhornV180      = "1f343ee4c467de1264682ecb069d8f2a62850977"
	longhornV182      = "5859e849c445b6144e8ab12db1472e26dc1ad4bd"
	natsV21029Commit  = "f91ddd892565760834f27404a92b80a57b8ec149"
	cniV100Commit     = "5608690f77380743f29bb314458da9a9fb88c003"
	etcdWebsitePin    = "71c99c6729f1bb9f007ef7dca9f3aed484229844"
	k8sWebsitePin     = "9f1af2971c32124bff0a1f42255ba5a2f3c8a16f"
	k8sWebsite133Head = "b9ab6105d0e3b6824dc368d3dd3b101fb4774575"
)

func TestParseLsRemoteAnnotatedAndLightweightTags(t *testing.T) {
	k8s := recordedListing(t, "kubernetes_kubernetes")
	got := k8s.Tags["v1.33.2"]
	if !got.Annotated || got.Object != k8sV1332Object || got.Commit != k8sV1332Commit {
		t.Fatalf("annotated tag must resolve to its peeled commit: %+v", got)
	}
	if k8s.Heads["release-1.37"] != k8sRelease137Head {
		t.Fatalf("branch heads must be recorded: %v", k8s.Heads["release-1.37"])
	}
	golang := recordedListing(t, "golang_go")
	got = golang.Tags["go1.21.4"]
	if got.Annotated || got.Object != goTag1214Commit || got.Commit != goTag1214Commit {
		t.Fatalf("lightweight tag must resolve to its own object: %+v", got)
	}
	if _, ok := k8s.Tags["v1.33.2^{}"]; ok {
		t.Fatal("a peeled entry must never become a tag of its own")
	}
}

func TestParseLsRemoteRejectsMalformedListings(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	cases := map[string]string{
		"peeled entry without its tag": b + "\trefs/tags/v1.0.0^{}\n",
		"tag listed twice":             a + "\trefs/tags/v1.0.0\n" + b + "\trefs/tags/v1.0.0\n",
		"short object id":              "abc\trefs/tags/v1.0.0\n",
		"upper-case object id":         strings.ToUpper(a) + "\trefs/tags/v1.0.0\n",
		"space instead of tab":         a + " refs/tags/v1.0.0\n",
		"empty ref":                    a + "\t\n",
		"ref with a space":             a + "\trefs/tags/v1.0.0 x\n",
	}
	for name, raw := range cases {
		if _, err := ParseLsRemote([]byte(raw)); !errors.Is(err, errRefListingMalformed) {
			t.Errorf("%s: expected a malformed listing, got %v", name, err)
		}
	}
	big := make([]byte, maxRefListingBytes+1)
	if _, err := ParseLsRemote(big); !errors.Is(err, errRefListingTooLarge) {
		t.Errorf("an oversized listing must be refused, got %v", err)
	}
}

// pktLine encodes one smart-HTTP packet line.
func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// advertisement re-encodes recorded ls-remote output as the protocol v0
// ref advertisement github.com serves to "git ls-remote".
func advertisement(lsRemote string) []byte {
	var b strings.Builder
	b.WriteString(pktLine("# service=git-upload-pack\n"))
	b.WriteString("0000")
	for i, line := range strings.Split(strings.TrimSpace(lsRemote), "\n") {
		object, ref, _ := strings.Cut(line, "\t")
		entry := object + " " + ref
		if i == 0 {
			entry += "\x00multi_ack thin-pack side-band agent=git/github"
		}
		b.WriteString(pktLine(entry + "\n"))
	}
	b.WriteString("0000")
	return []byte(b.String())
}

func TestUploadPackAdvertisementMatchesLsRemote(t *testing.T) {
	raw := recordedRaw(t, "kubernetes_kubernetes")
	text, err := parseUploadPackAdvertisement(advertisement(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	fromAdvert, err := ParseLsRemote(text)
	if err != nil {
		t.Fatal(err)
	}
	fromLs, _ := ParseLsRemote(raw)
	if fmt.Sprint(fromAdvert) != fmt.Sprint(fromLs) {
		t.Fatal("the advertisement and ls-remote forms of one listing must parse identically")
	}

	empty := pktLine("# service=git-upload-pack\n") + "0000" + pktLine(strings.Repeat("0", 40)+" capabilities^{}\x00agent=git\n") + "0000"
	if text, err := parseUploadPackAdvertisement([]byte(empty)); err != nil || len(text) != 0 {
		t.Fatalf("an empty repository advertises no refs: %q %v", text, err)
	}

	good := string(advertisement(string(raw)))
	bad := map[string]string{
		"not upload-pack":      pktLine("# service=git-receive-pack\n") + good[len(pktLine("# service=git-upload-pack\n")):],
		"missing flush":        pktLine("# service=git-upload-pack\n") + good[len(pktLine("# service=git-upload-pack\n"))+4:],
		"truncated":            good[:len(good)-10],
		"data after flush":     good + "0000",
		"bad length":           pktLine("# service=git-upload-pack\n") + "0000zzzz",
		"length past the end":  pktLine("# service=git-upload-pack\n") + "0000ffff",
		"ref line with no ref": pktLine("# service=git-upload-pack\n") + "0000" + pktLine("nonsense\n") + "0000",
		"protocol v2":          pktLine("version 2\n") + "0000",
	}
	for name, body := range bad {
		if _, err := parseUploadPackAdvertisement([]byte(body)); !errors.Is(err, errRefListingMalformed) {
			t.Errorf("%s: expected a malformed advertisement, got %v", name, err)
		}
	}
}

func TestClassifyNonRelease(t *testing.T) {
	cases := []struct {
		tag, prefix  string
		major, minor int
		want         onLineForm
	}{
		{"v1.25.4-rc.1", "v", 1, 25, formPrerelease},
		{"v2.10.29-RC.1", "v", 2, 10, formPrerelease},
		{"v1.33.0-alpha.3", "v", 1, 33, formPrerelease},
		{"v1.36.0-beta.0", "v", 1, 36, formPrerelease},
		{"v1.9.1-dev-20250601", "v", 1, 9, formPrerelease},
		{"v2.11.0-preview.1", "v", 2, 11, formPrerelease},
		{"go1.26rc1", "go", 1, 26, formPrerelease},
		{"go1.21rc4", "go", 1, 21, formPrerelease},
		{"v1.0.0-rc1", "v", 1, 0, formPrerelease},
		{"v1.9.0-hotfix-1", "v", 1, 9, formUnrecognised},
		{"v1.2.4-prebuilt", "v", 1, 2, formUnrecognised},
		{"v1.2.4-rc1-hotfix", "v", 1, 2, formUnrecognised},
		{"v1.2.4-devsecfix", "v", 1, 2, formUnrecognised},
		{"v1.2.4-preview-fix", "v", 1, 2, formUnrecognised},
		{"v1.2.4-rc.1.2", "v", 1, 2, formPrerelease},
		{"v2.10.27-binary", "v", 2, 10, formUnrecognised},
		{"v1.25.2.1", "v", 1, 25, formUnrecognised},
		{"go1.20", "go", 1, 20, formUnrecognised},
		{"v1.25", "v", 1, 25, formUnrecognised},
		{"v1.25.", "v", 1, 25, formUnrecognised},
		{"v1.25.01", "v", 1, 25, formUnrecognised},
		{"v1.25.3+build", "v", 1, 25, formUnrecognised},
		{"v1.250.0", "v", 1, 25, formNotOnLine},
		{"v1.26.0-rc.1", "v", 1, 25, formNotOnLine},
		{"api/v1.25.0-rc.1", "v", 1, 25, formNotOnLine},
		{"weekly.2012-03-27", "go", 1, 21, formNotOnLine},
	}
	for _, tc := range cases {
		if got := classifyNonRelease(tc.tag, tc.prefix, tc.major, tc.minor); got != tc.want {
			t.Errorf("classifyNonRelease(%q, %q, %d.%d) = %d, want %d", tc.tag, tc.prefix, tc.major, tc.minor, got, tc.want)
		}
	}
}

func TestParseTagLineTag(t *testing.T) {
	good := map[string]tagVersion{
		"go1.26.6":      {"go", 1, 26, 6},
		"v1.33.2":       {"v", 1, 33, 2},
		"1.2.3":         {"", 1, 2, 3},
		"release-1.2.3": {"release-", 1, 2, 3},
	}
	for tag, want := range good {
		if got, ok := parseTagLineTag(tag); !ok || got != want {
			t.Errorf("parseTagLineTag(%q) = %+v, %v; want %+v", tag, got, ok, want)
		}
	}
	for _, tag := range []string{"go1.26rc1", "go1.20", "Go1.2.3", "go2x1.2.3", "v1.2.3-rc.1", "weekly.2012-03-27", "release.r60.3", "v1.2.3.4", "go01.2.3", "go1.2.3 "} {
		if got, ok := parseTagLineTag(tag); ok {
			t.Errorf("parseTagLineTag(%q) accepted as %+v", tag, got)
		}
	}
	// The Releases grammar itself is unchanged: a bare word prefix is a
	// tag-line extension only.
	if _, ok := parseStrictTag("go1.26.6"); ok {
		t.Fatal("parseStrictTag must still refuse go1.26.6")
	}
}

func TestDeriveTagLineFromRecordedListings(t *testing.T) {
	type want struct {
		pinned, head, headCommit string
		ignored                  int
	}
	ok := map[string]struct {
		fixture, pin string
		want         want
	}{
		"go lightweight tags, rc pre-releases ignored": {"golang_go", goTag1214Commit, want{"go1.21.4", "go1.21.13", goTag12113Commit, 4}},
		"go newer line":                      {"golang_go", goTag1266Commit, want{"go1.26.6", "go1.26.8", goTag1268Commit, 3}},
		"pin is the line head":               {"golang_go", goTag1268Commit, want{"go1.26.8", "go1.26.8", goTag1268Commit, 3}},
		"pin is a tag and a branch head":     {"golang_go", goTag12113Commit, want{"go1.21.13", "go1.21.13", goTag12113Commit, 4}},
		"kubernetes annotated tags":          {"kubernetes_kubernetes", k8sV1332Commit, want{"v1.33.2", "v1.33.13", k8sV13313Commit, 7}},
		"dev and rc builds are pre-releases": {"longhorn_longhorn-manager", longhornV180, want{"v1.8.0", "v1.8.2", longhornV182, 49}},
	}
	for name, tc := range ok {
		got := deriveTagLine(recordedListing(t, tc.fixture), tc.pin)
		if got.unknown != "" || got.pinnedTag != tc.want.pinned || got.headTag != tc.want.head || got.head.Commit != tc.want.headCommit || got.ignoredN != tc.want.ignored {
			t.Errorf("%s: got pinned=%q head=%q commit=%q ignored=%d unknown=%q; want %+v", name, got.pinnedTag, got.headTag, got.head.Commit, got.ignoredN, got.unknown, tc.want)
		}
		if got.digest == "" || len(got.ignored) > maxIgnoredOnLine {
			t.Errorf("%s: missing digest or unbounded ignored list", name)
		}
		for _, ig := range got.ignored {
			if ig.Reason != ignoredPrerelease {
				t.Errorf("%s: ignored tag %q without the pre-release reason", name, ig.Tag)
			}
		}
	}

	unknown := map[string]struct {
		fixture, pin, contains string
		pinUnknown             bool
	}{
		"annotated tag object is not a commit":    {"kubernetes_kubernetes", k8sV1332Object, "no tag points at the pinned commit", true},
		"branch exists, the tag does not":         {"kubernetes_kubernetes", k8sRelease137Head, "head of branch release-1.37", true},
		"only a pre-release tag at the pin":       {"kubernetes_kubernetes", k8sV1380Alpha1, "no release tag", true},
		"bare go1.20 release is unorderable":      {"golang_go", goTag1205Commit, "go1.20", false},
		"hotfix tag on the line":                  {"longhorn_longhorn-manager", longhornV190, "v1.9.0-hotfix-1", false},
		"unrecognised -binary tag on the line":    {"nats-io_nats-server", natsV21029Commit, "v2.10.27-binary", false},
		"same commit under two prefixes":          {"containernetworking_cni", cniV100Commit, "prefixes other than none, v or go: \"spec-v\", \"v\"", true},
		"docs commit with no ref":                 {"etcd-io_website", etcdWebsitePin, "no tag points at the pinned commit", true},
		"docs pin that is no ref head":            {"kubernetes_website", k8sWebsitePin, "no tag points at the pinned commit", true},
		"docs release branch head has no release": {"kubernetes_website", k8sWebsite133Head, "head of branch release-1.33", true},
	}
	for name, tc := range unknown {
		got := deriveTagLine(recordedListing(t, tc.fixture), tc.pin)
		if got.unknown == "" || !strings.Contains(got.unknown, tc.contains) || got.pinUnknown != tc.pinUnknown || got.headTag != "" && got.unknown == "" {
			t.Errorf("%s: got unknown=%q pinUnknown=%v head=%q; want UNKNOWN containing %q (pinUnknown=%v)", name, got.unknown, got.pinUnknown, got.headTag, tc.contains, tc.pinUnknown)
		}
	}
}

// Same listing, any order: the derivation must not depend on it.
func TestDeriveTagLineIsOrderIndependent(t *testing.T) {
	raw := recordedRaw(t, "kubernetes_kubernetes")
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := deriveTagLine(recordedListing(t, "kubernetes_kubernetes"), k8sV1332Commit)
	sort.Sort(sort.Reverse(sort.StringSlice(lines)))
	listing, err := ParseLsRemote([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := deriveTagLine(listing, k8sV1332Commit); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order changed the result:\n got %+v\nwant %+v", got, want)
	}
}

// Synthetic edge cases the recorded listings do not show.
func TestDeriveTagLineEdgeCases(t *testing.T) {
	c := func(n int) string { return fmt.Sprintf("%040x", n) }
	cases := map[string]struct {
		lines    []string
		pin      string
		head     string
		contains string
	}{
		"higher patch on the line wins numerically": {[]string{c(1) + "\trefs/tags/v1.2.9", c(2) + "\trefs/tags/v1.2.10", c(3) + "\trefs/tags/v1.3.0"}, c(1), "v1.2.10", ""},
		"same numeric line under another prefix":    {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/api/v1.2.3"}, c(1), "", "prefixes other than none, v or go: \"api/v\", \"v\""},
		"another component's prefix anywhere":       {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/helm-chart-5.0.0"}, c(1), "", "prefixes other than none, v or go: \"helm-chart-\", \"v\""},
		"nested go module prefix":                   {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/sdk/go/v2.0.0"}, c(1), "", "prefixes other than none, v or go: \"sdk/go/v\", \"v\""},
		"calendar tags next to v tags":              {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/2024.10.15"}, c(1), "", "mixed prefixes: \"\", \"v\""},
		"mixed allowed prefixes":                    {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/1.3.0"}, c(1), "", "mixed prefixes: \"\", \"v\""},
		"pre-release under another prefix":          {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/chart-1.2.1-rc.1"}, c(1), "", "another prefix or a zero-padded version (chart-1.2.1-rc.1)"},
		"non-strict tag without the prefix":         {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/1.2.9-hotfix"}, c(1), "", "another prefix or a zero-padded version (1.2.9-hotfix)"},
		"zero-padded minor on the line":             {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/v1.02.9"}, c(1), "", "another prefix or a zero-padded version (v1.02.9)"},
		"post-release word starting like pre":       {[]string{c(1) + "\trefs/tags/v1.2.3", c(2) + "\trefs/tags/v1.2.4-prebuilt"}, c(1), "", "v1.2.4-prebuilt"},
		"hotfix of a release candidate":             {[]string{c(1) + "\trefs/tags/v1.2.3", c(2) + "\trefs/tags/v1.2.4-rc1-hotfix"}, c(1), "", "v1.2.4-rc1-hotfix"},
		"post-release word starting like dev":       {[]string{c(1) + "\trefs/tags/v1.2.3", c(2) + "\trefs/tags/v1.2.4-devsecfix"}, c(1), "", "v1.2.4-devsecfix"},
		"numbered pre-release is ignored":           {[]string{c(1) + "\trefs/tags/v1.2.3", c(2) + "\trefs/tags/v1.2.4-rc.1"}, c(1), "v1.2.3", ""},
		"two release tags at the pin":               {[]string{c(1) + "\trefs/tags/v1.2.0", c(1) + "\trefs/tags/v1.2.1"}, c(1), "", "more than one release tag"},
		"two lines at the pin":                      {[]string{c(1) + "\trefs/tags/v1.2.0", c(1) + "\trefs/tags/v1.3.0"}, c(1), "", "more than one release line"},
		"zero-padded tag on the line":               {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/v1.2.07"}, c(1), "", "v1.2.07"},
		"malformed tags elsewhere are ignored":      {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/nightly", c(3) + "\trefs/tags/v1.2", c(4) + "\trefs/tags/2024-10-15"}, c(1), "", "v1.2"},
		"unrelated malformed tags only":             {[]string{c(1) + "\trefs/tags/v1.2.0", c(2) + "\trefs/tags/nightly", c(4) + "\trefs/tags/2024-10-15", c(5) + "\trefs/tags/v1.20.0-hotfix"}, c(1), "v1.2.0", ""},
		"branch named like the line is no head":     {[]string{c(1) + "\trefs/tags/v1.2.0", c(9) + "\trefs/heads/release-1.2", c(8) + "\trefs/heads/v1.2.5"}, c(1), "v1.2.0", ""},
		"a branch with a tag name is not a tag":     {[]string{c(9) + "\trefs/heads/v1.2.0"}, c(9), "", "head of branch v1.2.0"},
		"annotated head resolves to its commit":     {[]string{c(1) + "\trefs/tags/v1.2.0", c(7) + "\trefs/tags/v1.2.1", c(2) + "\trefs/tags/v1.2.1^{}"}, c(1), "v1.2.1", ""},
	}
	for name, tc := range cases {
		listing, err := ParseLsRemote([]byte(strings.Join(tc.lines, "\n")))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := deriveTagLine(listing, tc.pin)
		switch {
		case tc.contains == "" && (got.unknown != "" || got.headTag != tc.head):
			t.Errorf("%s: got head=%q unknown=%q; want head %q", name, got.headTag, got.unknown, tc.head)
		case tc.contains != "" && !strings.Contains(got.unknown, tc.contains):
			t.Errorf("%s: got head=%q unknown=%q; want UNKNOWN containing %q", name, got.headTag, got.unknown, tc.contains)
		}
	}
	listing, _ := ParseLsRemote([]byte(c(1) + "\trefs/tags/v1.2.0\n" + c(7) + "\trefs/tags/v1.2.1\n" + c(2) + "\trefs/tags/v1.2.1^{}\n"))
	if got := deriveTagLine(listing, c(1)); got.head.Commit != c(2) {
		t.Fatalf("the compared commit of an annotated head is its peeled commit, got %s", got.head.Commit)
	}
}

// The rule must keep the shared latest-release semantics exactly.
func TestTagLineRepositoryAmbiguity(t *testing.T) {
	for _, ok := range [][]string{nil, {"v"}, {"v", "v"}, {""}, {"go", "go"}} {
		if got := tagLineRepositoryAmbiguity(ok); got != "" {
			t.Errorf("%q: unexpected ambiguity %q", ok, got)
		}
	}
	for _, bad := range [][]string{{"", "v"}, {"v", "go"}, {"release-"}, {"v", "api/v"}, {"helm-chart-"}} {
		if got := tagLineRepositoryAmbiguity(bad); got == "" {
			t.Errorf("%q: must be ambiguous", bad)
		}
	}
}

func TestTagLineBaselineConsistent(t *testing.T) {
	if !TagLineBaselineConsistent("go1.21.4", "go1.21.13", "1.21") {
		t.Fatal("a consistent go tag line must be accepted")
	}
	for name, args := range map[string][3]string{
		"older compared tag":  {"go1.21.4", "go1.21.3", "1.21"},
		"other line":          {"go1.21.4", "go1.26.8", "1.21"},
		"other prefix":        {"go1.21.4", "v1.21.13", "1.21"},
		"wrong line label":    {"go1.21.4", "go1.21.13", "1.26"},
		"pre-release compare": {"go1.21.4", "go1.21rc4", "1.21"},
		"unparseable pin":     {"go1.21", "go1.21.13", "1.21"},
	} {
		if TagLineBaselineConsistent(args[0], args[1], args[2]) {
			t.Errorf("%s: must be inconsistent", name)
		}
	}
	if LineBaselineConsistent("go1.21.4", "go1.21.13", "1.21") {
		t.Fatal("the Releases check must not accept the tag-line grammar")
	}
}

// Releases named as pre-releases are skipped even when GitHub does not flag
// them; a release with an unrecognised suffix still makes the line ambiguous.
func TestNewestOnLineSkipsUnflaggedPrereleaseReleases(t *testing.T) {
	pinned, _ := parseStrictTag("v1.30.0")
	tag, _, reason := newestOnLine(pinned, []releaseEntry{rel("v1.30.1", false), rel("v1.30.0", false), rel("v1.30.0-rc1", false), rel("v1.30.2-RC.1", false)})
	if reason != "" || tag != "v1.30.1" {
		t.Fatalf("got %q %q; want v1.30.1", tag, reason)
	}
	for _, suffix := range []string{"-binary", "-prebuilt", "-rc1-hotfix", "-devsecfix"} {
		if tag, _, reason := newestOnLine(pinned, []releaseEntry{rel("v1.30.0", false), rel("v1.30.1"+suffix, false)}); reason == "" {
			t.Errorf("an unflagged v1.30.1%s release must keep the line ambiguous, got head %q", suffix, tag)
		}
	}
}

// ---------------------------------------------------------------------
// End to end through BuildWorklistWithBaseline
// ---------------------------------------------------------------------

type fixtureRefs struct {
	listings map[string]RefListing
	err      error
	calls    int
}

func (f *fixtureRefs) GitRefs(_ context.Context, owner, repo string) (RefListing, error) {
	f.calls++
	if f.err != nil {
		return RefListing{}, f.err
	}
	listing, ok := f.listings[owner+"/"+repo]
	if !ok {
		return RefListing{}, errors.New("not recorded")
	}
	return listing, nil
}

// goWorld is golang/go as the dry run saw it: no GitHub Releases, and a tags
// fallback that picks an ancient tag for the whole repository.
func goWorld(t *testing.T) (*fakeAPIFetcher, fakeBlobFetcher) {
	api := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	api.responses["/repos/golang/go/releases?per_page=10"] = struct {
		body   []byte
		status int
	}{[]byte(`[]`), 200}
	api.responses["/repos/golang/go/tags?per_page=30"] = struct {
		body   []byte
		status int
	}{[]byte(`[{"name":"weekly.2012-03-27"}]`), 200}
	api.responses["/repos/golang/go/git/ref/tags/weekly.2012-03-27"] = struct {
		body   []byte
		status int
	}{[]byte(`{"object":{"sha":"3895b5051df256b442d0b0af50debfffd8d75164","type":"commit"}}`), 200}
	for tag, commit := range map[string]string{"go1.21.13": goTag12113Commit, "go1.26.8": goTag1268Commit, "go1.21.4": goTag1214Commit} {
		api.responses["/repos/golang/go/git/ref/tags/"+tag] = struct {
			body   []byte
			status int
		}{[]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`), 200}
	}
	blobs := fakeBlobFetcher{}
	put := func(commit, body string) {
		blobs["/golang/go/"+commit+"/src/flag/flag.go"] = sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: []byte(body)}
	}
	put(goTag1214Commit, "a\nb\nc\n")
	put(goTag12113Commit, "a\nb\nc\n")
	put(goTag1266Commit, "x\ny\nz\n")
	put(goTag1268Commit, "x\nY\nz\n")
	return api, blobs
}

func goCitation(id, commit, body string) Citation {
	return Citation{
		RulePack: "p", RuleID: "kyverno.rule-" + id, Project: "kyverno", SourceID: "go-flag-" + id,
		Owner: "golang", Repo: "go", Path: "src/flag/flag.go", OldCommit: commit, OldDigest: sourcecorpus.SHA([]byte(body)),
		StartLine: 2, EndLine: 2,
	}
}

func TestBuildWorklistDerivesTagLines(t *testing.T) {
	api, blobs := goWorld(t)
	refs := &fixtureRefs{listings: map[string]RefListing{"golang/go": recordedListing(t, "golang_go")}}
	citations := []Citation{goCitation("a", goTag1214Commit, "a\nb\nc\n"), goCitation("b", goTag1266Commit, "x\ny\nz\n")}
	state := newState()
	wl, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, state, withGitRefs{APIFetcher: api, refs: refs}, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	a, b := byClass(wl, "go-flag-a"), byClass(wl, "go-flag-b")
	if a.Class != ClassFileIdentical || a.Baseline != BaselineTagLine || a.BaselineTag != "go1.21.13" || a.NewCommit != goTag12113Commit ||
		a.PinnedTag != "go1.21.4" || a.BaselineLine != "1.21" || a.Resolution != "" || a.LineStatus != LineStatusLaterReleases {
		t.Fatalf("go1.21 citation: %+v", a)
	}
	if b.Class != ClassContentChanged || b.Baseline != BaselineTagLine || b.BaselineTag != "go1.26.8" {
		t.Fatalf("a change on the line must still be reported: %+v", b)
	}
	if len(wl.Lines) != 2 || wl.Lines[0].Basis != LineBasisGitTags || wl.Lines[0].Tag != "go1.21.13" || wl.Lines[0].Commit != goTag12113Commit || wl.Lines[0].TagsDigest == "" || wl.Lines[0].IgnoredTagCount != 4 {
		t.Fatalf("line records: %+v", wl.Lines)
	}
	if refs.calls != 1 {
		t.Fatalf("the listing must be fetched once per repository and run, got %d", refs.calls)
	}

	// A second run with the same state resumes the fresh tag-line results.
	again, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, state, withGitRefs{APIFetcher: api, refs: refs}, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(again.Citations) != fmt.Sprint(wl.Citations) || len(again.Lines) != 2 {
		t.Fatalf("resumed run differs:\n%+v\n%+v", again.Citations, wl.Citations)
	}
}

func TestBuildWorklistTagLineFailsClosed(t *testing.T) {
	citations := []Citation{goCitation("a", goTag1214Commit, "a\nb\nc\n")}
	run := func(fetcher APIFetcher) ClassResult {
		t.Helper()
		_, blobs := goWorld(t)
		wl, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, newState(), fetcher, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
		if err != nil {
			t.Fatal(err)
		}
		return wl.Citations[0]
	}
	api, _ := goWorld(t)

	if got := run(api); got.Baseline != BaselineLatest || got.Resolution != resolutionTagFallback || !strings.Contains(got.BaselineNote, "no release line") {
		t.Fatalf("without a ref source the citation keeps the tags fallback: %+v", got)
	}
	if got := run(withGitRefs{APIFetcher: api, refs: &fixtureRefs{err: errors.New("network down")}}); got.Class != ClassPending {
		t.Fatalf("an unavailable listing must leave the citation pending: %+v", got)
	}
	if got := run(withGitRefs{APIFetcher: api, refs: &fixtureRefs{err: fmt.Errorf("%w: x", errRefListingMalformed)}}); got.Baseline != BaselineLatest || got.Resolution != resolutionTagFallback || !strings.Contains(got.BaselineNote, "malformed") {
		t.Fatalf("a malformed listing must derive nothing: %+v", got)
	}
	noTag, _ := ParseLsRemote([]byte(goTag12113Commit + "\trefs/tags/go1.21.13\n"))
	if got := run(withGitRefs{APIFetcher: api, refs: &fixtureRefs{listings: map[string]RefListing{"golang/go": noTag}}}); got.Baseline != BaselineLatest || got.Resolution != resolutionTagFallback || !strings.Contains(got.BaselineNote, "no tag points at the pinned commit") {
		t.Fatalf("a pin without a tag must keep the latest baseline: %+v", got)
	}
	ambiguous, _ := ParseLsRemote([]byte(goTag1214Commit + "\trefs/tags/go1.21.4\n" + goTag12113Commit + "\trefs/tags/go1.21.13\n" + strings.Repeat("e", 40) + "\trefs/tags/go1.21.14-security\n"))
	state := newState()
	_, blobs := goWorld(t)
	wl, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, state, withGitRefs{APIFetcher: api, refs: &fixtureRefs{listings: map[string]RefListing{"golang/go": ambiguous}}}, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	if got := wl.Citations[0]; got.Baseline != BaselineLatest || !strings.Contains(got.BaselineNote, "go1.21.14-security") {
		t.Fatalf("an unorderable tag on the line must keep the latest baseline: %+v", got)
	}
	if line := state.Lines[tagLineKey("golang", "go", "go", "1.21")]; line.Status != lineUnderivable || line.Basis != LineBasisGitTags {
		t.Fatalf("the underivable line must be recorded with its reason: %+v", line)
	}
}

// A repository with GitHub Releases never takes the tag path, even when a
// ref source is present.
func TestTagLineOnlyForTagFallbackRepositories(t *testing.T) {
	f := newLineFixture([]string{"v1.25.0", "v1.25.3", "v1.26.0"}, nil, "v1.26.0")
	f.blob("v1.25.0", "a.txt", "one\ntwo\n")
	f.blob("v1.25.3", "a.txt", "one\ntwo\n")
	refs := &fixtureRefs{}
	wl, err := BuildWorklistWithBaseline(context.Background(), []Citation{f.citation("s", "v1.25.0", "a.txt", "one\ntwo\n", 1, 1)}, nil, 0, newState(), withGitRefs{APIFetcher: f.api, refs: refs}, f.blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	if got := wl.Citations[0]; got.Baseline != BaselineReleaseLine || refs.calls != 0 {
		t.Fatalf("Releases repositories keep the Releases line: %+v (ref calls %d)", got, refs.calls)
	}
}

func TestGitHubRefFetcherRefusesBadNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	for _, name := range [][2]string{{"a/b", "c"}, {"a", "../c"}, {"", "c"}, {"a", "c?x"}, {"a", ".."}, {".", "c"}} {
		if _, err := (GitHubRefFetcher{}).GitRefs(ctx, name[0], name[1]); !errors.Is(err, errRejected) || strings.Contains(fmt.Sprint(err), "transport") {
			t.Errorf("%v: expected a refusal before any request, got %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------
// The smart-HTTP fetcher, through a test transport (no network)
// ---------------------------------------------------------------------

type fakeTransport struct {
	handle   func(*http.Request) *http.Response
	requests []*http.Request
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, r)
	return f.handle(r), nil
}

func httpResponse(status int, contentType string, body []byte, header map[string]string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

const advertisementType = "application/x-git-upload-pack-advertisement"

func TestGitHubRefFetcherOverATestTransport(t *testing.T) {
	good := advertisement(string(recordedRaw(t, "golang_go")))
	ok := &fakeTransport{handle: func(*http.Request) *http.Response { return httpResponse(200, advertisementType, good, nil) }}
	listing, err := GitHubRefFetcher{transport: ok}.GitRefs(context.Background(), "golang", "go")
	if err != nil || listing.Tags["go1.21.4"].Commit != goTag1214Commit {
		t.Fatalf("a valid advertisement must parse: %v", err)
	}
	r := ok.requests[0]
	if r.URL.String() != "https://github.com/golang/go.git/info/refs?service=git-upload-pack" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
		t.Fatalf("unexpected request %s %s auth=%q", r.Method, r.URL, r.Header.Get("Authorization"))
	}

	cases := map[string]func(*http.Request) *http.Response{
		"redirect to another host": func(r *http.Request) *http.Response {
			if r.URL.Host == "github.com" {
				return httpResponse(302, "", nil, map[string]string{"Location": "https://example.invalid/refs"})
			}
			return httpResponse(200, advertisementType, good, nil)
		},
		"wrong content type": func(*http.Request) *http.Response { return httpResponse(200, "text/plain", good, nil) },
		"no content type":    func(*http.Request) *http.Response { return httpResponse(200, "", good, nil) },
		"not found":          func(*http.Request) *http.Response { return httpResponse(404, advertisementType, good, nil) },
		"server error":       func(*http.Request) *http.Response { return httpResponse(500, advertisementType, good, nil) },
		"oversized body": func(*http.Request) *http.Response {
			return httpResponse(200, advertisementType, make([]byte, maxRefListingBytes+1), nil)
		},
		"malformed body": func(*http.Request) *http.Response { return httpResponse(200, advertisementType, []byte("0000"), nil) },
		"protocol v2 answer": func(*http.Request) *http.Response {
			return httpResponse(200, advertisementType, []byte(pktLine("version 2\n")+"0000"), nil)
		},
	}
	for name, handle := range cases {
		tr := &fakeTransport{handle: handle}
		if _, err := (GitHubRefFetcher{transport: tr}).GitRefs(context.Background(), "golang", "go"); err == nil {
			t.Errorf("%s: must be refused", name)
		}
		for _, r := range tr.requests {
			if r.URL.Host != "github.com" {
				t.Errorf("%s: a request reached %s", name, r.URL.Host)
			}
		}
	}
}

// ---------------------------------------------------------------------
// An annotated line head, end to end, and a head that is not a commit
// ---------------------------------------------------------------------

func annotatedWorld(headRef string, extra map[string]string) (*fakeAPIFetcher, fakeBlobFetcher, RefListing, Citation) {
	pin, headObject, headCommit, latest := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40), strings.Repeat("4", 40)
	listing, _ := ParseLsRemote([]byte(pin + "\trefs/tags/v1.2.0\n" + headObject + "\trefs/tags/v1.2.1\n" + headCommit + "\trefs/tags/v1.2.1^{}\n" + latest + "\trefs/tags/v1.3.0\n"))
	api := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	set := func(path, body string) {
		api.responses[path] = struct {
			body   []byte
			status int
		}{[]byte(body), 200}
	}
	set("/repos/example/tags/releases?per_page=10", `[]`)
	set("/repos/example/tags/tags?per_page=30", `[{"name":"v1.3.0"}]`)
	set("/repos/example/tags/git/ref/tags/v1.3.0", `{"object":{"sha":"`+latest+`","type":"commit"}}`)
	set("/repos/example/tags/git/ref/tags/v1.2.1", headRef)
	for path, body := range extra {
		set(path, body)
	}
	blobs := fakeBlobFetcher{}
	for _, commit := range []string{pin, headCommit, latest} {
		blobs["/example/tags/"+commit+"/a.txt"] = sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: []byte("one\ntwo\n")}
	}
	citation := Citation{RulePack: "p", RuleID: "r", Project: "p", SourceID: "s", Owner: "example", Repo: "tags", Path: "a.txt",
		OldCommit: pin, OldDigest: sourcecorpus.SHA([]byte("one\ntwo\n")), StartLine: 1, EndLine: 1}
	return api, blobs, listing, citation
}

func TestTagLineAnnotatedHeadEndToEnd(t *testing.T) {
	headObject, headCommit := strings.Repeat("2", 40), strings.Repeat("3", 40)
	run := func(headRef string, extra map[string]string) (ClassResult, []LineResolution) {
		t.Helper()
		api, blobs, listing, citation := annotatedWorld(headRef, extra)
		refs := &fixtureRefs{listings: map[string]RefListing{"example/tags": listing}}
		wl, err := BuildWorklistWithBaseline(context.Background(), []Citation{citation}, nil, 0, newState(), withGitRefs{APIFetcher: api, refs: refs}, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
		if err != nil {
			t.Fatal(err)
		}
		return wl.Citations[0], wl.Lines
	}
	annotated := `{"object":{"sha":"` + headObject + `","type":"tag"}}`
	got, lines := run(annotated, map[string]string{"/repos/example/tags/git/tags/" + headObject: `{"object":{"sha":"` + headCommit + `","type":"commit"}}`})
	if got.Baseline != BaselineTagLine || got.BaselineTag != "v1.2.1" || got.NewCommit != headCommit || got.Class != ClassFileIdentical ||
		len(lines) != 1 || lines[0].Commit != headCommit || lines[0].Tag != "v1.2.1" {
		t.Fatalf("an annotated head is compared at its peeled commit: %+v %+v", got, lines)
	}

	for name, tc := range map[string]struct {
		ref   string
		extra map[string]string
	}{
		"head tag points at a tree":          {`{"object":{"sha":"` + headCommit + `","type":"tree"}}`, nil},
		"annotated head peels to a blob":     {annotated, map[string]string{"/repos/example/tags/git/tags/" + headObject: `{"object":{"sha":"` + headCommit + `","type":"blob"}}`}},
		"tag API names another commit":       {`{"object":{"sha":"` + strings.Repeat("9", 40) + `","type":"commit"}}`, nil},
		"tag API does not know the head tag": {`not json`, nil},
	} {
		got, lines := run(tc.ref, tc.extra)
		if got.Baseline != BaselineLatest || got.Resolution != resolutionTagFallback || !strings.Contains(got.BaselineNote, "does not resolve to the commit") || len(lines) != 0 {
			t.Errorf("%s: must keep the tags fallback: %+v %+v", name, got, lines)
		}
	}
}

// A Releases line record and a tag line record for the same repository,
// prefix and line live under different state keys.
func TestTagLineStateKeyIsSeparateFromReleasesLine(t *testing.T) {
	api, blobs := goWorld(t)
	refs := &fixtureRefs{listings: map[string]RefListing{"golang/go": recordedListing(t, "golang_go")}}
	state := newState()
	seeded := LineResolution{Owner: "golang", Repo: "go", Prefix: "go", Line: "1.21", Status: lineResolved, Tag: "go1.21.5", Commit: strings.Repeat("5", 40), ResolvedAt: fixedNow()().Format(time.RFC3339)}
	state.Lines[lineKey("golang", "go", "go", "1.21")] = seeded
	if _, err := BuildWorklistWithBaseline(context.Background(), []Citation{goCitation("a", goTag1214Commit, "a\nb\nc\n")}, nil, 0, state, withGitRefs{APIFetcher: api, refs: refs}, blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine); err != nil {
		t.Fatal(err)
	}
	if got := state.Lines[lineKey("golang", "go", "go", "1.21")]; !reflect.DeepEqual(got, seeded) {
		t.Fatalf("the Releases line record was overwritten: %+v", got)
	}
	if got := state.Lines[tagLineKey("golang", "go", "go", "1.21")]; got.Basis != LineBasisGitTags || got.Tag != "go1.21.13" {
		t.Fatalf("the tag line record is missing: %+v", got)
	}
}

func TestParseLsRemoteRejectsNUL(t *testing.T) {
	if _, err := ParseLsRemote([]byte(strings.Repeat("a", 40) + "\trefs/tags/v1.0.0\x00x\n")); !errors.Is(err, errRefListingMalformed) {
		t.Fatalf("a NUL in a ref must be refused, got %v", err)
	}
}
