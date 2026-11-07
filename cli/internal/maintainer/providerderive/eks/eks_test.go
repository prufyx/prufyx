// SPDX-License-Identifier: AGPL-3.0-only

package eks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/shared"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mutate(t *testing.T, name, from, to string) string {
	t.Helper()
	s := read(t, name)
	if !strings.Contains(s, from) {
		t.Fatalf("fixture lacks %q", from)
	}
	return strings.Replace(s, from, to, 1)
}

func input(body string) Input {
	src := "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.md"
	e := providerexcerpt.Entry{ID: "eks-release-calendar", Provider: Provider, Path: "eks/eks-release-calendar.txt", SourceURL: src,
		FetchedAt: "2026-11-07T09:47:35Z", Anchor: Anchor, Licence: providerexcerpt.LicenceUnknown, Form: providerexcerpt.FormParaphrase}
	data := []byte(providerexcerpt.FileMagic + "\nsource: " + src + "\nfetchedAt: " + e.FetchedAt + "\nanchor: " + Anchor +
		"\nlicence: " + e.Licence + "\nform: " + e.Form + "\npageSha256: sha256:" + strings.Repeat("1", 64) + "\nsentence: s-calendar\n---\n" + body)
	s := sha256.Sum256(data)
	e.SHA256 = "sha256:" + hex.EncodeToString(s[:])
	return Input{e, data}
}

func kind(err error) string { return shared.KindOf(err) }

func TestTwinsAgreeAndGolden(t *testing.T) {
	md, err := ParseMarkdown([]byte(read(t, "page.md")))
	if err != nil {
		t.Fatal(err)
	}
	hm, err := ParseHTML([]byte(read(t, "page.html")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Agree(md, hm); err != nil {
		t.Fatal(err)
	}
	body := Canonical(md)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.WriteFile("testdata/excerpt-body.golden.txt", []byte(body), 0o644)
	}
	if body != read(t, "excerpt-body.golden.txt") {
		t.Fatalf("canonical body mismatch:\n%s", body)
	}
	res, err := Derive(input(body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(res, "", " ")
	got := string(b) + "\n"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.WriteFile("testdata/derive.golden.json", []byte(got), 0o644)
	}
	if got != read(t, "derive.golden.json") {
		t.Fatalf("golden mismatch:\n%s", got)
	}
	res2, _ := Derive(input(body))
	b2, _ := json.MarshalIndent(res2, "", " ")
	if string(b2)+"\n" != got {
		t.Fatal("not deterministic")
	}
	if len(res.Lifecycle) != 4 || res.Lifecycle[0].Line != "1.34" || res.Lifecycle[3].Line != "1.37" {
		t.Fatalf("%+v", res.Lifecycle)
	}
	for _, l := range res.Lifecycle {
		if l.ExtendedRequiresOptIn == nil || *l.ExtendedRequiresOptIn || l.Precision != "day" {
			t.Fatalf("extended must be automatic (optIn false): %+v", l)
		}
	}
	if len(res.Warnings) != 0 || len(res.NotYetReleased) != 0 {
		t.Fatalf("%v %v", res.Warnings, res.NotYetReleased)
	}
	// the rows pass the record validator (evidence aside)
	rec := distribution.Record{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Lifecycle: res.Lifecycle,
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + strings.Repeat("a", 40) + "/versions.md", Revision: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}}}}
	if err := distribution.Validate(distribution.Section{Records: []distribution.Record{rec}, Applicability: []distribution.Applicability{}}); err != nil {
		t.Fatalf("rows refused by the record validator: %v", err)
	}
}

func TestMarkdownFailClosed(t *testing.T) {
	hdr := "| Kubernetes version | Upstream release | Amazon EKS release | End of standard support | End of extended support | "
	row := "|  `1.37`  | August 26, 2026 | October 1, 2026 | December 1, 2027 | December 1, 2028 | "
	cases := map[string]struct{ page, kind string }{
		"renamed header":  {mutate(t, "page.md", "End of standard support", "Standard support ends"), shared.KindHeader},
		"swapped columns": {mutate(t, "page.md", "| Upstream release | Amazon EKS release |", "| Amazon EKS release | Upstream release |"), shared.KindHeader},
		"sixth column":    {strings.ReplaceAll(mutate(t, "page.md", hdr, hdr+"Notes | "), "| --- | --- | --- | --- | --- |", "| --- | --- | --- | --- | --- | --- |"), shared.KindHeader},
		"missing column":  {strings.Replace(read(t, "page.md"), " End of extended support | ", "", 1), shared.KindHeader},
		"no heading":      {mutate(t, "page.md", "## Amazon EKS Kubernetes release calendar", "## Something else"), shared.KindMissing},
		"two tables":      {read(t, "page.md") + "\n| a | b |\n| --- | --- |\n| 1 | 2 |\n", shared.KindHeader},
		"iso date":        {mutate(t, "page.md", "December 1, 2027", "2027-12-01x"), shared.KindUnparsable},
		"short month":     {mutate(t, "page.md", "December 1, 2027", "Dec 1, 2027"), shared.KindUnparsable},
		"tbd mixed":       {mutate(t, "page.md", "December 1, 2027", "TBD"), shared.KindUnparsable},
		"footnote":        {mutate(t, "page.md", "December 1, 2027", "December 1, 2027*"), shared.KindUnparsable},
		"patch version":   {mutate(t, "page.md", "`1.37`", "`1.37.1`"), shared.KindUnparsable},
		"bare version":    {mutate(t, "page.md", "`1.37`", "1.37"), shared.KindUnparsable},
		"non-monotonic":   {mutate(t, "page.md", "`1.35`", "`1.38`"), shared.KindUnparsable},
		"short row":       {mutate(t, "page.md", "| December 1, 2028 | \n", "\n"), shared.KindUnparsable},
		"extended < std":  {mutate(t, "page.md", "December 1, 2028", "June 1, 2027"), shared.KindUnparsable},
		"mixed precision": {mutate(t, "page.md", "December 1, 2028", "December 2028"), shared.KindUnparsable},
		"empty":           {"", shared.KindEmpty},
		"interstitial":    {"<html><title>Sign in</title></html>", shared.KindMissing},
		"no rows":         {strings.Join(strings.Split(read(t, "page.md"), "\n")[:9], "\n") + "\n", shared.KindMissing},
		"crlf":            {strings.ReplaceAll(read(t, "page.md"), "\n", "\r\n"), shared.KindFormat},
	}
	_ = row
	for name, c := range cases {
		if _, err := ParseMarkdown([]byte(c.page)); kind(err) != c.kind {
			t.Errorf("%s: kind %q err %v", name, kind(err), err)
		}
	}
	// month-only is inside the grammar and keeps its precision
	rows, err := ParseMarkdown([]byte(strings.NewReplacer("December 1, 2027", "December 2027", "December 1, 2028", "December 2028", "October 1, 2026", "October 2026").Replace(read(t, "page.md"))))
	if err != nil || rows[0].StandardEnd.Precision != "month" || rows[0].StandardEnd.Value != "2027-12" {
		t.Fatalf("%+v %v", rows, err)
	}
}

func TestHTMLFailClosed(t *testing.T) {
	cases := map[string]struct{ page, kind string }{
		"renamed header": {mutate(t, "page.html", "End of standard support", "Standard support ends"), shared.KindHeader},
		"two tables":     {read(t, "page.html") + "<table><tr><td>x</td></tr></table>", shared.KindHeader},
		"no table":       {"<html><body>login required</body></html>", shared.KindHeader},
		"colspan":        {mutate(t, "page.html", "<td><p>August 26, 2026", "<td colspan=\"2\"><p>August 26, 2026"), shared.KindUnparsable},
		"bad cell":       {mutate(t, "page.html", "October 1, 2026", "1 Oct 2026"), shared.KindUnparsable},
		"missing cell":   {mutate(t, "page.html", "<td><p>December 1, 2028</p></td>", ""), shared.KindUnparsable},
		"empty":          {"", shared.KindEmpty},
		"no rows":        {"<table><thead><tr><th>Kubernetes version</th><th>Upstream release</th><th>Amazon EKS release</th><th>End of standard support</th><th>End of extended support</th></tr></thead></table>", shared.KindMissing},
	}
	for name, c := range cases {
		if _, err := ParseHTML([]byte(c.page)); kind(err) != c.kind {
			t.Errorf("%s: kind %q err %v", name, kind(err), err)
		}
	}
}

func TestTwinDisagreement(t *testing.T) {
	md, _ := ParseMarkdown([]byte(read(t, "page.md")))
	hm, err := ParseHTML([]byte(mutate(t, "page.html", "December 1, 2027", "December 2, 2027")))
	if err != nil {
		t.Fatal(err)
	}
	if kind(Agree(md, hm)) != shared.KindConflict || kind(Agree(md, hm[1:])) != shared.KindConflict {
		t.Fatal("disagreement not a conflict")
	}
}

func TestResponseGuards(t *testing.T) {
	if kind(shared.CheckResponse(404, "text/markdown", []byte("x"), "text/markdown")) != shared.KindStatus ||
		kind(shared.CheckResponse(200, "text/markdown", nil, "text/markdown")) != shared.KindEmpty ||
		kind(shared.CheckResponse(200, "text/html", []byte("<html>"), "text/markdown")) != shared.KindFormat {
		t.Fatal("response guard")
	}
}

func TestDeriveFailClosed(t *testing.T) {
	good := read(t, "excerpt-body.golden.txt")
	cases := map[string]struct{ body, kind string }{
		"garbage line":    {good + "eks 1.33 upstream today\n", shared.KindUnparsable},
		"bad date":        {strings.Replace(good, "2027-12-01", "2027-13-01", 1), shared.KindUnparsable},
		"ascending":       {"eks 1.34 upstream 2025-08-27 release 2025-10-02 standard-end 2026-12-02 extended-end 2027-12-02\neks 1.37 upstream 2026-08-26 release 2026-10-01 standard-end 2027-12-01 extended-end 2028-12-01\n", shared.KindUnparsable},
		"extended order":  {strings.Replace(good, "extended-end 2028-12-01", "extended-end 2027-01-01", 1), shared.KindUnparsable},
		"patch line":      {strings.Replace(good, "eks 1.37 ", "eks 1.37.1 ", 1), shared.KindUnparsable},
		"mixed precision": {strings.Replace(good, "extended-end 2028-12-01", "extended-end 2028-12", 1), shared.KindUnparsable},
		"tbd mixed":       {strings.Replace(good, "extended-end 2028-12-01", "extended-end tbd", 1), shared.KindUnparsable},
		"markup":          {"| eks 1.37 |\n", shared.KindExcerpt},
		"quote":           {"eks 1.37 \"quoted\"\n", shared.KindExcerpt},
	}
	for name, c := range cases {
		res, err := Derive(input(c.body))
		if kind(err) != c.kind || len(res.Lifecycle) != 0 {
			t.Errorf("%s: kind %q err %v", name, kind(err), err)
		}
	}
	in := input(good)
	w := in
	w.Entry.Anchor = "other"
	tam := in
	tam.Data = append([]byte(nil), in.Data...)
	tam.Data[len(tam.Data)-3] ^= 1
	verb := in
	verb.Entry.Form = providerexcerpt.FormVerbatim
	foreign := in
	foreign.Entry.SourceURL = "https://docs.aws.amazon.com/eks/latest/userguide/other.md"
	for name, x := range map[string]Input{"anchor": w, "tampered": tam, "verbatim": verb, "foreign url": foreign} {
		if _, err := Derive(x); kind(err) != shared.KindExcerpt {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPrereleaseAndRuleFlags(t *testing.T) {
	// a line whose upstream release is after the fetch day is not released: no support claim
	body := "eks 1.38 upstream 2027-02-01 release 2027-03-01 standard-end 2028-05-01 extended-end 2029-05-01\n" + read(t, "excerpt-body.golden.txt")
	res, err := Derive(input(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NotYetReleased) != 1 || res.NotYetReleased[0] != "1.38" || len(res.Lifecycle) != 4 {
		t.Fatalf("%+v", res)
	}
	// a row off the page's own 14+12 month rule is flagged, not normalised
	odd := strings.Replace(read(t, "excerpt-body.golden.txt"), "standard-end 2027-12-01", "standard-end 2027-12-15", 1)
	res, err = Derive(input(odd))
	if err != nil || len(res.Warnings) != 1 || res.Lifecycle[3].StandardEnd != "2027-12-15" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestTBDRow(t *testing.T) {
	body := "eks 1.38 upstream 2026-11-01 release tbd standard-end tbd extended-end tbd\n" + read(t, "excerpt-body.golden.txt")
	res, err := Derive(input(body))
	if err != nil {
		t.Fatal(err)
	}
	l := res.Lifecycle[4]
	if l.Line != "1.38" || l.Precision != "tbd" || l.GA != "" || l.ExtendedRequiresOptIn != nil {
		t.Fatalf("%+v", l)
	}
}
