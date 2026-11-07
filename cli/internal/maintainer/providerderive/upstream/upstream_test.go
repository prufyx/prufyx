// SPDX-License-Identifier: AGPL-3.0-only

package upstream

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

func input(file, anchor, body string) Input {
	src := "https://raw.githubusercontent.com/kubernetes/website/main/data/releases/" + file
	e := providerexcerpt.Entry{ID: "upstream-" + anchor, Provider: Provider, Path: "upstream/upstream-" + anchor + ".txt", SourceURL: src,
		FetchedAt: "2026-11-07T09:47:35Z", Anchor: anchor, Licence: providerexcerpt.LicencePermissive, Form: providerexcerpt.FormVerbatim}
	data := []byte(providerexcerpt.FileMagic + "\nsource: " + src + "\nfetchedAt: " + e.FetchedAt + "\nanchor: " + anchor +
		"\nlicence: " + e.Licence + "\nform: " + e.Form + "\npageSha256: sha256:" + strings.Repeat("1", 64) + "\n---\n" + body)
	s := sha256.Sum256(data)
	e.SHA256 = "sha256:" + hex.EncodeToString(s[:])
	return Input{e, data}
}

func good(t *testing.T) (Input, Input) {
	return input("schedule.yaml", AnchorSchedule, read(t, "schedule.yaml")), input("eol.yaml", AnchorEOL, read(t, "eol.yaml"))
}

func render(t *testing.T, r Result) string {
	t.Helper()
	b, err := json.MarshalIndent(struct {
		Lifecycle []distribution.Lifecycle
		Lines     []Line
		AsOf      string
		Warnings  []string
	}{r.Lifecycle, r.Lines, r.AsOf, r.Warnings}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestDeriveGolden(t *testing.T) {
	s, e := good(t)
	res, err := Derive(s, e, []byte(read(t, "stable.txt")))
	if err != nil {
		t.Fatal(err)
	}
	got := render(t, res)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile("testdata/derive.golden.json", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got != read(t, "derive.golden.json") {
		t.Fatalf("golden mismatch:\n%s", got)
	}
	res2, _ := Derive(s, e, []byte(read(t, "stable.txt")))
	if render(t, res2) != got {
		t.Fatal("not deterministic")
	}
	for _, l := range res.Lines {
		if l.Line == "1.37" && l.LatestPatch != "1.37.2" {
			t.Fatalf("1.37 %+v", l)
		}
	}
}

func TestRowsShape(t *testing.T) {
	s, e := good(t)
	res, err := Derive(s, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lifecycle) != 7 || res.Lifecycle[0].Line != "1.2" || res.Lifecycle[6].Line != "1.37" {
		t.Fatalf("%+v", res.Lifecycle)
	}
	for _, l := range res.Lifecycle {
		if l.ExtendedEnd != "" || l.ExtendedRequiresOptIn != nil || l.Precision != "day" || l.StandardEnd == "" {
			t.Fatalf("%+v", l)
		}
	}
	// the rows pass the record validator
	rec := distribution.Record{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Lifecycle: res.Lifecycle,
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + strings.Repeat("a", 40) + "/versions.md", Revision: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}}}}
	if err := distribution.Validate(distribution.Section{Records: []distribution.Record{rec}, Applicability: []distribution.Applicability{}}); err != nil {
		t.Fatalf("lifecycle rows refused by the record validator: %v", err)
	}
}

func mutate(t *testing.T, name, from, to string) string {
	t.Helper()
	s := read(t, name)
	if !strings.Contains(s, from) {
		t.Fatalf("fixture lacks %q", from)
	}
	return strings.Replace(s, from, to, 1)
}

func TestScheduleFailClosed(t *testing.T) {
	cases := map[string]struct{ body, kind string }{
		"duplicate release":    {mutate(t, "schedule.yaml", `release: "1.36"`, `release: "1.37"`), shared.KindFormat},
		"duplicate key":        {mutate(t, "schedule.yaml", "  releaseDate: \"2026-08-26\"\n", "  releaseDate: \"2026-08-26\"\n  releaseDate: \"2026-08-27\"\n"), shared.KindFormat},
		"unknown top key":      {read(t, "schedule.yaml") + "extra: 1\n", shared.KindHeader},
		"unknown entry key":    {mutate(t, "schedule.yaml", "  endOfLifeDate: \"2027-10-28\"\n", "  endOfLifeDate: \"2027-10-28\"\n  surprise: x\n"), shared.KindHeader},
		"missing eol":          {mutate(t, "schedule.yaml", "  endOfLifeDate: \"2026-10-27\"\n", ""), shared.KindMissing},
		"missing maintenance":  {mutate(t, "schedule.yaml", "  maintenanceModeStartDate: \"2026-08-27\"\n", ""), shared.KindMissing},
		"next without release": {mutate(t, "schedule.yaml", "    release: 1.37.2\n", ""), shared.KindMissing},
		"bad date":             {mutate(t, "schedule.yaml", `"2026-08-26"`, `"2026-13-40"`), shared.KindUnparsable},
		"unquoted date":        {mutate(t, "schedule.yaml", `"2026-08-26"`, `2026-08-26`), shared.KindUnparsable},
		"float minor":          {mutate(t, "schedule.yaml", `release: "1.35"`, `release: 1.3`), shared.KindUnparsable},
		"patch as minor":       {mutate(t, "schedule.yaml", `release: "1.35"`, `release: "1.35.1"`), shared.KindUnparsable},
		"patch of other line":  {mutate(t, "schedule.yaml", `release: 1.37.2`, `release: 1.36.2`), shared.KindUnparsable},
		"prerelease patch":     {mutate(t, "schedule.yaml", `release: 1.37.2`, `release: 1.37.0-beta.0`), shared.KindPrerelease},
		"dates out of order":   {mutate(t, "schedule.yaml", `"2027-08-28"`, `"2028-08-28"`), shared.KindUnparsable},
		"anchor":               {mutate(t, "schedule.yaml", "- release: \"1.35\"", "- &a\n  release: \"1.35\""), shared.KindFormat},
		"empty":                {"", shared.KindEmpty},
		"html":                 {"<html><body>404</body></html>", shared.KindFormat},
		"no schedules":         {"upcoming_releases: []\n", shared.KindMissing},
		"bad upcoming":         {mutate(t, "schedule.yaml", `targetDate: "2026-11-11"`, `targetDate: soon`), shared.KindUnparsable},
	}
	for name, c := range cases {
		if _, err := ParseSchedule(c.body); shared.KindOf(err) != c.kind {
			t.Errorf("%s: kind %q err %v", name, shared.KindOf(err), err)
		}
	}
}

func TestEOLFailClosed(t *testing.T) {
	cases := map[string]struct{ body, kind string }{
		"unknown top key":  {read(t, "eol.yaml") + "x: 1\n", shared.KindHeader},
		"missing final":    {mutate(t, "eol.yaml", "  finalPatchRelease: 1.33.13\n", ""), shared.KindMissing},
		"duplicate":        {mutate(t, "eol.yaml", `release: "1.26"`, `release: "1.33"`), shared.KindFormat},
		"float minor":      {mutate(t, "eol.yaml", `release: "1.26"`, `release: 1.26`), shared.KindUnparsable},
		"final not patch":  {mutate(t, "eol.yaml", `finalPatchRelease: 1.33.13`, `finalPatchRelease: 1.33`), shared.KindUnparsable},
		"bad date":         {mutate(t, "eol.yaml", `"2026-06-28"`, `"2026-06-31"`), shared.KindUnparsable},
		"final prerelease": {mutate(t, "eol.yaml", `finalPatchRelease: 1.33.13`, `finalPatchRelease: 1.33.13-rc.1`), shared.KindPrerelease},
		"empty":            {"", shared.KindEmpty},
	}
	for name, c := range cases {
		if _, err := ParseEOL(c.body); shared.KindOf(err) != c.kind {
			t.Errorf("%s: %q %v", name, shared.KindOf(err), err)
		}
	}
	if _, err := ParseEOL(mutate(t, "eol.yaml", `note: 1.26.15 was`, "note: [1, 2]\n  was")); err == nil {
		t.Error("non-string note accepted")
	}
}

func TestStable(t *testing.T) {
	line, patch, err := ParseStable("v1.37.2")
	if err != nil || line != "1.37" || patch != "1.37.2" {
		t.Fatal(line, patch, err)
	}
	if _, _, err := ParseStable("v1.37.2\n"); err != nil {
		t.Fatal(err)
	}
	for in, kind := range map[string]string{
		"v1.38.0-rc.1": shared.KindPrerelease, "v1.38.0-alpha.1": shared.KindPrerelease,
		"v1.37": shared.KindUnparsable, "1.37.2": shared.KindUnparsable, "<html>v1.37.2</html>": shared.KindUnparsable,
		"v1.37.2\n\n": shared.KindUnparsable, "": shared.KindEmpty, "v2.0.0": shared.KindUnparsable, "v1.037.2": shared.KindUnparsable,
	} {
		if _, _, err := ParseStable(in); shared.KindOf(err) != kind {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestDeriveFailClosed(t *testing.T) {
	s, e := good(t)
	if _, err := Derive(s, e, []byte("v1.50.0")); shared.KindOf(err) != shared.KindConflict {
		t.Errorf("unknown stable line: %v", err)
	}
	if _, err := Derive(s, e, []byte("v1.38.0-rc.1")); shared.KindOf(err) != shared.KindPrerelease {
		t.Errorf("prerelease stable: %v", err)
	}
	dup := input("eol.yaml", AnchorEOL, strings.Replace(mutate(t, "eol.yaml", `release: "1.26"`, `release: "1.34"`), "finalPatchRelease: 1.26.15", "finalPatchRelease: 1.34.15", 1))
	if _, err := Derive(s, dup, nil); shared.KindOf(err) != shared.KindConflict {
		t.Errorf("both files: %v", err)
	}
	wrong := s
	wrong.Entry.Anchor = AnchorEOL
	if _, err := Derive(wrong, e, nil); shared.KindOf(err) != shared.KindExcerpt {
		t.Errorf("anchor: %v", err)
	}
	other := input("eol.yaml", AnchorSchedule, read(t, "schedule.yaml"))
	if _, err := Derive(other, e, nil); shared.KindOf(err) != shared.KindExcerpt {
		t.Errorf("file/anchor mismatch: %v", err)
	}
	tam := s
	tam.Data = append([]byte(nil), s.Data...)
	tam.Data[len(tam.Data)-3] ^= 1
	if _, err := Derive(tam, e, nil); shared.KindOf(err) != shared.KindExcerpt {
		t.Errorf("tampered: %v", err)
	}
	badS := input("schedule.yaml", AnchorSchedule, mutate(t, "schedule.yaml", `"2026-08-26"`, `"2026-13-40"`))
	if res, err := Derive(badS, e, nil); err == nil || len(res.Lifecycle) != 0 {
		t.Errorf("partial output: %+v %v", res, err)
	}
	res, err := Derive(s, e, []byte("v1.37.3"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range res.Warnings {
		found = found || strings.Contains(w, "stable marker 1.37.3")
	}
	if !found {
		t.Errorf("no stale-next warning: %v", res.Warnings)
	}
}
