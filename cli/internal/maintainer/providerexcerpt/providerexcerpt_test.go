// SPDX-License-Identifier: AGPL-3.0-only

package providerexcerpt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

const pageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// build returns a valid entry and file for the given licence and body.
func build(licence, form, body string) (Entry, []byte) {
	src := "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"
	if licence == LicencePermissive {
		src = "https://github.com/kubernetes/website/blob/main/data/releases/schedule.yaml"
	}
	e := Entry{ID: "eks-1-33", Provider: "eks", Path: "eks/eks-1-33.txt",
		SourceURL: src,
		FetchedAt: "2026-11-07T10:00:00Z", Anchor: "standard-support", Licence: licence, Form: form}
	hdr := FileMagic + "\nsource: " + e.SourceURL + "\nfetchedAt: " + e.FetchedAt + "\nanchor: " + e.Anchor +
		"\nlicence: " + licence + "\nform: " + form + "\npageSha256: " + pageDigest + "\n"
	if form == FormParaphrase {
		hdr += "sentence: s-1\n"
	}
	data := []byte(hdr + "---\n" + body)
	e.SHA256 = digest(data)
	return e, data
}

func okParaphrase() (Entry, []byte) {
	return build(LicenceUnknown, FormParaphrase, "version 1.33 standard support ends 2026-07-29\n")
}

func TestExcerptAccepted(t *testing.T) {
	e, data := okParaphrase()
	start, end, err := ParseExcerpt(e, data)
	if err != nil || start != 10 || end != 10 {
		t.Fatalf("start=%d end=%d err=%v", start, end, err)
	}
	e2, d2 := build(LicencePermissive, FormVerbatim, "| 1.33 | 2026-07-29 |\n")
	if _, _, err := ParseExcerpt(e2, d2); err != nil {
		t.Fatal(err)
	}
}

func TestPermissiveOnlyOnPermissiveSource(t *testing.T) {
	e, _ := build(LicencePermissive, FormVerbatim, "x\n")
	for _, u := range []string{
		"https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
		"https://github.com/aws/eks-distro/releases",
		"https://github.com/kubernetes/other/blob/main/a",
		"https://github.com/kubernetes/website",
		"https://raw.githubusercontent.com/someone/else/main/a",
		"https://cloud.google.com/kubernetes-engine/docs/release-schedule",
	} {
		x := e
		x.SourceURL = u
		if err := validateEntry(x); err == nil {
			t.Errorf("verbatim/permissive accepted for %s", u)
		}
	}
	for _, u := range []string{
		"https://kubernetes.io/releases/",
		"https://raw.githubusercontent.com/k3s-io/k3s/main/a",
	} {
		x := e
		x.SourceURL = u
		if err := validateEntry(x); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
}

func TestFetchedAtFuture(t *testing.T) {
	e, _ := okParaphrase()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC).Add(-25 * time.Hour) }
	if err := validateEntry(e); err == nil {
		t.Fatal("far-future fetchedAt accepted")
	}
	nowFn = func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC).Add(-23 * time.Hour) }
	if err := validateEntry(e); err != nil {
		t.Fatalf("within 24h refused: %v", err)
	}
}

func TestFetchedAfterCommitRefused(t *testing.T) {
	e, data := okParaphrase()
	dir, rev := repo(t, e, data) // commit time is now (2020s real clock), fetchedAt 2026-11-07
	m, _ := ParseManifest(manifestJSON(t, e))
	s := source(e, rev, 10, 10)
	early := func(string) (time.Time, error) { return time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC), nil }
	late := func(string) (time.Time, error) { return time.Date(2026, 11, 7, 11, 0, 0, 0, time.UTC), nil }
	fail := func(string) (time.Time, error) { return time.Time{}, errors.New("x") }
	read := GitReader(dir)
	if err := CheckSourcesAt(m, []constraintengine.SourceEvidence{s}, read, early); err == nil {
		t.Error("fetchedAt after commit accepted")
	}
	if err := CheckSourcesAt(m, []constraintengine.SourceEvidence{s}, read, fail); err == nil {
		t.Error("commit-time failure accepted")
	}
	if err := CheckSourcesAt(m, []constraintengine.SourceEvidence{s}, read, late); err != nil {
		t.Errorf("valid refused: %v", err)
	}
}

func TestVerifyTreeSymlinkedManifestAndReadme(t *testing.T) {
	e, data := okParaphrase()
	root := t.TempDir()
	mk := func() {
		_ = os.MkdirAll(filepath.Join(root, "eks"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "real.json"), manifestJSON(t, e), 0o644)
		_ = os.WriteFile(filepath.Join(root, e.Path), data, 0o644)
	}
	mk()
	if err := os.Symlink("real.json", filepath.Join(root, "manifest.json")); err != nil {
		t.Skip("no symlinks")
	}
	if _, err := VerifyTree(root); err == nil {
		t.Fatal("symlinked manifest accepted")
	}
	_ = os.Remove(filepath.Join(root, "manifest.json"))
	_ = os.WriteFile(filepath.Join(root, "manifest.json"), manifestJSON(t, e), 0o644)
	_ = os.Symlink("real.json", filepath.Join(root, "README.md"))
	if _, err := VerifyTree(root); err == nil {
		t.Fatal("symlinked README accepted")
	}
}

func TestExcerptRejections(t *testing.T) {
	e, data := okParaphrase()
	big := build2(strings.Repeat("a", MaxExcerptBytes))
	cases := map[string]func() (Entry, []byte){
		"digest mismatch":   func() (Entry, []byte) { return e, append(append([]byte{}, data...), 'x', '\n') },
		"too large":         func() (Entry, []byte) { return big() },
		"verbatim unknown":  func() (Entry, []byte) { return build(LicenceUnknown, FormVerbatim, "x\n") },
		"quote in paraphr.": func() (Entry, []byte) { return build(LicenceUnknown, FormParaphrase, "it says \"ends soon\"\n") },
		"table in paraphr.": func() (Entry, []byte) { return build(LicenceUnknown, FormParaphrase, "| 1.33 | 2026 |\n") },
		"blockquote":        func() (Entry, []byte) { return build(LicenceUnknown, FormParaphrase, "> ends soon\n") },
		"cookie":            func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "Set-Cookie: a=b\n") },
		"authorization": func() (Entry, []byte) {
			return build(LicencePermissive, FormVerbatim, "Authorization: Bearer abcdefghijkl\n")
		},
		"tracking":    func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "see x utm_source=a\n") },
		"api key":     func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "api_key is here\n") },
		"private key": func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "-----BEGIN KEY\n") },
		"no final LF": func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "row") },
		"CR":          func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "a\r\n") },
		"NUL":         func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "a\x00\n") },
		"empty body":  func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, "  \n") },
		"too many lines": func() (Entry, []byte) {
			return build(LicencePermissive, FormVerbatim, strings.Repeat("a\n", MaxBodyLines+1))
		},
		"long paraphrase": func() (Entry, []byte) {
			return build(LicenceUnknown, FormParaphrase, strings.Repeat("a", MaxParaphrase+1)+"\n")
		},
		"header mismatch": func() (Entry, []byte) {
			x, d := okParaphrase()
			x.Anchor = "other"
			x.SHA256 = digest(d)
			return x, d
		},
		"no sentence id": func() (Entry, []byte) {
			x, d := okParaphrase()
			d = []byte(strings.Replace(string(d), "sentence: s-1\n", "", 1))
			x.SHA256 = digest(d)
			return x, d
		},
	}
	for name, f := range cases {
		ent, d := f()
		if _, _, err := ParseExcerpt(ent, d); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err=%v)", name, err)
		}
	}
}

// build2 makes a permissive file of exactly the given body size.
func build2(body string) func() (Entry, []byte) {
	return func() (Entry, []byte) { return build(LicencePermissive, FormVerbatim, body+"\n") }
}

func manifestJSON(t *testing.T, entries ...Entry) []byte {
	raw, err := json.Marshal(Manifest{Schema: ManifestSchema, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestRejections(t *testing.T) {
	e, _ := okParaphrase()
	if _, err := ParseManifest(manifestJSON(t, e)); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Entry)) []byte { x := e; f(&x); return manifestJSON(t, x) }
	cases := map[string][]byte{
		"verbatim unknown licence": mut(func(x *Entry) { x.Form = FormVerbatim }),
		"unknown licence class":    mut(func(x *Entry) { x.Licence = "cc-by" }),
		"host not allowlisted":     mut(func(x *Entry) { x.SourceURL = "https://example.com/a" }),
		"aggregator host":          mut(func(x *Entry) { x.SourceURL = "https://endoflife.date/amazon-eks" }),
		"http":                     mut(func(x *Entry) { x.SourceURL = "http://docs.aws.amazon.com/a" }),
		"query":                    mut(func(x *Entry) { x.SourceURL = "https://docs.aws.amazon.com/a?token=1" }),
		"userinfo":                 mut(func(x *Entry) { x.SourceURL = "https://u:p@docs.aws.amazon.com/a" }),
		"fragment":                 mut(func(x *Entry) { x.SourceURL = "https://docs.aws.amazon.com/a#x" }),
		"port":                     mut(func(x *Entry) { x.SourceURL = "https://docs.aws.amazon.com:8443/a" }),
		"escaped":                  mut(func(x *Entry) { x.SourceURL = "https://docs.aws.amazon.com/a%2f" }),
		"path traversal":           mut(func(x *Entry) { x.Path = "../eks/eks-1-33.txt" }),
		"path id mismatch":         mut(func(x *Entry) { x.Path = "eks/other.txt" }),
		"bad digest":               mut(func(x *Entry) { x.SHA256 = "sha256:abc" }),
		"bad time":                 mut(func(x *Entry) { x.FetchedAt = "2026-11-07 10:00" }),
		"non-UTC time":             mut(func(x *Entry) { x.FetchedAt = "2026-11-07T10:00:00+02:00" }),
		"unknown field":            []byte(strings.Replace(string(manifestJSON(t, e)), `"form"`, `"extra":1,"form"`, 1)),
		"wrong schema":             []byte(strings.Replace(string(manifestJSON(t, e)), "v1alpha1", "v2", 1)),
		"duplicate id":             manifestJSON(t, e, e),
		"trailing data":            append(manifestJSON(t, e), []byte(`{}`)...),
		"empty":                    nil,
	}
	for name, raw := range cases {
		if _, err := ParseManifest(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// repo creates a git repository holding the store and returns dir, commit.
func repo(t *testing.T, e Entry, data []byte) (string, string) {
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	p := filepath.Join(dir, Dir, e.Path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "excerpt")
	return dir, run("rev-parse", "HEAD")
}

func source(e Entry, rev string, start, end int) constraintengine.SourceEvidence {
	return constraintengine.SourceEvidence{ID: "src-1", Revision: rev, ContentDigest: e.SHA256, StartLine: start, EndLine: end,
		URL: "https://github.com/" + Repo + "/blob/" + rev + "/" + Dir + "/" + e.Path}
}

func TestCheckSourcesAtPinnedCommit(t *testing.T) {
	e, data := okParaphrase()
	dir, rev := repo(t, e, data)
	m, err := ParseManifest(manifestJSON(t, e))
	if err != nil {
		t.Fatal(err)
	}
	read := GitReader(dir)
	if err := VerifyAt(m, rev, read); err != nil {
		t.Fatal(err)
	}
	good := source(e, rev, 10, 10)
	if err := CheckSources(m, []constraintengine.SourceEvidence{good}, read); err != nil {
		t.Fatalf("valid citation refused: %v", err)
	}
	raw := good
	raw.URL = "https://raw.githubusercontent.com/" + Repo + "/" + rev + "/" + Dir + "/" + e.Path
	if err := CheckSources(m, []constraintengine.SourceEvidence{raw}, read); err != nil {
		t.Fatalf("raw URL citation refused: %v", err)
	}
	other := "0123456789012345678901234567890123456789"
	badCases := map[string]constraintengine.SourceEvidence{
		"span in header": source(e, rev, 1, 10),
		"span past body": source(e, rev, 10, 11),
		"wrong digest":   func() constraintengine.SourceEvidence { s := good; s.ContentDigest = pageDigest; return s }(),
		"non-git URL":    func() constraintengine.SourceEvidence { s := good; s.URL = e.SourceURL; return s }(),
		"other repository": func() constraintengine.SourceEvidence {
			s := good
			s.URL = strings.Replace(s.URL, Repo, "someone/else", 1)
			return s
		}(),
		"outside the store": func() constraintengine.SourceEvidence {
			s := good
			s.URL = strings.Replace(s.URL, Dir+"/", "cli/", 1)
			return s
		}(),
		"url revision differs": func() constraintengine.SourceEvidence {
			s := good
			s.URL = strings.Replace(s.URL, rev, other, 1)
			return s
		}(),
		"commit not present": func() constraintengine.SourceEvidence { s := source(e, other, 10, 10); return s }(),
		"unlisted path": func() constraintengine.SourceEvidence {
			s := good
			s.URL = strings.Replace(s.URL, "eks-1-33", "eks-1-34", 1)
			return s
		}(),
	}
	for name, s := range badCases {
		if err := CheckSources(m, []constraintengine.SourceEvidence{s}, read); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckSources(m, nil, read); err == nil {
		t.Error("no sources accepted")
	}
}

func TestVerifyAtDetectsTamperedCommit(t *testing.T) {
	e, data := okParaphrase()
	tampered := []byte(strings.Replace(string(data), "2026-07-29", "2027-07-29", 1))
	dir, rev := repo(t, e, tampered) // manifest still carries the old digest
	m, _ := ParseManifest(manifestJSON(t, e))
	if err := VerifyAt(m, rev, GitReader(dir)); err == nil {
		t.Fatal("tampered excerpt accepted at the pinned commit")
	}
	if _, err := GitReader(dir)("main", Dir+"/"+e.Path); err == nil {
		t.Fatal("non-40-hex revision accepted")
	}
}

func TestVerifyTree(t *testing.T) {
	e, data := okParaphrase()
	root := t.TempDir()
	write := func(rel string, b []byte) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", manifestJSON(t, e))
	write(e.Path, data)
	if _, err := VerifyTree(root); err != nil {
		t.Fatal(err)
	}
	write("eks/stray.txt", []byte("x\n"))
	if _, err := VerifyTree(root); err == nil {
		t.Fatal("unlisted file accepted")
	}
	_ = os.Remove(filepath.Join(root, "eks/stray.txt"))
	if err := os.Symlink("eks-1-33.txt", filepath.Join(root, "eks/link.txt")); err == nil {
		if _, err := VerifyTree(root); err == nil {
			t.Fatal("symlink accepted")
		}
		_ = os.Remove(filepath.Join(root, "eks/link.txt"))
	}
	write(e.Path, append(data, 'x', '\n'))
	if _, err := VerifyTree(root); err == nil {
		t.Fatal("modified excerpt accepted")
	}
}

// The committed store must itself verify.
func TestCommittedStore(t *testing.T) {
	if _, err := VerifyTree(filepath.Join("..", "..", "..", "knowledge", "provider-excerpts")); err != nil {
		t.Fatal(err)
	}
}
