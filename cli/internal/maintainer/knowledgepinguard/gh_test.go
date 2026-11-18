// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepinguard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// ghFake serves canned gh output and records the calls.
type ghFake struct {
	t      *testing.T
	files  map[string]string // downloaded assets
	verify error
	api    map[string]string // path prefix -> output
	calls  [][]string
}

func (g *ghFake) run(args ...string) ([]byte, error) {
	g.calls = append(g.calls, args)
	switch args[0] {
	case "release":
		dir := args[len(args)-1]
		for n, c := range g.files {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
				g.t.Fatal(err)
			}
		}
		return nil, nil
	case "attestation":
		return nil, g.verify
	case "api":
		for p, out := range g.api {
			if strings.Contains(args[3], p) {
				if out == "404" {
					return nil, errors.New("gh: Not Found (HTTP 404)")
				}
				return []byte(out), nil
			}
		}
		return nil, errors.New("unexpected api call " + args[3])
	}
	return nil, errors.New("unexpected")
}

func verifyFixture(t *testing.T, mutate func(*ghFake)) error {
	t.Helper()
	bin, deb := "binary", "package"
	sums := sum(bin) + "  prufyx_linux.tar.gz\n" + sum(deb) + "  prufyx_linux.deb\n"
	f := &ghFake{t: t, files: map[string]string{"prufyx_linux.tar.gz": bin, "prufyx_linux.deb": deb, "SHA256SUMS": sums}}
	if mutate != nil {
		mutate(f)
	}
	r := &Release{TagName: "v0.1.0-beta.1", Assets: []Asset{{Name: "prufyx_linux.tar.gz"}, {Name: "prufyx_linux.deb"}, {Name: "SHA256SUMS"}}}
	g := GH{Repo: "prufyx/prufyx", Run: f.run, WorkDir: t.TempDir()}
	err := g.VerifyAssets("v0.1.0-beta.1", refA, r)
	if err == nil {
		var attest []string
		for _, c := range f.calls {
			if c[0] == "attestation" {
				attest = c
			}
		}
		joined := " " + strings.Join(attest, " ") + " "
		for _, want := range []string{" --signer-workflow " + SignerWorkflow + " ", " --source-ref refs/tags/v0.1.0-beta.1 ", " --source-digest " + refA + " ", " --repo prufyx/prufyx "} {
			if !strings.Contains(joined, want) {
				t.Fatalf("attestation call lacks %q: %v", want, attest)
			}
		}
	}
	return err
}

func TestVerifyAssets(t *testing.T) {
	if err := verifyFixture(t, nil); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name string
		mut  func(*ghFake)
		want string
	}{
		{"no valid attestation or wrong signer workflow", func(f *ghFake) { f.verify = errors.New("verification failed") }, "no valid attestation"},
		{"asset changed after the sums", func(f *ghFake) { f.files["prufyx_linux.deb"] = "tampered" }, "does not match"},
		{"asset not in the sums", func(f *ghFake) {
			f.files["SHA256SUMS"] = sum("binary") + "  prufyx_linux.tar.gz\n"
		}, "not covered"},
		{"sums list a foreign file", func(f *ghFake) {
			f.files["SHA256SUMS"] += sum("x") + "  other.tar.gz\n"
		}, "not a release asset"},
		{"sums list an asset twice", func(f *ghFake) {
			f.files["SHA256SUMS"] += sum("binary") + "  prufyx_linux.tar.gz\n"
		}, "unusable line"},
		{"sums path traversal", func(f *ghFake) {
			f.files["SHA256SUMS"] += sum("x") + "  ../etc\n"
		}, "unusable line"},
		{"empty sums", func(f *ghFake) { f.files["SHA256SUMS"] = "" }, "not covered"},
		{"unlisted extra download", func(f *ghFake) { f.files["extra"] = "x" }, "differ"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyFixture(t, tc.mut)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyAssetsRefusesReleaseWithoutSums(t *testing.T) {
	g := GH{Repo: "prufyx/prufyx", Run: (&ghFake{t: t}).run, WorkDir: t.TempDir()}
	err := g.VerifyAssets("v0.1.0-beta.1", refA, &Release{Assets: []Asset{{Name: "a.tar.gz"}}})
	if err == nil || !strings.Contains(err.Error(), ChecksumAsset) {
		t.Fatal(err)
	}
	err = g.VerifyAssets("v0.1.0-beta.1", refA, &Release{})
	if err == nil {
		t.Fatal("release without assets accepted")
	}
}

func TestGHLookups(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(pin(refB, "v0.1.0-beta.1"))
	f := &ghFake{t: t, api: map[string]string{
		"releases/tags/v9":                     "404",
		"releases/tags/v0.1.0-b":               `{"tag_name":"v0.1.0-b","draft":true,"immutable":true,"assets":[{"name":"SHA256SUMS","size":5}]}`,
		"git/ref/tags/lw":                      "commit\t" + refA + "\n",
		"git/ref/tags/ann":                     "tag\t" + refB + "\n",
		"git/tags/" + refB:                     "commit\t" + refA + "\n",
		"git/ref/tags/blob":                    "blob\t" + refA + "\n",
		"compare/main..." + refA:               "identical\t" + refA + "\n",
		"compare/main..." + refB:               "ahead\t" + refA + "\n",
		"/runs?":                               refA + "\n" + refB + "\n",
		"contents/" + PinPath + "?ref=" + refA: "404",
		"contents/" + PinPath + "?ref=" + refB: enc[:20] + "\n" + enc[20:] + "\n",
	}}
	g := GH{Repo: "prufyx/prufyx", Run: f.run, WorkDir: t.TempDir()}
	if r, err := g.Release("v9"); r != nil || err != nil {
		t.Fatalf("404 must be 'no release': %v %v", r, err)
	}
	r, err := g.Release("v0.1.0-b")
	if err != nil || !r.Draft || r.Immutable == nil || !*r.Immutable || len(r.Assets) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	for tag, want := range map[string]string{"lw": refA, "ann": refA} {
		if got, err := g.TagCommit(tag); err != nil || got != want {
			t.Fatalf("%s: %q %v", tag, got, err)
		}
	}
	if _, err := g.TagCommit("blob"); err == nil {
		t.Fatal("a tag to a blob was accepted")
	}
	if ok, err := g.OnMain(refA); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := g.OnMain(refB); err != nil || ok {
		t.Fatal("an ahead commit was reported as on main", ok, err)
	}
	if v, ok, err := g.PreviousPin(); err != nil || !ok || v != "v0.1.0-beta.1" {
		t.Fatal(v, ok, err)
	}
}
