// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepinguard

import (
	"errors"
	"strings"
	"testing"
)

const (
	refA = "1111111111111111111111111111111111111111"
	refB = "2222222222222222222222222222222222222222"
)

type fakeForge struct {
	rel      *Release
	relErr   error
	commit   string
	onMain   bool
	verify   error
	prev     string
	prevOK   bool
	prevErr  error
	verified int
	calls    []string
}

func (f *fakeForge) Release(string) (*Release, error) {
	f.calls = append(f.calls, "release")
	return f.rel, f.relErr
}
func (f *fakeForge) TagCommit(string) (string, error) {
	f.calls = append(f.calls, "tag")
	return f.commit, nil
}
func (f *fakeForge) OnMain(string) (bool, error) {
	f.calls = append(f.calls, "main")
	return f.onMain, nil
}
func (f *fakeForge) VerifyAssets(string, string, *Release) error {
	f.verified++
	return f.verify
}
func (f *fakeForge) PreviousPin() (string, bool, error) { return f.prev, f.prevOK, f.prevErr }

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func good() *fakeForge {
	return &fakeForge{
		rel:    &Release{TagName: "v0.1.0-beta.1", Immutable: yes(), Assets: []Asset{{Name: "SHA256SUMS"}}},
		commit: refA, onMain: true, prev: "v0.1.0-beta.0", prevOK: true,
	}
}

func pin(ref, v string) []byte { return []byte("ref=" + ref + "\nversion=" + v + "\n") }

func TestCheckAccepts(t *testing.T) {
	f := good()
	res, err := Check(pin(refA, "v0.1.0-beta.1"), f, Options{})
	if err != nil || res.Legacy || res.Downgrade || f.verified != 1 {
		t.Fatalf("res=%+v err=%v verified=%d", res, err, f.verified)
	}
}

// The unchanged first-beta pin behaves as before: no release is read.
func TestCheckLegacyPinIsUntouched(t *testing.T) {
	f := &fakeForge{prevOK: true, prev: "v0.1.0-beta.0"}
	res, err := Check([]byte(LegacyPin), f, Options{})
	if err != nil || !res.Legacy || len(f.calls) != 0 || f.verified != 0 {
		t.Fatalf("res=%+v err=%v calls=%v", res, err, f.calls)
	}
	// With no earlier pin found, the floor is the legacy version: still fine.
	if _, err := Check([]byte(LegacyPin), &fakeForge{}, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRefuses(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*fakeForge)
		pin  []byte
		opt  Options
		want string
	}{
		{"no release", func(f *fakeForge) { f.rel = nil }, nil, Options{}, "not a published release"},
		{"release read error", func(f *fakeForge) { f.relErr = errors.New("boom") }, nil, Options{}, "cannot be read"},
		{"draft", func(f *fakeForge) { f.rel.Draft = true }, nil, Options{}, "draft"},
		{"release for another tag", func(f *fakeForge) { f.rel.TagName = "v0.1.0-beta.2" }, nil, Options{}, "not v0.1.0-beta.1"},
		{"tag points elsewhere", func(f *fakeForge) { f.commit = refB }, nil, Options{}, "not to the pinned ref"},
		{"tag resolves to nothing", func(f *fakeForge) { f.commit = "" }, nil, Options{}, "not to the pinned ref"},
		{"ref not on main", func(f *fakeForge) { f.onMain = false }, nil, Options{}, "not an ancestor of main"},
		{"mutable release", func(f *fakeForge) { f.rel.Immutable = no() }, nil, Options{}, "not immutable"},
		{"asset without attestation", func(f *fakeForge) { f.verify = errors.New("no attestation") }, nil, Options{}, "no attestation"},
		{"downgrade", func(f *fakeForge) { f.prev = "v0.1.0-beta.2" }, nil, Options{}, "lower than the last published pin"},
		{"downgrade below patch", func(f *fakeForge) { f.prev = "v0.1.1" }, nil, Options{}, "lower than"},
		{"previous pin unreadable", func(f *fakeForge) { f.prevErr = errors.New("api down") }, nil, Options{}, "last published pin cannot be read"},
		{"previous pin garbage", func(f *fakeForge) { f.prev = "main" }, nil, Options{}, "not a version"},
		{"malformed pin", nil, []byte("ref=abc\nversion=v0.1.0-beta.1\n"), Options{}, "40-hex"},
		{"extra line", nil, []byte("ref=" + refA + "\nversion=v0.1.0-beta.1\nx=1\n"), Options{}, "exactly the lines"},
		{"empty", nil, []byte(""), Options{}, "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := good()
			if tc.mut != nil {
				tc.mut(f)
			}
			raw := tc.pin
			if raw == nil {
				raw = pin(refA, "v0.1.0-beta.1")
			}
			_, err := Check(raw, f, tc.opt)
			var r *Refusal
			if !errors.As(err, &r) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want refusal containing %q", err, tc.want)
			}
		})
	}
}

// Downgrading to the legacy pin is refused by default and is an explicit
// owner input otherwise; the override never skips the release checks of a
// non-legacy pin.
func TestCheckDowngradeIsExplicit(t *testing.T) {
	f := good()
	f.prev = "v0.1.0-beta.2"
	if _, err := Check([]byte(LegacyPin), f, Options{}); err == nil {
		t.Fatal("legacy downgrade accepted by default")
	}
	res, err := Check([]byte(LegacyPin), f, Options{AllowDowngrade: true})
	if err != nil || !res.Downgrade || len(res.Notes) == 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f = good()
	f.prev = "v0.1.0-beta.2"
	f.rel = nil
	if _, err := Check(pin(refA, "v0.1.0-beta.1"), f, Options{AllowDowngrade: true}); err == nil {
		t.Fatal("override skipped the release check")
	}
}

// An unknown immutability state is refused, not noted (fail closed).
func TestCheckUnknownImmutabilityIsRefused(t *testing.T) {
	f := good()
	f.rel.Immutable = nil
	_, err := Check(pin(refA, "v0.1.0-beta.1"), f, Options{})
	var r *Refusal
	if !errors.As(err, &r) || !strings.Contains(err.Error(), "does not say") || f.verified != 0 {
		t.Fatalf("err=%v verified=%d", err, f.verified)
	}
}

// A rollback with every other check passing is the downgrade-only refusal
// (exit 22); one that also fails another check is an ordinary refusal, and the
// override flag never turns either into a pass without the flag.
func TestCheckDowngradeOnlyRefusal(t *testing.T) {
	f := good()
	f.prev = "v0.1.0-beta.2"
	_, err := Check(pin(refA, "v0.1.0-beta.1"), f, Options{})
	var r *Refusal
	if !errors.As(err, &r) || !r.DowngradeOnly {
		t.Fatalf("err = %v", err)
	}
	f.commit = refB
	_, err = Check(pin(refA, "v0.1.0-beta.1"), f, Options{})
	if !errors.As(err, &r) || r.DowngradeOnly {
		t.Fatalf("a rollback with a bad tag must not be downgrade-only: %v", err)
	}
	if _, err := Check([]byte(LegacyPin), &fakeForge{prev: "v0.1.0-beta.2", prevOK: true}, Options{}); !errors.As(err, &r) || !r.DowngradeOnly {
		t.Fatalf("legacy rollback: %v", err)
	}
}

type tagOnly struct {
	commit string
	err    error
}

func (t tagOnly) TagCommit(string) (string, error) { return t.commit, t.err }

// The read-only repeat run by the sign and deploy jobs.
func TestRecheck(t *testing.T) {
	raw := pin(refA, "v0.1.0-beta.1")
	if err := Recheck(raw, tagOnly{commit: refA}); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]tagOnly{"moved": {commit: refB}, "empty": {}, "error": {err: errors.New("api")}} {
		var r *Refusal
		if err := Recheck(raw, f); !errors.As(err, &r) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	var r *Refusal
	if err := Recheck([]byte("junk"), tagOnly{commit: refA}); !errors.As(err, &r) {
		t.Fatal(err)
	}
	// The grandfathered pin has no matching tag and is not rechecked.
	if err := Recheck([]byte(LegacyPin), tagOnly{commit: refB}); err != nil {
		t.Fatal(err)
	}
}

// With no earlier pin the floor is the first beta: an older version is refused.
func TestCheckFloorWithoutHistory(t *testing.T) {
	f := good()
	f.prevOK = false
	if _, err := Check(pin(refA, "v0.0.1-alpha.1"), f, Options{}); err == nil {
		t.Fatal("pin below the floor accepted")
	}
	if _, err := Check(pin(refA, "v0.1.0-beta.1"), f, Options{}); err != nil {
		t.Fatal(err)
	}
}

// The grandfathered pin is exactly version v0.1.0-beta.0 with ref 0a58fd2c
// (its tag resolves elsewhere). Any other value is checked in full, so the
// same version with another ref, or that ref with another version, is refused
// when the tag does not resolve to it.
func TestCheckLegacyExceptionIsExact(t *testing.T) {
	const legacyRef = "0a58fd2c5741d82cb9cd0c84deadad9eb627370f"
	tagCommit := "70f67cac4a3b88d084b4179a8bc857b63e655cb4"
	for _, raw := range [][]byte{pin(refA, "v0.1.0-beta.0"), pin(legacyRef, "v0.1.0-beta.1"), []byte(LegacyPin + "\n"), []byte(strings.TrimSuffix(LegacyPin, "\n"))} {
		f := good()
		f.rel = &Release{TagName: "v0.1.0-beta.0", Immutable: yes(), Assets: []Asset{{Name: "SHA256SUMS"}}}
		f.commit = tagCommit
		f.prev = "v0.1.0-beta.0"
		if _, err := Check(raw, f, Options{}); err == nil {
			t.Fatalf("pin %q accepted", raw)
		}
	}
}
