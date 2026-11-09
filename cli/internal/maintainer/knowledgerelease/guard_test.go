// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func utc(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// firstPackage publishes revision 91 (version 1) with the fixture keys and
// returns its options and result. The output is the live package of the tests.
func firstPackage(t *testing.T) (Options, Result) {
	t.Helper()
	o := projectsFixture(t)
	r, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	return o, r
}

// ciNext is a fully specified CI release 92 over the live package of first.
func ciNext(t *testing.T, first Options, firstResult Result) Options {
	t.Helper()
	next := first
	next.FirstRelease = false
	next.PreviousIndex = filepath.Join(first.OutputDir, "knowledge", "cncf", "index.v1.json")
	next.PreviousPackage = filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	next.ExpectPreviousPackageDigest = firstResult.PackageDigest
	next.Revision, next.Version = "92", 2
	next.OutputDir = filepath.Join(filepath.Dir(first.OutputDir), "out-next")
	next.CI, next.RunAttempt = true, "1"
	next.Expires = utc(first.Now.Add(18 * 24 * time.Hour))
	d, err := ComputeDigests(next)
	if err != nil {
		t.Fatal(err)
	}
	next.ExpectContentDigest, next.ExpectIndexDigest = d.ContentDigest, d.IndexDigest
	return next
}

func TestCIReleaseHappyPathBindsPacketAndSplitsExpiries(t *testing.T) {
	first, fr := firstPackage(t)
	next := ciNext(t, first, fr)
	r, err := Run(next)
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentDigest != next.ExpectContentDigest || r.IndexDigest != next.ExpectIndexDigest || r.IndexDigest != r.Receipt.TargetDigest || r.PackageDigest != r.Receipt.PackageDigest {
		t.Fatalf("result does not carry the bound digests: %+v", r)
	}
	if r.PreviousPackageDigest != fr.PackageDigest || r.TimestampVersion != 2 {
		t.Fatalf("previous binding missing: %+v", r)
	}
	// Targets and snapshot take the requested expiry; the timestamp is capped at now+14d.
	if r.Expires != next.Expires || r.TimestampExpires != utc(next.Now.Add(TimestampLifetime)) {
		t.Fatalf("expiry split wrong: targets %s timestamp %s", r.Expires, r.TimestampExpires)
	}
	if r.Receipt.Verification.Targets.Expires != r.Expires || r.Receipt.Verification.Snapshot.Expires != r.Expires || r.Receipt.Verification.Timestamp.Expires != r.TimestampExpires {
		t.Fatalf("signed metadata expiries differ from the result: %+v", r.Receipt.Verification)
	}
}

func TestDefaultExpiriesAreTwentyOneAndFourteenDays(t *testing.T) {
	o := projectsFixture(t)
	r, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Expires != utc(o.Now.Add(ContentLifetime)) || r.TimestampExpires != utc(o.Now.Add(TimestampLifetime)) {
		t.Fatalf("defaults: targets %s timestamp %s", r.Expires, r.TimestampExpires)
	}
}

// Every refusal below must be a pre-signing guard: all three key files are
// absent, so a refusal that came from key handling would not carry ErrGuard.
func TestReleaseGuardsRefuseBeforeAnyKeyIsRead(t *testing.T) {
	first, fr := firstPackage(t)
	zero := "sha256:" + strings.Repeat("0", 64)
	cases := map[string]func(*Options){
		"content digest mismatch":          func(o *Options) { o.ExpectContentDigest = zero },
		"index digest mismatch":            func(o *Options) { o.ExpectIndexDigest = zero },
		"previous package digest mismatch": func(o *Options) { o.ExpectPreviousPackageDigest = zero },
		"missing expires in CI":            func(o *Options) { o.Expires = "" },
		"missing content digest in CI":     func(o *Options) { o.ExpectContentDigest = "" },
		"missing index digest in CI":       func(o *Options) { o.ExpectIndexDigest = "" },
		"missing previous digest in CI":    func(o *Options) { o.ExpectPreviousPackageDigest = "" },
		"missing previous package in CI":   func(o *Options) { o.PreviousPackage = "" },
		"run attempt 2 in CI":              func(o *Options) { o.RunAttempt = "2" },
		"run attempt absent in CI":         func(o *Options) { o.RunAttempt = "" },
		"run attempt 2 outside CI":         func(o *Options) { o.CI, o.RunAttempt = false, "2" },
		"expires above the 21 day cap":     func(o *Options) { o.Expires = utc(o.Now.Add(22 * 24 * time.Hour)) },
		"expires beyond the evidence":      func(o *Options) { o.Expires = "2999-01-01T00:00:00Z" },
		"expires not canonical":            func(o *Options) { o.Expires = "2026-12-01T00:00:00+02:00" },
		"expires in the past":              func(o *Options) { o.Expires = utc(o.Now.Add(-time.Hour)) },
		"timestamp expires above 14 days":  func(o *Options) { o.TimestampExpires = utc(o.Now.Add(15 * 24 * time.Hour)) },
		"same version as live":             func(o *Options) { o.Version = 1 },
		"no live package with a previous":  func(o *Options) { o.NoLivePackage = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := ciNext(t, first, fr)
			o.TargetsKey = filepath.Join(filepath.Dir(o.Root), "absent-1.pem")
			o.SnapshotKey = filepath.Join(filepath.Dir(o.Root), "absent-2.pem")
			o.TimestampKey = filepath.Join(filepath.Dir(o.Root), "absent-3.pem")
			mutate(&o)
			_, err := Run(o)
			if err == nil || !errors.Is(err, ErrGuard) {
				t.Fatalf("want a pre-signing guard refusal, got %v", err)
			}
			if _, statErr := os.Stat(o.OutputDir); statErr == nil {
				t.Fatal("output directory exists after a refusal")
			}
		})
	}
}

// The export itself refuses a revision that does not advance the previous
// index, again before any key is read.
func TestReleaseRefusesARevisionThatDoesNotAdvance(t *testing.T) {
	first, fr := firstPackage(t)
	o := ciNext(t, first, fr)
	o.Revision = "91"
	o.TargetsKey = filepath.Join(filepath.Dir(o.Root), "absent.pem")
	if _, err := Run(o); err == nil {
		t.Fatal("expected refusal")
	}
	if _, err := os.Stat(o.OutputDir); err == nil {
		t.Fatal("output exists after a refusal")
	}
}

func TestReleaseRefusesAnUnverifiablePreviousPackage(t *testing.T) {
	first, fr := firstPackage(t)
	t.Run("tampered bytes", func(t *testing.T) {
		o := ciNext(t, first, fr)
		raw, err := os.ReadFile(o.PreviousPackage)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)/2] ^= 0xff
		o.PreviousPackage = filepath.Join(t.TempDir(), "p.tar")
		if err := os.WriteFile(o.PreviousPackage, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(o); err == nil || !errors.Is(err, ErrGuard) {
			t.Fatalf("want guard refusal, got %v", err)
		}
	})
	t.Run("wrong pinned root", func(t *testing.T) {
		o := ciNext(t, first, fr)
		other := fixture(t) // a second, unrelated key set and root
		o.Root, o.RootDigest = other.Root, other.RootDigest
		if _, err := Run(o); err == nil {
			t.Fatal("expected refusal")
		}
	})
}

func TestNonCIKeepsWorkingWithoutAttemptCounter(t *testing.T) {
	o := projectsFixture(t)
	o.RunAttempt = "1"
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
}

// firstCI is the fully specified CI release of a deployment with no live
// package at all: fresh layout and the explicit no-live-package declaration.
func firstCI(t *testing.T, base Options) Options {
	t.Helper()
	o := base
	o.FirstRelease, o.NoLivePackage = true, true
	o.CI, o.RunAttempt = true, "1"
	o.Expires = utc(base.Now.Add(18 * 24 * time.Hour))
	o.OutputDir = filepath.Join(filepath.Dir(base.OutputDir), "out-first-ci")
	d, err := ComputeDigests(o)
	if err != nil {
		t.Fatal(err)
	}
	o.ExpectContentDigest, o.ExpectIndexDigest = d.ContentDigest, d.IndexDigest
	return o
}

// capabilityCI is the CI release after an engine capability change: fresh
// index layout over a verified live package.
func capabilityCI(t *testing.T, first Options, fr Result) Options {
	t.Helper()
	o := ciNext(t, first, fr)
	o.FirstRelease, o.PreviousIndex = true, ""
	d, err := ComputeDigests(o)
	if err != nil {
		t.Fatal(err)
	}
	o.ExpectContentDigest, o.ExpectIndexDigest = d.ContentDigest, d.IndexDigest
	return o
}

func noKeys(o *Options) {
	o.TargetsKey = filepath.Join(filepath.Dir(o.Root), "absent-1.pem")
	o.SnapshotKey = filepath.Join(filepath.Dir(o.Root), "absent-2.pem")
	o.TimestampKey = filepath.Join(filepath.Dir(o.Root), "absent-3.pem")
}

// The four daily modes, each with the exact option set the workflow passes.
func TestCIModeFlagSetsAreAccepted(t *testing.T) {
	first, fr := firstPackage(t)
	modes := map[string]func() Options{
		"first (no live package)": func() Options { return firstCI(t, first) },
		"regular":                 func() Options { return ciNext(t, first, fr) },
		"capability (fresh layout over a live package)":         func() Options { return capabilityCI(t, first, fr) },
		"recovery (index and package of the recovered package)": func() Options { return ciNext(t, first, fr) },
	}
	for name, mk := range modes {
		t.Run(name, func(t *testing.T) {
			o := mk()
			o.OutputDir = filepath.Join(filepath.Dir(first.OutputDir), "out-"+strings.Fields(name)[0])
			r, err := Run(o)
			if err != nil {
				t.Fatal(err)
			}
			wantPrev := ""
			if !o.NoLivePackage {
				wantPrev = fr.PackageDigest
			}
			if r.PreviousPackageDigest != wantPrev {
				t.Fatalf("previous package digest %q, want %q", r.PreviousPackageDigest, wantPrev)
			}
		})
	}
}

func TestCIModeWrongFlagSetsAreRefused(t *testing.T) {
	first, fr := firstPackage(t)
	cases := map[string]func() Options{
		"first layout without the no-live declaration": func() Options {
			o := firstCI(t, first)
			o.NoLivePackage = false
			return o
		},
		"capability without a previous package": func() Options {
			o := capabilityCI(t, first, fr)
			o.PreviousPackage, o.ExpectPreviousPackageDigest = "", ""
			return o
		},
		"capability without the previous digest": func() Options {
			o := capabilityCI(t, first, fr)
			o.ExpectPreviousPackageDigest = ""
			return o
		},
		"no-live with a previous package": func() Options {
			o := firstCI(t, first)
			o.PreviousPackage = filepath.Join(first.OutputDir, "cncf-projects-91.tar")
			o.ExpectPreviousPackageDigest = fr.PackageDigest
			return o
		},
		"no-live with only a previous package path": func() Options {
			o := firstCI(t, first)
			o.PreviousPackage = filepath.Join(first.OutputDir, "cncf-projects-91.tar")
			return o
		},
		"no-live with only a previous digest": func() Options {
			o := firstCI(t, first)
			o.ExpectPreviousPackageDigest = fr.PackageDigest
			return o
		},
		"no-live over a previous package in the regular set": func() Options {
			o := ciNext(t, first, fr)
			o.NoLivePackage = true
			return o
		},
		"no-live with a previous index layout": func() Options {
			o := firstCI(t, first)
			o.FirstRelease, o.Revision, o.Version = false, "92", 2
			o.PreviousIndex = filepath.Join(first.OutputDir, "knowledge", "cncf", "index.v1.json")
			return o
		},
		"no-live outside CI with a previous package": func() Options {
			o := ciNext(t, first, fr)
			o.NoLivePackage, o.CI, o.RunAttempt = true, false, ""
			return o
		},
		"regular without a previous package": func() Options {
			o := ciNext(t, first, fr)
			o.PreviousPackage, o.ExpectPreviousPackageDigest = "", ""
			return o
		},
		"capability that does not exceed the live version": func() Options {
			o := capabilityCI(t, first, fr)
			o.Version = 1
			return o
		},
		"capability that does not exceed the live revision": func() Options {
			o := capabilityCI(t, first, fr)
			o.Revision = "91"
			return o
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			o := mk()
			noKeys(&o)
			_, err := Run(o)
			if err == nil || !errors.Is(err, ErrGuard) {
				t.Fatalf("want a pre-signing guard refusal, got %v", err)
			}
			if _, statErr := os.Stat(o.OutputDir); statErr == nil {
				t.Fatal("output directory exists after a refusal")
			}
		})
	}
}
