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
		"first release with a previous":    func(o *Options) { o.FirstRelease, o.PreviousIndex = true, "" },
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
