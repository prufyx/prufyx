// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clockMargin is the room the pinned test clock must keep below the embedded
// evidence horizon, beyond the 21 day content lifetime.
const clockMargin = 5 * 24 * time.Hour

func earliestValidUntil(t *testing.T, v any, best *time.Time) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "validUntil" {
				ts, err := time.Parse(time.RFC3339, s)
				if err != nil {
					t.Fatalf("validUntil %q: %v", s, err)
				}
				if best.IsZero() || ts.Before(*best) {
					*best = ts
				}
				continue
			}
			earliestValidUntil(t, e, best)
		}
	case []any:
		for _, e := range x {
			earliestValidUntil(t, e, best)
		}
	}
}

func TestPinnedClockLeavesTheEmbeddedEvidenceHorizonBehindIt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var earliest time.Time
	earliestValidUntil(t, doc, &earliest)
	if earliest.IsZero() {
		t.Fatal("no validUntil found in the embedded rules: the horizon guard would be vacuous")
	}
	if need := pinnedNow.Add(ContentLifetime + clockMargin); earliest.Before(need) {
		t.Fatalf("embedded evidence earliest validUntil %s < pinned clock %s + 21d + margin %s: move pinnedNow back or refresh the data deliberately",
			earliest.Format(time.RFC3339), pinnedNow.Format(time.RFC3339), need.Format(time.RFC3339))
	}
	first, fr := firstPackage(t)
	ev, err := parseUTC(fr.EvidenceExpiresAt)
	if err != nil || ev.Before(pinnedNow.Add(ContentLifetime+clockMargin)) {
		t.Fatalf("release evidence expiry %q leaves no room over the pinned clock %s", fr.EvidenceExpiresAt, first.Now)
	}
}

func TestVerifyClockDecidesExpiry(t *testing.T) {
	first, fr := firstPackage(t)
	live := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	ts, err := parseUTC(fr.TimestampExpires)
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Equal(first.Now.Add(TimestampLifetime)) {
		t.Fatalf("timestamp expiry %s, want pinned clock + 14d", ts)
	}
	at := func(now time.Time) error {
		_, err := InspectLiveAt(live, first.Root, first.RootDigest, ProfileCNCFProjects, fr.PackageDigest, now)
		return err
	}
	if err := at(first.Now.Add(time.Hour)); err != nil {
		t.Fatalf("clock before expiry must accept: %v", err)
	}
	if err := at(ts.Add(time.Second)); err == nil {
		t.Fatal("clock after the timestamp expiry must refuse")
	}
	if err := at(ts.Add(-time.Second)); err != nil {
		t.Fatalf("clock just before the timestamp expiry must accept: %v", err)
	}
	// Refresh and the previous-package check of the next release use the same clock.
	o := refreshOpts(t, first, live, ts.Add(time.Second))
	o.ExpectLivePackageDigest = fr.PackageDigest
	if _, err := Refresh(o); err == nil {
		t.Fatal("refresh with a clock after expiry must refuse")
	}
	// The previous package of the next release is verified at the injected clock.
	ok := ciNext(t, first, fr)
	ok.Now = ts.Add(-time.Hour)
	if _, err := Run(ok); err != nil {
		t.Fatalf("previous package unexpired at the injected clock must be accepted: %v", err)
	}
	late := ok
	late.Now = ts.Add(time.Second)
	late.OutputDir = filepath.Join(filepath.Dir(first.OutputDir), "out-late")
	_, err = Run(late)
	if !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), "previous package") {
		t.Fatalf("previous package expired at the injected clock must be refused by the previous-package guard, got %v", err)
	}
}

func TestZeroVerifyClockIsTheWallClock(t *testing.T) {
	first, fr := firstPackage(t)
	live := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	zero, zeroErr := InspectLiveAt(live, first.Root, first.RootDigest, ProfileCNCFProjects, fr.PackageDigest, time.Time{})
	wall, wallErr := InspectLiveAt(live, first.Root, first.RootDigest, ProfileCNCFProjects, fr.PackageDigest, time.Now().UTC())
	plain, plainErr := InspectLive(live, first.Root, first.RootDigest, ProfileCNCFProjects, fr.PackageDigest)
	if (zeroErr == nil) != (wallErr == nil) || (zeroErr == nil) != (plainErr == nil) {
		t.Fatalf("zero %v, wall %v, InspectLive %v", zeroErr, wallErr, plainErr)
	}
	if zeroErr == nil && (zero != wall || zero != plain) {
		t.Fatalf("states differ: %+v %+v %+v", zero, wall, plain)
	}
	// The pinned package expires at pinnedNow+14d: the wall clock decides it.
	ts, _ := parseUTC(fr.TimestampExpires)
	if want := time.Now().Before(ts); want != (zeroErr == nil) {
		t.Fatalf("zero clock verdict %v, wall clock says unexpired=%v", zeroErr, want)
	}
}
