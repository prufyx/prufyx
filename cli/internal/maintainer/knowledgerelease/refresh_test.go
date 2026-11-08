// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func refreshOpts(t *testing.T, base Options, live string, now time.Time) RefreshOptions {
	t.Helper()
	// The expected digest is mandatory: name the package that is about to be refreshed.
	digest := "sha256:" + strings.Repeat("0", 64) // unverifiable live packages are refused whatever is named
	if state, err := InspectLive(live, base.Root, base.RootDigest, ProfileCNCFProjects, ""); err == nil {
		digest = state.PackageDigest
	}
	return RefreshOptions{
		Profile: ProfileCNCFProjects, LivePackage: live, ExpectLivePackageDigest: digest, Root: base.Root, RootDigest: base.RootDigest,
		TimestampKey: base.TimestampKey, PassphraseFile: base.PassphraseFile,
		OutputDir: filepath.Join(t.TempDir(), "refresh"), Now: now,
	}
}

func membersOf(t *testing.T, path string) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadMembers(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRefreshExtendsOnlyTheTimestamp(t *testing.T) {
	first, fr := firstPackage(t)
	live := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	now := first.Now.Add(5 * 24 * time.Hour)
	o := refreshOpts(t, first, live, now)
	o.ExpectLivePackageDigest = fr.PackageDigest
	r, err := Refresh(o)
	if err != nil {
		t.Fatal(err)
	}
	if r.TimestampVersion != 2 || r.PreviousTimestampVersion != 1 || r.Revision != "91" || r.LivePackageDigest != fr.PackageDigest {
		t.Fatalf("unexpected result %+v", r)
	}
	// cap = min(snapshot +21d, targets +21d, evidence, now+14d) = first.Now+19d
	if want := utc(now.Add(TimestampLifetime)); r.Expires != want || r.Cap != want {
		t.Fatalf("expiry %s cap %s want %s", r.Expires, r.Cap, want)
	}
	before, after := membersOf(t, live), membersOf(t, filepath.Join(o.OutputDir, "cncf-projects-91.tar"))
	if err := assertOnlyTimestampChanged(before, after); err != nil {
		t.Fatal(err)
	}
	for name := range before {
		if name != "metadata/timestamp.json" && !bytes.Equal(before[name], after[name]) {
			t.Fatalf("%s changed", name)
		}
	}
	if bytes.Equal(before["metadata/timestamp.json"], after["metadata/timestamp.json"]) {
		t.Fatal("timestamp not replaced")
	}
	// The refreshed package verifies and a second refresh bumps the version again.
	state, err := InspectLive(filepath.Join(o.OutputDir, "cncf-projects-91.tar"), first.Root, first.RootDigest, ProfileCNCFProjects, r.PackageDigest)
	if err != nil || state.TimestampVersion != 2 || state.MinNextVersion != 3 {
		t.Fatalf("state %+v err %v", state, err)
	}
	o2 := refreshOpts(t, first, filepath.Join(o.OutputDir, "cncf-projects-91.tar"), first.Now.Add(10*24*time.Hour))
	r2, err := Refresh(o2)
	if err != nil {
		t.Fatal(err)
	}
	// cap now binds at the snapshot/targets expiry (first.Now+21d).
	if r2.TimestampVersion != 3 || r2.Expires != utc(first.Now.Add(ContentLifetime)) {
		t.Fatalf("second refresh %+v", r2)
	}
	// State is unchanged across a refresh, and the deploy guard accepts it.
	liveState, _ := InspectLive(live, first.Root, first.RootDigest, ProfileCNCFProjects, "")
	if !StateUnchanged(liveState, state) {
		t.Fatal("a refresh must leave the state unchanged")
	}
	if err := CheckDeploy(liveState, state, liveState.PackageDigest, o2.Now); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRefusals(t *testing.T) {
	first, fr := firstPackage(t)
	live := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	now := first.Now.Add(5 * 24 * time.Hour)
	zero := "sha256:" + strings.Repeat("0", 64)
	cases := map[string]func(*RefreshOptions){
		"no extension (same instant)":       func(o *RefreshOptions) { o.Now = first.Now },
		"expiry above the cap":              func(o *RefreshOptions) { o.Expires = utc(now.Add(TimestampLifetime + time.Second)) },
		"expiry in the past":                func(o *RefreshOptions) { o.Expires = utc(now.Add(-time.Hour)) },
		"expiry not canonical":              func(o *RefreshOptions) { o.Expires = "2030-01-01T00:00:00+01:00" },
		"snapshot and targets expired":      func(o *RefreshOptions) { o.Now = first.Now.Add(22 * 24 * time.Hour) },
		"less than a day for the others":    func(o *RefreshOptions) { o.Now = first.Now.Add(21*24*time.Hour - time.Hour) },
		"live digest mismatch":              func(o *RefreshOptions) { o.ExpectLivePackageDigest = zero },
		"empty expected live digest":        func(o *RefreshOptions) { o.ExpectLivePackageDigest = "" },
		"wrong pinned root digest":          func(o *RefreshOptions) { o.RootDigest = zero },
		"snapshot key instead of timestamp": func(o *RefreshOptions) { o.TimestampKey = first.SnapshotKey },
		"targets key instead of timestamp":  func(o *RefreshOptions) { o.TimestampKey = first.TargetsKey },
		"relative output":                   func(o *RefreshOptions) { o.OutputDir = "out" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := refreshOpts(t, first, live, now)
			_ = fr
			mutate(&o)
			if _, err := Refresh(o); err == nil {
				t.Fatal("expected refusal")
			}
			if filepath.IsAbs(o.OutputDir) {
				if _, err := os.Stat(o.OutputDir); err == nil {
					t.Fatal("output exists after a refusal")
				}
			}
		})
	}
	t.Run("key set of another root", func(t *testing.T) {
		other := fixture(t)
		o := refreshOpts(t, first, live, now)
		o.TimestampKey, o.PassphraseFile = other.TimestampKey, other.PassphraseFile
		if _, err := Refresh(o); err == nil {
			t.Fatal("expected refusal")
		}
	})
	t.Run("unverifiable live package", func(t *testing.T) {
		raw, _ := os.ReadFile(live)
		raw[len(raw)/3] ^= 0x01
		bad := filepath.Join(t.TempDir(), "live.tar")
		if err := os.WriteFile(bad, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		o := refreshOpts(t, first, bad, now)
		_, err := Refresh(o)
		if err == nil || !errors.Is(err, ErrGuard) {
			t.Fatalf("want guard refusal, got %v", err)
		}
	})
	t.Run("live package of another publisher", func(t *testing.T) {
		other := projectsFixture(t)
		if _, err := Run(other); err != nil {
			t.Fatal(err)
		}
		o := refreshOpts(t, first, filepath.Join(other.OutputDir, "cncf-projects-91.tar"), now)
		if _, err := Refresh(o); err == nil {
			t.Fatal("expected refusal")
		}
	})
}

// A snapshot that is already expired while the timestamp is not (a state the
// client does not cap) is refused by the publisher.
func TestRefreshRefusesAnAlreadyExpiredSnapshot(t *testing.T) {
	first := projectsFixture(t)
	first.Expires = utc(first.Now.Add(3 * 24 * time.Hour))
	first.TimestampExpires = utc(first.Now.Add(3 * 24 * time.Hour))
	r, err := Run(first)
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	o := refreshOpts(t, first, live, first.Now.Add(4*24*time.Hour))
	if _, err := Refresh(o); err == nil || !errors.Is(err, ErrGuard) {
		t.Fatalf("want guard refusal, got %v (live %s)", err, r.PackageDigest)
	}
}

func TestSameVersionRefreshIsNotPrepared(t *testing.T) {
	first, _ := firstPackage(t)
	m := membersOf(t, filepath.Join(first.OutputDir, "cncf-projects-91.tar"))
	rootRaw, _ := os.ReadFile(first.Root)
	state, err := InspectLive(filepath.Join(first.OutputDir, "cncf-projects-91.tar"), first.Root, first.RootDigest, ProfileCNCFProjects, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := knowledgepublish.TimestampRefreshOptions{
		Root: rootRaw, Targets: m["metadata/"+strconv.FormatInt(state.TargetsVersion, 10)+".targets.json"],
		Snapshot: m["metadata/"+strconv.FormatInt(state.SnapshotVersion, 10)+".snapshot.json"], RootDigest: first.RootDigest,
		TargetDigest: state.IndexDigest, PreviousVersion: state.TimestampVersion, Version: state.TimestampVersion + 1,
		Expires: utc(first.Now.Add(10 * 24 * time.Hour)),
	}
	if _, err := knowledgepublish.PrepareTimestampRefresh(opts); err != nil {
		t.Fatalf("version+1 must be prepared: %v", err)
	}
	for name, v := range map[string]int64{"same": state.TimestampVersion, "lower": state.TimestampVersion - 1} {
		bad := opts
		bad.Version = v
		if _, err := knowledgepublish.PrepareTimestampRefresh(bad); err == nil {
			t.Fatalf("%s version must be refused", name)
		}
	}
	// Tampered targets are refused (signature no longer verifies).
	bad := opts
	bad.Targets = append([]byte(nil), opts.Targets...)
	bad.Targets[len(bad.Targets)/2] ^= 0x01
	if _, err := knowledgepublish.PrepareTimestampRefresh(bad); err == nil {
		t.Fatal("tampered targets must be refused")
	}
	_ = metadata.TIMESTAMP
}

func TestByteIdentityAssertion(t *testing.T) {
	live := map[string][]byte{"metadata/timestamp.json": []byte("old"), "metadata/1.targets.json": []byte("t"), "metadata/1.snapshot.json": []byte("s")}
	clone := func() map[string][]byte {
		m := map[string][]byte{}
		for k, v := range live {
			m[k] = append([]byte(nil), v...)
		}
		return m
	}
	ok := clone()
	ok["metadata/timestamp.json"] = []byte("new")
	if err := assertOnlyTimestampChanged(live, ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string][]byte){
		"targets changed":     func(m map[string][]byte) { m["metadata/1.targets.json"] = []byte("T") },
		"snapshot changed":    func(m map[string][]byte) { m["metadata/1.snapshot.json"] = []byte("S") },
		"member added":        func(m map[string][]byte) { m["metadata/2.targets.json"] = []byte("x") },
		"member removed":      func(m map[string][]byte) { delete(m, "metadata/1.snapshot.json") },
		"timestamp unchanged": func(m map[string][]byte) { m["metadata/timestamp.json"] = []byte("old") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := clone()
			m["metadata/timestamp.json"] = []byte("new")
			mutate(m)
			if err := assertOnlyTimestampChanged(live, m); err == nil || !errors.Is(err, ErrGuard) {
				t.Fatalf("want guard refusal, got %v", err)
			}
		})
	}
}

func TestStateAndDeployGuards(t *testing.T) {
	first, fr := firstPackage(t)
	liveTar := filepath.Join(first.OutputDir, "cncf-projects-91.tar")
	live, err := InspectLive(liveTar, first.Root, first.RootDigest, ProfileCNCFProjects, fr.PackageDigest)
	if err != nil || live.PackageDigest != fr.PackageDigest || live.MinNextVersion != 2 {
		t.Fatalf("live %+v err %v", live, err)
	}
	next := ciNext(t, first, fr)
	nr, err := Run(next)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := InspectLive(filepath.Join(next.OutputDir, "cncf-projects-92.tar"), first.Root, first.RootDigest, ProfileCNCFProjects, nr.PackageDigest)
	if err != nil {
		t.Fatal(err)
	}
	if StateUnchanged(live, cand) {
		t.Fatal("a content release changes the state")
	}
	candExpiry, perr := parseUTC(cand.TimestampExpires)
	if perr != nil {
		t.Fatal(perr)
	}
	// The latest instant at which the candidate timestamp is still within Now+TimestampLifetime.
	boundary := candExpiry.Add(-TimestampLifetime)
	if err := CheckDeploy(live, cand, live.PackageDigest, boundary); err != nil {
		t.Fatalf("content candidate over the live package: %v", err)
	}
	if err := CheckDeploy(live, cand, live.PackageDigest, boundary.Add(time.Hour)); err != nil {
		t.Fatalf("candidate well inside the lifetime cap: %v", err)
	}
	checkDeployCap(t, live, cand)
	refuse := map[string]func(l, c *LiveState, pred *string){
		"predecessor mismatch":         func(l, c *LiveState, p *string) { *p = "sha256:" + strings.Repeat("1", 64) },
		"empty predecessor":            func(l, c *LiveState, p *string) { *p = "" },
		"timestamp not higher":         func(l, c *LiveState, p *string) { c.TimestampVersion = l.TimestampVersion },
		"older revision":               func(l, c *LiveState, p *string) { c.Revision = "90" },
		"same revision, other content": func(l, c *LiveState, p *string) { c.Revision = l.Revision },
		"targets version back":         func(l, c *LiveState, p *string) { l.TargetsVersion = c.TargetsVersion + 1 },
		"non numeric revision":         func(l, c *LiveState, p *string) { c.Revision = "x" },
	}
	for name, mutate := range refuse {
		t.Run(name, func(t *testing.T) {
			l, c, p := live, cand, live.PackageDigest
			mutate(&l, &c, &p)
			if err := CheckDeploy(l, c, p, boundary); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}

// checkDeployCap (run from TestStateAndDeployGuards, red first): a timestamp
// signed outside refresh-timestamp must not outlive its roles or the lifetime cap.
func checkDeployCap(t *testing.T, live, cand LiveState) {
	exp, err := parseUTC(cand.TimestampExpires)
	if err != nil {
		t.Fatal(err)
	}
	now := exp.Add(-TimestampLifetime)
	at := func(mutate func(c *LiveState), now time.Time) error {
		c := cand
		c.SnapshotExpires, c.TargetsExpires, c.EvidenceExpiresAt = utc(exp), utc(exp), utc(exp)
		mutate(&c)
		return CheckDeploy(live, c, live.PackageDigest, now)
	}
	none := func(*LiveState) {}
	if err := at(none, now); err != nil {
		t.Fatalf("equal to every cap must pass: %v", err)
	}
	for name, m := range map[string]func(*LiveState){
		"snapshot":              func(c *LiveState) { c.SnapshotExpires = utc(exp.Add(-time.Second)) },
		"targets":               func(c *LiveState) { c.TargetsExpires = utc(exp.Add(-time.Second)) },
		"evidence":              func(c *LiveState) { c.EvidenceExpiresAt = utc(exp.Add(-time.Second)) },
		"snapshot unparseable":  func(c *LiveState) { c.SnapshotExpires = "" },
		"targets unparseable":   func(c *LiveState) { c.TargetsExpires = "x" },
		"evidence unparseable":  func(c *LiveState) { c.EvidenceExpiresAt = "" },
		"timestamp unparseable": func(c *LiveState) { c.TimestampExpires = "" },
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			err := at(m, now)
			if err == nil || !errors.Is(err, ErrGuard) {
				t.Fatalf("expected a guard refusal, got %v", err)
			}
		})
	}
	t.Run("refuses lifetime cap plus one second", func(t *testing.T) {
		if err := at(none, now.Add(-time.Second)); err == nil || !errors.Is(err, ErrGuard) {
			t.Fatalf("expected a guard refusal, got %v", err)
		}
	})
	t.Run("refuses an already expired candidate", func(t *testing.T) {
		if err := at(none, exp); err == nil || !errors.Is(err, ErrGuard) {
			t.Fatalf("expected a guard refusal, got %v", err)
		}
	})
	t.Run("refusal text carries only times", func(t *testing.T) {
		err := at(func(c *LiveState) { c.SnapshotExpires = utc(exp.Add(-time.Second)) }, now)
		if err == nil || strings.Contains(err.Error(), "/") || strings.Contains(strings.ToLower(err.Error()), "key") {
			t.Fatalf("unexpected text %v", err)
		}
	})
}
