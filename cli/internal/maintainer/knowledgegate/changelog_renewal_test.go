// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

const (
	listedID        = "changelog.listed.prometheus"
	listedComponent = "pkg:github/prometheus/prometheus"
)

// listedUpstream is a synthetic Prometheus repository: one changelog file at
// each release tag, newest entry first.
type listedUpstream struct{ versions []string }

var listedVersions = []string{"3.3.0", "3.4.0", "3.4.1", "3.5.0", "3.5.1"}

func listedCommit(version string) string {
	return strings.Repeat("0", 34) + fmt.Sprintf("%06s", strings.ReplaceAll(version, ".", "0"))
}

func (u listedUpstream) Tags(extract.RepoRef) ([]extract.Tag, error) {
	var out []extract.Tag
	for _, v := range u.versions {
		out = append(out, extract.Tag{Name: "v" + v, Commit: listedCommit(v)})
	}
	return out, nil
}

func (u listedUpstream) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, nil
}

func (u listedUpstream) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Changelog\n\n## main / unreleased\n\n")
	on := false
	for i := len(u.versions) - 1; i >= 0; i-- {
		v := u.versions[i]
		on = on || listedCommit(v) == commit
		if on {
			fmt.Fprintf(&b, "## %s / 2025-01-01\n\n* [BUGFIX] Fix %s. #1\n\n", v, v)
		}
	}
	if !on || path != "CHANGELOG.md" {
		return nil, extract.ErrNotFound
	}
	return []byte(b.String()), nil
}

// renewalRecord derives the line 3.5 record at at, valid for lease.
func renewalRecord(t *testing.T, u listedUpstream, at time.Time, lease time.Duration) map[string]any {
	t.Helper()
	spec := extractcli.Catalog()[listedID]
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extract.Run(context.Background(), spec.New(1), u, u, extract.Options{Repo: repo, DerivedAt: at, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Attestations {
		if a.Line != "3.5" {
			continue
		}
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Fatal("line 3.5 is not attested")
	return nil
}

const listedDay = 24 * time.Hour

// listedTrees holds base and head in the CNCF pack as its only attestation. A
// head that does not load keeps the base's derived files.
func listedTrees(t *testing.T, base, head map[string]any) (Tree, Tree) {
	t.Helper()
	b, h := trees(t)
	set := func(tr Tree, record map[string]any) {
		raw, err := json.Marshal([]map[string]any{record})
		if err != nil {
			t.Fatal(err)
		}
		p := readPack(t, tr, cncfRulesPath)
		p.fields["lineAttestations"] = raw
		p.fields["schema"] = json.RawMessage(`"` + attestedPackSchema + `"`)
		p.write(t, tr, cncfRulesPath)
		if _, err := lineattest.Parse(raw); err == nil {
			regenerate(t, tr)
		}
	}
	set(b, base)
	set(h, head)
	return b, h
}

func TestGateChangelogRenewal(t *testing.T) {
	t.Parallel()
	u := listedUpstream{listedVersions}
	oldAt, newAt := gateNow.Add(-30*listedDay), gateNow.Add(-time.Hour)
	old := renewalRecord(t, u, oldAt, 40*listedDay)
	renewed := func() map[string]any { return renewalRecord(t, u, newAt, 80*listedDay) }
	id := evidencerepin.LineAttestationRecordID(listedComponent, lineattest.FamilyChangelogListedEntries, "3.5")
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	evidence := func(a map[string]any) map[string]any { return a["evidence"].(map[string]any) }
	source := func(a map[string]any) map[string]any { return evidence(a)["sources"].([]any)[0].(map[string]any) }
	releases := func(a map[string]any, side string) []any { return a["releases"].(map[string]any)[side].([]any) }
	build := func(a map[string]any) map[string]any { return evidence(a)["extractor"].(map[string]any) }
	shipped := build(old)
	otherDigest := "sha256:" + strings.Repeat("0", 64)

	admitted := func(t *testing.T, base, head map[string]any, src Source) {
		t.Helper()
		b, h := listedTrees(t, base, head)
		r := runGate(t, Options{Base: b, Head: h, Source: src, Author: DefaultBotLogin})
		if c := change(t, r, id); !c.OK || c.Proof != ProofRederived {
			t.Fatalf("not admitted: %+v", c)
		}
	}

	t.Run("time-only renewal", func(t *testing.T) { admitted(t, old, renewed(), u) })

	// A newer build is decided by re-derivation: the head record is the one
	// this gate derives.
	t.Run("new build", func(t *testing.T) {
		base := renewalRecord(t, u, oldAt, 40*listedDay)
		build(base)["codeDigest"] = otherDigest
		admitted(t, base, renewed(), u)
	})

	// New content is the ordinary intake and is admitted by re-derivation as
	// before: a line that gained a release.
	t.Run("new release of the line", func(t *testing.T) {
		more := listedUpstream{append(slices.Clone(listedVersions), "3.5.2")}
		admitted(t, old, renewalRecord(t, more, newAt, 80*listedDay), more)
	})

	const (
		dateEdit = "changelog-renewal/derivation-time: derivedAt is not later than the base record's: a date edit is not a renewal"
		changed  = "changelog-renewal/content-changed: the record differs in more than evidence.derivedAt, reviewedAt and validUntil"
	)
	differs := fmt.Sprintf("line attestation differs from what extractor %s %s derives from the pinned upstream bytes", listedID, shipped["version"])
	outside := func(now time.Time) string {
		return fmt.Sprintf("empty-list/%s: derivedAt %s is outside [now-24h, now+5m] of the gate's clock %s", emptyListFreshness, stamp(newAt), stamp(now))
	}
	for name, tc := range map[string]struct {
		base func() map[string]any
		head func(a map[string]any)
		src  Source
		now  time.Time
		want string
	}{
		// A date-only edit inside the derivation window: re-derivation alone
		// would admit it.
		"date-only edit under a fresh derivation time": {
			base: renewed,
			head: func(a map[string]any) { evidence(a)["validUntil"] = stamp(newAt.Add(85 * listedDay)) },
			want: dateEdit,
		},
		"derivation time moved back": {
			base: func() map[string]any { return renewalRecord(t, u, gateNow.Add(-time.Minute), 40*listedDay) },
			want: dateEdit,
		},
		"end moved back": {
			base: func() map[string]any { return renewalRecord(t, u, oldAt, 90*listedDay) },
			head: func(a map[string]any) { evidence(a)["validUntil"] = stamp(newAt.Add(40 * listedDay)) },
			want: "changelog-renewal/lease: validUntil is not later than the base one",
		},
		"changed range":  {head: func(a map[string]any) { source(a)["endLine"] = source(a)["endLine"].(float64) - 1 }, want: changed},
		"changed digest": {head: func(a map[string]any) { source(a)["contentDigest"] = otherDigest }, want: changed},
		"another file":   {head: func(a map[string]any) { source(a)["url"] = source(a)["url"].(string) + ".old" }, want: changed},
		"changed list, release dropped": {head: func(a map[string]any) {
			a["releases"].(map[string]any)["from"] = releases(a, "from")[:1]
		}, want: differs},
		"changed list, release commit": {head: func(a map[string]any) {
			releases(a, "from")[0].(map[string]any)["commit"] = listedCommit("9.9.9")
		}, want: differs},
		"upstream list grew under the same record": {
			src:  listedUpstream{append(slices.Clone(listedVersions), "3.5.2")},
			want: differs,
		},
		"other extractor": {
			head: func(a map[string]any) { build(a)["id"] = "changelog.listed.fluentd" },
			want: "empty-list/target-not-attesting: re-derivation failed: extractor changelog.listed.fluentd does not attest changelog.listed_entries for " + listedComponent,
		},
		"a build the gate does not run": {
			head: func(a map[string]any) { build(a)["codeDigest"] = otherDigest },
			want: fmt.Sprintf("empty-list/extractor-digest: re-derivation failed: the record names extractor %s %s %s, this gate runs %s %s %s",
				listedID, shipped["version"], otherDigest, listedID, shipped["version"], shipped["codeDigest"]),
		},
		"future T": {now: newAt.Add(-time.Hour), want: outside(newAt.Add(-time.Hour))},
		"stale T":  {now: newAt.Add(25 * time.Hour), want: outside(newAt.Add(25 * time.Hour))},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, head := old, renewed()
			if tc.base != nil {
				base = tc.base()
			}
			if tc.head != nil {
				tc.head(head)
			}
			src, now := tc.src, tc.now
			if src == nil {
				src = u
			}
			if now.IsZero() {
				now = gateNow
			}
			b, h := listedTrees(t, base, head)
			opts := Options{Base: b, Head: h, Source: src, Author: DefaultBotLogin, Now: now, Layout: DefaultLayout(), Citations: passingCitations{}}
			pinBaseKeys(&opts)
			fromBot(&opts)
			r, err := Verify(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if r.Passed() {
				t.Fatal("the gate passed")
			}
			if c := change(t, r, id); c.OK || c.Detail != tc.want {
				t.Fatalf("OK %v, detail %q\nwant %q", c.OK, c.Detail, tc.want)
			}
		})
	}

	// A head the pack loader refuses never reaches a change decision.
	for name, tc := range map[string]struct {
		head func(a map[string]any)
		want string
	}{
		"unpinned file": {func(a map[string]any) {
			source(a)["url"] = "https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md"
		}, "source URL"},
		"lease member": {func(a map[string]any) { evidence(a)["lease"] = "pinned" }, `unknown member "lease"`},
		"over the longest window": {func(a map[string]any) {
			evidence(a)["validUntil"] = stamp(newAt.Add(lineattest.MaxWindow + time.Second))
		}, "evidence.validUntil must be after reviewedAt and at most " + lineattest.MaxWindow.String() + " later"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			head := renewed()
			tc.head(head)
			raw, err := json.Marshal([]map[string]any{head})
			if err != nil {
				t.Fatal(err)
			}
			_, cause := lineattest.Parse(raw)
			if cause == nil || !strings.Contains(cause.Error(), tc.want) {
				t.Fatalf("the record loads or fails otherwise: %v", cause)
			}
			b, h := listedTrees(t, old, head)
			opts := Options{Base: b, Head: h, Source: u, Author: DefaultBotLogin, Now: gateNow, Layout: DefaultLayout(), Citations: passingCitations{}}
			pinBaseKeys(&opts)
			fromBot(&opts)
			r, err := Verify(context.Background(), opts)
			if err != nil {
				if !strings.Contains(err.Error(), cause.Error()) {
					t.Fatalf("error %v, want %v", err, cause)
				}
				return
			}
			if r.Passed() || !slices.ContainsFunc(failedChecks(r), func(f string) bool { return strings.Contains(f, cause.Error()) }) {
				t.Fatalf("want a failure naming %v:\n%s", cause, strings.Join(failedChecks(r), "\n"))
			}
		})
	}
}

// The gate's own pre-check, case by case. Through Verify an earlier check
// already refuses another extractor id, so that branch is reached here.
func TestChangelogRenewalPre(t *testing.T) {
	t.Parallel()
	at := gateNow.Add(-time.Hour).UTC().Format(time.RFC3339)
	before := gateNow.Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	side := func(id, derivedAt string) *record {
		return &record{
			Extractor:   &constraintengine.Extractor{ID: id, Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("1", 64)},
			DerivedAt:   derivedAt,
			attestation: &lineattest.LineAttestation{Component: listedComponent, FactFamily: lineattest.FamilyChangelogListedEntries, Line: "3.5"},
		}
	}
	const (
		other   = "changelog-renewal/other-extractor: the record names another extractor than the base record"
		notLate = "changelog-renewal/derivation-time: derivedAt is not later than the base record's: a date edit is not a renewal"
	)
	noExtractor := side(listedID, before)
	noExtractor.Extractor = nil
	noAttestation := side(listedID, before)
	noAttestation.attestation = nil
	newBuild := side(listedID, at)
	newBuild.Extractor.CodeDigest = "sha256:" + strings.Repeat("2", 64)
	otherFamily := side("changelog.listed.fluentd", at)
	otherFamily.attestation.FactFamily = lineattest.FamilyCustomResourceVersions
	for name, tc := range map[string]struct {
		base, head *record
		want       string
	}{
		"another extractor":        {side("changelog.listed.fluentd", before), side(listedID, at), other},
		"base names no extractor":  {noExtractor, side(listedID, at), other},
		"head names no extractor":  {side(listedID, before), noExtractor, other},
		"base not an attestation":  {noAttestation, side(listedID, at), "changelog-renewal/input: the base record is not a line attestation"},
		"same derivation time":     {side(listedID, at), side(listedID, at), notLate},
		"unreadable base time":     {side(listedID, "then"), side(listedID, at), notLate},
		"unreadable head time":     {side(listedID, before), side(listedID, "now"), notLate},
		"new build, older time":    {side(listedID, at), newBuild, notLate},
		"new build, later time":    {side(listedID, before), newBuild, ""},
		"a new record":             {nil, side(listedID, at), ""},
		"a removed record":         {side(listedID, before), nil, ""},
		"another fact family":      {side(listedID, before), otherFamily, ""},
		"same build, not readable": {side(listedID, before), side(listedID, at), "changelog-renewal/input: the base record: "},
	} {
		err := changelogRenewalPre(&Change{rbase: tc.base, rhead: tc.head})
		switch {
		case tc.want == "":
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case strings.HasSuffix(tc.want, ": "):
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Errorf("%s: %v, want %q...", name, err, tc.want)
			}
		case err == nil || err.Error() != tc.want:
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestChangelogRenewalCodeIsAGatePath(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	for _, p := range []string{"cli/internal/maintainer/changelogrenew/check.go", "cli/internal/maintainer/changelogrenew/assemble.go", "cli/cmd/prufyx-maintainer/changelog_renewal.go"} {
		if !layout.gatePath(p) {
			t.Errorf("%s is not a gate path", p)
		}
	}
}
