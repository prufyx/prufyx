// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func tm(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// attAt is attJSON with the review time and the end of validity chosen.
func attAt(line, reviewed, until string) string {
	a := attJSON(line, until)
	return strings.Replace(a, "2026-09-01T00:00:00Z", reviewed, 1)
}

// mechAt is a mechanical attestation: derivedAt = reviewedAt and an extractor.
func mechAt(line, at, until string) string {
	a := attAt(line, at, until)
	return strings.Replace(a, `"basis":"reviewed"`, fmt.Sprintf(`"basis":"mechanical","derivedAt":%q,"extractor":{"id":"crd.test","version":"2.11.0","codeDigest":"sha256:%s"}`, at, strings.Repeat("b", 64)), 1)
}

func pinnedFile(captured, on string) LinesFile { return LinesFile{CapturedOn: captured, PinnedOn: on} }

func linesDated(captured, pinnedOn string, window ...string) []byte {
	quoted := make([]string, len(window))
	for i, l := range window {
		quoted[i] = fmt.Sprintf("%q", l)
	}
	pin := ""
	if pinnedOn != "" {
		pin = fmt.Sprintf(`,"pinnedOn":%q`, pinnedOn)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"capturedOn":%q%s,"projects":{"kubernetes":{"lines":[%s]}}}`, LinesSchema, captured, pin, strings.Join(quoted, ",")))
}

func additionsOn(dates ...string) AdditionsFile {
	f := AdditionsFile{Additions: map[string]AdditionEntry{}}
	for i, d := range dates {
		f.Additions[fmt.Sprintf("p%d", i)] = AdditionEntry{CapturedOn: d}
	}
	return f
}

func unrelated() []string { return []string{ruleJSON("unrelated", "1.20.0", "1.21.0", "", valid)} }

func TestEvaluationClockFromPack(t *testing.T) {
	t.Parallel()
	pin := pinnedFile("2026-10-31", "2026-11-07")
	for _, c := range []struct {
		name string
		add  AdditionsFile
		atts []string
		want string
	}{
		{"no attestation: the date clock", additionsOn(), nil, "2026-11-07T12:00:00Z"},
		{"renewal after the pin (derivedAt=reviewedAt)", additionsOn(), []string{mechAt("1.32", "2026-11-09T10:02:09Z", valid)}, "2026-11-09T10:02:09Z"},
		{"reviewed attestation after the pin", additionsOn(), []string{attAt("1.32", "2026-11-08T01:00:00Z", valid)}, "2026-11-08T01:00:00Z"},
		{"newest of several", additionsOn(), []string{attAt("1.31", "2026-11-08T01:00:00Z", valid), attAt("1.32", "2026-11-09T05:00:00Z", valid)}, "2026-11-09T05:00:00Z"},
		{"attestation before the pin never moves it back", additionsOn(), []string{attAt("1.32", "2026-09-01T00:00:00Z", valid)}, "2026-11-07T12:00:00Z"},
		{"b: additions date later than the attestations (unchanged rule)", additionsOn("2026-11-10"), []string{mechAt("1.32", "2026-11-09T10:02:09Z", valid)}, "2026-11-10T12:00:00Z"},
		{"c: attestation later than the additions date", additionsOn("2026-11-10"), []string{attAt("1.32", "2026-11-12T08:00:00Z", valid)}, "2026-11-12T08:00:00Z"},
		{"c: attestation earlier than noon of the additions date", additionsOn("2026-11-10"), []string{attAt("1.32", "2026-11-10T08:00:00Z", valid)}, "2026-11-10T12:00:00Z"},
	} {
		got, err := EvaluationClockFromPack(pin, c.add, pack(unrelated(), c.atts))
		if err != nil || !got.Equal(tm(c.want)) {
			t.Errorf("%s: %v %v, want %s", c.name, got, err, c.want)
		}
		again, _ := EvaluationClockFromPack(pin, c.add, pack(unrelated(), c.atts))
		if !again.Equal(got) {
			t.Errorf("%s: not deterministic", c.name)
		}
	}
	// Fail closed: an attestation section that does not parse, or a pinned
	// snapshot without a date, gives no clock.
	if _, err := EvaluationClockFromPack(pin, additionsOn(), []byte(`{"schema":"t","revision":"r","entries":[],"lineAttestations":[{"x":1}]}`)); err == nil {
		t.Error("an invalid attestation section gave a clock")
	}
	if _, err := EvaluationClockFromPack(LinesFile{}, additionsOn(), pack(unrelated(), nil)); err == nil {
		t.Error("a snapshot without a date gave a clock")
	}
}

// The renewal incident: the factory stamps derivedAt=reviewedAt with the real
// derive time, after the pin. At the date clock the renewed pair was
// undecided; at the tree's clock it counts, and the floor compares equal
// decided counts for the old and the renewed attestation.
func TestRenewalCountsAtTheTreeClock(t *testing.T) {
	t.Parallel()
	pin := pinnedFile("2026-10-31", "2026-11-07")
	lf := linesDated("2026-10-31", "2026-11-07", "1.31", "1.32")
	compute := func(p []byte, now time.Time) Report {
		t.Helper()
		r, err := Compute(Input{Pack: p, Lines: lf, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	decided := func(r Report) int { return r.Fleet.A + r.Fleet.B }
	oldPack := pack(unrelated(), []string{attAt("1.32", "2026-09-01T00:00:00Z", valid)})
	renewed := pack(unrelated(), []string{mechAt("1.32", "2026-11-09T10:02:09Z", valid)})

	dateClock, err := EvaluationClock(pin, additionsOn())
	if err != nil {
		t.Fatal(err)
	}
	// Old behaviour, reproduced: the renewal is after the clock and undecided.
	before := compute(renewed, dateClock)
	if decided(before) != 0 || len(before.AttestedAfterClock) == 0 {
		t.Fatalf("the date clock decided the renewed pair: %d %v", decided(before), before.AttestedAfterClock)
	}
	// New behaviour: the clock of the renewed tree counts it.
	headClock, err := EvaluationClockFromPack(pin, additionsOn(), renewed)
	if err != nil {
		t.Fatal(err)
	}
	after := compute(renewed, headClock)
	if decided(after) != 1 || len(after.AttestedAfterClock) != 0 {
		t.Fatalf("the tree clock did not count the renewal: %d %v", decided(after), after.AttestedAfterClock)
	}
	if after.ClockAttestedAt != "2026-11-09T10:02:09Z" {
		t.Errorf("the clock source is not disclosed: %q", after.ClockAttestedAt)
	}
	// The base tree is evaluated at its own clock: equal decided counts.
	baseClock, _ := EvaluationClockFromPack(pin, additionsOn(), oldPack)
	if got := decided(compute(oldPack, baseClock)); got != decided(after) {
		t.Fatalf("base %d, head %d", got, decided(after))
	}
	if r := compute(oldPack, baseClock); r.ClockAttestedAt != "" {
		t.Errorf("a date clock discloses an attestation clock: %q", r.ClockAttestedAt)
	}
	// And the floor comparison itself accepts the pair.
	if err := CheckBaseline(Baseline{DecidedPairs: decided(compute(oldPack, baseClock))}, decided(after), after.CRDPublishedProjects, nil); err != nil {
		t.Errorf("equal decided counts refused: %v", err)
	}
}

// A clock moved later by one attestation can end another: the older one at its
// validUntil no longer counts (visible, never hidden), and an attestation
// whose validUntil is not later than the clock is not counted.
func TestLaterClockExpiresOtherAttestations(t *testing.T) {
	t.Parallel()
	pin := pinnedFile("2026-10-31", "2026-11-07")
	lf := linesDated("2026-10-31", "2026-11-07", "1.31", "1.32", "1.33")
	short := attAt("1.32", "2026-09-01T00:00:00Z", "2026-11-10T00:00:00Z")
	statusesAt := func(atts ...string) (string, string) {
		p := pack(unrelated(), atts)
		clock, err := EvaluationClockFromPack(pin, additionsOn(), p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Compute(Input{Pack: p, Lines: lf, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		return statuses(r.Projects[0]), clock.Format(time.RFC3339)
	}
	// The floor counts what attested() counts: an attestation is current while
	// validUntil is later than the clock. The 14-day horizon (ExpiryHorizon)
	// applies only to the ALL-window completeness clauses and to the
	// "expiring" figure, never to the decided A+B count, so "short" (under
	// three days left) is A here by the published rule, not by accident.
	if got, clock := statusesAt(short); got != "AG" || clock != "2026-11-07T12:00:00Z" {
		t.Fatalf("alone: %s at %s", got, clock)
	}
	if got, clock := statusesAt(short, attAt("1.33", "2026-11-12T08:00:00Z", valid)); got != "GA" || clock != "2026-11-12T08:00:00Z" {
		t.Fatalf("with a newer attestation: %s at %s", got, clock)
	}
	// An attestation that ends when it starts is invalid, not current.
	p := pack(unrelated(), []string{attAt("1.33", "2026-11-12T08:00:00Z", "2026-11-12T08:00:00Z")})
	if _, err := Compute(Input{Pack: p, Lines: lf, Now: tm("2026-11-12T08:00:00Z")}); err == nil {
		t.Error("an attestation that ends when it starts was accepted")
	}
}

// The newest time covers both packs (CNCF and community); empty packs are
// skipped and a pack without attestations adds nothing.
func TestNewestAttestationTimeCoversCommunity(t *testing.T) {
	t.Parallel()
	cncf := pack(unrelated(), []string{attAt("1.32", "2026-11-08T01:00:00Z", valid)})
	comm := pack(nil, []string{attAt("1.32", "2026-11-12T08:00:00Z", valid)})
	got, ok, err := NewestAttestationTime(cncf, comm, nil)
	if err != nil || !ok || !got.Equal(tm("2026-11-12T08:00:00Z")) {
		t.Fatalf("%v %v %v", got, ok, err)
	}
	if _, ok, err := NewestAttestationTime(pack(unrelated(), nil), nil); err != nil || ok {
		t.Fatalf("no attestation: %v %v", ok, err)
	}
	if _, _, err := NewestAttestationTime(cncf, []byte(`{"lineAttestations":[{"x":1}]}`)); err == nil {
		t.Fatal("an invalid community section was accepted")
	}
}

// README bytes: unchanged without an attestation clock, consistent with it.
func TestReadmeClockSentences(t *testing.T) {
	t.Parallel()
	var r Report
	r.Lines.CapturedOn, r.Lines.PinnedOn = "2026-10-31", "2026-11-07"
	r.Additions = &AdditionsInfo{Entries: 2, ClockOn: "2026-11-10"}
	plain := readmeClockText(r)
	if !strings.Contains(plain, "the block is evaluated on 2026-11-10 (the later of") || strings.Contains(plain, "newest line attestation") {
		t.Fatalf("without an attestation clock: %q", plain)
	}
	r.ClockAttestedAt = "2026-11-12T08:00:00Z"
	got := readmeClockText(r)
	if strings.Contains(got, "the block is evaluated on 2026-11-10") || !strings.Contains(got, "the date clock of the block is 2026-11-10") || !strings.Contains(got, "evaluated at 2026-11-12T08:00:00Z, the time of the newest line attestation") {
		t.Fatalf("with an attestation clock: %q", got)
	}
}
