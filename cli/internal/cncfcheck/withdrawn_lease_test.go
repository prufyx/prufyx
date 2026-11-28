// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// A withdrawn record gives no verdict, but its evidence end still counts
// toward the expiry of a published knowledge index (earliestExternalExpiry has
// no state filter). The checks below keep the re-reviewed withdrawn record
// named by withdrawnLeaseRuleID from ending the feed.
const withdrawnLeaseRuleID = "cri-o.artifact-short-name-rejected.1-35"

// withdrawnLeaseFloor is the evidence end that the record may never go below.
var withdrawnLeaseFloor = time.Date(2027, 1, 1, 6, 54, 28, 0, time.UTC)

const withdrawnLeaseMaxWindow = 90 * 24 * time.Hour

// The blocking violations of checkWithdrawnLease.
const (
	leaseMissingRecord     = "record missing"
	leaseDuplicateRecord   = "record listed more than once"
	leaseNotWithdrawn      = "record is not withdrawn"
	leaseBadReviewedAt     = "record reviewedAt missing or not UTC RFC 3339"
	leaseBadValidUntil     = "record validUntil missing or not UTC RFC 3339"
	leaseReviewedInFuture  = "record reviewedAt is in the future"
	leaseBadWindow         = "record window is outside (0, 90d]"
	leaseBelowFloor        = "record validUntil is below the floor"
	leaseNotAfterEarliest  = "record validUntil is not after the earliest other end"
	leaseNothingToCompare  = "no other evidence end to compare with"
	leaseUnreadableContent = "pack content cannot be read"
)

type withdrawnLeaseEvidence struct {
	State      string `json:"state"`
	ReviewedAt string `json:"reviewedAt"`
	ValidUntil string `json:"validUntil"`
}

type withdrawnLeaseItem struct {
	id       string
	evidence withdrawnLeaseEvidence
	// ends is the item's contribution to the applicable ends, with the
	// semantics of strictRuleEnds and sectionEnds.
	ends []time.Time
}

func withdrawnLeaseTime(value string) (time.Time, bool) {
	at, err := time.Parse(time.RFC3339, value)
	if err != nil || at.Location() != time.UTC || at.Format(time.RFC3339) != value {
		return time.Time{}, false
	}
	return at, true
}

// checkWithdrawnLease checks one pack. violations are blocking and concern
// only withdrawnLeaseRuleID (and applicable evidence that cannot be read).
// report lists every other item whose state is neither empty nor active; it
// never makes a pack fail, so a withdrawal is never blocked by this check.
func checkWithdrawnLease(pack rulePack, now time.Time) (violations, report []string) {
	var record []withdrawnLeaseEvidence
	var others []withdrawnLeaseItem

	for _, entry := range pack.Entries {
		var shape struct {
			ID       string                 `json:"id"`
			Evidence withdrawnLeaseEvidence `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil {
			return []string{leaseUnreadableContent}, nil
		}
		// The record never counts among the others, whatever its state.
		if shape.ID == withdrawnLeaseRuleID {
			record = append(record, shape.Evidence)
			continue
		}
		ends, err := strictRuleEnds([]Entry{entry})
		if err != nil {
			return []string{leaseUnreadableContent}, nil
		}
		others = append(others, withdrawnLeaseItem{id: "rule " + shape.ID, evidence: shape.Evidence, ends: ends})
	}

	for _, section := range []struct {
		kind string
		raw  json.RawMessage
	}{{"line attestation", pack.LineAttestations}, {"path policy", pack.PathPolicies}, {"served API list", pack.ServedAPIs}} {
		if len(section.raw) == 0 {
			continue
		}
		var items []json.RawMessage
		if json.Unmarshal(section.raw, &items) != nil {
			return []string{leaseUnreadableContent}, nil
		}
		for _, raw := range items {
			var shape struct {
				Component  string                 `json:"component"`
				Line       string                 `json:"line"`
				FactFamily string                 `json:"factFamily"`
				Policy     string                 `json:"policy"`
				Evidence   withdrawnLeaseEvidence `json:"evidence"`
			}
			if json.Unmarshal(raw, &shape) != nil {
				return []string{leaseUnreadableContent}, nil
			}
			one, err := json.Marshal([]json.RawMessage{raw})
			if err != nil {
				return []string{leaseUnreadableContent}, nil
			}
			ends, err := sectionEnds(one)
			if err != nil {
				return []string{leaseUnreadableContent}, nil
			}
			id := strings.Join(strings.Fields(strings.Join([]string{section.kind, shape.Component, shape.Line, shape.FactFamily, shape.Policy}, " ")), " ")
			others = append(others, withdrawnLeaseItem{id: id, evidence: shape.Evidence, ends: ends})
		}
	}

	// The comparison set: the applicable ends, plus the readable end of
	// every item excluded as not applicable, which still counts toward the
	// feed expiry.
	compare := make([][]time.Time, len(others))
	for i, item := range others {
		compare[i] = item.ends
		if len(item.ends) == 0 {
			if end, ok := withdrawnLeaseTime(item.evidence.ValidUntil); ok {
				compare[i] = []time.Time{end}
			}
		}
	}
	earliestExcept := func(skip int) (earliest time.Time) {
		for i, ends := range compare {
			if i == skip {
				continue
			}
			for _, end := range ends {
				if earliest.IsZero() || end.Before(earliest) {
					earliest = end
				}
			}
		}
		return earliest
	}

	for i, item := range others {
		if item.evidence.State == "" || item.evidence.State == "active" {
			continue
		}
		end, endOK := withdrawnLeaseTime(item.evidence.ValidUntil)
		_, reviewedOK := withdrawnLeaseTime(item.evidence.ReviewedAt)
		other := earliestExcept(i)
		report = append(report, fmt.Sprintf("%s: state %s, reviewedAt %q, validUntil %q, below floor %t, ends no later than the earliest other end %t, lacks a date %t",
			item.id, item.evidence.State, item.evidence.ReviewedAt, item.evidence.ValidUntil,
			endOK && end.Before(withdrawnLeaseFloor), endOK && !other.IsZero() && !end.After(other), !endOK || !reviewedOK))
	}

	switch {
	case len(record) == 0:
		return []string{leaseMissingRecord}, report
	case len(record) > 1:
		return []string{leaseDuplicateRecord}, report
	}
	evidence := record[0]
	if evidence.State != "withdrawn" {
		violations = append(violations, leaseNotWithdrawn)
	}
	reviewed, reviewedOK := withdrawnLeaseTime(evidence.ReviewedAt)
	if !reviewedOK {
		violations = append(violations, leaseBadReviewedAt)
	} else if reviewed.After(now) {
		violations = append(violations, leaseReviewedInFuture)
	}
	until, untilOK := withdrawnLeaseTime(evidence.ValidUntil)
	if !untilOK {
		violations = append(violations, leaseBadValidUntil)
	}
	if reviewedOK && untilOK {
		if window := until.Sub(reviewed); window <= 0 || window > withdrawnLeaseMaxWindow {
			violations = append(violations, leaseBadWindow)
		}
	}
	earliest := earliestExcept(-1)
	if earliest.IsZero() {
		violations = append(violations, leaseNothingToCompare)
	}
	if untilOK {
		if until.Before(withdrawnLeaseFloor) {
			violations = append(violations, leaseBelowFloor)
		}
		if !earliest.IsZero() && !until.After(earliest) {
			violations = append(violations, leaseNotAfterEarliest)
		}
	}
	return violations, report
}

// withdrawnLeaseProjectEnd is the earliest evidence end over everything of
// one project that a package for oldestClient ships: its rules and the records
// that name its components, in every state.
func withdrawnLeaseProjectEnd(t *testing.T, b bundle, project, oldestClient string) time.Time {
	t.Helper()
	var documents []json.RawMessage
	for _, entry := range b.pack.Entries {
		if entry.Project == project {
			documents = append(documents, entry.Rule)
		}
	}
	attestations, _, err := ExcludeListedAttestations(b.pack.LineAttestations, oldestClient)
	if err != nil {
		t.Fatal(err)
	}
	owners := recordOwners(b.knowledgeProjects())
	for _, section := range []json.RawMessage{attestations, b.pack.PathPolicies, b.pack.ServedAPIs} {
		if len(section) == 0 {
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(section, &items); err != nil {
			t.Fatal(err)
		}
		components, err := sectionComponents(section)
		if err != nil || len(components) != len(items) {
			t.Fatalf("section components: %d of %d: %v", len(components), len(items), err)
		}
		for i, item := range items {
			if owners[components[i]] == project {
				documents = append(documents, item)
			}
		}
	}
	var earliest time.Time
	for _, document := range documents {
		var shape struct {
			Evidence withdrawnLeaseEvidence `json:"evidence"`
		}
		if err := json.Unmarshal(document, &shape); err != nil {
			t.Fatal(err)
		}
		end, ok := withdrawnLeaseTime(shape.Evidence.ValidUntil)
		if !ok {
			t.Fatalf("%s: unreadable validUntil %q", project, shape.Evidence.ValidUntil)
		}
		if earliest.IsZero() || end.Before(earliest) {
			earliest = end
		}
	}
	if earliest.IsZero() {
		t.Fatalf("%s ships no evidence", project)
	}
	return earliest
}

// withdrawnLeaseSynthetic is a pack of the record with the given evidence and
// the given other items; every date is a constant, so the cases built on it do
// not move with the embedded data.
func withdrawnLeaseSynthetic(record string, rules []string, attestations ...string) rulePack {
	var pack rulePack
	if record != "" {
		pack.Entries = append(pack.Entries, Entry{Project: "cri-o", Rule: json.RawMessage(`{"id":"` + withdrawnLeaseRuleID + `","evidence":` + record + `}`)})
	}
	for i, evidence := range rules {
		pack.Entries = append(pack.Entries, Entry{Project: "other", Rule: json.RawMessage(fmt.Sprintf(`{"id":"other.rule-%d","evidence":%s}`, i, evidence))})
	}
	if len(attestations) > 0 {
		items := make([]string, 0, len(attestations))
		for i, evidence := range attestations {
			items = append(items, fmt.Sprintf(`{"component":"pkg:github/example/other","line":"1.%d","factFamily":"example.family","evidence":%s}`, i, evidence))
		}
		pack.LineAttestations = json.RawMessage("[" + strings.Join(items, ",") + "]")
	}
	return pack
}

func withdrawnLeaseDates(state, reviewedAt, validUntil string) string {
	raw, err := json.Marshal(withdrawnLeaseEvidence{State: state, ReviewedAt: reviewedAt, ValidUntil: validUntil})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// TestWithdrawnRecordDoesNotBoundEvidenceExpiry: the withdrawn CRI-O record
// stays withdrawn, was reviewed no later than now for at most 90 days, ends no
// earlier than the floor and after the earliest other evidence end, and is
// what the cri-o target of a published index carries.
func TestWithdrawnRecordDoesNotBoundEvidenceExpiry(t *testing.T) {
	t.Parallel()
	// The one wall-clock read: it only bounds reviewedAt, so data that
	// passes cannot start failing as time goes on.
	now := time.Now().UTC()

	t.Run("embedded", func(t *testing.T) {
		b, err := load()
		if err != nil {
			t.Fatal(err)
		}
		violations, report := checkWithdrawnLease(b.pack, now)
		for _, line := range report {
			t.Log("not active (report only): " + line)
		}
		for _, violation := range violations {
			t.Errorf("%s: %s", withdrawnLeaseRuleID, violation)
		}

		pin, err := os.ReadFile("../../knowledge/oldest-supported-client.txt")
		if err != nil {
			t.Fatal(err)
		}
		oldest := ""
		for _, line := range strings.Split(string(pin), "\n") {
			if value, ok := strings.CutPrefix(line, "version="); ok {
				oldest = value
			}
		}
		if oldest == "" {
			t.Fatal("the pin file names no version")
		}
		indexTarget, _, _, err := BuildEmbeddedExternalTargetsPinned("1", nil, oldest)
		if err != nil {
			t.Fatal(err)
		}
		index, err := ParseExternalIndex(indexTarget.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := index.Entry("cri-o")
		if !ok {
			t.Fatal("the index lists no cri-o target")
		}
		if want := withdrawnLeaseProjectEnd(t, b, "cri-o", oldest).Format(time.RFC3339); entry.EvidenceExpiresAt != want {
			t.Errorf("cri-o target evidence ends %s, the data says %s", entry.EvidenceExpiresAt, want)
		}
		admission, err := index.Admission()
		if err != nil {
			t.Fatal(err)
		}
		var earliest time.Time
		for _, listed := range index.Entries() {
			end, ok := withdrawnLeaseTime(listed.EvidenceExpiresAt)
			if !ok {
				t.Fatalf("%s: unreadable index expiry %q", listed.Project, listed.EvidenceExpiresAt)
			}
			if earliest.IsZero() || end.Before(earliest) {
				earliest = end
			}
		}
		if earliest.IsZero() || admission.EvidenceExpiresAt != earliest.Format(time.RFC3339) {
			t.Errorf("index evidence ends %s, the earliest entry is %s", admission.EvidenceExpiresAt, earliest.Format(time.RFC3339))
		}
		t.Logf("index evidence ends %s", admission.EvidenceExpiresAt)
	})

	const (
		early    = "2026-12-11T10:42:00Z"
		late     = "2027-03-01T00:00:00Z"
		reviewed = "2026-11-01T00:00:00Z"
		until    = "2027-01-29T00:00:00Z"
	)
	good := withdrawnLeaseDates("withdrawn", reviewed, until)
	active := withdrawnLeaseDates("active", reviewed, early)
	mechanical := withdrawnLeaseDates("", reviewed, early)
	format := func(at time.Time) string { return at.UTC().Truncate(time.Second).Format(time.RFC3339) }
	withdrawn := func(reviewedAt, validUntil string) rulePack {
		return withdrawnLeaseSynthetic(withdrawnLeaseDates("withdrawn", reviewedAt, validUntil), []string{active})
	}
	floorText := format(withdrawnLeaseFloor)
	// A valid end for the case reviewed one hour from now: a day after that
	// review, and never below the floor.
	reviewLater := now.Add(25 * time.Hour)
	if reviewLater.Before(withdrawnLeaseFloor) {
		reviewLater = withdrawnLeaseFloor
	}
	twice := withdrawnLeaseSynthetic(good, []string{active})
	twice.Entries = append(twice.Entries, twice.Entries[0])

	for name, c := range map[string]struct {
		pack rulePack
		want []string
	}{
		"old dates":                               {withdrawn("2026-09-11T00:25:14Z", "2026-12-10T00:25:14Z"), []string{leaseBelowFloor, leaseNotAfterEarliest}},
		"state active":                            {withdrawnLeaseSynthetic(withdrawnLeaseDates("active", reviewed, until), []string{active}), []string{leaseNotWithdrawn}},
		"state empty":                             {withdrawnLeaseSynthetic(withdrawnLeaseDates("", reviewed, until), []string{active}), []string{leaseNotWithdrawn}},
		"window 90d plus 1s":                      {withdrawn(reviewed, "2027-01-30T00:00:01Z"), []string{leaseBadWindow}},
		"validUntil equals reviewedAt":            {withdrawn("2026-09-11T00:25:14Z", "2026-09-11T00:25:14Z"), []string{leaseBadWindow, leaseBelowFloor, leaseNotAfterEarliest}},
		"validUntil before reviewedAt":            {withdrawn("2026-09-11T00:25:14Z", "2026-09-10T00:25:14Z"), []string{leaseBadWindow, leaseBelowFloor, leaseNotAfterEarliest}},
		"reviewedAt in one hour":                  {withdrawn(format(now.Add(time.Hour)), format(reviewLater)), []string{leaseReviewedInFuture}},
		"validUntil on 2026-12-12":                {withdrawn(reviewed, "2026-12-12T00:00:00Z"), []string{leaseBelowFloor}},
		"one second below the floor":              {withdrawn(reviewed, format(withdrawnLeaseFloor.Add(-time.Second))), []string{leaseBelowFloor}},
		"no reviewedAt":                           {withdrawn("", until), []string{leaseBadReviewedAt}},
		"no validUntil":                           {withdrawn(reviewed, ""), []string{leaseBadValidUntil}},
		"reviewedAt not UTC":                      {withdrawn("2026-11-01T02:00:00+02:00", until), []string{leaseBadReviewedAt}},
		"validUntil unreadable":                   {withdrawn(reviewed, "soon"), []string{leaseBadValidUntil}},
		"no record":                               {withdrawnLeaseSynthetic("", []string{active}), []string{leaseMissingRecord}},
		"record twice":                            {twice, []string{leaseDuplicateRecord}},
		"ends with the earliest rule":             {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("active", reviewed, until)}), []string{leaseNotAfterEarliest}},
		"ends with the earliest record":           {withdrawnLeaseSynthetic(good, nil, withdrawnLeaseDates("", reviewed, until)), []string{leaseNotAfterEarliest}},
		"every other end is later":                {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("active", reviewed, late)}, withdrawnLeaseDates("", reviewed, late)), []string{leaseNotAfterEarliest}},
		"nothing to compare":                      {withdrawnLeaseSynthetic(good, nil), []string{leaseNothingToCompare}},
		"active record is not its own comparison": {withdrawnLeaseSynthetic(withdrawnLeaseDates("active", reviewed, until), nil), []string{leaseNotWithdrawn, leaseNothingToCompare}},
		"only an undated withdrawn item":          {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("withdrawn", reviewed, "")}), []string{leaseNothingToCompare}},
		"active rule with unreadable date":        {withdrawnLeaseSynthetic(good, []string{active, withdrawnLeaseDates("active", reviewed, "soon")}), []string{leaseUnreadableContent}},
		"record section with unreadable date":     {withdrawnLeaseSynthetic(good, []string{active}, withdrawnLeaseDates("", reviewed, "soon")), []string{leaseUnreadableContent}},
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			got, _ := checkWithdrawnLease(c.pack, now)
			got, want := slices.Clone(got), slices.Clone(c.want)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("violations %q, want %q", got, want)
			}
		})
	}

	pinned := `{"state":"active","lease":"pinned","reviewedAt":"` + reviewed + `","validUntil":"` + early + `"}`
	for name, c := range map[string]struct {
		pack     rulePack
		reported int
	}{
		"good record":                    {withdrawnLeaseSynthetic(good, []string{active}), 0},
		"window of exactly 90 days":      {withdrawn(reviewed, "2027-01-30T00:00:00Z"), 0},
		"exactly the floor":              {withdrawn(reviewed, floorText), 0},
		"one second after the earliest":  {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("active", reviewed, "2027-01-28T23:59:59Z")}), 0},
		"mechanical record is the other": {withdrawnLeaseSynthetic(good, nil, mechanical), 0},
		"pinned rule counts":             {withdrawnLeaseSynthetic(good, []string{pinned}), 0},
		"another rule withdrawn early":   {withdrawnLeaseSynthetic(good, []string{active, withdrawnLeaseDates("withdrawn", reviewed, "2026-12-01T00:00:00Z")}), 1},
		"earliest rule withdrawn":        {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("withdrawn", reviewed, early), withdrawnLeaseDates("active", reviewed, late)}), 1},
		"record withdrawn early":         {withdrawnLeaseSynthetic(good, []string{active}, withdrawnLeaseDates("withdrawn", reviewed, "2026-12-01T00:00:00Z")), 1},
		"earliest record withdrawn":      {withdrawnLeaseSynthetic(good, []string{withdrawnLeaseDates("active", reviewed, late)}, withdrawnLeaseDates("withdrawn", reviewed, early)), 1},
		"other state in a section":       {withdrawnLeaseSynthetic(good, nil, withdrawnLeaseDates("superseded", reviewed, early)), 1},
		"withdrawn without dates":        {withdrawnLeaseSynthetic(good, []string{active, withdrawnLeaseDates("withdrawn", "", "")}), 1},
		"withdrawn with unreadable date": {withdrawnLeaseSynthetic(good, []string{active}, withdrawnLeaseDates("withdrawn", reviewed, "soon")), 1},
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			violations, report := checkWithdrawnLease(c.pack, now)
			if len(violations) != 0 || len(report) != c.reported {
				t.Fatalf("violations %q, report %q, want %d reported", violations, report, c.reported)
			}
		})
	}
}
