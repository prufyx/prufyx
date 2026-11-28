// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

const (
	recordTestProject = "kubernetes"
	recordTestLine    = "1.37"
)

// recordStore is the kubernetes target of a store whose pack is the packaged
// one with edit applied.
func recordStore(t *testing.T, edit func(pack map[string]any)) ExternalBundle {
	t.Helper()
	raw, err := packagedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(pack)
	}
	edited, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	// The pack schema is the level of what the edited pack holds.
	var typed rulePack
	if err := json.Unmarshal(edited, &typed); err != nil {
		t.Fatal(err)
	}
	if pack["schema"], err = requiredPackSchema(typed); err != nil {
		t.Fatal(err)
	}
	if edited, err = json.Marshal(pack); err != nil {
		t.Fatal(err)
	}
	_, targets, err := BuildExternalTargetsFromPack(edited, "99")
	if err != nil {
		t.Fatalf("build targets (schema %v): %v", pack["schema"], err)
	}
	for _, target := range targets {
		if target.Path == ProjectTargetPath(recordTestProject) {
			bundle, err := ParseExternalBundle(target.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			return bundle
		}
	}
	t.Fatal("no kubernetes target")
	return ExternalBundle{}
}

func recordSnapshot(t *testing.T, store ExternalBundle) *ScanKnowledge {
	t.Helper()
	snapshot, err := NewStoreScanKnowledge(map[string]ExternalBundle{recordTestProject: store})
	if err != nil {
		t.Fatal(err)
	}
	if !store.valid() {
		t.Fatal("envelope changed")
	}
	return snapshot
}

// removedReviews are the packaged review times of one line attestation and one
// served list of the test line.
func removedReviews(t *testing.T) (lineattest.Key, time.Time, time.Time) {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	key := lineattest.Key{Component: servedapis.KubernetesComponent, Line: recordTestLine, Family: lineattest.FamilyKubernetesRemovedServedGVK}
	attested := base.attestations.AttestationsFor(key.Component, key.Line, key.Family, time.Time{})
	served, ok := base.servedAPIs.For(servedapis.KubernetesComponent, recordTestLine, time.Time{})
	if len(attested) != 1 || !ok {
		t.Fatal("the packaged pack lacks the records this test needs")
	}
	a, err := reviewTime(attested[0].Attestation.Evidence.ReviewedAt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := reviewTime(served.Record.Evidence.ReviewedAt)
	if err != nil {
		t.Fatal(err)
	}
	return key, a, s
}

// setRemoved replaces the compiled removals for one test. Its callers do not
// run in parallel.
func setRemoved(t *testing.T, removed recordWithdrawals) {
	t.Helper()
	previous := compiledRecordWithdrawals
	compiledRecordWithdrawals = removed
	t.Cleanup(func() { compiledRecordWithdrawals = previous })
}

// A line attestation or served list this build removed stays removed in a
// store unless the store record was reviewed strictly later.
func TestStoreCannotRestoreRemovedRecords(t *testing.T) {
	key, attested, served := removedReviews(t)
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	store := recordStore(t, nil)
	for name, c := range map[string]struct {
		shift time.Duration
		held  bool
	}{
		"removal at the store's review":    {0, false},
		"removal after the store's review": {time.Second, false},
		"store reviewed strictly later":    {-time.Second, true},
	} {
		setRemoved(t, recordWithdrawals{
			attestations: map[lineattest.Key]string{key: stamp(attested.Add(c.shift))},
			servedLists:  map[servedScope]string{{key.Component, key.Line}: stamp(served.Add(c.shift))},
		})
		snapshot := recordSnapshot(t, store)
		now := attested.Add(24 * time.Hour)
		if served.After(attested) {
			now = served.Add(24 * time.Hour)
		}
		if got := snapshot.AttestationsFor(key.Component, key.Line, key.Family, now); (len(got) == 1) != c.held {
			t.Fatalf("%s: attestations %d", name, len(got))
		}
		if _, got := snapshot.ServedAPIsFor(key.Component, key.Line, now); got != c.held {
			t.Fatalf("%s: served list held=%v", name, got)
		}
		if line, found := snapshot.NewestServedLine(key.Component, now); (found && line == key.Line) != c.held {
			t.Fatalf("%s: newest served line %q", name, line)
		}
		// Only the removed scope is affected.
		if _, got := snapshot.ServedAPIsFor(key.Component, "1.36", now); !got {
			t.Fatalf("%s: another served list is gone", name)
		}
		if got := snapshot.AttestationsFor(key.Component, "1.36", key.Family, now); len(got) != 1 {
			t.Fatalf("%s: another attestation is gone", name)
		}
	}
}

// A removal date that cannot be read refuses the store.
func TestStoreRecordRemovalDateMustBeReadable(t *testing.T) {
	key, _, _ := removedReviews(t)
	store := recordStore(t, nil)
	for _, bad := range []string{"", "later", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00.5Z"} {
		for name, removed := range map[string]recordWithdrawals{
			"attestation": {attestations: map[lineattest.Key]string{key: bad}},
			"served list": {servedLists: map[servedScope]string{{key.Component, key.Line}: bad}},
		} {
			setRemoved(t, removed)
			if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{recordTestProject: store}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s %q: %v", name, bad, err)
			}
		}
	}
}

// The embedded pack never holds a record this build says it removed, unless it
// was reviewed again after the removal.
func TestCompiledRecordWithdrawalsAgreeWithPack(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	check := func(scope string, held, removed string) {
		newer, err := reviewedAfter(held, removed)
		if err != nil || !newer {
			t.Fatalf("%s: removed at %s, packaged review %s (%v)", scope, removed, held, err)
		}
	}
	for key, at := range compiledRecordWithdrawals.attestations {
		if _, err := reviewTime(at); err != nil {
			t.Fatalf("%s: %q", key, at)
		}
		for _, status := range base.attestations.AttestationsFor(key.Component, key.Line, key.Family, time.Time{}) {
			check(key.String(), status.Attestation.Evidence.ReviewedAt, at)
		}
	}
	for scope, at := range compiledRecordWithdrawals.servedLists {
		if _, err := reviewTime(at); err != nil {
			t.Fatalf("%v: %q", scope, at)
		}
		if status, ok := base.servedAPIs.For(scope.component, scope.line, time.Time{}); ok {
			check(scope.component+" "+scope.line, status.Record.Evidence.ReviewedAt, at)
		}
	}
}

func TestPoliciesUnderWithdrawals(t *testing.T) {
	t.Parallel()
	const component = "pkg:github/kubernetes/kubernetes"
	record := func(state, reviewedAt string) string {
		return `[{"component":"` + component + `","policy":"direct","evidence":{"state":"` + state + `","reviewedAt":"` + reviewedAt + `","validUntil":"2026-11-30T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}}]`
	}
	pack := func(section string) rulePack {
		if section == "" {
			return rulePack{}
		}
		return rulePack{PathPolicies: json.RawMessage(section)}
	}
	identity := projectIdentity{Slug: "kubernetes", RepositoryURL: "https://github.com/kubernetes/kubernetes"}
	other := projectIdentity{Slug: "cri-o", RepositoryURL: "https://github.com/cri-o/cri-o"}
	gone := pack(record("withdrawn", "2026-10-02T00:00:00Z"))
	for name, c := range map[string]struct {
		embedded, external rulePack
		project            projectIdentity
		want               []string // evidence states
	}{
		"same date":                   {gone, pack(record("active", "2026-10-02T00:00:00Z")), identity, []string{"withdrawn"}},
		"earlier date":                {gone, pack(record("active", "2026-10-01T23:59:59Z")), identity, []string{"withdrawn"}},
		"strictly later":              {gone, pack(record("active", "2026-10-02T00:00:01Z")), identity, []string{"active"}},
		"later but withdrawn":         {gone, pack(record("withdrawn", "2026-10-03T00:00:00Z")), identity, []string{"withdrawn"}},
		"store without the record":    {gone, pack(""), identity, []string{"withdrawn"}},
		"other project gets none":     {gone, pack(""), other, nil},
		"bound in any project":        {gone, pack(record("active", "2026-10-02T00:00:00Z")), other, []string{"withdrawn"}},
		"nothing withdrawn":           {pack(record("active", "2026-10-09T00:00:00Z")), pack(record("active", "2026-10-01T00:00:00Z")), identity, []string{"active"}},
		"nothing withdrawn, no store": {pack(record("active", "2026-10-09T00:00:00Z")), pack(""), identity, nil},
	} {
		before := string(c.external.PathPolicies)
		got, err := policiesUnderWithdrawals(c.embedded, c.external, c.project)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var states []string
		for _, r := range got {
			states = append(states, r.Evidence.State)
		}
		if len(states) != len(c.want) || (len(states) == 1 && states[0] != c.want[0]) {
			t.Fatalf("%s: %v, want %v", name, states, c.want)
		}
		if string(c.external.PathPolicies) != before {
			t.Fatalf("%s: store section changed", name)
		}
	}
	for name, c := range map[string][2]rulePack{
		"unreadable store":    {gone, pack(`[{}]`)},
		"unreadable embedded": {pack(`[{}]`), pack("")},
		"offset review":       {gone, pack(record("active", "2026-10-03T00:00:00+00:00"))},
	} {
		if _, err := policiesUnderWithdrawals(c[0], c[1], identity); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
