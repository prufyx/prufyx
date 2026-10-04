// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// singleRecordCache maps a prior pack's digest to the review records
// withSampleRecords last settled on for it, so singleRecords can return
// the records a single-rule fixture's statement was prepared with.
var singleRecordCache = map[string]map[string][]byte{}

// withSampleRecords prepares opts the way a maintainer does: it prepares,
// writes a sample review record (NewSampleReview, decided at attestedAt) for
// every sampled rule without a recorded review, and prepares again. A
// declared review record supplied for a rule that turns out to be sampled
// no longer satisfies the sample; it is replaced the same way.
// It returns the final options, with the records in ReviewRecords.
func withSampleRecords(t *testing.T, opts PrepareOptions) PrepareOptions {
	t.Helper()
	records := map[string][]byte{}
	for id, raw := range opts.ReviewRecords {
		records[id] = raw
	}
	for attempt := 0; attempt < 16; attempt++ {
		opts.ReviewRecords = records
		res, err := Prepare(opts)
		if err != nil {
			t.Fatalf("withSampleRecords: Prepare: %v", err)
		}
		missing := false
		for _, s := range res.Statement.SampledForFullReview {
			if s.ReviewRecordDigest != "" {
				continue
			}
			missing = true
			raw, err := NewSampleReview(SampleReviewOptions{
				StatementRaw: res.StatementCanonical, PriorPackRaw: opts.PackRaw, WorklistRaw: opts.WorklistRaw,
				PackName: opts.PackName, PackPath: opts.PackPath, EngineCapabilityDigest: opts.EngineCapabilityDigest,
				RuleID: s.RuleID, Reviewer: "airstand", DecidedAt: opts.AttestedAt.UTC(), Now: opts.AttestedAt.UTC(),
			})
			if err != nil {
				t.Fatalf("withSampleRecords: NewSampleReview %s: %v", s.RuleID, err)
			}
			records[s.RuleID] = raw
		}
		if !missing {
			cached := map[string][]byte{}
			for id, raw := range records {
				cached[id] = raw
			}
			singleRecordCache[sourcecorpus.SHA(opts.PackRaw)] = cached
			return opts
		}
	}
	t.Fatal("withSampleRecords: the sample did not settle")
	return opts
}

// prepareWithSample is Prepare(withSampleRecords(opts)), returning the
// result and the records it was prepared with.
func prepareWithSample(t *testing.T, opts PrepareOptions) (PrepareResult, map[string][]byte) {
	t.Helper()
	opts = withSampleRecords(t, opts)
	res, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return res, opts.ReviewRecords
}
