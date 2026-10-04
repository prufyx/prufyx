// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/consensus"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// ConsensusVerdict is what the consensus verifier said about the claims
// bundle a consensus rule carries. It is reported only: a consensus rule
// is never admitted by this gate, whatever the verdict.
type ConsensusVerdict struct {
	// Claims is the bundle's path in the head.
	Claims   string `json:"claims"`
	Verified int    `json:"verified"`
	Lead     int    `json:"lead"`
	Dropped  int    `json:"dropped"`
	// Results lists each claim's verdict and reason.
	Results []ConsensusClaimVerdict `json:"results,omitempty"`
	// Error says why the verifier could not run.
	Error string `json:"error,omitempty"`
}

// ConsensusClaimVerdict is one claim's verdict.
type ConsensusClaimVerdict struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

func (v *ConsensusVerdict) summary() string {
	if v.Error != "" {
		return "not run: " + v.Error
	}
	return fmt.Sprintf("%d verified, %d lead, %d dropped", v.Verified, v.Lead, v.Dropped)
}

// reportConsensus re-runs the consensus verifier, with the code this gate
// was built from, on the claims bundle of a changed consensus rule
// (<ConsensusClaimsDir>/<pack>/<rule id>.json in the head), against the
// gate's own upstream source, and adds the verdict to the change. It never
// changes whether the change is admitted.
func reportConsensus(ctx context.Context, c *Change, opts Options) {
	if opts.Layout.ConsensusClaimsDir == "" || c.RuleID == "" {
		return
	}
	rel := opts.Layout.ConsensusClaimsDir + "/" + c.Pack + "/" + c.RuleID + ".json"
	raw, err := opts.Head.ReadOptional(rel, consensus.MaxBundleBytes+1)
	if err == nil && raw == nil {
		return
	}
	v := &ConsensusVerdict{Claims: rel}
	defer func() {
		c.Consensus = v
		c.Detail += "; consensus verifier (report only): " + v.summary()
	}()
	if err != nil {
		v.Error = err.Error()
		return
	}
	bundle, err := consensus.DecodeBundle(raw)
	if err != nil {
		v.Error = err.Error()
		return
	}
	if opts.Source == nil {
		v.Error = "no upstream source"
		return
	}
	in := consensus.Inputs{
		Reader: opts.Source, Tags: opts.Source,
		Inventory: &consensus.ExtractorInventories{Reader: opts.Source, Concurrency: opts.Concurrency},
	}
	switch src := opts.Source.(type) {
	case extract.FixtureReader:
		in.History = consensus.FixtureHistory{Root: src.Root}
	case consensus.History:
		in.History = src
	}
	rep, err := consensus.Verify(ctx, bundle, in)
	if err != nil {
		v.Error = err.Error()
		return
	}
	v.Verified, v.Lead, v.Dropped = rep.Summary.Verified, rep.Summary.Lead, rep.Summary.Dropped
	for _, r := range rep.Claims {
		v.Results = append(v.Results, ConsensusClaimVerdict{ID: r.ID, Verdict: r.Verdict, Reason: r.Reason})
	}
}
