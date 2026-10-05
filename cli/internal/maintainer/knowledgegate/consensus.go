// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"fmt"
	"time"

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

// Bounds of the consensus verifier's work in one gate run.
const (
	// MaxConsensusBundles is how many claims bundles one run verifies;
	// further bundles are reported as not run.
	MaxConsensusBundles = 20
	// ConsensusBudget bounds the verification of all bundles of one run
	// together; every upstream read honours it.
	ConsensusBudget = 10 * time.Minute
)

// consensusRun is the consensus verifier's state for one gate run: one
// inventory cache shared by every bundle, and the bundle count.
type consensusRun struct {
	inventories *consensus.ExtractorInventories
	bundles     int
	ctx         context.Context
	cancel      context.CancelFunc
	reader      extract.PinnedReader
}

// close releases the run's deadline.
func (r *consensusRun) close() {
	if r.cancel != nil {
		r.cancel()
	}
}

// report re-runs the consensus verifier, with the code this gate was built
// from, on the claims bundle of a changed consensus rule
// (<ConsensusClaimsDir>/<pack>/<rule id>.json in the head), against the
// gate's own upstream source, and adds the verdict to the change. It never
// changes whether the change is admitted.
func (r *consensusRun) report(ctx context.Context, c *Change, opts Options) {
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
	if r.bundles >= MaxConsensusBundles {
		v.Error = fmt.Sprintf("more than %d claims bundles in one run", MaxConsensusBundles)
		return
	}
	r.bundles++
	bundle, err := consensus.DecodeBundle(raw)
	if err != nil {
		v.Error = err.Error()
		return
	}
	if opts.Source == nil {
		v.Error = "no upstream source"
		return
	}
	if r.ctx == nil {
		r.ctx, r.cancel = context.WithTimeout(ctx, ConsensusBudget)
		r.reader = consensus.ContextReader(r.ctx, opts.Source)
		r.inventories = &consensus.ExtractorInventories{Reader: r.reader, Concurrency: opts.Concurrency}
	}
	in := consensus.Inputs{Reader: r.reader, Tags: opts.Source, Inventory: r.inventories}
	switch src := opts.Source.(type) {
	case extract.FixtureReader:
		in.History = consensus.FixtureHistory{Root: src.Root}
	case consensus.History:
		in.History = src
	}
	rep, err := consensus.Verify(r.ctx, bundle, in)
	if err != nil {
		v.Error = err.Error()
		return
	}
	v.Verified, v.Lead, v.Dropped = rep.Summary.Verified, rep.Summary.Lead, rep.Summary.Dropped
	for _, cl := range rep.Claims {
		v.Results = append(v.Results, ConsensusClaimVerdict{ID: cl.ID, Verdict: cl.Verdict, Reason: cl.Reason})
	}
}
