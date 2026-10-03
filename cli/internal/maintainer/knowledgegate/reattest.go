// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
)

// maxChainFiles bounds a statement chain directory (two files per entry).
const maxChainFiles = 2 * evidencereattest.MaxChainEntries

const (
	chainStatementSuffix = ".statement.json"
	chainEnvelopeSuffix  = ".statement.sig.json"
	worklistSuffix       = ".worklist.json"
	reviewRecordSuffix   = ".json"
)

// statementResult is the outcome of verifying the one statement a change
// appends to a pack's reattestation chain.
type statementResult struct {
	OK      bool
	Detail  string
	Role    string
	Stem    string
	Renewed map[string]bool
}

// readChain reads one chain directory into entries ordered by stem. Every
// file must be <stem>.statement.json or <stem>.statement.sig.json and every
// stem must have both. One trailing newline is trimmed from each file.
func readChain(files map[string][]byte) ([]evidencereattest.ChainEntry, error) {
	statements, envelopes := map[string][]byte{}, map[string][]byte{}
	for name, raw := range files {
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		switch {
		case strings.HasSuffix(name, chainEnvelopeSuffix) && len(name) > len(chainEnvelopeSuffix):
			envelopes[strings.TrimSuffix(name, chainEnvelopeSuffix)] = raw
		case strings.HasSuffix(name, chainStatementSuffix) && len(name) > len(chainStatementSuffix):
			statements[strings.TrimSuffix(name, chainStatementSuffix)] = raw
		default:
			return nil, fmt.Errorf("unexpected file %s in the statement chain", name)
		}
	}
	if len(statements) != len(envelopes) {
		return nil, fmt.Errorf("statement chain has unpaired files")
	}
	stems := make([]string, 0, len(statements))
	for stem := range statements {
		if _, ok := envelopes[stem]; !ok {
			return nil, fmt.Errorf("statement %s has no signature", stem)
		}
		stems = append(stems, stem)
	}
	sort.Strings(stems)
	out := make([]evidencereattest.ChainEntry, 0, len(stems))
	for _, stem := range stems {
		out = append(out, evidencereattest.ChainEntry{Name: stem, Statement: statements[stem], Envelope: envelopes[stem]})
	}
	return out, nil
}

// verifyStatement verifies the statement a change appends to one pack's
// chain with every reattestation invariant (V1-V9, the independent
// worklist comparison included) and its signature under the trust root
// pinned in the base tree by the digest the caller supplies.
func verifyStatement(layout Layout, spec PackSpec, base, head Tree, basePack, headPack *loadedPack, opts Options) statementResult {
	fail := func(format string, args ...any) statementResult {
		return statementResult{Detail: fmt.Sprintf(format, args...)}
	}
	dir := layout.ReattestDir + "/" + spec.Name
	baseFiles, err := base.Dir(dir+"/chain", evidencereattest.MaxStatementBytes+1, maxChainFiles)
	if err != nil {
		return fail("base statement chain: %v", err)
	}
	headFiles, err := head.Dir(dir+"/chain", evidencereattest.MaxStatementBytes+1, maxChainFiles)
	if err != nil {
		return fail("statement chain: %v", err)
	}
	baseChain, err := readChain(baseFiles)
	if err != nil {
		return fail("base statement chain: %v", err)
	}
	headChain, err := readChain(headFiles)
	if err != nil {
		return fail("statement chain: %v", err)
	}
	inBase := map[string]bool{}
	for _, e := range baseChain {
		inBase[e.Name+"\x00"+string(e.Statement)+"\x00"+string(e.Envelope)] = true
	}
	var added []evidencereattest.ChainEntry
	for _, e := range headChain {
		if !inBase[e.Name+"\x00"+string(e.Statement)+"\x00"+string(e.Envelope)] {
			added = append(added, e)
		}
	}
	if len(added) != 1 {
		return fail("the change must append exactly one statement to the %s chain, it appends %d", spec.Name, len(added))
	}
	stmt := added[0]
	if opts.TrustRootDigest == "" {
		return fail("no reattestation trust root digest is configured")
	}
	trustRoot, err := base.Read(layout.TrustRootPath, evidencereattest.MaxTrustRootBytes+1)
	if err != nil {
		return fail("reattestation trust root: %v", err)
	}
	trustRoot = bytes.TrimSuffix(trustRoot, []byte("\n"))
	if len(opts.RerunWorklist) == 0 {
		return fail("a worklist produced by this job's own evidence repin run is required")
	}
	worklist, err := head.Read(dir+"/worklists/"+stmt.Name+worklistSuffix, evidencereattest.MaxWorklistBytes)
	if err != nil {
		return fail("retained worklist: %v", err)
	}
	recordFiles, err := head.Dir(dir+"/review-records", evidencereattest.MaxReviewRecordBytes, evidencereattest.MaxChainEntries)
	if err != nil {
		return fail("review records: %v", err)
	}
	records := map[string][]byte{}
	for name, raw := range recordFiles {
		id := strings.TrimSuffix(name, reviewRecordSuffix)
		if id == "" || id == name || len(raw) == 0 {
			return fail("review record file %s is not <rule id>.json", name)
		}
		records[id] = raw
	}
	capability, err := spec.CapabilityDigest()
	if err != nil {
		return fail("engine capability digest: %v", err)
	}
	now := opts.Now.UTC()
	headCh := &evidencereattest.Chain{Entries: headChain, TrustRoot: trustRoot, ExpectedTrustRootDigest: opts.TrustRootDigest}
	baseCh := &evidencereattest.Chain{Entries: baseChain, TrustRoot: trustRoot, ExpectedTrustRootDigest: opts.TrustRootDigest}
	result, err := evidencereattest.Verify(evidencereattest.VerifyOptions{
		StatementRaw: stmt.Statement, PriorPackRaw: basePack.Raw, NextPackRaw: headPack.Raw,
		WorklistRaw: worklist, Chain: headCh, BaseChain: baseCh,
		PackName: spec.Name, PackPath: spec.Path, EngineCapabilityDigest: capability,
		AttestedAtNow: now, ReviewRecords: records, IndependentWorklistRaw: opts.RerunWorklist,
	})
	if err != nil {
		return fail("statement %s: %v", stmt.Name, err)
	}
	sig, err := evidencereattest.VerifySignature(evidencereattest.VerifySignatureOptions{
		Statement: stmt.Statement, Envelope: stmt.Envelope, TrustRoot: trustRoot, ExpectedTrustRootDigest: opts.TrustRootDigest, Now: now,
	})
	if err != nil {
		return fail("statement %s signature: %v", stmt.Name, err)
	}
	statement, err := evidencereattest.ParseStatement(stmt.Statement)
	if err != nil {
		return fail("statement %s: %v", stmt.Name, err)
	}
	renewed := map[string]bool{}
	for _, r := range statement.Rules {
		renewed[r.RuleID] = true
	}
	if len(renewed) != result.RuleCount {
		return fail("statement %s: renewed rule count mismatch", stmt.Name)
	}
	return statementResult{OK: true, Role: sig.SignerRole, Stem: stmt.Name, Renewed: renewed}
}
