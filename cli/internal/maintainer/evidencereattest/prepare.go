// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// resolutionTagFallback mirrors evidencerepin's own (unexported) constant
// of the same name and value: a RepoResolution or ClassResult whose
// "resolution" field carries this value was resolved from the GitHub tags
// list rather than GitHub Releases, and is weaker evidence (see E3).
const resolutionTagFallback = "tag_fallback"

// notExtended reason codes for rules this package itself excludes, distinct
// from a citation drift class (which is used verbatim as the worstClass
// when the exclusion is E1: a citation not batch-attestable).
const (
	reasonScopeIncomplete        = "WORKLIST_SCOPE_INCOMPLETE"
	reasonTagFallbackBaseline    = "TAG_FALLBACK_BASELINE"
	reasonStaleBaseline          = "STALE_BASELINE"
	reasonLineBaselineUnverified = "RELEASE_LINE_BASELINE_UNVERIFIED"
	reasonRangedRule             = "RANGED_RULE_EXCLUDED"
	reasonMechanicalRule         = "MECHANICAL_RULE_EXCLUDED"
	reasonConsecutiveCycleCap    = "CONSECUTIVE_BATCH_CYCLE_CAP"
	reasonInactiveOrWithdrawn    = "EVIDENCE_NOT_ACTIVE"
	reasonCorpusMismatchProject  = "CORPUS_DIGEST_MISMATCH_IN_PROJECT"
	reasonUncoveredSource        = "SOURCE_WITHOUT_CITATION"
	reasonUnknownCitation        = "CITATION_WITHOUT_SOURCE"
	reasonDuplicateCitation      = "DUPLICATE_CITATION_FOR_SOURCE"
	reasonCitationCommitMismatch = "CITATION_COMMIT_DOES_NOT_MATCH_PINNED_SOURCE"
	reasonStaggerDeferred        = "STAGGER_DEFERRED"
	reasonNotLaterThanCurrent    = "NOT_LATER_THAN_CURRENT"
	reasonNotYetDue              = "NOT_YET_DUE"
	// reasonLatestBaselineNotAutomatable is automated mode only: a
	// citation compared with the repository's latest release rather than
	// with the newest release on its pinned tag's own release line. The
	// owner's approval of automated renewal covers byte-identical citations
	// on their release line only, so such a rule is left to a human
	// statement.
	reasonLatestBaselineNotAutomatable = "LATEST_BASELINE_NOT_AUTOMATABLE"
	// reasonReviewedOutsideChain is automated mode only: the rule's
	// reviewedAt in the prior pack is later than the chain head's
	// attestedAt, so its evidence dates were moved by something the chain
	// does not record. Automation never counts a review record, so the
	// rule is left to a human statement.
	reasonReviewedOutsideChain = "REVIEWED_OUTSIDE_STATEMENT_CHAIN"
)

// PrepareOptions names every input Prepare needs. It performs no I/O and
// makes no network access: every byte it reasons over is supplied by the
// caller.
type PrepareOptions struct {
	// WorklistRaw is the exact bytes of a retained "evidence repin"
	// worklist (see evidencerepin.Worklist).
	WorklistRaw []byte
	// PackName is PackCNCF or PackCommunity.
	PackName string
	// PackPath is this pack's rules.json path, exactly as it appears in
	// the worklist's Scope.RulePacks and each Citation/RuleVerdict's
	// RulePack field, so Prepare can select the citations and rule
	// verdicts belonging to this pack out of a worklist that may cover
	// more than one pack.
	PackPath string
	// PackRaw is the exact bytes of that same rules.json file.
	PackRaw []byte
	// Chain is this pack's signed statement chain (see Chain). Required:
	// pass a Chain with no entries for a pack with no attestation history.
	// Every rule's consecutive-batch-cycle count and the statement's
	// previousAttestationDigest are derived from it (see
	// deriveChainState), never taken from a caller-supplied value.
	Chain *Chain
	// Mode is ModeHuman (the default when empty) or ModeAutomated. It
	// decides the statement's signerRole and which renewal policy applies:
	// see evaluateEligibility, scheduleAutomated and checkRolePolicy.
	Mode string
	// Wave is the 1..7 stagger slot a human-mode batch renews into (see
	// SlotDate). It must be 0 in automated mode, which schedules each rule
	// into its own week instead (see scheduleAutomated).
	Wave int
	// AttestedAt is the instant this batch is being prepared, normally
	// "now" from the caller's clock. It must not be after Now.
	AttestedAt time.Time
	// Now is the caller's clock. Required: Prepare rejects an AttestedAt
	// later than Now, and a chain entry attested later than Now, so a
	// future-dated statement can never be prepared or built upon.
	Now time.Time
	// NextRevision is the new pack revision string for rules.next.json.
	NextRevision string
	// EngineCapabilityDigest identifies the compiled engine this batch was
	// prepared against (see PackRef.EngineCapabilityDigest). The caller
	// supplies it so this package stays decoupled from cncfcheck/
	// projectcheck and stays testable with synthetic packs.
	EngineCapabilityDigest string
	// ReviewRecords maps a rule ID to the exact bytes of its individual
	// review record (maintainer/reviewrecord's format), when one has been
	// produced for it. A record whose digest the chain has not recorded
	// for that rule before must pass chainState.reviewsFromRecords' checks
	// or Prepare fails; a record that does is a new individual review: it
	// is listed in the statement's individualReviews and resets the rule's
	// consecutive-batch-cycle count. A sampled rule with no new review
	// record gets an empty reviewRecordDigest in the statement, which Sign
	// refuses to sign.
	ReviewRecords map[string][]byte
}

// PrepareResult is everything Prepare produces.
type PrepareResult struct {
	Statement            Statement
	StatementCanonical   []byte
	NextPack             []byte
	Summary              []byte
	EligibleRuleCount    int
	SampledRuleCount     int
	NotExtendedRuleCount int
}

// ruleCandidate is one pack rule joined with its own citation results, for
// eligibility evaluation. It deliberately does not carry the worklist's own
// per-rule RuleVerdict: eligibility is recomputed directly from Citations
// against Fields.Evidence.Sources (see evaluateEligibility), never taken
// from that rolled-up verdict.
type ruleCandidate struct {
	RuleID    string
	Project   string
	Raw       json.RawMessage
	Fields    ruleFields
	Citations []evidencerepin.ClassResult
}

// matchesPack requires an exact match against the RulePack path as it
// appears in the worklist. A worklist commonly covers more than one pack
// (e.g. the CNCF and community packs together), and both files are
// conventionally named rules.json, so matching by base name alone would
// silently conflate two different packs' citations; the caller must supply
// the worklist's own path string (PrepareOptions.PackPath /
// VerifyOptions.PackPath) when it differs from the on-disk path being read.
func matchesPack(rulePackField, wantPath string) bool {
	return rulePackField == wantPath
}

// Prepare computes batch re-attestation eligibility from a retained
// worklist and the current rule pack, and renders the canonical statement,
// the candidate next pack, and a deterministic human summary. It never
// declares eligibility; every rule's inclusion is recomputed here from the
// worklist and pack bytes the caller supplied.
func Prepare(opts PrepareOptions) (PrepareResult, error) {
	if opts.Now.IsZero() {
		return PrepareResult{}, fmt.Errorf("%w: the caller's current time is required", ErrRejected)
	}
	if opts.AttestedAt.After(opts.Now) {
		return PrepareResult{}, fmt.Errorf("%w: attestedAt is in the future", ErrRejected)
	}
	state, err := deriveChainState(opts.Chain, opts.PackName, opts.Now.UTC(), "")
	if err != nil {
		return PrepareResult{}, err
	}
	return prepareWithChain(opts, state)
}

// prepareWithChain is Prepare after the chain has been derived. Verify
// calls it directly with the chain state it derived itself, so Prepare and
// Verify always reason over the same chain derivation.
func prepareWithChain(opts PrepareOptions, state chainState) (PrepareResult, error) {
	if opts.PackName != PackCNCF && opts.PackName != PackCommunity {
		return PrepareResult{}, fmt.Errorf("%w: unknown pack", ErrRejected)
	}
	role, err := roleForMode(opts.Mode)
	if err != nil {
		return PrepareResult{}, err
	}
	automated := role == RoleAutomation
	if automated && opts.Wave != 0 {
		return PrepareResult{}, fmt.Errorf("%w: automated mode takes no wave", ErrRejected)
	}
	if !automated && (opts.Wave < minWave || opts.Wave > maxWave) {
		return PrepareResult{}, fmt.Errorf("%w: wave out of range", ErrRejected)
	}
	if opts.PackPath == "" || opts.NextRevision == "" || opts.EngineCapabilityDigest == "" {
		return PrepareResult{}, fmt.Errorf("%w: missing required option", ErrRejected)
	}
	attestedAt := opts.AttestedAt.UTC()

	if len(opts.WorklistRaw) == 0 || len(opts.WorklistRaw) > MaxWorklistBytes {
		return PrepareResult{}, fmt.Errorf("%w: worklist size rejected", ErrRejected)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(opts.WorklistRaw, &wl); err != nil || (wl.Schema != evidencerepin.Schema && wl.Schema != evidencerepin.SchemaV1) {
		return PrepareResult{}, fmt.Errorf("%w: decode worklist", ErrRejected)
	}
	// Automated mode needs the baseline records a v1 worklist predates.
	if automated && wl.Schema != evidencerepin.Schema {
		return PrepareResult{}, fmt.Errorf("%w: automated mode requires a current-schema worklist", ErrRejected)
	}
	worklistDigest := sourcecorpus.SHA(opts.WorklistRaw)

	doc, err := loadPack(opts.PackRaw)
	if err != nil {
		return PrepareResult{}, err
	}
	priorPackDigest := packDigest(opts.PackRaw)
	priorRuleSetDigest, err := ruleSetDigest(doc)
	if err != nil {
		return PrepareResult{}, err
	}

	var validUntilAt time.Time
	if automated {
		validUntilAt, err = automatedHorizon(attestedAt)
	} else {
		validUntilAt, err = SlotDate(opts.Wave, attestedAt)
	}
	if err != nil {
		return PrepareResult{}, err
	}
	validUntil := validUntilAt.Format(time.RFC3339)
	attestedAtString := attestedAt.Format(time.RFC3339)

	// E2 is a single worklist-wide gate: an incompletely scoped or still-
	// pending worklist disqualifies every rule, not just the ones it
	// happens to touch. Pending is counted directly from this pack's own
	// citations, never taken from the worklist's self-reported
	// Summary.Pending, which a caller could hand-edit independently of the
	// citations it actually carries.
	pendingCount := 0
	for _, citation := range wl.Citations {
		if matchesPack(citation.RulePack, opts.PackPath) && citation.Class == evidencerepin.ClassPending {
			pendingCount++
		}
	}
	e2ok := pendingCount == 0 && len(wl.Scope.Projects) == 0 && wl.Scope.Limit == 0
	// E4's worklist-wide half: this run's own age relative to attestedAt.
	generatedAt, genErr := time.Parse(time.RFC3339, wl.GeneratedAt)
	e4worklist := genErr == nil && !attestedAt.Before(generatedAt) && !attestedAt.After(generatedAt.Add(freshnessBound))

	// A v1 worklist predates baselines: every citation in it was compared
	// with the latest release and carries no release-line record.
	lines := wl.Lines
	repoByKey := map[string]evidencerepin.RepoResolution{}
	for _, repo := range wl.Repos {
		repoByKey[repo.Owner+"/"+repo.Repo] = repo
	}

	citationsByRule := map[string][]evidencerepin.ClassResult{}
	mismatchProjects := map[string]bool{}
	for _, citation := range wl.Citations {
		if !matchesPack(citation.RulePack, opts.PackPath) {
			continue
		}
		citationsByRule[citation.RuleID] = append(citationsByRule[citation.RuleID], citation)
		if citation.Class == evidencerepin.ClassCorpusDigestMismatch {
			mismatchProjects[citation.Project] = true
		}
	}
	candidates, priorRules, err := packCandidates(doc)
	if err != nil {
		return PrepareResult{}, err
	}
	for i := range candidates {
		candidates[i].Citations = citationsByRule[candidates[i].RuleID]
	}

	// Chain-derived per-rule state: which supplied review records are new
	// individual reviews, and each rule's consecutive-batch-cycle count.
	//
	// An automated statement never counts a review record: no person signs
	// it, and a record is only a maintainer's unauthenticated declaration.
	records := opts.ReviewRecords
	if automated {
		records = nil
	}
	fresh, err := state.reviewsFromRecords(candidatesByID(candidates), records, attestedAt)
	if err != nil {
		return PrepareResult{}, err
	}
	outsideChain, err := state.checkPriorPackCovered(priorRules, fresh, automated)
	if err != nil {
		return PrepareResult{}, err
	}

	var eligibleIDs []string
	eligible := map[string]bool{}
	notExtended := make([]NotExtendedEntry, 0)
	ruleAttestations := map[string]RuleAttestation{}

	for _, candidate := range candidates {
		if outsideChain[candidate.RuleID] {
			notExtended = append(notExtended, NotExtendedEntry{RuleID: candidate.RuleID, WorstClass: reasonReviewedOutsideChain})
			continue
		}
		_, reviewedNow := fresh[candidate.RuleID]
		cycles := state.expectedCycles(candidate.RuleID, reviewedNow)
		reason, ok := evaluateEligibility(candidate, e2ok, e4worklist, attestedAt, repoByKey, lines, mismatchProjects, cycles, automated)
		if !ok {
			notExtended = append(notExtended, NotExtendedEntry{RuleID: candidate.RuleID, WorstClass: reason})
			continue
		}
		eligibleIDs = append(eligibleIDs, candidate.RuleID)
	}

	// A renewal must move validUntil later: an otherwise eligible rule
	// whose current validUntil is not before this batch's slot date is
	// not renewed (NOT_LATER_THAN_CURRENT), and neither is one whose lease
	// still runs for longer than the renewal window (NOT_YET_DUE). V7
	// then caps the batch so the slot week stays within the stagger cap:
	// the remaining rules are taken soonest-expiring first, then by rule
	// ID, and the rest are deferred to a later wave.
	//
	// Automated mode schedules each rule into its own week instead (see
	// scheduleAutomated), under the same V7 cap.
	var chosen, notLater, notDue, deferred []string
	ruleValidUntil := map[string]time.Time{}
	if automated {
		ruleValidUntil, notLater, notDue, deferred, err = scheduleAutomated(candidates, eligibleIDs, attestedAt)
		for id := range ruleValidUntil {
			chosen = append(chosen, id)
		}
	} else {
		chosen, notLater, notDue, deferred, err = staggerBatch(candidates, eligibleIDs, attestedAt, validUntilAt)
		for _, id := range chosen {
			ruleValidUntil[id] = validUntilAt
		}
	}
	if err != nil {
		return PrepareResult{}, err
	}
	for _, id := range notLater {
		notExtended = append(notExtended, NotExtendedEntry{RuleID: id, WorstClass: reasonNotLaterThanCurrent})
	}
	for _, id := range notDue {
		notExtended = append(notExtended, NotExtendedEntry{RuleID: id, WorstClass: reasonNotYetDue})
	}
	for _, id := range deferred {
		notExtended = append(notExtended, NotExtendedEntry{RuleID: id, WorstClass: reasonStaggerDeferred})
	}
	eligibleIDs = chosen
	for _, id := range eligibleIDs {
		eligible[id] = true
	}
	sort.Strings(eligibleIDs)

	// The seeded sample is the human path's audit; an automated statement
	// has none (see checkSampleReviewed).
	sampleSize := int(math.Ceil(sampleFraction * float64(len(eligibleIDs))))
	if automated {
		sampleSize = 0
	}
	sampled := sampleRuleIDs(worklistDigest, eligibleIDs, sampleSize)
	sampledSet := map[string]bool{}
	for _, id := range sampled {
		sampledSet[id] = true
	}

	candidateByID := candidatesByID(candidates)

	nextDoc := doc
	nextDoc.Revision = opts.NextRevision
	repoTags := map[string]map[string]bool{}
	for i := range nextDoc.Entries {
		fields, _ := parseRuleFields(nextDoc.Entries[i].Rule)
		if !eligible[fields.ID] {
			continue
		}
		candidate := candidateByID[fields.ID]
		renewedUntil := ruleValidUntil[fields.ID].Format(time.RFC3339)
		mutated, err := mutateRuleEvidenceDates(nextDoc.Entries[i].Rule, attestedAtString, renewedUntil)
		if err != nil {
			return PrepareResult{}, err
		}
		nextDoc.Entries[i].Rule = mutated

		priorRuleDigest, _, sourcesDigest, err := ruleDigestAndEvidence(candidate.Raw)
		if err != nil {
			return PrepareResult{}, err
		}
		nextRuleDigest, _, nextSourcesDigest, err := ruleDigestAndEvidence(mutated)
		if err != nil {
			return PrepareResult{}, err
		}
		if sourcesDigest != nextSourcesDigest {
			return PrepareResult{}, fmt.Errorf("%w: sources digest changed under mutation", ErrRejected)
		}

		contentDigestBySource := map[string]string{}
		for _, source := range candidate.Fields.Evidence.Sources {
			contentDigestBySource[source.ID] = source.ContentDigest
		}
		citations := citationsByRule[fields.ID]
		sort.Slice(citations, func(i, j int) bool { return citations[i].SourceID < citations[j].SourceID })
		citationAttestations := make([]CitationAttestation, 0, len(citations))
		for _, c := range citations {
			repo := repoByKey[c.Owner+"/"+c.Repo]
			attestation := CitationAttestation{
				SourceID: c.SourceID, Class: c.Class, PinnedCommit: c.OldCommit,
				ComparedTag: repo.CurrentTag, ComparedCommit: c.NewCommit, ContentDigest: contentDigestBySource[c.SourceID],
			}
			if c.Baseline == evidencerepin.BaselineReleaseLine {
				attestation.ComparedTag = c.BaselineTag
				attestation.Baseline = c.Baseline
				attestation.BaselineLine = c.BaselineLine
				attestation.PinnedTag = c.PinnedTag
			}
			citationAttestations = append(citationAttestations, attestation)
			if attestation.ComparedTag != "" {
				repoName := c.Owner + "/" + c.Repo
				if repoTags[repoName] == nil {
					repoTags[repoName] = map[string]bool{}
				}
				repoTags[repoName][attestation.ComparedTag] = true
			}
		}

		_, reviewedNow := fresh[fields.ID]
		ra := RuleAttestation{
			RuleID: fields.ID, Project: candidate.Project,
			PriorRuleDigest: priorRuleDigest, NextRuleDigest: nextRuleDigest, SourcesDigest: sourcesDigest,
			PriorReviewedAt:        fields.Evidence.ReviewedAt,
			LastIndividualReviewAt: state.expectedLastReview(fields.ID, reviewedNow, attestedAtString, fields.Evidence.ReviewedAt),
			ConsecutiveBatchCycles: state.expectedCycles(fields.ID, reviewedNow), Citations: citationAttestations,
		}
		if automated {
			ra.ValidUntil = renewedUntil
		}
		ruleAttestations[fields.ID] = ra
	}

	rules := make([]RuleAttestation, 0, len(eligibleIDs))
	for _, id := range eligibleIDs {
		rules = append(rules, ruleAttestations[id])
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	sort.Slice(notExtended, func(i, j int) bool { return notExtended[i].RuleID < notExtended[j].RuleID })

	sampledEntries := make([]SampledEntry, 0, len(sampled))
	for _, id := range sampled {
		// Only a new individual review satisfies the sample: a record the
		// chain already counted once for this rule leaves the entry empty.
		sampledEntries = append(sampledEntries, SampledEntry{RuleID: id, ReviewRecordDigest: fresh[id]})
	}
	sort.Slice(sampledEntries, func(i, j int) bool { return sampledEntries[i].RuleID < sampledEntries[j].RuleID })

	individualReviews := make([]IndividualReview, 0, len(fresh))
	for id, digest := range fresh {
		individualReviews = append(individualReviews, IndividualReview{RuleID: id, ReviewRecordDigest: digest})
	}
	sort.Slice(individualReviews, func(i, j int) bool { return individualReviews[i].RuleID < individualReviews[j].RuleID })

	releases := make([]UpstreamRelease, 0, len(repoTags))
	for repo, tagSet := range repoTags {
		tags := make([]string, 0, len(tagSet))
		for tag := range tagSet {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		releases = append(releases, UpstreamRelease{Repo: repo, Tags: tags})
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Repo < releases[j].Repo })

	nextPackRaw, err := buildNextPack(nextDoc)
	if err != nil {
		return PrepareResult{}, err
	}
	nextPackDigestValue := packDigest(nextPackRaw)
	nextRuleSetDigestValue, err := ruleSetDigest(nextDoc)
	if err != nil {
		return PrepareResult{}, err
	}

	var previousDigest *string
	if state.headDigest != nil {
		digestValue := *state.headDigest
		previousDigest = &digestValue
	}

	authority, text, wave := Authority, FixedStatementText(wl.GeneratedAt, validUntil), opts.Wave
	if automated {
		authority, text, wave = AuthorityAutomated, AutomatedStatementText(wl.GeneratedAt, validUntil), 0
	}
	statement := Statement{
		Schema: StatementSchema, Purpose: Purpose, Audience: Audience, Authority: authority, SignerRole: role,
		Pack: PackRef{
			Name: opts.PackName, Schema: doc.Schema, PolicyID: doc.PolicyID, PolicyDigest: doc.PolicyDigest,
			EngineCapabilityDigest: opts.EngineCapabilityDigest,
			Prior:                  PackVersion{Revision: doc.Revision, PackDigest: priorPackDigest, RuleSetDigest: priorRuleSetDigest},
			Next:                   PackVersion{Revision: opts.NextRevision, PackDigest: nextPackDigestValue, RuleSetDigest: nextRuleSetDigestValue},
		},
		PreviousAttestationDigest: previousDigest,
		Worklist: WorklistRef{
			Schema: wl.Schema, Digest: worklistDigest, GeneratedAt: wl.GeneratedAt,
			OldestRepoResolvedAt: wl.Summary.OldestResolvedAt, Pending: wl.Summary.Pending,
			ToolIdentityDigest: toolIdentityDigest(),
		},
		Wave: wave, AttestedAt: attestedAtString, ValidUntil: validUntil,
		Rules: rules, SampledForFullReview: sampledEntries, IndividualReviews: individualReviews, NotExtended: notExtended,
		UpstreamReleasesSincePrior: releases,
		Statement:                  text,
	}
	canonical, err := CanonicalStatement(statement)
	if err != nil {
		return PrepareResult{}, err
	}
	if _, err := ParseStatement(canonical); err != nil {
		return PrepareResult{}, fmt.Errorf("%w: statement failed self-verification", ErrRejected)
	}
	// Self-check against the same V5 and V7 definitions Verify applies, so
	// Prepare never emits a statement Verify rejects for those reasons.
	selfCheck := state.clone()
	if err := selfCheck.apply(statement); err != nil {
		return PrepareResult{}, fmt.Errorf("%w: statement failed chain self-check: %v", ErrRejected, err)
	}
	nextByID, err := rulesByID(nextDoc)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := checkV7(statement, nextByID); err != nil {
		return PrepareResult{}, fmt.Errorf("%w: statement failed stagger self-check: %v", ErrRejected, err)
	}
	if err := checkRolePolicy(statement, candidateByID); err != nil {
		return PrepareResult{}, fmt.Errorf("%w: statement failed role-policy self-check: %v", ErrRejected, err)
	}

	summary := renderSummary(statement, opts, doc.Entries)

	return PrepareResult{
		Statement: statement, StatementCanonical: canonical, NextPack: nextPackRaw, Summary: summary,
		EligibleRuleCount: len(rules), SampledRuleCount: len(sampledEntries), NotExtendedRuleCount: len(notExtended),
	}, nil
}

// evaluateEligibility checks E1-E7 for one rule and returns the worst
// (highest-priority) failure reason when ineligible. consecutiveCycles is
// the count the chain derivation assigns the rule if it is renewed now
// (see chainState.expectedCycles).
func evaluateEligibility(
	candidate ruleCandidate, e2ok, e4worklist bool, attestedAt time.Time,
	repoByKey map[string]evidencerepin.RepoResolution, lines []evidencerepin.LineResolution, mismatchProjects map[string]bool,
	consecutiveCycles int, automated bool,
) (string, bool) {
	if !e2ok {
		return reasonScopeIncomplete, false
	}

	// A reviewer's reattestation renews only evidence a person interpreted.
	// A rule derived from source by an extractor carries no such review to
	// extend: its lease is renewed by re-deriving it, so it is never renewed
	// here, however unchanged its citations are.
	if candidate.Fields.isMechanical() {
		return reasonMechanicalRule, false
	}

	// E1 is recomputed here from the citations themselves; the worklist's
	// own BatchEligible/WorstClass verdict is never trusted (a caller could
	// hand the worklist's rollup independently of what its citations
	// actually say). The set of citation SourceIDs must equal the rule's
	// evidence.sources[].id set exactly, one citation per source, and each
	// citation must classify as mechanically unchanged, fresh, resolved
	// through Releases (not the tags fallback), and pinned to the exact
	// commit the source itself declares.
	if len(candidate.Fields.Evidence.Sources) == 0 {
		return reasonUncoveredSource, false
	}
	citationsBySource := map[string][]evidencerepin.ClassResult{}
	for _, citation := range candidate.Citations {
		citationsBySource[citation.SourceID] = append(citationsBySource[citation.SourceID], citation)
	}
	sourceIDs := map[string]bool{}
	for _, source := range candidate.Fields.Evidence.Sources {
		sourceIDs[source.ID] = true
		matches := citationsBySource[source.ID]
		if len(matches) == 0 {
			return reasonUncoveredSource, false
		}
		if len(matches) > 1 {
			return reasonDuplicateCitation, false
		}
		citation := matches[0]
		if citation.Class != evidencerepin.ClassNoNewRelease && citation.Class != evidencerepin.ClassFileIdentical && citation.Class != evidencerepin.ClassSpanIdentical {
			return citation.Class, false
		}
		if citation.Stale {
			return reasonStaleBaseline, false
		}
		if citation.Resolution == resolutionTagFallback {
			return reasonTagFallbackBaseline, false
		}
		if citation.OldCommit != source.Revision {
			return reasonCitationCommitMismatch, false
		}
		// A release-line baseline is never weaker than the latest-release
		// baseline: it must also carry a mutually consistent pinned tag,
		// line and compared tag, and it must be backed by a worklist line
		// record that resolved this very tag and commit.
		switch citation.Baseline {
		case "", evidencerepin.BaselineLatest:
			// The owner's approval of automated renewal covers a citation
			// whose cited commit is byte-identical on its own release
			// line only; a comparison with the repository's latest
			// release is left to a human statement.
			if automated {
				return reasonLatestBaselineNotAutomatable, false
			}
		case evidencerepin.BaselineReleaseLine:
			if !lineBaselineVerified(citation, lines) {
				return reasonLineBaselineUnverified, false
			}
		default:
			return reasonLineBaselineUnverified, false
		}
	}
	for sourceID := range citationsBySource {
		if !sourceIDs[sourceID] {
			return reasonUnknownCitation, false
		}
	}

	if !e4worklist {
		return reasonStaleBaseline, false
	}
	for _, citation := range candidate.Citations {
		repo, known := repoByKey[citation.Owner+"/"+citation.Repo]
		if !known {
			return reasonStaleBaseline, false
		}
		// A repository resolved from a mirror is as old as the mirror's own
		// last look at it, not as old as the run that read the mirror.
		resolvedAt, ok := repo.EvidenceAt()
		if !ok || repo.Stale || attestedAt.Before(resolvedAt) || attestedAt.Sub(resolvedAt) > freshnessBound {
			return reasonStaleBaseline, false
		}
		if citation.Baseline == evidencerepin.BaselineReleaseLine {
			line, _ := matchingLine(citation, lines)
			lineResolvedAt, ok := line.EvidenceAt()
			if !ok || line.Stale || attestedAt.Before(lineResolvedAt) || attestedAt.Sub(lineResolvedAt) > freshnessBound {
				return reasonStaleBaseline, false
			}
		}
	}
	if hasRange(candidate.Fields.Range) {
		return reasonRangedRule, false
	}
	if consecutiveCycles > maxConsecutiveBatchCycles {
		return reasonConsecutiveCycleCap, false
	}
	if candidate.Fields.Evidence.State != "active" {
		return reasonInactiveOrWithdrawn, false
	}
	if mismatchProjects[candidate.Project] {
		return reasonCorpusMismatchProject, false
	}
	return "", true
}

// matchingLine finds the worklist line record a release-line citation's
// baseline must be backed by: same repository and line, resolved, and
// naming exactly the compared tag and commit.
func matchingLine(citation evidencerepin.ClassResult, lines []evidencerepin.LineResolution) (evidencerepin.LineResolution, bool) {
	for _, line := range lines {
		if line.Owner == citation.Owner && line.Repo == citation.Repo && line.Line == citation.BaselineLine &&
			line.Status == "RESOLVED" && line.Tag == citation.BaselineTag && line.Commit == citation.NewCommit && line.Commit != "" {
			return line, true
		}
	}
	return evidencerepin.LineResolution{}, false
}

func lineBaselineVerified(citation evidencerepin.ClassResult, lines []evidencerepin.LineResolution) bool {
	if citation.PinnedTag == "" || citation.BaselineTag == "" || citation.BaselineLine == "" || citation.NewCommit == "" {
		return false
	}
	if !evidencerepin.LineBaselineConsistent(citation.PinnedTag, citation.BaselineTag, citation.BaselineLine) {
		return false
	}
	_, ok := matchingLine(citation, lines)
	return ok
}

// staggerCap is V7's per-week cap for a pack of total rules:
// floor(staggerCapPercent% of total), and never less than one.
func staggerCap(total int) int {
	weekCap := total * staggerCapPercent / 100
	if weekCap < 1 {
		weekCap = 1
	}
	return weekCap
}

func isoWeek(t time.Time) string {
	year, week := t.UTC().ISOWeek()
	return fmt.Sprintf("%04d-W%02d", year, week)
}

// staggerBatch selects which eligible rules this batch renews. A rule is
// renewed only if the batch's slot date is strictly later than its current
// validUntil (otherwise it is returned in notLater), so a renewal never
// moves a rule's validUntil earlier or leaves it unchanged; and only if its
// current validUntil is no more than renewalWindow after attestedAt
// (otherwise it is returned in notDue), so a rule renewed recently is not
// picked again, spending its consecutive-batch-cycle budget, while most of
// its lease is still left. The remaining rules are capped so the ISO week
// of slot holds no more than staggerCap(len(candidates)) validUntil values
// once the batch is applied: they are ordered by how soon they expire
// relative to slot (earliest current validUntil first), then rule ID, and
// taken in that order while they fit; the first one that does not fit,
// and every one after it, is deferred. A rule whose current validUntil
// already falls in the slot week does not add to the count.
func staggerBatch(candidates []ruleCandidate, eligibleIDs []string, attestedAt, slot time.Time) (chosen, notLater, notDue, deferred []string, err error) {
	slotWeek := isoWeek(slot)
	weekCap := staggerCap(len(candidates))
	current := map[string]time.Time{}
	inWeek := 0
	for _, candidate := range candidates {
		validUntil, err := parseUTC(candidate.Fields.Evidence.ValidUntil)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%w: V7: rule %s validUntil", ErrRejected, candidate.RuleID)
		}
		current[candidate.RuleID] = validUntil
		if isoWeek(validUntil) == slotWeek {
			inWeek++
		}
	}
	ordered := make([]string, 0, len(eligibleIDs))
	for _, id := range eligibleIDs {
		switch {
		case !slot.After(current[id]):
			notLater = append(notLater, id)
		case current[id].Sub(attestedAt) > renewalWindow:
			notDue = append(notDue, id)
		default:
			ordered = append(ordered, id)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := slot.Sub(current[ordered[i]]), slot.Sub(current[ordered[j]])
		if a != b {
			return a > b
		}
		return ordered[i] < ordered[j]
	})
	for i, id := range ordered {
		add := 1
		if isoWeek(current[id]) == slotWeek {
			add = 0
		}
		if inWeek+add > weekCap {
			return chosen, notLater, notDue, ordered[i:], nil
		}
		inWeek += add
		chosen = append(chosen, id)
	}
	return chosen, notLater, notDue, nil, nil
}

// slotPreference is a rule's preferred index among n automated slots:
// sha256 of a fixed domain and the rule ID, read as a big-endian integer,
// modulo n. It depends on nothing but the rule ID, so rules spread over
// the slots independently of pack order and of each other.
func slotPreference(ruleID string, n int) int {
	sum := sha256.Sum256([]byte(automatedSlotDomain + ruleID))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

// scheduleAutomated is automated mode's replacement for wave slots: it
// picks each renewed rule's own new validUntil among AutomatedSlots(
// attestedAt), so daily automated runs spread validUntil values over the
// weeks of the lease window instead of piling one wave's rules into one
// week.
//
// The rules considered are the eligible ones that are due: a rule whose
// current validUntil is further than renewalWindow from attestedAt is not
// yet due (notDue), exactly as in human mode. They are placed one at a
// time, soonest-expiring first, then by rule ID. Each rule starts at its
// own preferred slot (slotPreference) and takes the first slot, going
// later and wrapping around to the earliest, whose ISO week stays within
// the V7 cap counting every rule's validUntil as it will be in the next
// pack. A rule no slot accepts is deferred. An eligible rule whose current
// validUntil is not before the latest slot is notLater (checked first, as
// in human mode); every slot is later than a due rule's current
// validUntil, so a renewal always moves validUntil later. The result is a pure
// function of the pack's rules, the eligible IDs and attestedAt, so Verify
// recomputes it identically.
func scheduleAutomated(candidates []ruleCandidate, eligibleIDs []string, attestedAt time.Time) (chosen map[string]time.Time, notLater, notDue, deferred []string, err error) {
	slots := AutomatedSlots(attestedAt)
	if len(slots) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("%w: no automated slot", ErrRejected)
	}
	weekCap := staggerCap(len(candidates))
	current := map[string]time.Time{}
	counts := map[string]int{}
	for _, candidate := range candidates {
		validUntil, err := parseUTC(candidate.Fields.Evidence.ValidUntil)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%w: V7: rule %s validUntil", ErrRejected, candidate.RuleID)
		}
		current[candidate.RuleID] = validUntil
		counts[isoWeek(validUntil)]++
	}
	ordered := make([]string, 0, len(eligibleIDs))
	for _, id := range eligibleIDs {
		switch {
		case !slots[len(slots)-1].After(current[id]):
			notLater = append(notLater, id)
		case current[id].Sub(attestedAt) > renewalWindow:
			notDue = append(notDue, id)
		default:
			ordered = append(ordered, id)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := current[ordered[i]], current[ordered[j]]
		if !a.Equal(b) {
			return a.Before(b)
		}
		return ordered[i] < ordered[j]
	})
	chosen = map[string]time.Time{}
	for _, id := range ordered {
		start := slotPreference(id, len(slots))
		placed := false
		for k := 0; k < len(slots); k++ {
			// Every slot is later than any due rule's current validUntil:
			// slots start more than automatedMinLease after attestedAt,
			// and a due rule's lease ends within renewalWindow of it.
			slot := slots[(start+k)%len(slots)]
			oldWeek, newWeek := isoWeek(current[id]), isoWeek(slot)
			if oldWeek != newWeek && counts[newWeek]+1 > weekCap {
				continue
			}
			counts[oldWeek]--
			counts[newWeek]++
			chosen[id] = slot
			placed = true
			break
		}
		if !placed {
			deferred = append(deferred, id)
		}
	}
	return chosen, notLater, notDue, deferred, nil
}

// packCandidates parses every rule in doc into a ruleCandidate (without
// citations), sorted by rule ID, and also returns the rules' typed fields
// in pack order.
func packCandidates(doc packDocument) ([]ruleCandidate, []ruleFields, error) {
	candidates := make([]ruleCandidate, 0, len(doc.Entries))
	priorRules := make([]ruleFields, 0, len(doc.Entries))
	for _, entry := range doc.Entries {
		fields, err := parseRuleFields(entry.Rule)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, ruleCandidate{RuleID: fields.ID, Project: entry.Project, Raw: entry.Rule, Fields: fields})
		priorRules = append(priorRules, fields)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].RuleID < candidates[j].RuleID })
	return candidates, priorRules, nil
}

func candidatesByID(candidates []ruleCandidate) map[string]ruleCandidate {
	byID := make(map[string]ruleCandidate, len(candidates))
	for _, c := range candidates {
		byID[c.RuleID] = c
	}
	return byID
}

func hasRange(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

// sampleRuleIDs implements the seeded 10% audit: sort
// eligible rule IDs by sha256(worklistDigest || ruleId) and take the first
// sampleSize. The seed is entirely a function of inputs the maintainer does
// not control after the fact (the worklist digest and the rule IDs
// themselves), so the sample cannot be chosen or predicted before repin
// runs.
func sampleRuleIDs(worklistDigest string, eligibleIDs []string, sampleSize int) []string {
	if sampleSize <= 0 || len(eligibleIDs) == 0 {
		return nil
	}
	if sampleSize > len(eligibleIDs) {
		sampleSize = len(eligibleIDs)
	}
	type keyed struct {
		id  string
		key string
	}
	keys := make([]keyed, 0, len(eligibleIDs))
	for _, id := range eligibleIDs {
		keys = append(keys, keyed{id: id, key: sourcecorpus.SHA([]byte(worklistDigest + id))})
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].key != keys[j].key {
			return keys[i].key < keys[j].key
		}
		return keys[i].id < keys[j].id
	})
	out := make([]string, 0, sampleSize)
	for i := 0; i < sampleSize; i++ {
		out = append(out, keys[i].id)
	}
	sort.Strings(out)
	return out
}

func renderSummary(statement Statement, opts PrepareOptions, entries []packEntryDoc) []byte {
	byProject := map[string][]string{}
	for _, ra := range statement.Rules {
		byProject[ra.Project] = append(byProject[ra.Project], ra.RuleID)
	}
	projects := make([]string, 0, len(byProject))
	for project := range byProject {
		projects = append(projects, project)
	}
	sort.Strings(projects)

	classCounts := map[string]int{}
	for _, ne := range statement.NotExtended {
		classCounts[ne.WorstClass]++
	}
	classes := make([]string, 0, len(classCounts))
	for class := range classCounts {
		classes = append(classes, class)
	}
	sort.Strings(classes)

	digest, _ := CanonicalStatement(statement)
	statementDigest := sourcecorpus.SHA(digest)

	var b strings.Builder
	fmt.Fprintf(&b, "pack: %s\n", statement.Pack.Name)
	role, _ := statementRole(statement)
	fmt.Fprintf(&b, "signer role: %s\n", role)
	fmt.Fprintf(&b, "prior revision: %s (packDigest %s)\n", statement.Pack.Prior.Revision, statement.Pack.Prior.PackDigest)
	fmt.Fprintf(&b, "next revision: %s (packDigest %s)\n", statement.Pack.Next.Revision, statement.Pack.Next.PackDigest)
	fmt.Fprintf(&b, "eligible: %d, sampled for full review: %d, not extended: %d, total rules in pack: %d\n",
		len(statement.Rules), len(statement.SampledForFullReview), len(statement.NotExtended), len(entries))
	fmt.Fprintf(&b, "not-extended breakdown:\n")
	for _, class := range classes {
		fmt.Fprintf(&b, "  %s: %d\n", class, classCounts[class])
	}
	fmt.Fprintf(&b, "extended rules by project:\n")
	for _, project := range projects {
		ids := byProject[project]
		sort.Strings(ids)
		fmt.Fprintf(&b, "  %s: %s\n", project, strings.Join(ids, ", "))
	}
	if role == RoleAutomation {
		fmt.Fprintf(&b, "per-rule validUntil (automated schedule):\n")
		for _, ra := range statement.Rules {
			fmt.Fprintf(&b, "  %s: %s\n", ra.RuleID, ra.ValidUntil)
		}
	}
	fmt.Fprintf(&b, "sampled for full review (must be individually reviewed before signing):\n")
	for _, s := range statement.SampledForFullReview {
		status := "MISSING REVIEW RECORD"
		if s.ReviewRecordDigest != "" {
			status = s.ReviewRecordDigest
		}
		fmt.Fprintf(&b, "  %s: %s\n", s.RuleID, status)
	}
	fmt.Fprintf(&b, "new individual review records (each resets that rule's consecutive batch-cycle count):\n")
	for _, review := range statement.IndividualReviews {
		fmt.Fprintf(&b, "  %s: %s\n", review.RuleID, review.ReviewRecordDigest)
	}
	previous := "none (first statement in this pack's chain)"
	if statement.PreviousAttestationDigest != nil {
		previous = *statement.PreviousAttestationDigest
	}
	fmt.Fprintf(&b, "previous attestation: %s\n", previous)
	fmt.Fprintf(&b, "upstream releases since prior attestation (latest resolved release only; see docs):\n")
	for _, release := range statement.UpstreamReleasesSincePrior {
		fmt.Fprintf(&b, "  %s: %s\n", release.Repo, strings.Join(release.Tags, ", "))
	}
	fmt.Fprintf(&b, "attestedAt: %s\n", statement.AttestedAt)
	fmt.Fprintf(&b, "validUntil: %s\n", statement.ValidUntil)
	if role == RoleHuman {
		fmt.Fprintf(&b, "wave: %s\n", strconv.Itoa(statement.Wave))
	}
	fmt.Fprintf(&b, "statementDigest: %s\n", statementDigest)
	return []byte(b.String())
}
