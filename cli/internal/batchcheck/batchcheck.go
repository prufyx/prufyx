// SPDX-License-Identifier: AGPL-3.0-only

// Package batchcheck evaluates a bounded set of already prepared local inputs.
// It has no downloader, subprocess, network, or cluster capability. A declared
// mode may read one explicit signed local knowledge store after input preflight;
// current verification can advance that store's clock floor.
package batchcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const (
	PlanSchema    = "prufyx.io/batch-check-plan/v1alpha1"
	PlanAuthority = "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS"
	ReportSchema  = "prufyx.io/batch-check-report/v1alpha1"
	maxPlanBytes  = 256 << 10
	maxInputBytes = 1 << 20
	maxItems      = 64

	KnowledgeEmbeddedOnly                  = "embedded_only"
	KnowledgeExternalCNCFEmbeddedCommunity = "external_cncf_embedded_community"
)

var (
	ErrInvalid   = errors.New("invalid batch check request")
	ErrIntegrity = errors.New("batch check integrity failure")
	identifierRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionRE    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Plan struct {
	Schema    string             `json:"schema"`
	Authority string             `json:"authority"`
	Knowledge KnowledgeSelection `json:"knowledge"`
	Items     []Item             `json:"items"`
}

type KnowledgeSelection struct {
	Mode             string `json:"mode"`
	CNCF             string `json:"cncf,omitempty"`
	CommunityProject string `json:"communityProject,omitempty"`
}

type Item struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Project     string `json:"project"`
	From        string `json:"from"`
	To          string `json:"to"`
	InputPath   string `json:"inputPath"`
	InputDigest string `json:"inputDigest,omitempty"`
}

type ItemResult struct {
	ID string `json:"id"`
	// Position is the stable, non-sensitive item identity in the report. The
	// operator supplied plan label is deliberately not echoed.
	Position        int             `json:"position"`
	Kind            string          `json:"kind"`
	Project         string          `json:"project"`
	KnowledgeOrigin string          `json:"knowledgeOrigin"`
	Outcome         string          `json:"outcome"`
	Category        string          `json:"category"`
	ReasonCode      string          `json:"reasonCode"`
	Categories      []string        `json:"categories"`
	Report          json.RawMessage `json:"report,omitempty"`
	// age is set for an item evaluated against a selected store; not encoded.
	age *knowledgeage.Source
	// notes are the human-output lines an item's claims call for beyond its
	// outcome: the support-range note and any one-way notices with their
	// scope. They are not encoded; the sealed child report carries the claims.
	notes []string
}

// Notes returns the extra human-output lines of an item (see ItemResult.notes).
func (r ItemResult) Notes() []string { return append([]string(nil), r.notes...) }

type Report struct {
	Schema                      string       `json:"schema"`
	PlanDigest                  string       `json:"planDigest"`
	EvaluatedAt                 string       `json:"evaluatedAt"`
	KnowledgeMode               string       `json:"knowledgeMode"`
	KnowledgeRevision           string       `json:"knowledgeRevision,omitempty"`
	KnowledgeBundleDigest       string       `json:"knowledgeBundleDigest,omitempty"`
	KnowledgeTrustReceiptDigest string       `json:"knowledgeTrustReceiptDigest,omitempty"`
	NetworkUsed                 bool         `json:"networkUsed"`
	Decision                    string       `json:"decision"`
	AggregateCategory           string       `json:"aggregateCategory"`
	Items                       []ItemResult `json:"items"`
	// ages and embeddedCNCF describe the CNCF knowledge the items used. They
	// are not part of the report and are never encoded.
	ages         []knowledgeage.Source
	embeddedCNCF bool
}

// KnowledgeAge lists the end dates of the active rules of the CNCF
// knowledge the batch used from the selected store, and reports whether any
// item was evaluated against the embedded CNCF knowledge instead.
func (r Report) KnowledgeAge() (sources []knowledgeage.Source, embedded bool) {
	return append([]knowledgeage.Source(nil), r.ages...), r.embeddedCNCF
}

type loadedItem struct {
	item Item
	raw  []byte
}

type rootOpener func(string) (*os.File, error)

// knowledgeOpener opens the selected CNCF revision once per batch. projects
// names every CNCF project in the plan, so a per-project store reads only
// those project targets.
type knowledgeOpener func(knowledge.SelectionRequest, []string) (knowledge.VerifiedRevision, error)

// Evaluate validates the complete plan and all item files before evaluating
// any item. Paths are relative to root and are opened with no-follow checks.
func Evaluate(planPath, root string, now time.Time) (Report, int, error) {
	if now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return Report{}, 2, ErrInvalid
	}
	return evaluate(planPath, root, now, "", currentbundle.OpenDirectoryNoFollow, knowledge.OpenSelectedCNCF)
}

// EvaluateWithStore opens the selected signed CNCF revision once, after the
// complete plan and every input have passed local admission. Its verifier clock
// is used for every item in the batch; callers cannot supply --now in this mode.
func EvaluateWithStore(planPath, root, storeRoot string) (Report, int, error) {
	if storeRoot == "" {
		return Report{}, 2, ErrInvalid
	}
	return evaluate(planPath, root, time.Time{}, storeRoot, currentbundle.OpenDirectoryNoFollow, knowledge.OpenSelectedCNCF)
}

func evaluate(planPath, root string, now time.Time, storeRoot string, acquireRoot rootOpener, openKnowledge knowledgeOpener) (Report, int, error) {
	if root == "" || planPath == "" || acquireRoot == nil || openKnowledge == nil {
		return Report{}, 2, ErrInvalid
	}
	planRaw, err := currentbundle.ReadBoundedFile(planPath, maxPlanBytes)
	if err != nil {
		return Report{}, 2, ErrInvalid
	}
	var plan Plan
	if err := decodeStrict(planRaw, &plan); err != nil || !validPlan(plan) {
		return Report{}, 2, ErrInvalid
	}
	signed := plan.Knowledge.Mode == KnowledgeExternalCNCFEmbeddedCommunity
	if signed != (storeRoot != "") || !signed && (now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0) {
		return Report{}, 2, ErrInvalid
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return Report{}, 2, ErrInvalid
	}
	heldRoot, err := acquireRoot(rootAbs)
	if err != nil {
		return Report{}, 2, ErrInvalid
	}
	defer heldRoot.Close()
	loaded := make([]loadedItem, len(plan.Items))
	for i, item := range plan.Items {
		raw, readErr := currentbundle.ReadBoundedRelative(heldRoot, item.InputPath, maxInputBytes)
		if readErr != nil {
			if errors.Is(readErr, currentbundle.ErrIntegrity) {
				return Report{}, 3, ErrIntegrity
			}
			return Report{}, 2, ErrInvalid
		}
		if item.InputDigest != "" && digest(raw) != item.InputDigest {
			return Report{}, 3, ErrIntegrity
		}
		if !canonicalJSON(raw) || !canonicalBinding(item, raw) {
			return Report{}, 2, ErrInvalid
		}
		if item.Kind == "cncf" {
			if validationErr := cncfcheck.ValidateCanonicalInput(item.Project, raw); validationErr != nil {
				if errors.Is(validationErr, cncfcheck.ErrIntegrity) {
					return Report{}, 3, ErrIntegrity
				}
				return Report{}, 2, ErrInvalid
			}
		} else if validationErr := projectcheck.ValidateCanonicalInput(item.Project, raw); validationErr != nil {
			if errors.Is(validationErr, projectcheck.ErrIntegrity) {
				return Report{}, 3, ErrIntegrity
			}
			return Report{}, 2, ErrInvalid
		}
		loaded[i] = loadedItem{item: item, raw: raw}
	}
	var selected knowledge.VerifiedRevision
	if signed {
		selected, err = openKnowledge(knowledge.SelectionRequest{StoreRoot: storeRoot}, cncfProjects(plan))
		if err != nil {
			if errors.Is(err, knowledge.ErrNoSelection) {
				return Report{}, 11, err
			}
			return Report{}, 3, err
		}
		if !selected.Valid() || selected.Mode() != knowledge.SelectionCurrent {
			return Report{}, 3, ErrIntegrity
		}
		now = selected.VerifiedAt().UTC().Truncate(time.Second)
	}
	results := make([]ItemResult, 0, len(loaded))
	for _, current := range loaded {
		result := evaluateItem(current.item, current.raw, now, selected)
		result.Position = len(results) + 1
		result.ID = fmt.Sprintf("item-%03d", result.Position)
		results = append(results, result)
	}
	// Preserve plan order for positions, while aggregate selection is based on
	// fixed category precedence and is therefore order independent.
	category, exit := aggregate(results)
	report := Report{Schema: ReportSchema, PlanDigest: digest(planRaw), EvaluatedAt: now.Format(time.RFC3339), KnowledgeMode: plan.Knowledge.Mode, NetworkUsed: false, Decision: "UNKNOWN", AggregateCategory: category, Items: results}
	seen := map[string]bool{}
	for _, result := range results {
		switch {
		case result.age != nil && !seen[result.age.ID]:
			seen[result.age.ID] = true
			report.ages = append(report.ages, *result.age)
		case result.Kind == "cncf" && result.KnowledgeOrigin == "embedded":
			report.embeddedCNCF = true
		}
	}
	if signed {
		report.KnowledgeRevision = selected.Revision()
		report.KnowledgeBundleDigest = selected.BundleDigest()
		report.KnowledgeTrustReceiptDigest = selected.TrustReceiptDigest()
	}
	return report, exit, nil
}

func validPlan(plan Plan) bool {
	embedded := plan.Knowledge.Mode == KnowledgeEmbeddedOnly && plan.Knowledge.CNCF == "" && plan.Knowledge.CommunityProject == ""
	external := plan.Knowledge.Mode == KnowledgeExternalCNCFEmbeddedCommunity && plan.Knowledge.CNCF == "external_signed_local" && plan.Knowledge.CommunityProject == "embedded"
	if plan.Schema != PlanSchema || plan.Authority != PlanAuthority || (!embedded && !external) || len(plan.Items) == 0 || len(plan.Items) > maxItems {
		return false
	}
	seen := map[string]bool{}
	hasCNCF := false
	for _, item := range plan.Items {
		if !identifierRE.MatchString(item.ID) || seen[item.ID] || (item.Kind != "cncf" && item.Kind != "community_project") || !identifierRE.MatchString(item.Project) || !versionRE.MatchString(item.From) || !versionRE.MatchString(item.To) || item.From == item.To || !validRelativePath(item.InputPath) || item.InputDigest != "" && !digestRE.MatchString(item.InputDigest) {
			return false
		}
		seen[item.ID] = true
		if item.Kind == "cncf" {
			hasCNCF = true
			if _, err := cncfcheck.Component(item.Project); err != nil {
				return false
			}
			if embedded {
				catalogue, err := cncfcheck.Catalog(false, item.Project)
				if err != nil || len(catalogue.Projects) != 1 || catalogue.Projects[0].SourceRuleCount+catalogue.Projects[0].WithdrawnRuleCount == 0 {
					return false
				}
			}
		} else {
			projects, err := projectcheck.Projects()
			if err != nil || !contains(projects, item.Project) {
				return false
			}
		}
	}
	return embedded || hasCNCF
}

func canonicalJSON(raw []byte) bool {
	if !noDuplicateJSON(raw) {
		return false
	}
	var envelope struct {
		Schema    string          `json:"schema"`
		Authority string          `json:"authority"`
		Current   json.RawMessage `json:"current"`
		Proposed  json.RawMessage `json:"proposed"`
	}
	return decodeStrict(raw, &envelope) == nil && envelope.Schema == "prufyx.io/operator-declared-constraint-input/v1alpha1" && envelope.Authority == "OPERATOR_DECLARED_MINIMIZED" && len(envelope.Current) > 0 && len(envelope.Proposed) > 0
}

func canonicalBinding(item Item, raw []byte) bool {
	type component struct {
		Component string          `json:"component"`
		Version   string          `json:"version"`
		Facts     json.RawMessage `json:"facts"`
	}
	var envelope struct {
		Schema    string `json:"schema"`
		Authority string `json:"authority"`
		Current   struct {
			Components []component `json:"components"`
		} `json:"current"`
		Proposed struct {
			Components []component `json:"components"`
		} `json:"proposed"`
	}
	if decodeStrict(raw, &envelope) != nil || envelope.Schema != "prufyx.io/operator-declared-constraint-input/v1alpha1" || envelope.Authority != "OPERATOR_DECLARED_MINIMIZED" {
		return false
	}
	expected := ""
	var err error
	if item.Kind == "cncf" {
		expected, err = cncfcheck.Component(item.Project)
	} else {
		expected, err = projectcheck.Component(item.Project)
	}
	if err != nil {
		return false
	}
	find := func(components []component) (string, int) {
		version, matches := "", 0
		for _, candidate := range components {
			if candidate.Component == expected {
				version = candidate.Version
				matches++
			}
		}
		return version, matches
	}
	currentVersion, currentMatches := find(envelope.Current.Components)
	proposedVersion, proposedMatches := find(envelope.Proposed.Components)
	return currentMatches == 1 && proposedMatches == 1 && currentVersion == item.From && proposedVersion == item.To
}

func evaluateItem(item Item, raw []byte, now time.Time, selected knowledge.VerifiedRevision) ItemResult {
	result := ItemResult{Kind: item.Kind, Project: item.Project, KnowledgeOrigin: "embedded", Outcome: "UNKNOWN", Category: "UNKNOWN_CLAIM", ReasonCode: "EVALUATION_UNKNOWN", Categories: []string{"UNKNOWN_CLAIM"}}
	if item.Kind == "cncf" {
		if selected.Valid() {
			return evaluateExternalCNCF(result, item, raw, selected)
		}
		report, err := cncfcheck.Check(item.Project, raw, now)
		if err != nil {
			result.Category = "INTEGRITY_ERROR"
			result.Categories = []string{"INTEGRITY_ERROR"}
			result.ReasonCode = "CNCF_CHECK_INTEGRITY_ERROR"
			if !errors.Is(err, cncfcheck.ErrIntegrity) {
				result.Category = "INPUT_ERROR"
				result.Categories = []string{"INPUT_ERROR"}
				result.ReasonCode = "CNCF_CHECK_INPUT_ERROR"
			}
			return result
		}
		sealed, err := cncfcheck.MarshalReport(report)
		if err != nil {
			result.Category = "INTEGRITY_ERROR"
			result.Categories = []string{"INTEGRITY_ERROR"}
			result.ReasonCode = "CNCF_REPORT_INTEGRITY_ERROR"
			return result
		}
		if len(sealed) == 0 || len(sealed) > maxInputBytes {
			result.Category = "INTEGRITY_ERROR"
			result.ReasonCode = "CNCF_REPORT_SIZE_INVALID"
			result.Categories = []string{"INTEGRITY_ERROR"}
			return result
		}
		result.Report = append(json.RawMessage(nil), sealed...)
		return fromClaims(result, cncfClaimViews(report.Check.Claims))
	}
	report, err := projectcheck.Check(item.Project, raw, now)
	if err != nil {
		result.Category = "INTEGRITY_ERROR"
		result.Categories = []string{"INTEGRITY_ERROR"}
		result.ReasonCode = "COMMUNITY_CHECK_INTEGRITY_ERROR"
		if !errors.Is(err, projectcheck.ErrIntegrity) {
			result.Category = "INPUT_ERROR"
			result.Categories = []string{"INPUT_ERROR"}
			result.ReasonCode = "COMMUNITY_CHECK_INPUT_ERROR"
		}
		return result
	}
	sealed, err := projectcheck.MarshalReport(report)
	if err != nil {
		result.Category = "INTEGRITY_ERROR"
		result.Categories = []string{"INTEGRITY_ERROR"}
		result.ReasonCode = "COMMUNITY_REPORT_INTEGRITY_ERROR"
		return result
	}
	if len(sealed) == 0 || len(sealed) > maxInputBytes {
		result.Category = "INTEGRITY_ERROR"
		result.ReasonCode = "COMMUNITY_REPORT_SIZE_INVALID"
		result.Categories = []string{"INTEGRITY_ERROR"}
		return result
	}
	result.Report = append(json.RawMessage(nil), sealed...)
	result = fromClaims(result, communityClaimViews(report.Check.Claims))
	result.notes = claimNotes(report.Check.Claims)
	return result
}

func evaluateExternalCNCF(result ItemResult, item Item, raw []byte, selected knowledge.VerifiedRevision) ItemResult {
	result.KnowledgeOrigin = "external_signed_local"
	report, err := cncfknowledge.EvaluateVerified(selected, cncfknowledge.CheckInput{Project: item.Project, Input: raw, InputDigest: digest(raw)})
	if err != nil {
		result.Category = "INTEGRITY_ERROR"
		result.Categories = []string{"INTEGRITY_ERROR"}
		result.ReasonCode = "CNCF_KNOWLEDGE_INTEGRITY_ERROR"
		if errors.Is(err, cncfknowledge.ErrInvalid) || errors.Is(err, cncfcheck.ErrInvalid) {
			result.Category = "INPUT_ERROR"
			result.Categories = []string{"INPUT_ERROR"}
			result.ReasonCode = "CNCF_KNOWLEDGE_INPUT_ERROR"
		}
		return result
	}
	sealed, err := cncfknowledge.MarshalReport(report)
	if err != nil || len(sealed) == 0 || len(sealed) > maxInputBytes {
		result.Category = "INTEGRITY_ERROR"
		result.Categories = []string{"INTEGRITY_ERROR"}
		result.ReasonCode = "CNCF_KNOWLEDGE_REPORT_INTEGRITY_ERROR"
		return result
	}
	result.Report = append(json.RawMessage(nil), sealed...)
	age := report.KnowledgeAge()
	result.age = &age
	result = fromClaims(result, cncfClaimViews(report.Check.Check.Claims))
	result.notes = claimNotes(report.Check.Check.Claims)
	return result
}

// claimNotes are the human lines of an item's claims that its outcome line
// does not carry: the note for combinations outside a documented support
// range (not verified, not shown to be broken) and each applicable one-way
// notice, followed by one scope line when a notice was established. A notice
// that does not apply contributes nothing.
func claimNotes(claims []constraintengine.Claim) []string {
	var notes []string
	if note, ok := constraintengine.UnsupportedNote(claims); ok {
		notes = append(notes, note)
	}
	established := false
	for _, claim := range claims {
		if lines, notice := claim.NoticeLines(); notice && claim.IsNotice() {
			notes = append(notes, lines...)
			if len(lines) > 0 && claim.Status == constraintengine.StatusNotice {
				established = true
			}
		}
	}
	if established {
		notes = append(notes, constraintengine.NoticeScopeLine)
	}
	return notes
}

// communityClaimViews keeps the claims that decide an outcome, as the CNCF
// route does: a one-way notice is informational and never does, so an item
// whose only claims are notices keeps the UNKNOWN outcome of an item without
// claims, and a notice never turns a pass into an unknown. An UNSUPPORTED
// claim is kept as it is: it is neither a pass nor a blocker.
func communityClaimViews(claims []constraintengine.Claim) []claimView {
	views := make([]claimView, 0, len(claims))
	for _, claim := range claims {
		if claim.IsVerdictNeutral() {
			continue
		}
		views = append(views, claimView{Status: claim.Status, ReasonCode: claim.ReasonCode, EvidenceFreshness: claim.EvidenceFreshness})
	}
	return views
}

type claimView struct{ Status, ReasonCode, EvidenceFreshness string }

// cncfClaimViews keeps the claims that decide an outcome. One-way notices and
// leads are informational and never do: an item whose only claims are such
// keeps the UNKNOWN outcome of an item without claims. A pass of a rule that
// reads a custom-resource version set counts as unknown: nothing yet shows
// that the published rules name every version a release stops serving.
func cncfClaimViews(claims []constraintengine.Claim) []claimView {
	views := make([]claimView, 0, len(claims))
	for _, claim := range claims {
		if claim.IsVerdictNeutral() {
			continue
		}
		view := claimView{Status: claim.Status, ReasonCode: claim.ReasonCode, EvidenceFreshness: claim.EvidenceFreshness}
		if view.Status == "PASS" && cncfcheck.ReadsCustomResourceVersions(claim) {
			view.Status, view.ReasonCode = "UNKNOWN", ""
		}
		views = append(views, view)
	}
	return views
}

func fromClaims(result ItemResult, claims []claimView) ItemResult {
	if len(claims) == 0 {
		return result
	}
	result.Categories = nil
	seen := map[string]bool{}
	for _, claim := range claims {
		category := claimCategory(claim)
		if !seen[category] {
			seen[category] = true
			result.Categories = append(result.Categories, category)
		}
	}
	sort.SliceStable(result.Categories, func(i, j int) bool {
		ri, _ := categoryRank(result.Categories[i])
		rj, _ := categoryRank(result.Categories[j])
		return ri > rj
	})
	result.Category = result.Categories[0]
	result.ReasonCode = reasonForCategory(result.Category)
	// Keep a source-owned reason code, choosing lexicographically so the
	// summary cannot change when a sealed child report changes claim order.
	sourceReason := ""
	for _, claim := range claims {
		if claimCategory(claim) == result.Category && claim.ReasonCode != "" && (sourceReason == "" || claim.ReasonCode < sourceReason) {
			sourceReason = claim.ReasonCode
		}
	}
	if sourceReason != "" {
		result.ReasonCode = sourceReason
	}
	if result.Category == "PASS" {
		result.Outcome = "PASS"
		result.ReasonCode = "SCOPED_CLAIMS_PASS"
	} else if result.Category == "BLOCKED" {
		result.Outcome = "BLOCKED"
	}
	return result
}

func claimCategory(claim claimView) string {
	if claim.Status == "BLOCKED" {
		return "BLOCKED"
	}
	if claim.EvidenceFreshness == "stale" || claim.ReasonCode == "RULE_EVIDENCE_STALE" {
		return "STALE_EVIDENCE"
	}
	if claim.EvidenceFreshness == "clock_before_review" || claim.ReasonCode == "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW" {
		return "NOT_YET_REVIEWED"
	}
	if claim.Status != "PASS" {
		return "UNKNOWN_CLAIM"
	}
	return "PASS"
}

func reasonForCategory(category string) string {
	switch category {
	case "BLOCKED":
		return "SCOPED_CLAIM_BLOCKED"
	case "STALE_EVIDENCE":
		return "RULE_EVIDENCE_STALE"
	case "NOT_YET_REVIEWED":
		return "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW"
	case "UNKNOWN_CLAIM":
		return "SCOPED_CLAIM_UNKNOWN"
	default:
		return "SCOPED_CLAIMS_PASS"
	}
}

func aggregate(results []ItemResult) (string, int) {
	best := "PASS"
	exit := 0
	bestRank := 0
	for _, result := range results {
		category := result.Category
		rank, code := categoryRank(category)
		if rank > bestRank {
			best, exit, bestRank = category, code, rank
		}
	}
	return best, exit
}

func categoryRank(category string) (int, int) {
	switch category {
	case "INTEGRITY_ERROR":
		return 6, 3
	case "INPUT_ERROR":
		return 5, 2
	case "BLOCKED":
		return 4, 10
	case "NOT_YET_REVIEWED":
		return 3, 11
	case "STALE_EVIDENCE":
		return 2, 11
	case "UNKNOWN_CLAIM":
		return 1, 11
	default:
		return 0, 0
	}
}

// ExitForMode keeps legacy unknown exits while allowing automation to
// distinguish stale evidence from an evaluation clock before review time.
func ExitForMode(report Report, mode string) (int, error) {
	if mode != "legacy" && mode != "detailed" {
		return 2, ErrInvalid
	}
	_, legacy := aggregate(report.Items)
	if report.AggregateCategory != "" {
		_, legacy = categoryRank(report.AggregateCategory)
	}
	if mode == "legacy" {
		return legacy, nil
	}
	switch report.AggregateCategory {
	case "STALE_EVIDENCE":
		return 12, nil
	case "NOT_YET_REVIEWED":
		return 13, nil
	default:
		return legacy, nil
	}
}

func validRelativePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func decodeStrict(raw []byte, target any) error {
	if !noDuplicateJSON(raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func noDuplicateJSON(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					keyToken, keyErr := decoder.Token()
					key, ok := keyToken.(string)
					if keyErr != nil || !ok || seen[key] {
						return false
					}
					seen[key] = true
					if !walk() {
						return false
					}
				}
				end, err := decoder.Token()
				return err == nil && end == json.Delim('}')
			case '[':
				for decoder.More() {
					if !walk() {
						return false
					}
				}
				end, err := decoder.Token()
				return err == nil && end == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !walk() {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// cncfProjects lists the distinct CNCF projects of a validated plan in order.
func cncfProjects(plan Plan) []string {
	seen := map[string]bool{}
	projects := []string{}
	for _, item := range plan.Items {
		if item.Kind == "cncf" && !seen[item.Project] {
			seen[item.Project] = true
			projects = append(projects, item.Project)
		}
	}
	sort.Strings(projects)
	return projects
}
