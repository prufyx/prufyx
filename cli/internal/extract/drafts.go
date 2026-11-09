// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// FileDrafts is written only by a run that produced at least one draft. It is
// never a pack, and neither the pack writer nor an importer reads it.
const FileDrafts = "drafts.json"

// PairReasonDraftOnly is the NotAttested reason of a pair that produced drafts.
const PairReasonDraftOnly = "DRAFT_ONLY"

// FamilyFeatureGatesSet is the fact family of the Kubernetes component
// feature-gate set facts.
const FamilyFeatureGatesSet = "kubernetes.feature_gates_set"

// mechanicalExtractorIDs is the allowlist of extractors that may emit
// mechanical Candidates, keyed by id prefix (a family of extractors, not one
// entry per project, so a new target does not move every code digest). It
// lives in the framework source, so changing it moves every code digest. An
// extractor must be listed here AND implement MechanicalEmitter: either alone
// is a run error. A drift test over the catalog checks both directions.
var mechanicalExtractorIDs = []string{
	"k8s.feature-gate-removal",
	"k8s.served-api-removal",
	"crd.version-removal.",
}

// MechanicalExtractorPrefixes returns a copy of the allowlist keys.
func MechanicalExtractorPrefixes() []string {
	return append([]string(nil), mechanicalExtractorIDs...)
}

// mechanicalAllowed reports whether id is covered by the allowlist.
func mechanicalAllowed(id string) bool {
	for _, p := range mechanicalExtractorIDs {
		if p != "" && strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

var factFamilyRules = []struct {
	re     *regexp.Regexp
	family string
}{
	{regexp.MustCompile(`^component\.kubernetes\.[a-z0-9_]+_feature_gates_set$`), FamilyFeatureGatesSet},
	{regexp.MustCompile(`^component\.kubernetes\.[a-z0-9_]+_removed_gvk_present$`), lineattest.FamilyKubernetesRemovedServedGVK},
	{regexp.MustCompile(`^component\.[a-z0-9][a-z0-9_-]*\.custom_resource_versions_set$`), lineattest.FamilyCustomResourceVersions},
}

// FactFamily names the fact family of a required fact, or "" when the fact is
// in no known family (which makes a mechanical rule over it a run error).
func FactFamily(f Fact) string {
	for _, r := range factFamilyRules {
		if r.re.MatchString(f.ID) {
			return r.family
		}
	}
	return ""
}

// checkMechanicalCandidate is the one place that admits a Candidate as
// mechanical: the extractor must be a MechanicalEmitter on the allowlist and
// the Candidate's required facts must all lie in its declared families. An
// error aborts the run; there is no downgrade.
func checkMechanicalCandidate(exID string, fams map[string]bool, c Candidate) error {
	if len(c.RequiredFacts) == 0 {
		return fmt.Errorf("extractor %s: mechanical rule %s requires no fact, so it has no family", exID, c.Rule.ID)
	}
	for _, f := range c.RequiredFacts {
		fam := FactFamily(f)
		if fam == "" || !fams[fam] {
			return fmt.Errorf("extractor %s: mechanical rule %s requires fact %s of family %q, which the extractor does not declare mechanical", exID, c.Rule.ID, f.ID, fam)
		}
	}
	return nil
}

// DraftEntry is one lead in drafts.json. It is not a pack entry: it has no
// rule, no evidence block, no vectors and no lease, only what a person needs
// to author a reviewed rule.
type DraftEntry struct {
	Draft     bool                              `json:"draft"`
	Basis     string                            `json:"basis"`
	Extractor constraintengine.Extractor        `json:"extractor"`
	Project   string                            `json:"project"`
	From      string                            `json:"from"`
	To        string                            `json:"to"`
	Reason    string                            `json:"reason"`
	Quote     string                            `json:"quote"`
	Sources   []constraintengine.SourceEvidence `json:"sources"`
}

// NewDraft is the constructor of a draft Candidate. There is no constructor
// for a mechanical Candidate outside the mechanical extractors.
func NewDraft(project, reason, quote string, sources []SourceRef) Candidate {
	return Candidate{Basis: BasisDraft, Project: project, Reason: reason, Quote: quote, Sources: sources}
}

// NewNeedsReview is the constructor of a needs_review Candidate.
func NewNeedsReview(project, reason, quote string, sources []SourceRef) Candidate {
	return Candidate{Basis: BasisNeedsReview, Project: project, Reason: reason, Quote: quote, Sources: sources}
}

const (
	maxDraftQuote  = 240
	maxDraftReason = 160
)

var (
	draftURLRE   = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|www\.)\S*`)
	draftHandle  = regexp.MustCompile(`@[A-Za-z0-9_-]+`)
	draftBadChar = regexp.MustCompile(`[^A-Za-z0-9 .,:;_/+=-]`)
	draftSpaceRE = regexp.MustCompile(` {2,}`)
)

// sanitizeDraftText reduces upstream text to a short plain string: URLs and
// @handles removed, every character outside a small charset replaced by a
// space (so no markdown survives), whitespace collapsed, length capped. It
// never extends or rewrites words.
func sanitizeDraftText(s string, max int) string {
	s = draftURLRE.ReplaceAllString(s, " ")
	s = draftHandle.ReplaceAllString(s, " ")
	s = draftBadChar.ReplaceAllString(s, " ")
	s = strings.TrimSpace(draftSpaceRE.ReplaceAllString(s, " "))
	if len(s) > max {
		s = strings.TrimSpace(s[:max])
	}
	return s
}

// stampDraft turns a draft or needs_review Candidate into a DraftEntry. It
// cites only bytes the extractor read (the recorder checks every source).
func stampDraft(c Candidate, basis string, pair VersionPair, rec *Recorder, id constraintengine.Extractor) (DraftEntry, error) {
	if basis != BasisDraft && basis != BasisNeedsReview {
		return DraftEntry{}, fmt.Errorf("stampDraft: basis %q is not a draft basis", basis)
	}
	quote := sanitizeDraftText(c.Quote, maxDraftQuote)
	reason := sanitizeDraftText(c.Reason, maxDraftReason)
	if quote == "" || reason == "" {
		return DraftEntry{}, fmt.Errorf("draft of %s has an empty quote or reason after sanitizing", c.Project)
	}
	sources, err := stampSources("draft "+c.Project, c.Sources, rec)
	if err != nil {
		return DraftEntry{}, err
	}
	return DraftEntry{Draft: true, Basis: basis, Extractor: id, Project: c.Project, From: pair.From, To: pair.To, Reason: reason, Quote: quote, Sources: sources}, nil
}

// sortDrafts puts drafts in a canonical order.
func sortDrafts(d []DraftEntry) error {
	keys := make([]string, len(d))
	for i := range d {
		raw, err := json.Marshal(d[i])
		if err != nil {
			return err
		}
		keys[i] = string(raw)
	}
	idx := make([]int, len(d))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	out := make([]DraftEntry, len(d))
	for i, j := range idx {
		out[i] = d[j]
	}
	copy(d, out)
	return nil
}

// CheckPairDrafts reports whether a recorded pair keeps the draft rules: a
// non-negative count, and no attestation of a pair with drafts. Run produces
// only such pairs; a hand-edited record that breaks them is refused here.
func CheckPairDrafts(p PairRecord) error {
	if p.Drafts < 0 {
		return fmt.Errorf("pair %s->%s: negative draft count", p.From, p.To)
	}
	if p.Drafts == 0 {
		return nil
	}
	if p.Attestation == nil || p.Attestation.Status != PairNotAttested || len(p.Attestation.Families) > 0 || p.Attestation.Reason != PairReasonDraftOnly {
		return fmt.Errorf("pair %s->%s: has drafts but is not recorded as not attested (%s)", p.From, p.To, PairReasonDraftOnly)
	}
	if len(p.Rules) > 0 {
		return fmt.Errorf("pair %s->%s: lists rules together with drafts", p.From, p.To)
	}
	return nil
}

// checkDraftOutputs checks files read from a run directory: drafts.json holds
// only draft entries of a known draft basis, and candidates.json holds only
// mechanical entries. It returns problems, never aborts.
func checkDraftOutputs(candidates, drafts []byte) []string {
	var problems []string
	if len(candidates) > 0 {
		var raws []json.RawMessage
		if err := json.Unmarshal(candidates, &raws); err != nil {
			problems = append(problems, FileCandidates+": not a list")
		}
		for i, r := range raws {
			var probe struct {
				Draft *json.RawMessage `json:"draft"`
				Basis *json.RawMessage `json:"basis"`
				Rule  struct {
					Evidence struct {
						Basis string `json:"basis"`
					} `json:"evidence"`
				} `json:"rule"`
			}
			if err := json.Unmarshal(r, &probe); err != nil {
				problems = append(problems, fmt.Sprintf("%s: entry %d unreadable", FileCandidates, i))
				continue
			}
			if probe.Draft != nil || probe.Basis != nil || probe.Rule.Evidence.Basis != BasisMechanical {
				problems = append(problems, fmt.Sprintf("%s: entry %d is not a mechanical pack entry (draft or non-mechanical basis)", FileCandidates, i))
			}
		}
	}
	if len(drafts) > 0 {
		var ds []DraftEntry
		dec := json.NewDecoder(strings.NewReader(string(drafts)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ds); err != nil {
			problems = append(problems, FileDrafts+": "+err.Error())
		}
		for i, d := range ds {
			if !d.Draft || (d.Basis != BasisDraft && d.Basis != BasisNeedsReview) {
				problems = append(problems, fmt.Sprintf("%s: entry %d has an unknown basis", FileDrafts, i))
			}
		}
	}
	return problems
}

// Skeleton renders a starting point for a person who authors a reviewed rule
// from a draft: stdout text only, never a pack file. It is deliberately not a
// pack entry: every field a reviewer must decide holds a <PLACEHOLDER> token,
// and there is no evidence block, no extractor and no derivedAt (an omitted
// basis would read as reviewed, so the placeholders are what keep it from
// parsing).
func Skeleton(d DraftEntry) ([]byte, error) {
	if !d.Draft || (d.Basis != BasisDraft && d.Basis != BasisNeedsReview) {
		return nil, fmt.Errorf("skeleton: not a draft entry")
	}
	sk := map[string]any{
		"project":       "<REVIEWER-PROJECT>",
		"description":   "<REVIEWER-DESCRIPTION>",
		"requiredFacts": []any{"<REVIEWER-FACT>"},
		"rule": map[string]any{
			"id":         "<REVIEWER-RULE-ID>",
			"operator":   "<REVIEWER-OPERATOR>",
			"subject":    map[string]any{"component": "<REVIEWER-COMPONENT>", "from": d.From, "to": d.To},
			"reasonCode": "<REVIEWER-REASON-CODE>",
			"nextAction": "<REVIEWER-NEXT-ACTION>",
			"evidence":   "<REVIEWER-EVIDENCE-AFTER-REVIEW>",
		},
		"lead": map[string]any{"quote": d.Quote, "reason": d.Reason},
	}
	return Canonical(sk)
}
