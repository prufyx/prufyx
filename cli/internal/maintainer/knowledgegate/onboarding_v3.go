// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// Onboarding v3: the v1 record plus, per kind-new project, the binding of the
// project's release-line tag file and additions entry. It is owner tier only
// (a bot key never signs or verifies v3), has its own signing domain and its
// own types, so a v1 or v2 file refuses the additions member by strict decode
// and a v3 signature never verifies as another schema. The v1 and v2 types,
// domains and digests are untouched.
const (
	OnboardingSchemaV3 = "prufyx.io/knowledge-onboarding-batch/v3"
	// OnboardingDomainV3 prefixes the signed bytes of a v3 batch.
	OnboardingDomainV3 = OnboardingSchemaV3 + "\x00"

	onboardingSampleDomainV3 = OnboardingSchemaV3 + "/sample\x00"
)

// OnboardingAdditions is what a batch binds for one project's additions
// entry. Both values use the public forms of package coveragereport:
// TagFileSha256 is TagFileDigest of the raw tag file, EntryDigest is
// EntryDigestOf the entry. Members are declared in JSON-name order.
type OnboardingAdditions struct {
	EntryDigest   string `json:"entryDigest"`
	TagFileSha256 string `json:"tagFileSha256"`
}

// OnboardingProjectV3 is a project with the optional additions member, first
// in JSON-name order.
type OnboardingProjectV3 struct {
	Additions *OnboardingAdditions `json:"additions,omitempty"`
	OnboardingProject
}

// OnboardingRecordV3 is the signed content of a v3 batch: the fields of
// OnboardingRecord in the same order, over OnboardingProjectV3.
type OnboardingRecordV3 struct {
	Base            OnboardingState       `json:"base"`
	BatchID         string                `json:"batchId"`
	CandidateID     string                `json:"candidateId"`
	ChangeSetDigest string                `json:"changeSetDigest"`
	DecidedAt       string                `json:"decidedAt"`
	Decision        string                `json:"decision"`
	Head            OnboardingState       `json:"head"`
	Identity        string                `json:"identity"`
	Nonce           string                `json:"nonce"`
	NotAfter        string                `json:"notAfter"`
	Projects        []OnboardingProjectV3 `json:"projects"`
	Sample          []int                 `json:"sample"`
	SummaryDigest   string                `json:"summaryDigest"`
}

// OnboardingEnvelopeV3 is the committed v3 file.
type OnboardingEnvelopeV3 struct {
	Schema    string             `json:"schema"`
	Record    OnboardingRecordV3 `json:"record"`
	KeyID     string             `json:"keyId"`
	Signature string             `json:"signature"`
}

// split returns the v1 projection of the record, which carries the additions
// of its projects in its unexported adds map.
func (r OnboardingRecordV3) split() OnboardingRecord {
	rec := OnboardingRecord{
		Base: r.Base, BatchID: r.BatchID, CandidateID: r.CandidateID, ChangeSetDigest: r.ChangeSetDigest,
		DecidedAt: r.DecidedAt, Decision: r.Decision, Head: r.Head, Identity: r.Identity, Nonce: r.Nonce,
		NotAfter: r.NotAfter, Sample: r.Sample, SummaryDigest: r.SummaryDigest,
	}
	adds := map[string]OnboardingAdditions{}
	for _, p := range r.Projects {
		rec.Projects = append(rec.Projects, p.OnboardingProject)
		if p.Additions != nil {
			adds[p.Slug] = *p.Additions
		}
	}
	rec.adds = adds
	return rec
}

// joinV3 is the inverse of split. A project is given additions only from the
// record's adds map.
func joinV3(rec OnboardingRecord) OnboardingRecordV3 {
	out := OnboardingRecordV3{
		Base: rec.Base, BatchID: rec.BatchID, CandidateID: rec.CandidateID, ChangeSetDigest: rec.ChangeSetDigest,
		DecidedAt: rec.DecidedAt, Decision: rec.Decision, Head: rec.Head, Identity: rec.Identity, Nonce: rec.Nonce,
		NotAfter: rec.NotAfter, Sample: rec.Sample, SummaryDigest: rec.SummaryDigest,
	}
	for _, p := range rec.Projects {
		pv := OnboardingProjectV3{OnboardingProject: p}
		if a, ok := rec.adds[p.Slug]; ok {
			a := a
			pv.Additions = &a
		}
		out.Projects = append(out.Projects, pv)
	}
	return out
}

func (a OnboardingAdditions) validate() error {
	if !validBatchDigest(a.EntryDigest) || !validBatchDigest(a.TagFileSha256) {
		return errors.New("additions digest out of range")
	}
	return nil
}

// validate checks the v1 rules over the projection, then the additions: only
// on kind new projects, both digests well formed, at least one project
// carrying them.
func (r OnboardingRecordV3) validate() error {
	rec := r.split()
	if err := rec.validate(); err != nil {
		return err
	}
	n := 0
	for _, p := range r.Projects {
		if p.Additions == nil {
			continue
		}
		n++
		if p.Kind != OnboardingKindNew || !coveragereport.ValidSlug(p.Slug) {
			return fmt.Errorf("project %s: additions are bound only for a new project with a valid slug", logSafe(p.Slug))
		}
		if err := p.Additions.validate(); err != nil {
			return fmt.Errorf("project %s: %w", logSafe(p.Slug), err)
		}
	}
	if n == 0 {
		return errors.New("a v3 batch binds additions for at least one project")
	}
	return nil
}

// SignedOnboardingV3Bytes returns the exact bytes a v3 signature covers.
func SignedOnboardingV3Bytes(r OnboardingRecordV3) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(OnboardingDomainV3), raw...), nil
}

// onboardingCoreV3 is what the v3 sample is drawn from.
type onboardingCoreV3 struct {
	Base            OnboardingState       `json:"base"`
	BatchID         string                `json:"batchId"`
	CandidateID     string                `json:"candidateId"`
	ChangeSetDigest string                `json:"changeSetDigest"`
	Head            OnboardingState       `json:"head"`
	Nonce           string                `json:"nonce"`
	Projects        []OnboardingProjectV3 `json:"projects"`
}

// recordSample draws the sample of a record: v3 (a record carrying additions)
// in its own domain over the projects with their additions, every other
// record as before.
func recordSample(rec OnboardingRecord) ([]int, error) {
	if len(rec.adds) == 0 {
		return onboardingSample(rec.core())
	}
	v := joinV3(rec)
	raw, err := json.Marshal(onboardingCoreV3{Base: v.Base, BatchID: v.BatchID, CandidateID: v.CandidateID, ChangeSetDigest: v.ChangeSetDigest, Head: v.Head, Nonce: v.Nonce, Projects: v.Projects})
	if err != nil {
		return nil, err
	}
	return onboardingSampleBytes(raw, onboardingSampleDomainV3, len(v.Projects))
}

// additionsSummary is the v3 section of the review summary: both digests per
// project, so the owner signs what the gate checks.
func additionsSummary(rec OnboardingRecord) string {
	slugs := make([]string, 0, len(rec.adds))
	for s := range rec.adds {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	var b strings.Builder
	b.WriteString("\n## Release-line additions (v3)\n\n")
	b.WriteString("The gate requires, per project below, the committed tag file to have this sha256 and the additions entry to have this entry digest and to be the offline reading of that tag file. It does not check the tag list against upstream.\n\n")
	b.WriteString("| Slug | Tag file sha256 | Entry digest |\n| --- | --- | --- |\n")
	for _, s := range slugs {
		a := rec.adds[s]
		fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(s), cell(a.TagFileSha256), cell(a.EntryDigest))
	}
	return b.String()
}

// additionsFromHead reads the binding of the named projects from the head
// tree, as the signing tool does: the digest of the tag file and of the entry
// of lines-additions.json. The gate recomputes and compares them.
func additionsFromHead(head Tree, slugs []string) (map[string]OnboardingAdditions, error) {
	file, _, _, err := treeAdditions(head)
	if err != nil {
		return nil, fmt.Errorf("the head's additions file is unreadable or invalid: %w", err)
	}
	out := map[string]OnboardingAdditions{}
	for _, s := range slugs {
		if !coveragereport.ValidSlug(s) {
			return nil, fmt.Errorf("additions slug %s is not valid", logSafe(s))
		}
		if _, dup := out[s]; dup {
			return nil, fmt.Errorf("additions slug %s is listed twice", logSafe(s))
		}
		entry, ok := file.Additions[s]
		if !ok {
			return nil, fmt.Errorf("the head's additions file has no entry for %s", logSafe(s))
		}
		raw, err := head.Read(coveragereport.PinnedTagsDir+"/"+coveragereport.TagFileName(s), MaxFileBytes)
		if err != nil {
			return nil, fmt.Errorf("the head's tag file of %s is unreadable: %w", logSafe(s), err)
		}
		out[s] = OnboardingAdditions{EntryDigest: coveragereport.EntryDigestOf(entry), TagFileSha256: coveragereport.TagFileDigest(raw)}
	}
	return out, nil
}
