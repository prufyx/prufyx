// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// packDocument mirrors the shape shared by cncfcheck's and projectcheck's
// data/rules.json (see cncfcheck's rulePack/Entry), in the field order
// those files are actually written in, so a round trip through this type
// changes nothing but the fields this package explicitly sets (see
// nextPackDocument). LandscapeFileDigest and RegistryDigest are present
// only in the CNCF pack; the community pack omits them.
type packDocument struct {
	Schema              string         `json:"schema"`
	Revision            string         `json:"revision"`
	PolicyID            string         `json:"policyId"`
	PolicyDigest        string         `json:"policyDigest"`
	LandscapeFileDigest string         `json:"landscapeFileDigest,omitempty"`
	RegistryDigest      string         `json:"registryDigest,omitempty"`
	Entries             []packEntryDoc `json:"entries"`
}

// packEntryDoc mirrors one pack entry in its actual on-disk field order.
type packEntryDoc struct {
	Description   string          `json:"description"`
	Project       string          `json:"project"`
	RequiredFacts json.RawMessage `json:"requiredFacts"`
	Rule          json.RawMessage `json:"rule"`
}

// ruleSourceField is one evidence.sources[] entry, decoded losslessly for
// the fields this package needs to read (not for digesting: digests use the
// generic decode path in digest.go, never this typed view).
type ruleSourceField struct {
	ID            string `json:"id"`
	Revision      string `json:"revision"`
	ContentDigest string `json:"contentDigest"`
}

// isMechanical reports whether the rule's evidence was derived from source by
// an extractor. Such a rule is renewed only by the derivation path, never by a
// reviewer's reattestation.
func (f ruleFields) isMechanical() bool {
	return f.Evidence.Basis == constraintengine.BasisMechanical
}

// ruleFields is a typed, lossy view of one rule's identity, evidence, and
// range presence. It is read-only: it is never remarshaled to produce
// output bytes (see nextPackDocument, which mutates the generic decode
// instead, so untouched fields survive byte-for-byte).
type ruleFields struct {
	ID       string          `json:"id"`
	Range    json.RawMessage `json:"range"`
	Evidence struct {
		State      string                      `json:"state"`
		Basis      string                      `json:"basis"`
		Extractor  *constraintengine.Extractor `json:"extractor"`
		DerivedAt  string                      `json:"derivedAt"`
		ReviewedAt string                      `json:"reviewedAt"`
		ValidUntil string                      `json:"validUntil"`
		Sources    []ruleSourceField           `json:"sources"`
	} `json:"evidence"`
}

func parseRuleFields(raw json.RawMessage) (ruleFields, error) {
	var fields ruleFields
	if err := json.Unmarshal(raw, &fields); err != nil || fields.ID == "" {
		return ruleFields{}, fmt.Errorf("%w: malformed rule", ErrRejected)
	}
	// The basis vocabulary is closed. An unknown token, or a mechanical rule
	// without its extractor, is a malformed rule here exactly as it is to the
	// engine, so no later step has to guess what it is renewing.
	var presence struct {
		Evidence map[string]json.RawMessage `json:"evidence"`
	}
	_ = json.Unmarshal(raw, &presence)
	for _, key := range []string{"basis", "derivedAt"} {
		if value, present := presence.Evidence[key]; present && (string(value) == `""` || string(value) == "null") {
			return ruleFields{}, fmt.Errorf("%w: rule %s evidence %s", ErrRejected, fields.ID, key)
		}
	}
	if value, present := presence.Evidence["extractor"]; present && string(value) == "null" {
		return ruleFields{}, fmt.Errorf("%w: rule %s evidence extractor", ErrRejected, fields.ID)
	}
	if err := constraintengine.ValidateBasis(fields.Evidence.Basis, fields.Evidence.Extractor, fields.Evidence.DerivedAt); err != nil {
		return ruleFields{}, fmt.Errorf("%w: rule %s evidence basis", ErrRejected, fields.ID)
	}
	return fields, nil
}

// loadPack reads and strictly parses one rule pack file. It returns both
// the exact raw bytes (for digesting: see packDigest) and the parsed
// document.
func loadPack(raw []byte) (packDocument, error) {
	if len(raw) == 0 || len(raw) > MaxPackBytes {
		return packDocument{}, fmt.Errorf("%w: rule pack size rejected", ErrRejected)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc packDocument
	if err := decoder.Decode(&doc); err != nil {
		return packDocument{}, fmt.Errorf("%w: decode rule pack: %v", ErrRejected, err)
	}
	if doc.Schema == "" || doc.Revision == "" || len(doc.Entries) == 0 {
		return packDocument{}, fmt.Errorf("%w: rule pack missing required fields", ErrRejected)
	}
	for _, entry := range doc.Entries {
		if _, err := parseRuleFields(entry.Rule); err != nil {
			return packDocument{}, err
		}
	}
	return doc, nil
}

// packDigest is the pack's whole-file digest, computed the same way
// corpusattest.verifyPackBinding computes it.
func packDigest(raw []byte) string { return sourcecorpus.SHA(raw) }

// ruleSetDigest is the digest over just the pack's rule array in canonical
// form. It is a self-consistent identity for this package's own prior/next
// binding (V4); it is deliberately NOT claimed to equal the runtime
// engine's internal RuleSet digest (constraintengine.RuleSet.Digest is
// unexported and tied to the compiled, embedded pack, not an arbitrary
// on-disk file), and this gap is documented in
// cli/docs/evidence-reattestation.md.
func ruleSetDigest(doc packDocument) (string, error) {
	rules := make([]json.RawMessage, 0, len(doc.Entries))
	for _, entry := range doc.Entries {
		rules = append(rules, entry.Rule)
	}
	var generic []any
	for _, rule := range rules {
		value, err := sourcecorpus.DecodeBounded(rule, int64(len(rule)))
		if err != nil {
			return "", fmt.Errorf("%w: rule set digest", ErrRejected)
		}
		generic = append(generic, value)
	}
	canon, err := sourcecorpus.Canonical(generic)
	if err != nil {
		return "", fmt.Errorf("%w: rule set digest", ErrRejected)
	}
	return sourcecorpus.SHA(canon), nil
}

// ruleDigestAndEvidence computes a rule's whole-rule digest, its evidence
// block digest, and its evidence.sources digest, all using
// sourcecorpus.Canonical/SHA over the generically decoded rule (the same
// canonical-digest scheme maintainer/reviewrecord uses for its own
// RuleDigest binding). This is NOT byte-identical to the engine's internal
// claims[].ruleDigest (constraintengine's digestJSON marshals a typed
// struct in Go field-declaration order, not sorted-key canonical order,
// and is unexported); see cli/docs/evidence-reattestation.md for why this
// package uses the canonical scheme instead. Used consistently on both
// sides of every comparison this package makes, so the mismatch changes no
// invariant this package checks.
func ruleDigestAndEvidence(raw json.RawMessage) (ruleDigest, evidenceDigest, sourcesDigest string, err error) {
	value, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)))
	if err != nil {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	ruleCanon, err := sourcecorpus.Canonical(value)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	evidence, ok := obj["evidence"]
	if !ok {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	evidenceCanon, err := sourcecorpus.Canonical(evidence)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	evidenceObj, ok := evidence.(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	sources, ok := evidenceObj["sources"]
	if !ok {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	sourcesCanon, err := sourcecorpus.Canonical(sources)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: rule digest", ErrRejected)
	}
	return sourcecorpus.SHA(ruleCanon), sourcecorpus.SHA(evidenceCanon), sourcecorpus.SHA(sourcesCanon), nil
}

// mutateRuleEvidenceDates returns the exact bytes for one rule with only
// evidence.reviewedAt and evidence.validUntil replaced, reusing the
// generic decode/re-encode path so every other byte, including nested key
// order, survives unchanged (rules.json's nested objects are already
// written in sorted-key order; see pack.go's doc comment on packDocument).
func mutateRuleEvidenceDates(raw json.RawMessage, reviewedAt, validUntil string) (json.RawMessage, error) {
	value, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: mutate rule", ErrRejected)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: mutate rule", ErrRejected)
	}
	evidence, ok := obj["evidence"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: mutate rule", ErrRejected)
	}
	evidence["reviewedAt"] = reviewedAt
	evidence["validUntil"] = validUntil
	canon, err := sourcecorpus.Canonical(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: mutate rule", ErrRejected)
	}
	return json.RawMessage(canon), nil
}

// buildNextPack renders the exact bytes for rules.next.json: the same
// packDocument shape and entry order, with only the entries the caller
// already mutated (via mutateRuleEvidenceDates) different from the source
// pack, using the same 2-space-indented, trailing-newline style as the
// shipped rule packs.
func buildNextPack(doc packDocument) ([]byte, error) {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: render next pack", ErrRejected)
	}
	return append(raw, '\n'), nil
}
