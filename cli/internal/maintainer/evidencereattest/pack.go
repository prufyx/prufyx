// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
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
	// LineAttestations and PathPolicies are the pack's optional record
	// sections (lineattest.PackMember, upgradepath.PackMember), carried as
	// their exact bytes. A pack without them re-renders without them, so
	// its bytes do not change. Only a renewed record's two validity fields
	// ever differ between a prior and a next pack (see renewRecords, V10).
	LineAttestations json.RawMessage `json:"lineAttestations,omitempty"`
	PathPolicies     json.RawMessage `json:"pathPolicies,omitempty"`

	// records holds the records of both sections in section order, as
	// evidencerepin.PackRecords located and parsed them. It is never
	// rendered.
	records []evidencerepin.PackRecord
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
	// record is true for the view of a line attestation or path-policy
	// record (see recordFields); it is never decoded.
	record   bool
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
	// Only reviewed and mechanical rules are renewed here: an empirical,
	// consensus or lead rule is renewed by its own evidence, never by a
	// reviewer's reattestation.
	if err := constraintengine.ValidateReviewedOrMechanicalBasis(fields.Evidence.Basis, fields.Evidence.Extractor, fields.Evidence.DerivedAt); err != nil {
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
	ruleIDs := map[string]bool{}
	for _, entry := range doc.Entries {
		fields, err := parseRuleFields(entry.Rule)
		if err != nil {
			return packDocument{}, err
		}
		ruleIDs[fields.ID] = true
	}
	if err := loadRecords(raw, &doc, ruleIDs); err != nil {
		return packDocument{}, err
	}
	return doc, nil
}

// loadRecords reads the pack's line attestation and path-policy sections.
// Each is located by its exact member name (a case variant, or a repeated
// or unknown top-level member, rejects the pack: encoding/json would
// otherwise fold a variant onto the field) and parsed strictly; the decoded
// fields must hold exactly those bytes. Every line attestation must list
// exactly the pack's rules for its scope, each covering the whole line
// (lineattest.CheckRuleSets), so a renewal can never carry an attestation
// the pack no longer supports. No record ID may equal a rule ID.
func loadRecords(raw []byte, doc *packDocument, ruleIDs map[string]bool) error {
	records, err := evidencerepin.PackRecords(raw)
	if err != nil {
		return fmt.Errorf("%w: pack records: %v", ErrRejected, err)
	}
	for _, member := range []struct {
		name  string
		field json.RawMessage
	}{{lineattest.PackMember, doc.LineAttestations}, {upgradepath.PackMember, doc.PathPolicies}} {
		section, present, err := lineattest.PackMemberSection(raw, member.name)
		if err != nil || present != (member.field != nil) || !bytes.Equal(section, member.field) {
			return fmt.Errorf("%w: pack section %s", ErrRejected, member.name)
		}
	}
	if doc.LineAttestations != nil {
		atts, err := lineattest.Parse(doc.LineAttestations)
		if err != nil {
			return fmt.Errorf("%w: line attestations: %v", ErrRejected, err)
		}
		rules := make([]json.RawMessage, 0, len(doc.Entries))
		for _, entry := range doc.Entries {
			rules = append(rules, entry.Rule)
		}
		problems, err := lineattest.CheckRuleSets(atts, rules)
		if err != nil || len(problems) > 0 {
			return fmt.Errorf("%w: line attestations do not match the pack's rules (%d problems): %v", ErrRejected, len(problems), err)
		}
	}
	for _, record := range records {
		if ruleIDs[record.ID] {
			return fmt.Errorf("%w: record %s has the ID of a rule", ErrRejected, record.ID)
		}
	}
	doc.records = records
	return nil
}

// recordFields is the typed view of one record that eligibility, the
// statement chain and V8 read, exactly as they read a rule's. A record has
// no range. A line attestation has no evidence state (see
// evidencerepin.PackRecord.State).
func recordFields(record evidencerepin.PackRecord) ruleFields {
	fields := ruleFields{record: true, ID: record.ID}
	fields.Evidence.State = record.State
	fields.Evidence.Basis = record.Basis
	fields.Evidence.ReviewedAt = record.ReviewedAt
	fields.Evidence.ValidUntil = record.ValidUntil
	for _, source := range record.Sources {
		fields.Evidence.Sources = append(fields.Evidence.Sources, ruleSourceField{ID: source.ID, Revision: source.Revision, ContentDigest: source.ContentDigest})
	}
	return fields
}

// recordView renders a record as the minimal rule-shaped document
// {"evidence": <the record's evidence>, "id": <record ID>} that V6 and V7
// read with parseRuleFields, so their checks on evidence dates and basis
// apply to records exactly as to rules.
func recordView(record evidencerepin.PackRecord) (json.RawMessage, error) {
	value, err := sourcecorpus.DecodeBounded(record.Raw, int64(len(record.Raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: record %s", ErrRejected, record.ID)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: record %s", ErrRejected, record.ID)
	}
	evidence, ok := obj["evidence"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: record %s evidence", ErrRejected, record.ID)
	}
	canon, err := sourcecorpus.Canonical(map[string]any{"id": record.ID, "evidence": evidence})
	if err != nil {
		return nil, fmt.Errorf("%w: record %s", ErrRejected, record.ID)
	}
	return json.RawMessage(canon), nil
}

// recordDates is the reviewedAt and validUntil a renewal gives one record.
type recordDates struct{ reviewedAt, validUntil string }

// renewRecords returns doc with the records named in renew given their new
// dates, and the renewed records' new bytes by record ID. Only the two date
// values inside each renewed record's evidence change, in place: every
// other byte of the record, including member order, is kept (see
// setRecordDates). A section with no renewed record is kept as it is.
func renewRecords(doc packDocument, renew map[string]recordDates) (packDocument, map[string]json.RawMessage, error) {
	renewed := map[string]json.RawMessage{}
	sections := map[string][]json.RawMessage{}
	changed := map[string]bool{}
	records := make([]evidencerepin.PackRecord, 0, len(doc.records))
	for _, record := range doc.records {
		if dates, ok := renew[record.ID]; ok {
			mutated, err := setRecordDates(record.Raw, dates.reviewedAt, dates.validUntil)
			if err != nil {
				return packDocument{}, nil, err
			}
			record.Raw, record.ReviewedAt, record.ValidUntil = mutated, dates.reviewedAt, dates.validUntil
			renewed[record.ID], changed[record.Project] = mutated, true
		}
		records = append(records, record)
		sections[record.Project] = append(sections[record.Project], record.Raw)
	}
	doc.records = records
	if len(renewed) != len(renew) {
		return packDocument{}, nil, fmt.Errorf("%w: a renewed record is not in the pack", ErrRejected)
	}
	join := func(items []json.RawMessage) json.RawMessage {
		parts := make([][]byte, len(items))
		for i, item := range items {
			parts[i] = item
		}
		return json.RawMessage("[" + string(bytes.Join(parts, []byte(","))) + "]")
	}
	if changed[evidencerepin.RecordProjectLineAttestations] {
		doc.LineAttestations = join(sections[evidencerepin.RecordProjectLineAttestations])
	}
	if changed[evidencerepin.RecordProjectPathPolicies] {
		doc.PathPolicies = join(sections[evidencerepin.RecordProjectPathPolicies])
	}
	return doc, renewed, nil
}

// setRecordDates replaces the values of evidence.reviewedAt and
// evidence.validUntil in one record's exact bytes and changes nothing else.
// Each member must occur exactly once; the result is checked to differ from
// the input in those two values only.
func setRecordDates(raw json.RawMessage, reviewedAt, validUntil string) (json.RawMessage, error) {
	evStart, evEnd, err := memberSpan(raw, "evidence")
	if err != nil {
		return nil, err
	}
	evidence := raw[evStart:evEnd]
	type span struct{ start, end int }
	replacements := map[span][]byte{}
	for name, value := range map[string]string{"reviewedAt": reviewedAt, "validUntil": validUntil} {
		start, end, err := memberSpan(evidence, name)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w: record dates", ErrRejected)
		}
		replacements[span{evStart + start, evStart + end}] = encoded
	}
	spans := make([]span, 0, len(replacements))
	for s := range replacements {
		spans = append(spans, s)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	out := append([]byte(nil), raw...)
	for _, s := range spans {
		out = append(out[:s.start], append(append([]byte(nil), replacements[s]...), out[s.end:]...)...)
	}
	if !sameOutsideValidity(raw, out) {
		return nil, fmt.Errorf("%w: record dates changed more than the validity window", ErrRejected)
	}
	return json.RawMessage(out), nil
}

// memberSpan returns the byte span of the value of member name in the JSON
// object raw. The member must occur exactly once at the top level of raw.
func memberSpan(raw []byte, name string) (start, end int, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return 0, 0, fmt.Errorf("%w: record is not an object", ErrRejected)
	}
	found := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return 0, 0, fmt.Errorf("%w: record member", ErrRejected)
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return 0, 0, fmt.Errorf("%w: record member %s", ErrRejected, key)
		}
		if key != name {
			continue
		}
		if found {
			return 0, 0, fmt.Errorf("%w: record member %s repeats", ErrRejected, name)
		}
		found = true
		end = int(dec.InputOffset())
		start = end - len(value)
		if start < 0 || !bytes.Equal(raw[start:end], value) {
			return 0, 0, fmt.Errorf("%w: record member %s", ErrRejected, name)
		}
	}
	if !found {
		return 0, 0, fmt.Errorf("%w: record member %s missing", ErrRejected, name)
	}
	return start, end, nil
}

// withoutValidity is a record's canonical form with evidence.reviewedAt and
// evidence.validUntil removed: what a renewal must leave unchanged.
func withoutValidity(raw json.RawMessage) (string, error) {
	value, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)))
	if err != nil {
		return "", fmt.Errorf("%w: record", ErrRejected)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: record", ErrRejected)
	}
	evidence, ok := obj["evidence"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: record evidence", ErrRejected)
	}
	delete(evidence, "reviewedAt")
	delete(evidence, "validUntil")
	canon, err := sourcecorpus.Canonical(obj)
	if err != nil {
		return "", fmt.Errorf("%w: record", ErrRejected)
	}
	return string(canon), nil
}

func sameOutsideValidity(a, b json.RawMessage) bool {
	left, err1 := withoutValidity(a)
	right, err2 := withoutValidity(b)
	return err1 == nil && err2 == nil && left == right
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
