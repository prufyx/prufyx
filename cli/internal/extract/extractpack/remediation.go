// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// KindRemediationText classifies a renewal whose only content change is the
// remediation advice (rule.nextAction). It is derived from the old and new
// text of the rule, never declared by a run.
const KindRemediationText = "remediation-text"

// RemediationAllowListVersion is the version of the pending-migration list
// below. Raise it whenever the list changes.
const RemediationAllowListVersion = 1

// RemediationPair is one reviewed advice migration: the rule, the sha256
// (hex) of the published nextAction and the sha256 (hex) of the nextAction
// the current crd.version-removal extractor derives for the same inputs.
type RemediationPair struct {
	RuleID    string `json:"ruleId"`
	OldSHA256 string `json:"oldSha256"`
	NewSHA256 string `json:"newSha256"`
}

// remediationAllowList is the bounded set of renewals that may change
// nextAction. It is data, not a rule: it lists the published
// crd.version-removal rules that carry the wording of extractor 2.7.0 and
// earlier. A test in the extractor package derives every pair by calling the
// extractor's own nextAction on the inputs of the published rule and fails
// when this list and that derivation differ. Entries are removed as the
// renewals land.
var remediationAllowList = []RemediationPair{
	// filled in by the generator test (see crdversions remediation test)
}

// RemediationAllowList returns a copy of the pending-migration list.
func RemediationAllowList() []RemediationPair {
	return append([]RemediationPair(nil), remediationAllowList...)
}

// RemediationRecord says what a remediation-text renewal changed: the rule,
// the advice before and after, and the extractor transition.
type RemediationRecord struct {
	Kind          string `json:"kind"`
	RuleID        string `json:"ruleId"`
	Before        string `json:"before"`
	After         string `json:"after"`
	ExtractorFrom string `json:"extractorFrom"` // id@version
	ExtractorTo   string `json:"extractorTo"`
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// maxStrictDepth bounds the nesting the strict reader accepts.
const maxStrictDepth = 64

// strictJSON parses raw as exactly one JSON object. It refuses trailing
// data, a repeated member name, two member names that differ only in letter
// case, and nesting deeper than maxStrictDepth. Numbers stay json.Number, so
// a large number is compared as written and never through a float.
func strictJSON(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := strictValue(dec, 0)
	if err != nil {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func strictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxStrictDepth {
		return nil, errors.New("too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		obj := map[string]any{}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("bad key")
			}
			folded := strings.ToLower(k)
			if seen[folded] {
				return nil, errors.New("repeated or case-colliding member")
			}
			seen[folded] = true
			if obj[k], err = strictValue(dec, depth+1); err != nil {
				return nil, err
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := strictValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, errors.New("unexpected delimiter")
}

var releaseVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// parseRelease reads an extractor release version "MAJOR.MINOR.PATCH" with
// no prefix, suffix or leading zeros.
func parseRelease(s string) ([3]int, bool) {
	m := releaseVersionRE.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func releaseLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// remediationRenewal reports whether nw may replace old, the published entry
// of the same rule id, as a remediation-text renewal, and what it changed.
//
// Admitted only when all of these hold (anything else is refused):
//   - both entries parse strictly (see strictJSON) and both rules carry a
//     string rule.nextAction;
//   - allow lists the rule id, the sha256 of old's nextAction equals the
//     pair's old hash, the sha256 of nw's nextAction equals its new hash, and
//     the two texts differ;
//   - both are active mechanical rules of one extractor id, and nw's
//     extractor release version is strictly greater than old's (both parsed
//     as MAJOR.MINOR.PATCH);
//   - the entries are equal as canonical JSON once rule.nextAction and
//     rule.evidence.{extractor, derivedAt, reviewedAt, validUntil, sources}
//     are removed: every other member, known or not, is compared as written;
//   - the pinned evidence is unchanged: both source lists hold the same
//     sources in the same order, equal in every member except startLine and
//     endLine (so source id, repository, revision, url and content digest are
//     the same upstream bytes), which are the inputs the advice is derived
//     from together with the rule's own members, subject and id;
//   - nw's derivedAt is later than old's, its reviewedAt is its derivedAt and
//     its validUntil is later than its derivedAt.
func remediationRenewal(allow []RemediationPair, old, nw []byte) (RemediationRecord, bool) {
	var rec RemediationRecord
	og, ok1 := strictJSON(old)
	ng, ok2 := strictJSON(nw)
	if !ok1 || !ok2 {
		return rec, false
	}
	ou, ok1 := remediationUnits(og)
	nu, ok2 := remediationUnits(ng)
	if !ok1 || !ok2 {
		return rec, false
	}
	if ou.id == "" || ou.id != nu.id || ou.next == nu.next {
		return rec, false
	}
	listed := false
	for _, p := range allow {
		if p.RuleID == ou.id && p.OldSHA256 == shaHex(ou.next) && p.NewSHA256 == shaHex(nu.next) {
			listed = true
			break
		}
	}
	if !listed {
		return rec, false
	}
	if ou.basis != "mechanical" || nu.basis != "mechanical" || ou.state != "active" || nu.state != "active" {
		return rec, false
	}
	if ou.extID == "" || ou.extID != nu.extID {
		return rec, false
	}
	ov, okO := parseRelease(ou.extVersion)
	nv, okN := parseRelease(nu.extVersion)
	if !okO || !okN || !releaseLess(ov, nv) {
		return rec, false
	}
	oc, err1 := extract.Canonical(og)
	nc, err2 := extract.Canonical(ng)
	if err1 != nil || err2 != nil || !bytes.Equal(oc, nc) {
		return rec, false
	}
	if !equalPinnedSources(ou.sources, nu.sources) {
		return rec, false
	}
	od, err1 := time.Parse(time.RFC3339, ou.derivedAt)
	nd, err2 := time.Parse(time.RFC3339, nu.derivedAt)
	nvu, err3 := time.Parse(time.RFC3339, nu.validUntil)
	if err1 != nil || err2 != nil || err3 != nil || !nd.After(od) || nu.reviewed != nu.derivedAt || !nvu.After(nd) {
		return rec, false
	}
	return RemediationRecord{
		Kind: KindRemediationText, RuleID: ou.id, Before: ou.next, After: nu.next,
		ExtractorFrom: ou.extID + "@" + ou.extVersion, ExtractorTo: nu.extID + "@" + nu.extVersion,
	}, true
}

// remediationOnly is the audit-side check on two canonical entries: the
// pack-wide list decides, so a result is held to the same proof the merge
// used.
func remediationOnly(a, b []byte) bool {
	_, ok := remediationRenewal(remediationAllowList, a, b)
	return ok
}

type remediationUnit struct {
	id, next, basis, state, extID, extVersion string
	derivedAt, reviewed, validUntil           string
	sources                                   []any
}

// remediationUnits reads the members the predicate decides on and removes,
// from g, the ones a remediation renewal may change. Each must have the
// expected JSON type; absent, null or a wrong type refuses. It edits g.
func remediationUnits(g map[string]any) (remediationUnit, bool) {
	var u remediationUnit
	rule, ok := g["rule"].(map[string]any)
	if !ok {
		return u, false
	}
	ev, ok1 := rule["evidence"].(map[string]any)
	ext, ok2 := ev["extractor"].(map[string]any)
	if !ok1 || !ok2 {
		return u, false
	}
	str := func(m map[string]any, k string) (string, bool) { s, ok := m[k].(string); return s, ok && s != "" }
	var oks [10]bool
	u.id, oks[0] = str(rule, "id")
	u.next, oks[1] = str(rule, "nextAction")
	u.basis, oks[2] = str(ev, "basis")
	u.state, oks[3] = str(ev, "state")
	u.extID, oks[4] = str(ext, "id")
	u.extVersion, oks[5] = str(ext, "version")
	u.derivedAt, oks[6] = str(ev, "derivedAt")
	u.reviewed, oks[7] = str(ev, "reviewedAt")
	u.validUntil, oks[8] = str(ev, "validUntil")
	srcs, okS := ev["sources"].([]any)
	oks[9] = okS && len(srcs) > 0
	for _, o := range oks {
		if !o {
			return u, false
		}
	}
	u.sources = srcs
	delete(rule, "nextAction")
	for _, k := range []string{"extractor", "derivedAt", "reviewedAt", "validUntil", "sources"} {
		delete(ev, k)
	}
	return u, true
}

// equalPinnedSources compares two source lists member by member, in order,
// ignoring only startLine and endLine.
func equalPinnedSources(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		am, ok1 := a[i].(map[string]any)
		bm, ok2 := b[i].(map[string]any)
		if !ok1 || !ok2 {
			return false
		}
		for _, m := range []map[string]any{am, bm} {
			delete(m, "startLine")
			delete(m, "endLine")
		}
		ac, err1 := extract.Canonical(am)
		bc, err2 := extract.Canonical(bm)
		if err1 != nil || err2 != nil || !bytes.Equal(ac, bc) {
			return false
		}
		if _, hasID := am["id"].(string); !hasID {
			return false
		}
	}
	return true
}
