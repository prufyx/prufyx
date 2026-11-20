// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ReceiptTag opens every receipt line.
const ReceiptTag = "receipt/v1"

// Receipt is the one canonical line propose-rows and rows-check print per row.
// It holds a component slug and digests only, never changelog text. Field
// order is fixed: step, component, rowDigest, tagsDigest, mirrorDigest,
// codeDigest (sha256:<hex>). MirrorDigest is "none" when the source has no mirror state.
// TagsDigest is "unreadable" when the tag list could not be read (a consumer
// must refuse such a receipt).
type Receipt struct {
	Step         string // "propose" or "check"
	Component    string
	RowDigest    string
	TagsDigest   string
	MirrorDigest string
	CodeDigest   string
	// HintDigest is the sha256 (hex) of the hint file a propose run was given.
	// Empty for a run without a hint; then the line has no hintDigest field.
	HintDigest string
}

// Line renders the canonical receipt line without a newline.
func (r Receipt) Line() string {
	l := fmt.Sprintf("%s step=%s component=%s rowDigest=%s tagsDigest=%s mirrorDigest=%s codeDigest=%s",
		ReceiptTag, r.Step, r.Component, r.RowDigest, r.TagsDigest, r.MirrorDigest, r.CodeDigest)
	if r.HintDigest != "" {
		l += " hintDigest=" + r.HintDigest
	}
	return l
}

var (
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// The code digest is the extractor form "sha256:<hex>".
	codeDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	slugRE       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	fields       = []string{"step", "component", "rowDigest", "tagsDigest", "mirrorDigest", "codeDigest"}
)

// ParseReceipt reads one canonical receipt line. It refuses any other field
// order, a missing, repeated or unknown field, extra spaces, and any value
// outside its closed shape.
func ParseReceipt(line string) (Receipt, error) {
	parts := strings.Split(line, " ")
	if (len(parts) != len(fields)+1 && len(parts) != len(fields)+2) || parts[0] != ReceiptTag {
		return Receipt{}, errors.New("receipt: not a canonical receipt/v1 line")
	}
	hinted := len(parts) == len(fields)+2
	v := make([]string, len(fields))
	for i, f := range fields {
		k, val, ok := strings.Cut(parts[i+1], "=")
		if !ok || k != f || val == "" {
			return Receipt{}, fmt.Errorf("receipt: field %d must be %s=<value>", i+1, f)
		}
		v[i] = val
	}
	r := Receipt{Step: v[0], Component: v[1], RowDigest: v[2], TagsDigest: v[3], MirrorDigest: v[4], CodeDigest: v[5]}
	if hinted {
		k, val, ok := strings.Cut(parts[len(fields)+1], "=")
		if !ok || k != "hintDigest" || !hex64RE.MatchString(val) {
			return Receipt{}, errors.New("receipt: the optional last field must be hintDigest=<sha256 hex>")
		}
		r.HintDigest = val
	}
	switch {
	case hinted && r.Step != "propose":
		return Receipt{}, errors.New("receipt: only a propose receipt carries hintDigest")
	case r.Step != "propose" && r.Step != "check":
		return Receipt{}, errors.New("receipt: step must be propose or check")
	case len(r.Component) > 63 || !slugRE.MatchString(r.Component):
		return Receipt{}, errors.New("receipt: component is not a slug")
	case !hex64RE.MatchString(r.RowDigest):
		return Receipt{}, errors.New("receipt: rowDigest must be sha256 hex")
	case !codeDigestRE.MatchString(r.CodeDigest):
		return Receipt{}, errors.New("receipt: codeDigest must be sha256:<hex>")
	case !hex64RE.MatchString(r.TagsDigest) && r.TagsDigest != "unreadable":
		return Receipt{}, errors.New("receipt: tagsDigest must be sha256 hex or unreadable")
	case !hex64RE.MatchString(r.MirrorDigest) && r.MirrorDigest != "none":
		return Receipt{}, errors.New("receipt: mirrorDigest must be sha256 hex (64) or none")
	}
	return r, nil
}

// Admissible is the consumer-side check a production consumer (batcher, QA
// gate) must apply to a parsed receipt. It always refuses an unreadable tag
// list, and refuses mirrorDigest=none unless the caller declares a fixture
// run. Fail closed: anything else is admitted only if it has the closed shape
// ParseReceipt enforces.
func (r Receipt) Admissible(fixtureRun bool) error {
	if r.TagsDigest == "unreadable" || !hex64RE.MatchString(r.TagsDigest) {
		return errors.New("receipt: tag list was unreadable")
	}
	if r.MirrorDigest == "none" {
		if !fixtureRun {
			return errors.New("receipt: no mirror state (mirrorDigest=none) outside a declared fixture run")
		}
	} else if !hex64RE.MatchString(r.MirrorDigest) {
		return errors.New("receipt: mirrorDigest must be 64 hex")
	}
	return nil
}

// ParseReceiptStrict parses a line and applies Admissible.
func ParseReceiptStrict(line string, fixtureRun bool) (Receipt, error) {
	r, err := ParseReceipt(line)
	if err != nil {
		return Receipt{}, err
	}
	if err := r.Admissible(fixtureRun); err != nil {
		return Receipt{}, err
	}
	return r, nil
}
