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
}

// Line renders the canonical receipt line without a newline.
func (r Receipt) Line() string {
	return fmt.Sprintf("%s step=%s component=%s rowDigest=%s tagsDigest=%s mirrorDigest=%s codeDigest=%s",
		ReceiptTag, r.Step, r.Component, r.RowDigest, r.TagsDigest, r.MirrorDigest, r.CodeDigest)
}

var (
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// The code digest is the extractor form "sha256:<hex>".
	codeDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// The mirror index digest is the first 8 bytes of its hash (16 hex).
	mirrorHexRE = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	slugRE      = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	fields      = []string{"step", "component", "rowDigest", "tagsDigest", "mirrorDigest", "codeDigest"}
)

// ParseReceipt reads one canonical receipt line. It refuses any other field
// order, a missing, repeated or unknown field, extra spaces, and any value
// outside its closed shape.
func ParseReceipt(line string) (Receipt, error) {
	parts := strings.Split(line, " ")
	if len(parts) != len(fields)+1 || parts[0] != ReceiptTag {
		return Receipt{}, errors.New("receipt: not a canonical receipt/v1 line")
	}
	v := make([]string, len(fields))
	for i, f := range fields {
		k, val, ok := strings.Cut(parts[i+1], "=")
		if !ok || k != f || val == "" {
			return Receipt{}, fmt.Errorf("receipt: field %d must be %s=<value>", i+1, f)
		}
		v[i] = val
	}
	r := Receipt{Step: v[0], Component: v[1], RowDigest: v[2], TagsDigest: v[3], MirrorDigest: v[4], CodeDigest: v[5]}
	switch {
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
	case !mirrorHexRE.MatchString(r.MirrorDigest) && r.MirrorDigest != "none":
		return Receipt{}, errors.New("receipt: mirrorDigest must be hex or none")
	}
	return r, nil
}
