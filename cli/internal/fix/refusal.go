// SPDX-License-Identifier: AGPL-3.0-only

package fix

import "errors"

// Reason names why a fix, or a whole file, was refused. The set is closed.
type Reason string

const (
	// ReasonUnsupportedYAML: the bytes are outside the strict YAML subset
	// (anchors, aliases, merge keys, custom tags, non-string or duplicate
	// keys) or do not decode.
	ReasonUnsupportedYAML Reason = "UNSUPPORTED_YAML"
	// ReasonUnsupportedEncoding: invalid UTF-8, a byte order mark anywhere but
	// at the start, a bare carriage return, or a line break other than LF and
	// CRLF.
	ReasonUnsupportedEncoding Reason = "UNSUPPORTED_ENCODING"
	// ReasonTemplated: the file contains template syntax.
	ReasonTemplated Reason = "TEMPLATED"
	// ReasonSecretDocument: the file holds a Secret, before or after the fix.
	ReasonSecretDocument Reason = "SECRET_DOCUMENT"
	// ReasonPathNotFound: the target path does not exist in the document.
	ReasonPathNotFound Reason = "PATH_NOT_FOUND"
	// ReasonBlockScalar: the target is a literal or folded block scalar.
	ReasonBlockScalar Reason = "BLOCK_SCALAR"
	// ReasonMultiLineScalar: the target scalar spans more than one line.
	ReasonMultiLineScalar Reason = "MULTI_LINE_SCALAR"
	// ReasonSpanNotIsolated: the exact bytes of the target token cannot be
	// isolated, or an edit does not cover exactly one key or scalar token.
	ReasonSpanNotIsolated Reason = "SPAN_NOT_ISOLATED"
	// ReasonInvalidEdit: an edit is out of bounds, names another file, or
	// carries a replacement that is not a single-line scalar token.
	ReasonInvalidEdit Reason = "INVALID_EDIT"
	// ReasonConflictingEdits: two edits on one file overlap.
	ReasonConflictingEdits Reason = "CONFLICTING_EDITS"
	// ReasonDecodeMismatch: the edited file does not decode to the original
	// values with exactly the targeted substitutions.
	ReasonDecodeMismatch Reason = "DECODE_MISMATCH"
	// ReasonNotIdempotent: planning the fix again on its own output yields
	// further edits.
	ReasonNotIdempotent Reason = "NOT_IDEMPOTENT"
	// ReasonUnknownKind: no compiled fix kind has the requested id.
	ReasonUnknownKind Reason = "UNKNOWN_KIND"
	// ReasonInvalidParams: the fix parameters do not validate.
	ReasonInvalidParams Reason = "INVALID_PARAMS"
	// ReasonKindRefused: the fix kind declined to plan an edit.
	ReasonKindRefused Reason = "KIND_REFUSED"
	// ReasonLimit: a size or count bound was exceeded.
	ReasonLimit Reason = "LIMIT"
	// ReasonFileChanged: the file's digest differs from the planned digest.
	ReasonFileChanged Reason = "FILE_CHANGED"
	// ReasonUnsafeFile: the file is a symlink, sits below a symlink, is not a
	// regular file, is group or other writable, has special mode bits, more
	// than one link, or another owner.
	ReasonUnsafeFile Reason = "UNSAFE_FILE"
	// ReasonOutsideRoots: the file is not inside a declared root.
	ReasonOutsideRoots Reason = "OUTSIDE_ROOTS"
	// ReasonWriteFailed: the file could not be written; it is unchanged.
	ReasonWriteFailed Reason = "WRITE_FAILED"
)

// maxDetail bounds the explanation of a refusal.
const maxDetail = 256

// Refusal is the error type of this package. Detail is a fixed explanation
// that never carries file content.
type Refusal struct {
	Reason Reason
	Detail string
}

func (r *Refusal) Error() string { return string(r.Reason) + ": " + r.Detail }

func refuse(reason Reason, detail string) *Refusal {
	if len(detail) > maxDetail {
		detail = detail[:maxDetail]
	}
	return &Refusal{Reason: reason, Detail: detail}
}

// ReasonOf returns the reason of a refusal, or "" for any other error.
func ReasonOf(err error) Reason {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}
