// SPDX-License-Identifier: AGPL-3.0-only

package validation

import "errors"

// ErrUnsupportedPlatform is returned by every descriptor-relative primitive on
// Windows (it is declared on every platform so callers can name it). Prufyx's
// input admission rests on openat/no-follow semantics and on POSIX owner,
// link-count and mode bits; Windows has none of these in a form that can be
// checked here, so file and directory input is refused rather than opened
// with weaker guarantees. Standard input is unaffected.
var ErrUnsupportedPlatform = errors.New("secure file input is not supported on Windows; pipe the manifest on standard input")
