// Package pathset computes the canonical digest of a set of changed paths and
// validates the set it is computed over. It is a leaf package: standard
// library only, pure (no IO, environment or clock).
//
// The digest binds an admission decision to the exact list of paths it judged,
// so every producer and consumer must compute it identically.
//
// Algorithm (Digest):
//
//  1. Valid(paths) must hold, otherwise Digest returns the error.
//  2. Copy the list and sort it bytewise on the UTF-8 bytes (Go string order;
//     not locale order, not UTF-16 order, no case folding).
//  3. Join with a single "\n" (0x0A), no trailing separator.
//  4. SHA-256 of the UTF-8 bytes of the joined string.
//  5. Result is "sha256:" followed by 64 lowercase hex digits.
//
// Valid refuses, with a typed error (use errors.Is):
//
//   - ErrEmptySet: no paths at all.
//   - ErrTooManyPaths: more than MaxPaths (10000) paths.
//   - ErrEmptyPath: a path that is the empty string.
//   - ErrNewline: a path containing "\n" (the separator; it would make
//     {"a\nb"} collide with {"a","b"}).
//   - ErrNUL: a path containing a NUL byte.
//   - ErrInvalidUTF8: a path that is not valid UTF-8.
//   - ErrPathTooLong: a path longer than MaxPathBytes (4096) bytes.
//   - ErrDuplicate: the same path twice (byte-identical).
//
// There is no normalisation: paths are never cleaned, no "." or ".." handling,
// no trailing-slash trimming, no case folding, no Unicode normalisation.
// "a/b" and "a/b/" are different paths; so are "A/x" and "a/x". Callers that
// need a path policy apply it before calling this package. A rename is
// expressed as the old path and the new path.
//
// Other implementations (for example Python) must reproduce
// testdata/vectors.json exactly; testdata/pathset_ref.py is a stdlib-only
// reference that does, and is not run by the Go tests. Run it by hand with
// "python3 -I testdata/pathset_ref.py testdata/vectors.json". Any change to
// the algorithm or the vectors is a change to the admission wire.
package pathset
