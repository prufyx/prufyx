// SPDX-License-Identifier: AGPL-3.0-only

// Package fix turns findings into small, reviewable edits of the files a
// user scanned, and applies them safely when asked.
//
// Guarantees:
//
//   - A fix kind is compiled code registered at start-up. Kinds are looked up
//     by id from a closed set; nothing is generated, templated or fetched.
//   - An edit replaces the exact bytes of one YAML key or scalar token in the
//     original file. Files are never re-serialised: comments, ordering,
//     quoting and whitespace outside the edited tokens stay byte-identical.
//   - Anything ambiguous is refused, never approximated. Every refusal names
//     a reason from a closed list (see Reason).
//   - After the edits are applied in memory the result is decoded again with
//     the strict decoder. It must still decode, hold the same documents, and
//     differ from the original only in the targeted values; otherwise the
//     whole file is refused.
//   - Applying the same fix to its own output plans no further edits; this is
//     checked by default.
//   - A plan is never trusted: applying it runs the requested kinds again on
//     the bytes at hand and requires exactly the plan's edits and diff. The
//     diff that is reported is computed from the edits that were applied.
//   - A replacement is one scalar token. A plain token that YAML 1.1 readers
//     (Kubernetes clients) would read as a boolean, number, null or date is
//     refused, and so is any replacement whose decoded text has a control
//     character; quote such values.
//   - A file holding a Secret anywhere (any mapping with kind Secret or
//     SecretList, at any depth) is refused as a whole.
//   - Writing to disk is opt-in (Apply). A file is written only when it lies
//     inside the declared roots, is reached without following any symlink, is
//     a regular file owned by the current user with a single link and no
//     group or other write permission, and still has the digest it had when
//     the fix was planned. The directory must not be group or other writable
//     unless it is sticky. The new content is written to a temporary file in
//     the same directory and renamed over the original, keeping its
//     permission bits and group; a file with extended attributes or flags
//     that a replacement would drop is refused. Files with Secret documents,
//     and files with template syntax, are never edited.
package fix
