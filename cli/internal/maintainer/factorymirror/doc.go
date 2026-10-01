// SPDX-License-Identifier: AGPL-3.0-only

// Package factorymirror keeps a local, read-only mirror of the upstream git
// repositories that rule evidence cites, so that every other maintenance
// step can work from local bytes without any network access.
//
// The mirror lives in a state directory:
//
//	<state>/mirror/<host>/<owner>/<repo>.git   partial (blobless) bare clones
//	<state>/mirror-index.json                  tags, heads, releases, alarms
//	<state>/locks/mirror.lock                  single-writer lock
//
// The package is deterministic and involves no model. Two roles are kept
// strictly apart:
//
//   - The mirror command (Run, Materialize) is the only code that talks to
//     the network. It detects upstream change with "git ls-remote", fetches
//     only when something changed, records tag -> commit SHA, and raises an
//     alarm record when a tag that was recorded earlier now points at a
//     different commit (or has disappeared). Blob contents that a later step
//     needs at a pinned commit are fetched here, on request (Materialize),
//     never by the reader.
//
//   - The Reader opens the mirror strictly offline. Network transports and
//     lazy blob fetching are disabled for every git process it starts, so a
//     blob that was not materialized is reported as such instead of being
//     downloaded.
//
// Absence of information is reported as unknown: without a GitHub credential
// the release metadata of a repository is marked unknown rather than guessed
// from tags.
package factorymirror
