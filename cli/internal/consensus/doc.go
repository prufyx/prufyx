// SPDX-License-Identifier: AGPL-3.0-only

// Package consensus decides, deterministically and offline, whether a
// proposed removal claim read from upstream release notes may ever be
// treated as a consensus candidate. A claim names only a kind and the
// names it is about; everything else is computed here from pinned bytes:
//
//   - the release notes file is read by commit SHA and its digest must
//     match the claims bundle;
//   - the release's own section is selected and normalised: HTML comments,
//     raw HTML, link reference definitions, images, fenced code blocks and
//     invisible or control characters are removed, line endings are
//     unified, and every normalised line maps to its original line;
//   - each name must occur, as a whole token, in exactly one list item of
//     that section that also carries a removal cue; the item is the
//     citation and its full text the quote;
//   - each name must exist in the complete mechanical inventory of the
//     earlier release and must be absent from that of the later release;
//   - the cited item must reference at least one pull request of the same
//     repository, and every such pull request must appear in a commit
//     subject of the release range.
//
// Any failed or unavailable step leaves the claim a lead or drops it; no
// step can turn a failure into a verified claim. Incomplete inputs are an
// error, never a partial result. Nothing in this package calls a model or
// the network.
package consensus
