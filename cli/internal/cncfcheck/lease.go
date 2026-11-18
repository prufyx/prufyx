// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

// PinnedLeaseMinClientVersion is the first release whose clients read the
// evidence.lease field of a rule. A rule pack that carries a pinned lease is
// admitted only while the oldest supported client is this version or later
// (knowledgegate), so no feed serves a pinned rule to a client that would
// refuse the unknown field as an integrity failure. It is a build-time
// constant: raising it is a code change.
const PinnedLeaseMinClientVersion = "v0.1.0-beta.2"
