// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "time"

// withdrawnReviewProblem says why a rule change is refused because it moves
// the review date of a withdrawn rule earlier; empty when it does not. A
// withdrawal binds a downloaded database up to that date, so an earlier date
// would let a database signed before it count as reviewed later. It covers a
// rule withdrawn before or after the change, and no proof admits it.
func withdrawnReviewProblem(c *Change) string {
	if c.Section != "" || c.base == nil || c.head == nil || (c.base.Evidence.State != "withdrawn" && c.head.Evidence.State != "withdrawn") {
		return ""
	}
	base, errBase := time.Parse(time.RFC3339, c.base.Evidence.ReviewedAt)
	head, errHead := time.Parse(time.RFC3339, c.head.Evidence.ReviewedAt)
	switch {
	case errBase != nil || errHead != nil:
		return "the review date of a withdrawn rule cannot be read"
	case head.Before(base):
		return "the review date of a withdrawn rule may not move earlier: a database signed before it would count as reviewed after the withdrawal"
	}
	return ""
}
