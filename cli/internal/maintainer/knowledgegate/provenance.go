// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// maxCommitListBytes bounds the commit list file.
const maxCommitListBytes = 4 << 20

// Freshness of a re-derived mechanical rule: a loosening change must carry
// a derivation time inside [now-MaxDerivationAge, now+derivationClockSkew]
// of the gate's clock, so a rule cannot be minted ahead of time and become
// current later, or be presented as derived long ago.
const (
	MaxDerivationAge    = 24 * time.Hour
	derivationClockSkew = 5 * time.Minute
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CommitList is the commit range of a change, as GitHub's compare API
// reports it (base...head), reduced to what the gate checks.
type CommitList struct {
	Status       string         `json:"status"`
	AheadBy      int            `json:"ahead_by"`
	BehindBy     int            `json:"behind_by"`
	TotalCommits int            `json:"total_commits"`
	Commits      []CommitRecord `json:"commits"`
}

// CommitRecord is one commit of a CommitList.
type CommitRecord struct {
	SHA       string      `json:"sha"`
	Author    *loginField `json:"author"`
	Committer *loginField `json:"committer"`
	Commit    struct {
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	} `json:"commit"`
}

type loginField struct {
	Login string `json:"login"`
}

// ParseCommitList parses a commit list. Members the gate does not read are
// ignored; repeated or case-variant members are refused.
func ParseCommitList(raw []byte) (*CommitList, error) {
	if len(raw) > maxCommitListBytes {
		return nil, errors.New("commit list too large")
	}
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("commit list: %w", err)
	}
	var out CommitList
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("commit list: %w", err)
	}
	return &out, nil
}

// commitReasons lists why the change's commits do not all come from the
// automation account: every commit in base..head must be authored and
// committed by it and carry a signature GitHub verified, the list must be
// complete, and its last commit must be the head the gate checked.
func commitReasons(opts Options) []string {
	list := opts.Commits
	if list == nil {
		return []string{"the change's commit list was not supplied"}
	}
	var reasons []string
	if list.BehindBy != 0 || list.AheadBy < 1 || list.Status != "ahead" {
		reasons = append(reasons, fmt.Sprintf("the head is not strictly ahead of the base (status %s)", logSafe(list.Status)))
	}
	if list.TotalCommits != len(list.Commits) || len(list.Commits) == 0 {
		reasons = append(reasons, fmt.Sprintf("the commit list is incomplete (%d of %d commits)", len(list.Commits), list.TotalCommits))
	}
	for _, c := range list.Commits {
		switch {
		case c.Author == nil || c.Author.Login != opts.BotLogin:
			reasons = append(reasons, fmt.Sprintf("commit %s is not authored by the automation account", shortSHA(c.SHA)))
		case c.Committer == nil || c.Committer.Login != opts.BotLogin:
			reasons = append(reasons, fmt.Sprintf("commit %s is not committed by the automation account", shortSHA(c.SHA)))
		case !c.Commit.Verification.Verified:
			reasons = append(reasons, fmt.Sprintf("commit %s has no verified signature", shortSHA(c.SHA)))
		}
	}
	if !shaRE.MatchString(opts.HeadSHA) {
		reasons = append(reasons, "the head commit was not supplied")
	} else if n := len(list.Commits); n > 0 && list.Commits[n-1].SHA != opts.HeadSHA {
		reasons = append(reasons, "the commit list does not end at the head the gate checked")
	}
	return reasons
}

func shortSHA(s string) string {
	if shaRE.MatchString(s) {
		return s[:12]
	}
	return logSafe(s)
}

// botChange reports whether the automation account may have produced the
// change: its author or the event sender is the automation account, or
// the author is unknown.
func botChange(opts Options) bool {
	return opts.Author == "" || opts.Author == opts.BotLogin || opts.Sender == opts.BotLogin
}

// pinnedDigest is the digest a repository variable pins a trust file by:
// sha256 of the file with one trailing newline removed.
func pinnedDigest(raw []byte) string {
	if n := len(raw); n > 0 && raw[n-1] == '\n' {
		raw = raw[:n-1]
	}
	return sourcecorpus.SHA(raw)
}

// trustPath reports whether rel is trust material: the reattestation trust
// root, the owner-approval keys, anything under a trust directory, and any
// file named like a trust root or an approval key file anywhere.
func (l Layout) trustPath(rel string) bool {
	for _, p := range l.TrustPaths {
		if strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p) || rel == p {
			return true
		}
	}
	name := strings.ToLower(path.Base(rel))
	return strings.HasPrefix(name, "trust-root") || strings.Contains(name, "approval-keys")
}

// trustCheck fails every change to trust material, except one proposed by
// a person (not the automation account) whose new file is exactly the one
// a repository variable pins. Trust files are only ever read from the base.
func (r *Report) trustCheck(opts Options) {
	pins := map[string]string{opts.Layout.TrustRootPath: opts.TrustRootDigest, opts.Layout.ApprovalKeysPath: opts.ApprovalKeysDigest}
	var bad []string
	changed := 0
	for _, p := range r.ChangedPaths {
		if !opts.Layout.trustPath(p) {
			continue
		}
		changed++
		pin := pins[p]
		switch {
		case botChange(opts):
			bad = append(bad, p+" (the automation account may not change trust material)")
		case pin == "":
			bad = append(bad, p+" (no pinned digest for this file)")
		default:
			raw, err := opts.Head.Read(p, MaxFileBytes)
			if err != nil {
				bad = append(bad, p+" ("+err.Error()+")")
			} else if pinnedDigest(raw) != pin {
				bad = append(bad, p+" (does not match the pinned digest)")
			}
		}
	}
	r.add("trust-material", len(bad) == 0, "%d trust files changed%s", changed, listDetail(bad))
}

// recordCheck allows changes to the reattestation worklists and review
// records, and to owner approvals, only together with what they belong
// to: a worklist with the statement appended for it, a review record of a
// rule that statement renews, and an approval with the rule change it
// admitted. Anything else in those directories fails.
func (r *Report) recordCheck(cls *Classification, statements map[string]statementResult, opts Options) {
	admitted := map[string]*Change{}
	for _, c := range cls.Changes {
		if c.OK && c.RuleID != "" {
			admitted[c.Pack+"\x00"+c.RuleID] = c
		}
	}
	packs := map[string]bool{}
	for _, spec := range opts.Layout.Packs {
		packs[spec.Name] = true
	}
	var bad []string
	n := 0
	for _, p := range r.ChangedPaths {
		var why string
		switch {
		case opts.Layout.trustPath(p):
			continue // trustCheck
		case strings.HasPrefix(p, opts.Layout.ApprovalDir+"/"):
			n++
			inHead := opts.Head.Exists(p)
			why = approvalPathReason(strings.TrimPrefix(p, opts.Layout.ApprovalDir+"/"), packs, admitted, inHead)
			if why == "" && !inHead {
				why = liveRecordApproval(opts, p)
			}
		case strings.HasPrefix(p, opts.Layout.ReattestDir+"/"):
			n++
			why = reattestPathReason(strings.TrimPrefix(p, opts.Layout.ReattestDir+"/"), packs, statements, opts.Base.Exists(p), opts.Head.Exists(p))
		default:
			continue
		}
		if why != "" {
			bad = append(bad, p+" ("+why+")")
		}
	}
	r.add("knowledge-records", len(bad) == 0, "%d record files changed%s", n, listDetail(bad))
}

// liveRecordApproval refuses deleting a record approval that could still
// verify (decided within MaxApprovalAge of the gate's clock): a removed
// record's approval then stays in the base, where it cannot be used again
// (see approvalInBase). Rule approvals, and files that are not record
// approvals, are not affected.
func liveRecordApproval(opts Options, p string) string {
	raw, err := opts.Base.ReadOptional(p, maxApprovalBytes+1)
	if err != nil || raw == nil {
		return ""
	}
	env, err := decodeApproval(raw)
	if err != nil || env.Record.Subject == "" {
		return ""
	}
	decided, err := time.Parse(time.RFC3339, env.Record.DecidedAt)
	if err != nil || opts.Now.Sub(decided) <= MaxApprovalAge {
		return "a record approval may not be removed while it could still verify"
	}
	return ""
}

func approvalPathReason(rest string, packs map[string]bool, admitted map[string]*Change, inHead bool) string {
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || !packs[parts[0]] || !strings.HasSuffix(parts[1], ".json") {
		return "not <pack>/<rule id>.json"
	}
	c := admitted[parts[0]+"\x00"+strings.TrimSuffix(parts[1], ".json")]
	switch {
	case c == nil:
		return "no admitted change of this rule"
	case inHead && c.Proof != ProofApproval:
		return "the rule change was not admitted by this approval"
	}
	return ""
}

func reattestPathReason(rest string, packs map[string]bool, statements map[string]statementResult, inBase, inHead bool) string {
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || !packs[parts[0]] {
		return "unexpected file"
	}
	stmt := statements[parts[0]]
	switch parts[1] {
	case "chain":
		return "" // verified as the appended statement
	case "worklists":
		switch {
		case !stmt.OK:
			return "no verified statement appended in this change"
		case inBase || !inHead:
			return "worklists are append-only"
		case parts[2] != stmt.Stem+worklistSuffix:
			return "not the worklist of the appended statement"
		}
		return ""
	case "review-records":
		id := strings.TrimSuffix(parts[2], reviewRecordSuffix)
		switch {
		case evidencerepin.IsRecordID(id):
			// No tool produces or verifies a review record for a line
			// attestation or a path policy yet.
			return "review records for line attestations and path policies are not accepted"
		case !stmt.OK:
			return "no verified statement appended in this change"
		case !inHead:
			return "review records may not be removed"
		case id == parts[2] || !stmt.Renewed[id]:
			return "not a record of a rule the appended statement renews"
		}
		return ""
	}
	return "unexpected file"
}

// freshDerivation applies the derivation-time bound to a loosening
// mechanical change.
func freshDerivation(e *entry, now time.Time) error {
	at, err := time.Parse(time.RFC3339, e.Evidence.DerivedAt)
	if err != nil {
		return fmt.Errorf("derivedAt %q is not a time", logSafe(e.Evidence.DerivedAt))
	}
	if at.Before(now.Add(-MaxDerivationAge)) || at.After(now.Add(derivationClockSkew)) {
		return fmt.Errorf("derivedAt %s is outside [now-24h, now+5m] of the gate's clock %s", at.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}
