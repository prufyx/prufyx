// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// LiveState is what a package that verifies against the pinned root says about
// itself. It is the unit the plan, sign, refresh and deploy steps compare.
type LiveState struct {
	Profile           string `json:"profile"`
	PackageDigest     string `json:"packageDigest"`
	Revision          string `json:"revision"`
	IndexDigest       string `json:"indexDigest"`
	TimestampVersion  int64  `json:"timestampVersion"`
	TimestampDigest   string `json:"timestampDigest"`
	TimestampExpires  string `json:"timestampExpires"`
	SnapshotVersion   int64  `json:"snapshotVersion"`
	SnapshotDigest    string `json:"snapshotDigest"`
	SnapshotExpires   string `json:"snapshotExpires"`
	TargetsVersion    int64  `json:"targetsVersion"`
	TargetsDigest     string `json:"targetsDigest"`
	TargetsExpires    string `json:"targetsExpires"`
	EvidenceExpiresAt string `json:"evidenceExpiresAt"`
	// MinNextVersion is the lowest TUF version a signer may use next: the
	// timestamp version moves on refreshes too, so it is read at sign time.
	MinNextVersion int64 `json:"minNextVersion"`
}

// InspectLive verifies a package against the pinned root at the real clock and
// reports its state. expectDigest, when set, must equal the package digest.
func InspectLive(packagePath, rootPath, rootDigest, profile, expectDigest string) (LiveState, error) {
	req := knowledge.VerifyRequest{PackagePath: packagePath, BootstrapRootPath: rootPath, BootstrapRootDigest: rootDigest, ExpectedPackageDigest: expectDigest}
	var receipt knowledge.PackageVerificationReceipt
	var err error
	switch profile {
	case ProfileCNCFProjects:
		receipt, err = knowledge.VerifyConstraintsProjects(req)
	case "", ProfileCNCF:
		receipt, err = knowledge.VerifyConstraints(req)
	default:
		return LiveState{}, ErrRejected
	}
	if err != nil || receipt.Status != "VERIFIED" || receipt.PackageDigest == "" || receipt.TargetDigest == "" {
		return LiveState{}, ErrRejected
	}
	return LiveState{
		Profile: receipt.Profile, PackageDigest: receipt.PackageDigest, Revision: receipt.KnowledgeRevision, IndexDigest: receipt.TargetDigest,
		TimestampVersion: receipt.Timestamp.Version, TimestampDigest: receipt.Timestamp.Digest, TimestampExpires: receipt.Timestamp.Expires,
		SnapshotVersion: receipt.Snapshot.Version, SnapshotDigest: receipt.Snapshot.Digest, SnapshotExpires: receipt.Snapshot.Expires,
		TargetsVersion: receipt.Targets.Version, TargetsDigest: receipt.Targets.Digest, TargetsExpires: receipt.Targets.Expires,
		EvidenceExpiresAt: receipt.EvidenceExpiresAt, MinNextVersion: receipt.Timestamp.Version + 1,
	}, nil
}

// StateUnchanged is the plan/sign definition of "nothing moved": the same
// revision and byte-identical targets.json and snapshot.json. A timestamp-only
// refresh changes neither, so a waiting content run stays valid across it.
func StateUnchanged(a, b LiveState) bool {
	return a.Revision != "" && a.Revision == b.Revision &&
		a.TargetsDigest != "" && a.TargetsDigest == b.TargetsDigest &&
		a.SnapshotDigest != "" && a.SnapshotDigest == b.SnapshotDigest
}

// CheckDeploy is the deploy guard: the candidate may replace live only if it was
// built over exactly the live package (predecessor digest), its timestamp
// version is higher, and either its revision is higher or it is a pure refresh
// of the same revision (targets and snapshot byte-identical). It replaces the
// workflow run number as the ordering rule. Clients do not cap the timestamp,
// so the guard does: the candidate timestamp must be unexpired at now and must
// not outlive min(snapshot, targets, evidence expiry) nor now+TimestampLifetime,
// the same cap refresh-timestamp applies. Unparseable times refuse.
func CheckDeploy(live, candidate LiveState, predecessorDigest string, now time.Time) error {
	if now.IsZero() {
		return guard("deploy guard has no clock")
	}
	if err := checkTimestampCap(candidate, now.UTC()); err != nil {
		return err
	}
	if predecessorDigest == "" || live.PackageDigest == "" || predecessorDigest != live.PackageDigest {
		return guard("candidate was not built over the live package")
	}
	if candidate.TimestampVersion <= live.TimestampVersion {
		return guard("timestamp version %d does not exceed live %d", candidate.TimestampVersion, live.TimestampVersion)
	}
	cr, err1 := strconv.ParseUint(candidate.Revision, 10, 63)
	lr, err2 := strconv.ParseUint(live.Revision, 10, 63)
	if err1 != nil || err2 != nil {
		return guard("revision is not numeric")
	}
	switch {
	case cr < lr:
		return guard("revision %d is older than live %d", cr, lr)
	case cr == lr:
		if !StateUnchanged(live, candidate) {
			return guard("same revision but different targets or snapshot")
		}
	default:
		if candidate.TargetsVersion < live.TargetsVersion || candidate.SnapshotVersion < live.SnapshotVersion {
			return guard("targets or snapshot version moves backwards")
		}
	}
	return nil
}

func checkTimestampCap(c LiveState, now time.Time) error {
	ts, err := parseUTC(c.TimestampExpires)
	if err != nil {
		return guard("candidate timestamp expiry is not canonical UTC")
	}
	limit := now.Add(TimestampLifetime)
	for _, v := range []struct{ name, value string }{
		{"snapshot", c.SnapshotExpires}, {"targets", c.TargetsExpires}, {"evidence", c.EvidenceExpiresAt},
	} {
		end, perr := parseUTC(v.value)
		if perr != nil {
			return guard("candidate %s expiry is not canonical UTC", v.name)
		}
		limit = minTime(limit, end)
	}
	if !ts.After(now) {
		return guard("candidate timestamp is already expired")
	}
	if ts.After(limit) {
		return guard("candidate timestamp expires %s, after the cap %s", ts.Format(time.RFC3339), limit.Format(time.RFC3339))
	}
	return nil
}
