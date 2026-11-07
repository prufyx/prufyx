// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepack"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// RefreshOptions are the inputs of a timestamp-only refresh. There is
// deliberately no targets or snapshot key: no other key material is loaded.
type RefreshOptions struct {
	Profile                 string
	LivePackage             string
	ExpectLivePackageDigest string
	Root, RootDigest        string
	TimestampKey            string
	PassphraseFile          string
	OutputDir               string
	// Expires optionally sets an earlier timestamp expiry (exact UTC RFC3339).
	Expires string
	Now     time.Time
}

// RefreshResult describes the written refresh.
type RefreshResult struct {
	Revision                 string   `json:"revision"`
	LivePackageDigest        string   `json:"livePackageDigest"`
	PackageDigest            string   `json:"packageDigest"`
	PreviousTimestampVersion int64    `json:"previousTimestampVersion"`
	TimestampVersion         int64    `json:"timestampVersion"`
	Expires                  string   `json:"expires"`
	Cap                      string   `json:"cap"`
	TargetsDigest            string   `json:"targetsDigest"`
	SnapshotDigest           string   `json:"snapshotDigest"`
	IndexDigest              string   `json:"indexDigest"`
	Files                    []string `json:"files"`
}

const maxLivePackageBytes = knowledgepack.MaxSplitPackageBytes

// Refresh signs a new timestamp (live version + 1) over the live, unchanged
// snapshot and targets and writes it together with the repackaged package.
// The cap, enforced here because clients do not cap the timestamp, is
// min(snapshot expiry, targets expiry, evidence expiry, Now+TimestampLifetime).
func Refresh(o RefreshOptions) (RefreshResult, error) {
	for _, p := range []string{o.Root, o.LivePackage, o.TimestampKey, o.PassphraseFile, o.OutputDir} {
		if !filepath.IsAbs(p) {
			return RefreshResult{}, ErrRejected
		}
	}
	if o.RootDigest == "" || o.Now.IsZero() {
		return RefreshResult{}, ErrRejected
	}
	rootRaw, err := read(o.Root, knowledgepublish.MaxRootBytes)
	if err != nil {
		return RefreshResult{}, ErrRejected
	}
	// The live package must verify against the pinned root before anything else.
	live, err := InspectLive(o.LivePackage, o.Root, o.RootDigest, o.Profile, o.ExpectLivePackageDigest)
	if err != nil {
		return RefreshResult{}, guard("live package does not verify against the pinned root")
	}
	if o.ExpectLivePackageDigest != "" && live.PackageDigest != o.ExpectLivePackageDigest {
		return RefreshResult{}, guard("live package digest differs from the expected one")
	}
	liveRaw, err := currentbundle.ReadBoundedFile(o.LivePackage, maxLivePackageBytes)
	if err != nil {
		return RefreshResult{}, ErrRejected
	}
	members, err := ReadMembers(liveRaw)
	if err != nil {
		return RefreshResult{}, ErrRejected
	}
	targetsName := fmt.Sprintf("metadata/%d.targets.json", live.TargetsVersion)
	snapshotName := fmt.Sprintf("metadata/%d.snapshot.json", live.SnapshotVersion)
	targetsRaw, snapshotRaw := members[targetsName], members[snapshotName]
	if len(targetsRaw) == 0 || len(snapshotRaw) == 0 || digestOf(targetsRaw) != live.TargetsDigest || digestOf(snapshotRaw) != live.SnapshotDigest {
		return RefreshResult{}, guard("live package members do not match the verified targets and snapshot")
	}

	limit, err := o.cap(live)
	if err != nil {
		return RefreshResult{}, err
	}
	expires := limit
	if o.Expires != "" {
		requested, perr := parseUTC(o.Expires)
		if perr != nil || requested.After(limit) {
			return RefreshResult{}, guard("expires is not canonical UTC or exceeds the refresh cap %s", limit.Format(time.RFC3339))
		}
		expires = requested
	}
	liveExpiry, err := parseUTC(live.TimestampExpires)
	if err != nil {
		return RefreshResult{}, ErrRejected
	}
	if expires.Before(liveExpiry.Add(minRefreshMargin)) {
		return RefreshResult{}, guard("refresh would not extend the live timestamp by at least a day")
	}

	version := live.TimestampVersion + 1
	oo := Options{RootDigest: o.RootDigest, PassphraseFile: o.PassphraseFile}
	timestampRaw, err := signRole(oo, rootRaw, metadata.TIMESTAMP, o.TimestampKey, func() (knowledgepublish.Preparation, error) {
		return knowledgepublish.PrepareTimestampRefresh(knowledgepublish.TimestampRefreshOptions{
			Root: rootRaw, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: o.RootDigest, TargetDigest: live.IndexDigest,
			PreviousVersion: live.TimestampVersion, Version: version, Expires: expires.Format(time.RFC3339),
		})
	})
	if err != nil {
		return RefreshResult{}, err
	}

	next := make(map[string][]byte, len(members))
	for name, raw := range members {
		next[name] = raw
	}
	next["metadata/timestamp.json"] = timestampRaw
	packageRaw, err := repackage(next, live.Profile)
	if err != nil {
		return RefreshResult{}, ErrRejected
	}
	if err := assertOnlyTimestampChanged(members, next); err != nil {
		return RefreshResult{}, err
	}
	after, err := verifyBytes(packageRaw, o.Root, o.RootDigest, live.Profile)
	if err != nil {
		return RefreshResult{}, guard("refreshed package does not verify: %v", err)
	}
	if after.TimestampVersion != version || after.TimestampDigest != digestOf(timestampRaw) ||
		after.TargetsDigest != live.TargetsDigest || after.SnapshotDigest != live.SnapshotDigest ||
		after.IndexDigest != live.IndexDigest || after.Revision != live.Revision {
		return RefreshResult{}, guard("refreshed package state differs from the live state")
	}

	if err := os.Mkdir(o.OutputDir, 0o700); err != nil {
		return RefreshResult{}, ErrRejected
	}
	result := RefreshResult{
		Revision: live.Revision, LivePackageDigest: live.PackageDigest, PackageDigest: after.PackageDigest,
		PreviousTimestampVersion: live.TimestampVersion, TimestampVersion: version,
		Expires: expires.Format(time.RFC3339), Cap: limit.Format(time.RFC3339),
		TargetsDigest: live.TargetsDigest, SnapshotDigest: live.SnapshotDigest, IndexDigest: live.IndexDigest,
	}
	prefix := "cncf-"
	if live.Profile == ProfileCNCFProjects {
		prefix = ProfileCNCFProjects + "-"
	}
	for _, f := range []outFile{{"timestamp.json", timestampRaw}, {prefix + live.Revision + ".tar", packageRaw}} {
		if err := knowledgepublish.WriteExclusive(filepath.Join(o.OutputDir, f.name), f.raw); err != nil {
			return RefreshResult{}, ErrRejected
		}
		result.Files = append(result.Files, f.name)
	}
	return result, nil
}

// cap is min(snapshot expiry, targets expiry, evidence expiry, Now+14d). It
// refuses when the live package is already expired for any role at Now, or
// when less than a day remains for targets, snapshot or evidence: only a
// content release can help then.
func (o RefreshOptions) cap(live LiveState) (time.Time, error) {
	limit := o.Now.UTC().Add(TimestampLifetime)
	for _, v := range []struct{ name, at string }{{"snapshot", live.SnapshotExpires}, {"targets", live.TargetsExpires}, {"evidence", live.EvidenceExpiresAt}} {
		end, err := parseUTC(v.at)
		if err != nil {
			return time.Time{}, ErrRejected
		}
		if !end.After(o.Now) {
			return time.Time{}, guard("%s is already expired: a content release is needed", v.name)
		}
		if end.Before(o.Now.Add(minRefreshMargin)) {
			return time.Time{}, guard("less than a day of %s validity remains: a content release is needed", v.name)
		}
		limit = minTime(limit, end)
	}
	tsEnd, err := parseUTC(live.TimestampExpires)
	if err != nil || !tsEnd.After(o.Now) {
		return time.Time{}, guard("live timestamp is already expired")
	}
	return limit, nil
}

// ReadMembers parses a package tar into its members. It only splits the
// archive; the verifier has already judged canonical form and authenticity.
func ReadMembers(raw []byte) (map[string][]byte, error) {
	members := map[string][]byte{}
	r := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return members, nil
		}
		if err != nil || h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > 1<<20 {
			return nil, ErrRejected
		}
		data, err := io.ReadAll(io.LimitReader(r, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, ErrRejected
		}
		if _, dup := members[h.Name]; dup {
			return nil, ErrRejected
		}
		members[h.Name] = data
	}
}

// repackage writes the members into a scratch repository and packs them with
// the same canonical packer the release uses.
func repackage(members map[string][]byte, profile string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "prufyx-knowledge-refresh-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	for name, raw := range members {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, raw, 0o600); err != nil {
			return nil, err
		}
	}
	return knowledgepack.PackageDirectory(dir, packProfile(profile))
}

func packProfile(profile string) string {
	if profile == ProfileCNCFProjects {
		return knowledgepack.ProfileCNCFProjects
	}
	return "cncf"
}

// assertOnlyTimestampChanged is the byte-identity assertion: the refreshed
// package has exactly the live member set and every member except
// metadata/timestamp.json is byte-for-byte the live one, which must change.
func assertOnlyTimestampChanged(live, next map[string][]byte) error {
	if len(live) != len(next) {
		return guard("refreshed package has a different member set")
	}
	for name, raw := range live {
		got, ok := next[name]
		if !ok {
			return guard("refreshed package lost member %s", name)
		}
		if name == "metadata/timestamp.json" {
			if bytes.Equal(raw, got) {
				return guard("timestamp was not replaced")
			}
			continue
		}
		if !bytes.Equal(raw, got) {
			return guard("member %s differs from the live package", name)
		}
	}
	return nil
}

// verifyBytes verifies package bytes by staging them in a private file.
func verifyBytes(packageRaw []byte, rootPath, rootDigest, profile string) (LiveState, error) {
	dir, err := os.MkdirTemp("", "prufyx-knowledge-refresh-verify-")
	if err != nil {
		return LiveState{}, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return LiveState{}, err
	}
	p := filepath.Join(dir, "package.tar")
	if err := os.WriteFile(p, packageRaw, 0o600); err != nil {
		return LiveState{}, err
	}
	return InspectLive(p, rootPath, rootDigest, profile, digestOf(packageRaw))
}

func digestOf(raw []byte) string { return payloadDigest(raw) }
