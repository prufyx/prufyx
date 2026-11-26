// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
)

// BoundaryCoveredFloor is the oldest client a package carrying the opt-in
// boundary-covered pack level may be built for. A client that does not know
// the level fails such a target as an integrity error, so a package that
// carries it names this version as its minClientVersion, an older client
// reports the package as too new, and no publication build carries it while
// the oldest supported client is below this version. It is a build-time
// constant: changing it is a code change. It must be above every release cut
// before the one that ships the level (a test pins that) and is never below
// ListedFamilyFloor; it may be above the first release that knows the level.
const BoundaryCoveredFloor = ListedFamilyFloor

// ErrOptInBelowFloor is joined with ErrIntegrity when a package would carry
// the opt-in pack level while the oldest supported client is below
// BoundaryCoveredFloor, unknown or not a version.
var ErrOptInBelowFloor = errors.New("the oldest supported client cannot read the opt-in pack level")

// targetsCarryOptIn reports whether any project target declares an opt-in
// pack level. A target that cannot be read is an error, so a caller refuses
// on doubt.
func targetsCarryOptIn(targets [][]byte) (bool, error) {
	carries := false
	for _, raw := range targets {
		var envelope struct {
			Pack struct {
				Schema string `json:"schema"`
			} `json:"pack"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.Pack.Schema == "" {
			return false, errors.New("a project target cannot be read")
		}
		if PackSchemaIsOptIn(envelope.Pack.Schema) {
			carries = true
		}
	}
	return carries, nil
}

// atLeastVersion reports whether version is a version at or above floor.
// Anything that is not a version is below every floor.
func atLeastVersion(version, floor string) bool {
	return buildidentity.ValidVersion(version) && buildidentity.AtLeast(version, floor)
}

// CheckOptInFloor refuses a package that carries an opt-in pack level unless
// its index names a minClientVersion at or above BoundaryCoveredFloor. Every
// admission of a target set runs it. A package without the level is not
// constrained; a target that cannot be read refuses.
func CheckOptInFloor(index []byte, targets [][]byte) error {
	_, err := checkOptInFloor(index, targets)
	return err
}

// CheckOptInShipping is CheckOptInFloor for a built package: a package that
// carries the level is also refused unless the oldest supported client is
// itself at or above the floor.
func CheckOptInShipping(index []byte, targets [][]byte, oldestClient string) error {
	carries, err := checkOptInFloor(index, targets)
	if err != nil || !carries {
		return err
	}
	if !atLeastVersion(oldestClient, BoundaryCoveredFloor) {
		return errors.Join(ErrIntegrity, ErrOptInBelowFloor)
	}
	return nil
}

func checkOptInFloor(index []byte, targets [][]byte) (bool, error) {
	carries, err := targetsCarryOptIn(targets)
	if err != nil || !carries {
		return false, err
	}
	if min, ok := ExternalIndexMinClient(index); !ok || !atLeastVersion(min, BoundaryCoveredFloor) {
		return true, fmt.Errorf("the package carries an opt-in pack level but its minClientVersion is absent or below %s", BoundaryCoveredFloor)
	}
	return true, nil
}
