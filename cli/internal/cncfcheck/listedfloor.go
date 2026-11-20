// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// ListedFamilyFloor is the first release whose clients know the
// changelog.listed_entries attestation family. The family list of an older
// client is closed, so such a client fails a package that carries the family
// as an integrity error (exit 3). A package that carries the family therefore
// names this version as its minClientVersion, so an older client reports it
// as too new (exit 15) before it reads any project target. It is a
// build-time constant: raising it is a code change, and it must be above
// every release tag cut before the release that ships the family (a test
// pins that) and above the oldest supported client.
const ListedFamilyFloor = "v0.1.0-beta.3"

// ErrListedFloorInvalid is joined with ErrIntegrity when the listed-family
// floor, or the oldest supported client version it is compared with, is not a
// version.
var ErrListedFloorInvalid = errors.New("the listed-family client floor or the oldest supported client is not a version")

// ListedFamilyShips reports whether a package built for clients no older than
// oldestClient may carry the listed family: only when oldestClient is a
// version at or above the floor. An empty or unreadable version never ships
// the family; the first return is the decision, the error is set only for a
// non-empty value that is not a version.
func ListedFamilyShips(oldestClient string) (bool, error) {
	return listedFamilyShips(oldestClient, ListedFamilyFloor)
}

func listedFamilyShips(oldestClient, floor string) (bool, error) {
	if !buildidentity.ValidVersion(floor) {
		return false, errors.Join(ErrIntegrity, ErrListedFloorInvalid)
	}
	if oldestClient == "" {
		return false, nil
	}
	if !buildidentity.ValidVersion(oldestClient) {
		return false, errors.Join(ErrIntegrity, ErrListedFloorInvalid)
	}
	return buildidentity.AtLeast(oldestClient, floor), nil
}

// ExcludeListedAttestations is the one function that decides which listed
// attestations a published package carries. section is the exact bytes of a
// pack's lineAttestations section (nil or empty when the pack has none). While
// the oldest supported client is below the floor, or not known (empty), every
// changelog.listed_entries attestation is removed and counted; otherwise the
// section is returned unchanged. The result is nil, never an empty array,
// when nothing is left: a present but empty section is refused by the pack
// admission (a present section must hold records), so an emptied section is
// absent. Output is canonical and depends only on the input, so the same
// input gives the same bytes and digest. It runs before anything is signed.
func ExcludeListedAttestations(section json.RawMessage, oldestClient string) (kept json.RawMessage, excluded int, err error) {
	return excludeListed(section, oldestClient, ListedFamilyFloor)
}

func excludeListed(section json.RawMessage, oldestClient, floor string) (json.RawMessage, int, error) {
	ships, err := listedFamilyShips(oldestClient, floor)
	if err != nil {
		return nil, 0, err
	}
	if len(section) == 0 {
		return nil, 0, nil
	}
	if ships {
		return section, 0, nil
	}
	atts, err := lineattest.Parse(section)
	if err != nil {
		return nil, 0, ErrIntegrity
	}
	keep := make([]lineattest.LineAttestation, 0, len(atts))
	for _, a := range atts {
		if a.FactFamily != lineattest.FamilyChangelogListedEntries {
			keep = append(keep, a)
		}
	}
	excluded := len(atts) - len(keep)
	if excluded == 0 {
		return section, 0, nil
	}
	if len(keep) == 0 {
		return nil, excluded, nil
	}
	raw, err := lineattest.Marshal(keep)
	if err != nil {
		return nil, 0, ErrIntegrity
	}
	return raw, excluded, nil
}

// SectionCarriesListedFamily reports whether a lineAttestations section holds
// a changelog.listed_entries attestation. A section that cannot be read counts
// as carrying it, so a caller that refuses on true refuses on doubt.
func SectionCarriesListedFamily(section json.RawMessage) bool {
	if len(section) == 0 {
		return false
	}
	atts, err := lineattest.Parse(section)
	if err != nil {
		return true
	}
	for _, a := range atts {
		if a.FactFamily == lineattest.FamilyChangelogListedEntries {
			return true
		}
	}
	return false
}

// CheckListedFamilyShipping is the publish check for a built package: index
// is the exact index target and targets the exact project targets. A package
// that carries the listed family is refused unless its index names a
// minClientVersion that is a version at or above the floor, and unless the
// oldest supported client is itself at or above the floor (the exclusion
// makes the second case unreachable, so reaching it is a defect). A package
// without the family is not constrained. Any target that cannot be read
// refuses.
func CheckListedFamilyShipping(index []byte, targets [][]byte, oldestClient string) error {
	carries, err := checkListedFamilyFloor(index, targets)
	if err != nil || !carries {
		return err
	}
	ships, err := ListedFamilyShips(oldestClient)
	if err != nil || !ships {
		return fmt.Errorf("the package carries changelog.listed_entries while the oldest supported client is below %s", ListedFamilyFloor)
	}
	return nil
}

// CheckListedFamilyFloor is the part of the shipping check that needs no
// knowledge of the oldest supported client: a package that carries the listed
// family is refused unless its index names a minClientVersion at or above the
// floor. Every admission of a target set runs it, so a set read from a
// directory is held to the same floor as a built release.
func CheckListedFamilyFloor(index []byte, targets [][]byte) error {
	_, err := checkListedFamilyFloor(index, targets)
	return err
}

func checkListedFamilyFloor(index []byte, targets [][]byte) (bool, error) {
	carries := false
	for _, raw := range targets {
		var envelope struct {
			Pack struct {
				LineAttestations json.RawMessage `json:"lineAttestations"`
			} `json:"pack"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			return false, fmt.Errorf("a project target cannot be read")
		}
		if SectionCarriesListedFamily(envelope.Pack.LineAttestations) {
			carries = true
		}
	}
	if !carries {
		return false, nil
	}
	min, ok := ExternalIndexMinClient(index)
	if !ok || !buildidentity.ValidVersion(min) || !buildidentity.AtLeast(min, ListedFamilyFloor) {
		return true, fmt.Errorf("the package carries changelog.listed_entries but its minClientVersion is absent or below %s", ListedFamilyFloor)
	}
	return true, nil
}
