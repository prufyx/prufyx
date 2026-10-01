// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

var cephOSDIDRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// PrepareSelectedOSDMetadata inspects one caller-selected current-side OSD
// metadata object. complete is limited to that object; it says nothing about
// other OSDs, cluster inventory, or the target deployment.
func PrepareSelectedOSDMetadata(project string, raw []byte, selectedID, from, to string, complete bool) (Prepared, error) {
	if project != CephProject || len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validCephOSDID(selectedID) || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	filestore, supported, err := cephSelectedObjectStore(raw, selectedID)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: CephFact, State: "unsupported"}
	state, reason := "UNKNOWN", "SELECTED_CURRENT_OSD_METADATA_INCOMPLETE_OR_UNSUPPORTED"
	if complete && supported {
		fact = inputFact{ID: CephFact, State: "declared", BoolValue: &filestore}
		state, reason = "PREPARED", "SELECTED_CURRENT_OSD_OBJECTSTORE_INSPECTED"
	}
	canonical, err := marshalInputSides(CephComponent, from, to, []inputFact{fact}, nil)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SELECTED_CURRENT_OSD_METADATA_NOT_LIVE_OBSERVATION",
			"OTHER_OSDS_AND_CLUSTER_INVENTORY_NOT_ASSESSED",
			"TARGET_DEPLOYMENT_AND_RUNTIME_NOT_OBSERVED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func cephSelectedObjectStore(raw []byte, selectedID string) (bool, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return false, false, ErrInvalid
	}
	if token, extra := decoder.Token(); extra != io.EOF || token != nil {
		return false, false, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok || hasCaseVariant(object, "id") || hasCaseVariant(object, "osd_objectstore") {
		return false, false, nil
	}
	id, ok := object["id"].(json.Number)
	if !ok || !validCephOSDID(id.String()) || id.String() != selectedID {
		return false, false, nil
	}
	store, ok := object["osd_objectstore"].(string)
	if !ok {
		return false, false, nil
	}
	switch store {
	case "filestore":
		return true, true, nil
	case "bluestore":
		return false, true, nil
	default:
		return false, false, nil
	}
}

func validCephOSDID(value string) bool {
	if !cephOSDIDRE.MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && parsed >= 0
}
