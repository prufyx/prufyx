// SPDX-License-Identifier: AGPL-3.0-only

package cloudeventsstructuredjson

import "time"

type Claim struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Reason     string `json:"reason"`
	Action     string `json:"action"`
}

func Evaluate(profile Profile, observation Observation, evaluatedAt time.Time) Claim {
	if evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC || validateProfile(profile) != nil || observation.Schema != ObservationSchema {
		return unknown("EVALUATION_INPUT_INVALID", "the structured-event observation or evaluation context was not valid")
	}
	rule, ok := profile.Rule()
	if !ok {
		return unknown("PROFILE_NO_APPLICABLE_RULE", "the selected profile contains no active conformance rule")
	}
	expires, _ := parseUTC(rule.EvidenceExpiresAt)
	if !evaluatedAt.Before(expires) {
		return unknown("PROFILE_EVIDENCE_EXPIRED", "the selected rule evidence had expired at evaluation time")
	}
	switch observation.RootAdmission {
	case "unsupported_root_shape":
		return unknown("UNSUPPORTED_ROOT_SHAPE", "the supplied JSON document is not a structured-event object")
	case "duplicate_decoded_root_name":
		return unknown("DUPLICATE_DECODED_ROOT_NAME", "the supplied object repeats an exact decoded top-level member name")
	case "admitted_root_object":
	default:
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the root observation was outside the reviewed subset")
	}
	if observation.EditionAdmission == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the edition observation was unavailable")
	}
	switch *observation.EditionAdmission {
	case "missing_or_invalid":
		return fail("SPECVERSION_REQUIRED_VALID_STRING", "the supplied object does not have a valid nonempty specversion String", "set specversion to a valid CloudEvents edition String; this profile covers edition 1.0")
	case "other_valid_edition":
		return unknown("UNSUPPORTED_STANDARD_EDITION", "the supplied object declares an edition outside this profile")
	case "valid_1_0":
	default:
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the edition observation was outside the reviewed subset")
	}
	if observation.IDIsNonemptyValidString == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the id observation was unavailable")
	}
	if !*observation.IDIsNonemptyValidString {
		return fail("ID_REQUIRED_VALID_STRING", "the supplied 1.0 object does not have a valid nonempty id String", "set id to a valid nonempty CloudEvents String")
	}
	if observation.SourceAdmission == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the source observation was unavailable")
	}
	switch *observation.SourceAdmission {
	case "missing_or_invalid":
		return fail("SOURCE_REQUIRED_NONEMPTY_JSON_STRING", "the supplied 1.0 object does not have a nonempty source JSON string", "set source to the intended nonempty JSON string and separately validate its URI-reference semantics")
	case "repair_detected":
		return unknown("SOURCE_REPAIR_DETECTED", "the supplied source token requires Unicode surrogate repair outside this profile")
	case "admitted_nonempty_json_string":
	default:
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the source observation was outside the reviewed subset")
	}
	if observation.TypeIsNonemptyValidString == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the type observation was unavailable")
	}
	if !*observation.TypeIsNonemptyValidString {
		return fail("TYPE_REQUIRED_VALID_STRING", "the supplied 1.0 object does not have a valid nonempty type String", "set type to a valid nonempty CloudEvents String")
	}
	if observation.DataAndDataBase64NotBothPresent == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the data-member observation was unavailable")
	}
	if !*observation.DataAndDataBase64NotBothPresent {
		return fail("DATA_AND_DATA_BASE64_MUTUALLY_EXCLUSIVE", "the supplied object contains both data and data_base64", "retain only the payload member appropriate for the event representation")
	}
	return Claim{Status: "PASS", ReasonCode: "STRUCTURED_JSON_CORE_ENVELOPE_SUBSET_PASS", Reason: "the supplied object satisfies this structured JSON core-envelope subset", Action: "continue separate validation of source URI-reference semantics, payload, extensions, transport, SDK, signing, delivery, authentication, and runtime behavior"}
}

func fail(code, reason, action string) Claim {
	return Claim{Status: "FAIL", ReasonCode: code, Reason: reason, Action: action}
}
func unknown(code, reason string) Claim {
	if code == "" {
		code = "OBSERVATION_NOT_IN_REVIEWED_SUBSET"
	}
	return Claim{Status: "UNKNOWN", ReasonCode: code, Reason: reason, Action: "review the complete CloudEvents event, transport, and runtime requirements outside this named subset"}
}
func ClaimExit(claim Claim) int {
	switch claim.Status {
	case "PASS":
		return 0
	case "FAIL":
		return 10
	default:
		return 11
	}
}
