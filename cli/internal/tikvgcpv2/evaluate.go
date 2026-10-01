// SPDX-License-Identifier: AGPL-3.0-only

package tikvgcpv2

import "time"

type Claim struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Reason     string `json:"reason"`
	Action     string `json:"action"`
}

func Evaluate(profile Profile, observation Observation, evaluatedAt time.Time) Claim {
	if evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC || validateProfile(profile) != nil || observation.Schema != ObservationSchema || observation.Component != Component {
		return unknown("EVALUATION_INPUT_INVALID", "the TiKV observation or evaluation context was not valid")
	}
	rule, ok := profile.Rule()
	if !ok {
		return unknown("PROFILE_NO_APPLICABLE_RULE", "the selected profile contains no active target preflight rule")
	}
	expires, _ := parseUTC(rule.EvidenceExpiresAt)
	if !evaluatedAt.Before(expires) {
		return unknown("PROFILE_EVIDENCE_EXPIRED", "the selected rule evidence had expired at evaluation time")
	}
	if observation.TargetVersionClass != CoveredTarget {
		return unknown("TIKV_TARGET_VERSION_NOT_COVERED", "the supplied target version is outside this reviewed profile")
	}
	if !observation.PlannedGCSFullBackupWithWIF {
		return unknown("TIKV_OPERATION_OUTSIDE_REVIEWED_WIF_FULL_BACKUP_SCOPE", "the declared operation is outside the reviewed GCS WIF full-backup scope")
	}
	if observation.BackupGCPV2Enable == nil {
		return unknown("TIKV_GCP_V2_SETTING_NOT_UNAMBIGUOUS_EXPLICIT_BOOLEAN", "the supplied configuration does not contain one unambiguous explicit Boolean GCP v2 backup setting")
	}
	if !*observation.BackupGCPV2Enable {
		return Claim{Status: "BLOCKED", ReasonCode: "TIKV_GCP_V2_WIF_FULL_BACKUP_SETTING_DISABLED", Reason: "the supplied TiKV 8.5.8 configuration explicitly disables GCP v2 backup for the declared GCS WIF full-backup plan", Action: "set exactly one [backup] gcp-v2-enable or gcp_v2_enable Boolean to true, run TiKV --config-check separately, then recheck this plan"}
	}
	return Claim{Status: "PASS", ReasonCode: "TIKV_GCP_V2_WIF_FULL_BACKUP_SETTING_ENABLED", Reason: "the supplied TiKV 8.5.8 configuration explicitly enables GCP v2 backup for the declared GCS WIF full-backup plan", Action: "continue separate validation of credentials, GCS access, backup execution, completion, restore requirements, and runtime safety"}
}

func unknown(code, reason string) Claim {
	return Claim{Status: "UNKNOWN", ReasonCode: code, Reason: reason, Action: "review the complete TiKV configuration and GCS WIF full-backup requirements outside this scoped setting check"}
}

func ClaimExit(claim Claim) int {
	switch claim.Status {
	case "PASS":
		return 0
	case "BLOCKED":
		return 10
	default:
		return 11
	}
}
