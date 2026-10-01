// SPDX-License-Identifier: AGPL-3.0-only

package spiffex509svid

import "time"

type Claim struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Reason     string `json:"reason"`
	Action     string `json:"action"`
}

func Evaluate(profile Profile, observation Observation, evaluatedAt time.Time) Claim {
	if evaluatedAt.IsZero() || evaluatedAt.Location() != time.UTC || validateProfile(profile) != nil || observation.Schema != ObservationSchema {
		return unknown("EVALUATION_INPUT_INVALID", "the conformance observation or evaluation context was not valid")
	}
	rule, ok := profile.Rule()
	if !ok {
		return unknown("PROFILE_NO_APPLICABLE_RULE", "the selected profile contains no active conformance rule")
	}
	expires, _ := parseUTC(rule.EvidenceExpiresAt)
	if !evaluatedAt.Before(expires) {
		return unknown("PROFILE_EVIDENCE_EXPIRED", "the selected rule evidence had expired at evaluation time")
	}
	if observation.IsCA {
		return unknown("CERTIFICATE_NOT_PUBLIC_LEAF", "the supplied certificate is a CA certificate, outside this public-leaf subset")
	}
	if observation.URISANCardinality == nil {
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the supplied certificate is outside the reviewed URI-SAN subset")
	}
	switch *observation.URISANCardinality {
	case "zero":
		return fail("SPIFFE_URI_SAN_MISSING", "the supplied public leaf has no URI SAN", "issue a public leaf with exactly one URI SAN for this named subset")
	case "multiple":
		return fail("SPIFFE_URI_SAN_MULTIPLE", "the supplied public leaf has multiple URI SANs", "issue a public leaf with exactly one URI SAN for this named subset")
	case "one":
	default:
		return unknown("OBSERVATION_NOT_IN_REVIEWED_SUBSET", "the URI-SAN observation was outside the reviewed subset")
	}
	if observation.URISANSchemeIsSPIFFE == nil {
		return unknown("URI_SAN_SHAPE_NOT_IN_REVIEWED_SUBSET", "the sole URI SAN uses a representation outside the reviewed subset")
	}
	if !*observation.URISANSchemeIsSPIFFE {
		return fail("SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE", "the sole URI SAN does not use the lowercase spiffe scheme", "issue a public leaf whose sole URI SAN uses the spiffe scheme")
	}
	if observation.URISANPathIsNonRoot == nil {
		return unknown("URI_SAN_SHAPE_NOT_IN_REVIEWED_SUBSET", "the sole SPIFFE URI SAN path could not be assessed in the reviewed subset")
	}
	if !*observation.URISANPathIsNonRoot {
		return fail("SPIFFE_ID_ROOT_PATH", "the sole SPIFFE URI SAN identifies the trust-domain root", "issue a public leaf whose sole SPIFFE URI SAN has a non-root path")
	}
	return Claim{Status: "PASS", ReasonCode: "SPIFFE_PUBLIC_LEAF_URI_SAN_PROFILE_SATISFIED", Reason: "the supplied public non-CA leaf has exactly one reviewed-form SPIFFE URI SAN with a non-root path", Action: "continue the separate checks for chain, signature, issuer, trust bundle, possession, authentication, issuance, and runtime use"}
}

func fail(code, reason, action string) Claim {
	return Claim{Status: "FAIL", ReasonCode: code, Reason: reason, Action: action}
}
func unknown(code, reason string) Claim {
	if code == "" {
		code = "OBSERVATION_NOT_IN_REVIEWED_SUBSET"
	}
	return Claim{Status: "UNKNOWN", ReasonCode: code, Reason: reason, Action: "review the complete SPIFFE X.509-SVID and deployment requirements outside this named subset"}
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
