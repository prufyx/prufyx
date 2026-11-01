// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

// Withhold reasons. A pair with at least one of these is not complete: the
// fact says complete=false and the reasons travel in the report omissions.
const (
	ReasonParseUnproven   = "CRD_PARSE_UNPROVEN"
	ReasonTooLarge        = "CRD_TOO_LARGE"
	ReasonConversion      = "CRD_CONVERSION_WEBHOOK"
	ReasonVersionSpecific = "CRD_FIELD_VERSION_SPECIFIC"
	ReasonPresence        = "CRD_PRESENCE_UNSTABLE"
	ReasonPreserveUnknown = "PRESERVE_UNKNOWN"
	ReasonRename          = "RENAME_CANDIDATE"
	ReasonSecret          = "SECRET_KIND"
	ReasonNonCRD          = "NON_CRD_DOCUMENT"
	ReasonPathMissing     = "INVENTORY_FAULT_path_missing"
	ReasonSourceKind      = "INVENTORY_FAULT_source_kind"
	ReasonUnlistedSubtree = "INVENTORY_FAULT_unlisted_subtree"
	ReasonMemberCharset   = "MEMBER_CHARSET"
	ReasonMemberTooLong   = "MEMBER_TOO_LONG"
	ReasonMemberAmbiguous = "MEMBER_AMBIGUOUS"
	ReasonSetTooLarge     = "MEMBER_SET_TOO_LARGE"
)

// ReasonStatusPath is a scope exclusion, not a withhold: a removal under
// status is listed in the ledger and does not make the pair incomplete. It
// applies to every CRD, whether or not it declares a status subresource.
const ReasonStatusPath = "CRD_STATUS_PATH"

// Limits. Anything above them is withheld, never truncated.
const (
	maxFileBytes   = 8 << 20
	maxYAMLNodes   = 4_000_000
	maxYAMLDepth   = 200
	maxSchemaNodes = 400_000
	maxSchemaDepth = 64
	maxDocuments   = 256
	maxDirEntries  = 1024
)
