// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

// Binary-level withhold reasons. A binary with at least one of these has an
// incomplete flag set: its Set says complete=false and the result ledger
// names the reason and the binary directory.
const (
	// ReasonDynamicRegistration: a flag name that is not a plain string
	// literal (variable, constant, concatenation, Sprintf, prefix chain), or
	// a urfave flag literal without a literal Name.
	ReasonDynamicRegistration = "FLAG_DYNAMIC_REGISTRATION"
	// ReasonRegistrationInLoop: a registration inside a for or range body,
	// or in a function called from one.
	ReasonRegistrationInLoop = "FLAG_REGISTRATION_IN_LOOP"
	// ReasonBuildConstrained: a registration in a file with a build
	// constraint or a GOOS/GOARCH file name suffix, or under a runtime.GOOS
	// or runtime.GOARCH branch.
	ReasonBuildConstrained = "FLAG_BUILD_CONSTRAINED"
	// ReasonIdiomUnsupported: an import that is neither standard library,
	// in-module, nor on the reviewed allowlist (see imports.go).
	ReasonIdiomUnsupported = "FLAG_IDIOM_UNSUPPORTED"
	// ReasonInitRegistration: a registration inside init() or inside a
	// function literal (callback), or in a function called from either.
	ReasonInitRegistration = "FLAG_INIT_REGISTRATION"
	// ReasonDelegatedUnresolved: a flag set escapes where it cannot be
	// followed (unresolvable callee, delegation deeper than MaxFollowDepth,
	// returned or stored flag set, registration-shaped call on a receiver
	// that cannot be proven, AddFlag/AddFlagSet).
	ReasonDelegatedUnresolved = "FLAG_DELEGATED_UNRESOLVED"
	// ReasonGlobalFlagsetShared: AddGoFlagSet or InitFlags: flags added by a
	// library are invisible to the source.
	ReasonGlobalFlagsetShared = "FLAG_GLOBAL_FLAGSET_SHARED"
	// ReasonNormalizeFunc: SetNormalizeFunc, so names can be accepted that
	// are not registered.
	ReasonNormalizeFunc = "FLAG_NORMALIZE_FUNC"
	// ReasonDuplicateRegistration: the same name registered twice on one
	// flag set.
	ReasonDuplicateRegistration = "FLAG_DUPLICATE_REGISTRATION"
	// ReasonArgsRewritten: os.Args used other than verbatim os.Args or
	// os.Args[1:] passed to a parser (os.Args[0] is allowed), or SetArgs with
	// a value that is not verbatim os.Args or os.Args[1:].
	ReasonArgsRewritten = "FLAG_ARGS_REWRITTEN"
	// ReasonSetTooLarge: more members than a set fact can hold.
	ReasonSetTooLarge = "MEMBER_SET_TOO_LARGE"
)

// Flag-level withhold reasons. They are listed on the Flag, not in the
// ledger: the flag stays in the registered set (so a later pair check sees it
// as present) but a removal of it cannot be stated.
const (
	// ReasonHasShorthand: the flag has a one-character alias (pflag P
	// variants, urfave one-character alias or "long, c" name, kingpin Short).
	ReasonHasShorthand = "FLAG_HAS_SHORTHAND"
	// ReasonNameNotLong: a one-character name.
	ReasonNameNotLong = "FLAG_NAME_NOT_LONG"
	// ReasonNameUppercase: the name holds an upper-case letter.
	ReasonNameUppercase = "FLAG_NAME_UPPERCASE"
	// ReasonKingpinNegation: a kingpin flag named no-*, which is
	// indistinguishable from the automatic negation of another flag.
	ReasonKingpinNegation = "FLAG_KINGPIN_NEGATION"
	// ReasonReachabilityUnproven: every registration of the name is in a
	// function that no call or reference from main, init or a package-level
	// initialiser reaches (by name). Such a flag may never have been
	// accepted, so its removal is not stated.
	ReasonReachabilityUnproven = "FLAG_REACHABILITY_UNPROVEN"
	// ReasonBuiltinName: help and version, which every flag library may
	// accept without a registration, so that a removed registration does not
	// mean a removed name.
	ReasonBuiltinName = "FLAG_BUILTIN_NAME"
	// ReasonMemberCharset: a name outside the member charset.
	ReasonMemberCharset = "MEMBER_CHARSET"
	// ReasonMemberTooLong: a name longer than MaxMemberBytes.
	ReasonMemberTooLong = "MEMBER_TOO_LONG"
)

// Inventory faults: what the scanner could not read or bound.
const (
	ReasonGoModMissing     = "INVENTORY_FAULT_GO_MOD_MISSING"
	ReasonGoModInvalid     = "INVENTORY_FAULT_GO_MOD_INVALID"
	ReasonTreeMissing      = "INVENTORY_FAULT_TREE_MISSING"
	ReasonNoBinary         = "INVENTORY_FAULT_NO_BINARY"
	ReasonParseError       = "INVENTORY_FAULT_PARSE_ERROR"
	ReasonTooLarge         = "INVENTORY_FAULT_TOO_LARGE"
	ReasonNestedModule     = "INVENTORY_FAULT_NESTED_MODULE"
	ReasonSubmodule        = "INVENTORY_FAULT_SUBMODULE"
	ReasonSourceKind       = "INVENTORY_FAULT_SOURCE_KIND"
	ReasonPackageMissing   = "INVENTORY_FAULT_PACKAGE_MISSING"
	ReasonExclusionUnknown = "INVENTORY_FAULT_EXCLUSION_UNKNOWN"
	ReasonPanic            = "INVENTORY_FAULT_PANIC"
)

// Pair-level codes. Scan never produces them: they belong to the code that
// compares two scans and are defined here so that the vocabulary is one list.
const (
	// ReasonNameStillPresent: the name is still registered by some binary of
	// the newer commit, so its removal from another binary is not a removal
	// from the component.
	ReasonNameStillPresent = "FLAG_NAME_STILL_PRESENT"
	// ReasonRenameCandidate is information only: a rename is an ordinary
	// removal, and "possible replacement" is all a same-target flag proves.
	// Only a MarkDeprecated literal is authoritative about a replacement.
	ReasonRenameCandidate = "FLAG_RENAME_CANDIDATE"
)

// limits bound one scan. Anything above them is withheld, never truncated.
type limits struct {
	dirs, filesPerDir, depth, fileBytes, files, totalBytes, packages, follows int
}

func defaultLimits() limits {
	return limits{dirs: 8192, filesPerDir: 2048, depth: 16, fileBytes: 2 << 20, files: 60000,
		totalBytes: 64 << 20, packages: 4096, follows: 20000}
}

const (
	maxGoModBytes = 1 << 20
	maxNameBytes  = 1024

	// MaxFollowDepth is the most calls a registrar is followed through: a
	// registrar known in function F reaches registrations in functions up
	// to MaxFollowDepth calls below F. One call deeper is
	// ReasonDelegatedUnresolved.
	MaxFollowDepth = 3
	// MaxMemberBytes is the longest flag name that can be a set member.
	MaxMemberBytes = 128
)
