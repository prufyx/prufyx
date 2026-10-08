// SPDX-License-Identifier: AGPL-3.0-only

// Package buildidentity contains the small, linker-injected identity surface
// for a Prufyx binary. It deliberately has no filesystem, VCS, environment,
// network, or clock dependencies.
package buildidentity

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// DevelopmentValue is used for values that are not bound to a release
	// input. It is intentionally explicit in the version output.
	DevelopmentValue   = "unbound"
	DevelopmentVersion = "dev"
	DevelopmentProfile = "development"

	// ReleaseStateDevelopment and ReleaseStateRelease are the only release
	// state values emitted by this package.
	ReleaseStateDevelopment = "development"
	ReleaseStateRelease     = "release"

	// IdentityMarkerPrefix and IdentityMarkerSuffix delimit the canonical
	// release identity embedded in every candidate binary.  The payload is a
	// fixed-order, ASCII, pipe-delimited record; all values are constrained by
	// validate and therefore cannot contain the delimiter.  This is an
	// extraction contract for cross-target verification, not a signature.
	IdentityMarkerPrefix = "PRUFYX_BUILD_IDENTITY_V1_BEGIN|"
	IdentityMarkerSuffix = "|PRUFYX_BUILD_IDENTITY_V1_END"

	// UnpinnedTrustRoot is the only trust root value a release identity may
	// carry. A binary is built before any signed statement that could pin a
	// root exists, and nothing in the binary verifies the field, so a digest
	// here would be an unverifiable trust claim copied into `prufyx version`
	// and every report. The knowledge trust root the binary actually
	// enforces is internal/knowledgepin, not this field.
	UnpinnedTrustRoot = "UNPINNED"
)

// These variables are the only linker inputs for release identity. Keep them
// as plain string variables: `go build -ldflags -X` can replace their values
// without making the runtime depend on local build state.
var (
	Version          = DevelopmentVersion
	SourceRevision   = DevelopmentValue
	SourceTreeDigest = DevelopmentValue
	AllowlistDigest  = DevelopmentValue
	BuildProfile     = DevelopmentProfile
	BuildEpoch       = DevelopmentValue
	TrustRootDigest  = DevelopmentValue
	// EmbeddedIdentity is injected with the same linker inputs as the other
	// fields. Report validates it at runtime, making the byte-extractable
	// marker part of the executable's identity rather than dead metadata.
	EmbeddedIdentity = DevelopmentValue
)

// Identity is the path-free data returned by `prufyx version`.
type Identity struct {
	Version          string `json:"version"`
	ReleaseState     string `json:"releaseState"`
	SourceRevision   string `json:"sourceRevision"`
	SourceTreeDigest string `json:"sourceTreeDigest"`
	AllowlistDigest  string `json:"allowlistDigest"`
	BuildProfile     string `json:"buildProfile"`
	BuildEpoch       string `json:"buildEpoch"`
	GoVersion        string `json:"goVersion"`
	TrustRootDigest  string `json:"trustRootDigest"`
	CandidateOnly    bool   `json:"candidateOnly"`
}

var (
	ErrIntegrity = errors.New("build identity integrity failure")
	semverRE     = regexp.MustCompile(`^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionRE   = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	// Profiles are target identities, not free-form labels.  Keeping this
	// vocabulary closed prevents a caller from relabelling a binary for a
	// different platform (or inventing a profile that consumers cannot
	// validate).
	//
	// releaseProfileRE is the strict, Linux-only vocabulary produced by the
	// signed-release pipeline (internal/maintainer/releaseworkflow). Its
	// membership and semantics are unchanged by the addition of the
	// community family below: a community profile can never match this
	// pattern, so it can never be mistaken for, or pass a check that
	// specifically requires, a signed-release profile.
	releaseProfileRE = regexp.MustCompile(`^linux-(?:amd64|arm64)$`)
	// communityProfileRE is the distinct, clearly-labeled family produced by
	// the public GitHub Actions release workflow
	// (.github/workflows/release.yml). It covers every OS/arch pair that
	// workflow builds and reports itself honestly as a community build,
	// never as a signed release.
	communityProfileRE = regexp.MustCompile(`^community-(?:linux|darwin)-(?:amd64|arm64)$`)
)

// Report validates the values currently compiled into the package and
// returns the canonical identity. Development is valid only when all linker
// inputs remain at their explicit development defaults.
func Report() (Identity, error) {
	return ReportForVersion(Version)
}

// ReportForVersion is used by the app seam so existing callers that pass a
// display version continue to behave deterministically. Production passes the
// linker variable itself; all other identity fields still come from this
// package's linker inputs.
func ReportForVersion(version string) (Identity, error) {
	// The app seam historically accepted a display version.  It must never be
	// able to diverge from the linker-bound identity in a release binary.
	if Version != DevelopmentVersion && version != Version {
		return Identity{}, invalid("version", version, "the linker-injected Version")
	}
	values := linkerValues{
		version:          version,
		sourceRevision:   SourceRevision,
		sourceTreeDigest: SourceTreeDigest,
		allowlistDigest:  AllowlistDigest,
		buildProfile:     BuildProfile,
		buildEpoch:       BuildEpoch,
		trustRootDigest:  TrustRootDigest,
	}
	if values.isDevelopment() {
		return Identity{
			Version:          DevelopmentVersion,
			ReleaseState:     ReleaseStateDevelopment,
			SourceRevision:   DevelopmentValue,
			SourceTreeDigest: DevelopmentValue,
			AllowlistDigest:  DevelopmentValue,
			BuildProfile:     DevelopmentProfile,
			BuildEpoch:       DevelopmentValue,
			GoVersion:        runtime.Version(),
			TrustRootDigest:  DevelopmentValue,
			CandidateOnly:    true,
		}, nil
	}

	if err := values.validate(); err != nil {
		return Identity{}, err
	}
	epoch, err := epochInstant(values.buildEpoch)
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{
		Version:          values.version,
		ReleaseState:     ReleaseStateRelease,
		SourceRevision:   values.sourceRevision,
		SourceTreeDigest: values.sourceTreeDigest,
		AllowlistDigest:  values.allowlistDigest,
		BuildProfile:     values.buildProfile,
		BuildEpoch:       epoch,
		GoVersion:        runtime.Version(),
		TrustRootDigest:  values.trustRootDigest,
		CandidateOnly:    true,
	}
	if err := validateEmbeddedIdentity(identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// Marker returns the canonical byte-extractable representation used by the
// release builder. Keep the field order stable: verifiers outside Go use this
// contract when they cannot execute a target architecture.
func Marker(identity Identity) string {
	return IdentityMarkerPrefix + strings.Join([]string{
		identity.Version,
		identity.ReleaseState,
		identity.SourceRevision,
		identity.SourceTreeDigest,
		identity.AllowlistDigest,
		identity.BuildProfile,
		identity.BuildEpoch,
		identity.GoVersion,
		identity.TrustRootDigest,
		strconv.FormatBool(identity.CandidateOnly),
	}, "|") + IdentityMarkerSuffix
}

func validateEmbeddedIdentity(identity Identity) error {
	if EmbeddedIdentity == DevelopmentValue {
		return invalid("embeddedIdentity", EmbeddedIdentity, "the canonical release identity marker")
	}
	if !strings.HasPrefix(EmbeddedIdentity, IdentityMarkerPrefix) || !strings.HasSuffix(EmbeddedIdentity, IdentityMarkerSuffix) {
		return invalid("embeddedIdentity", EmbeddedIdentity, "the canonical release identity marker")
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(EmbeddedIdentity, IdentityMarkerPrefix), IdentityMarkerSuffix)
	parts := strings.Split(payload, "|")
	if len(parts) != 10 || strings.Join(parts, "|") != payload {
		return invalid("embeddedIdentity", EmbeddedIdentity, "the canonical release identity marker")
	}
	want := Marker(identity)
	if EmbeddedIdentity != want {
		return invalid("embeddedIdentity", EmbeddedIdentity, "the linker-bound identity")
	}
	return nil
}

type linkerValues struct {
	version, sourceRevision, sourceTreeDigest, allowlistDigest string
	buildProfile, buildEpoch, trustRootDigest                  string
}

// isDevelopment requires every linker input, the embedded marker included,
// to be at its development default: a release marker in an otherwise
// development binary would be accepted by a verifier that extracts the
// marker bytes while the binary itself reports a development build.
func (v linkerValues) isDevelopment() bool {
	return EmbeddedIdentity == DevelopmentValue &&
		v.version == DevelopmentVersion &&
		v.sourceRevision == DevelopmentValue &&
		v.sourceTreeDigest == DevelopmentValue &&
		v.allowlistDigest == DevelopmentValue &&
		v.buildProfile == DevelopmentProfile &&
		v.buildEpoch == DevelopmentValue &&
		v.trustRootDigest == DevelopmentValue
}

func (v linkerValues) validate() error {
	if !semverRE.MatchString(v.version) {
		return invalid("version", v.version, "a release semantic version (MAJOR.MINOR.PATCH)")
	}
	if !revisionRE.MatchString(v.sourceRevision) {
		return invalid("sourceRevision", v.sourceRevision, "7-64 lowercase hexadecimal revision characters")
	}
	if !digestRE.MatchString(v.sourceTreeDigest) {
		return invalid("sourceTreeDigest", v.sourceTreeDigest, "sha256:<64 lowercase hex characters>")
	}
	if !digestRE.MatchString(v.allowlistDigest) {
		return invalid("allowlistDigest", v.allowlistDigest, "sha256:<64 lowercase hex characters>")
	}
	if !releaseProfileRE.MatchString(v.buildProfile) && !communityProfileRE.MatchString(v.buildProfile) {
		return invalid("buildProfile", v.buildProfile, "a lowercase path-free build profile")
	}
	if _, err := epochInstant(v.buildEpoch); err != nil {
		return err
	}
	if v.trustRootDigest != UnpinnedTrustRoot {
		return invalid("trustRootDigest", v.trustRootDigest, UnpinnedTrustRoot)
	}
	return nil
}

// ValidVersion reports whether value is a version a release identity
// accepts: a semantic version, optionally with a leading "v".
func ValidVersion(value string) bool { return semverRE.MatchString(value) }

// IsReleaseProfile reports whether profile is one of the two Linux profiles
// produced by the strict, signed-release pipeline
// (internal/maintainer/releaseworkflow). A community profile never
// satisfies this.
func IsReleaseProfile(profile string) bool { return releaseProfileRE.MatchString(profile) }

// IsCommunityProfile reports whether profile is a community-release profile
// produced by the public release workflow (.github/workflows/release.yml).
// It never satisfies IsReleaseProfile.
func IsCommunityProfile(profile string) bool { return communityProfileRE.MatchString(profile) }

func token(value string) bool {
	if value == "" || len(value) > 256 || value == DevelopmentValue {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func epochInstant(value string) (string, error) {
	if value == "" || value == DevelopmentValue {
		return "", invalid("buildEpoch", value, "a nonnegative decimal SOURCE_DATE_EPOCH")
	}
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return "", invalid("buildEpoch", value, "a nonnegative decimal SOURCE_DATE_EPOCH")
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 {
		return "", invalid("buildEpoch", value, "a nonnegative decimal SOURCE_DATE_EPOCH")
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
}

func invalid(field, value, want string) error {
	// Keep the value in the error bounded and path-free. The command emits a
	// generic safe error, while package callers still get useful diagnostics.
	if len(value) > 256 {
		value = value[:256]
	}
	return fmt.Errorf("%w: %s %q is not %s", ErrIntegrity, field, value, want)
}
