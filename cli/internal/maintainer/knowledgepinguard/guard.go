// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgepinguard decides, before anything is signed, whether the
// oldest-supported-client pin of the knowledge feed may be advertised.
//
// The pin names the client release that the feed promises to keep readable.
// Moving it to a release that does not exist yet (or exists only as a draft,
// or was built from another commit, or was not attested by the release
// workflow) would make the feed unreadable for every client. The guard
// refuses, closed, in every one of those cases and leaves the last package
// in place. It holds no secret and only reads.
package knowledgepinguard

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
)

// ExitCode is the distinct process exit code of a refusal.
const ExitCode = 21

// SignerWorkflow is the only workflow whose attestations are accepted.
const SignerWorkflow = "prufyx/prufyx/.github/workflows/release.yml"

// ChecksumAsset lists every other release asset with its digest.
const ChecksumAsset = "SHA256SUMS"

// LegacyPin is the pin that predates the release procedure (the first beta).
// While the pin file holds exactly these bytes the guard checks the file only,
// so an unchanged pin behaves as it always did.
const LegacyPin = "ref=0a58fd2c5741d82cb9cd0c84deadad9eb627370f\nversion=v0.1.0-beta.0\n"

// LegacyVersion is the version of LegacyPin and the floor when no earlier pin
// can be found.
const LegacyVersion = "v0.1.0-beta.0"

var (
	refRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	assetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

// Refusal is a guard failure that must stop the publish.
type Refusal struct{ Msg string }

func (r *Refusal) Error() string { return r.Msg }

func refuse(format string, a ...any) error { return &Refusal{Msg: fmt.Sprintf(format, a...)} }

// Asset is one release asset.
type Asset struct {
	Name string
	Size int64
}

// Release is a published GitHub release.
type Release struct {
	TagName string
	Draft   bool
	// Immutable is nil when the API does not expose the setting.
	Immutable *bool
	Assets    []Asset
}

// Forge is everything the guard reads. Every method fails closed: an error is
// a refusal, never a pass.
type Forge interface {
	// Release returns the published release of tag, or nil when there is none
	// (a draft is not returned by the API either).
	Release(tag string) (*Release, error)
	// TagCommit resolves the tag now to a commit id.
	TagCommit(tag string) (string, error)
	// OnMain reports whether the commit is an ancestor of (or is) main.
	OnMain(commit string) (bool, error)
	// VerifyAssets proves every asset of the release is attested by the
	// release workflow for refs/tags/<tag> at commit.
	VerifyAssets(tag, commit string, r *Release) error
	// PreviousPin is the version of the pin at the last successful publish.
	PreviousPin() (version string, found bool, err error)
}

// Options are the explicit owner inputs. Both default to off.
type Options struct {
	// AllowDowngrade lets the pin version be lower than the last published pin.
	AllowDowngrade bool
}

// Result describes an accepted pin.
type Result struct {
	Version   string
	Ref       string
	Legacy    bool
	Downgrade bool
	Notes     []string
}

// ParsePin reads a pin file: exactly the lines ref=<40 hex> and version=<v>.
func ParsePin(raw []byte) (ref, version string, err error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return "", "", errors.New("the pin file is empty or larger than 1 KiB")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		return "", "", errors.New("the pin file must hold exactly the lines ref= and version=")
	}
	r, ok1 := strings.CutPrefix(lines[0], "ref=")
	v, ok2 := strings.CutPrefix(lines[1], "version=")
	if !ok1 || !ok2 || !refRE.MatchString(r) || !buildidentity.ValidVersion(v) {
		return "", "", errors.New("the pin file must hold ref=<40-hex commit> and version=vMAJOR.MINOR.PATCH[-pre.N]")
	}
	return r, v, nil
}

// Check applies the guard to the pin file bytes.
func Check(raw []byte, f Forge, o Options) (Result, error) {
	ref, version, err := ParsePin(raw)
	if err != nil {
		return Result{}, refuse("pin refused: %v", err)
	}
	res := Result{Version: version, Ref: ref}

	prev, found, err := f.PreviousPin()
	if err != nil {
		return res, refuse("pin refused: the last published pin cannot be read: %v", err)
	}
	if !found {
		prev = LegacyVersion
	}
	if !buildidentity.ValidVersion(prev) {
		return res, refuse("pin refused: the last published pin version %q is not a version", prev)
	}
	if !buildidentity.AtLeast(version, prev) {
		if !o.AllowDowngrade {
			return res, refuse("pin refused: %s is lower than the last published pin %s; moving the pin back needs the owner-only allow_pin_downgrade input", version, prev)
		}
		res.Downgrade = true
		res.Notes = append(res.Notes, fmt.Sprintf("OWNER OVERRIDE: pin moved back from %s to %s", prev, version))
	}

	if string(raw) == LegacyPin {
		res.Legacy = true
		return res, nil
	}

	if !refRE.MatchString(ref) {
		return res, refuse("pin refused: ref is not a 40-hex commit")
	}
	rel, err := f.Release(version)
	if err != nil {
		return res, refuse("pin refused: the release %s cannot be read: %v", version, err)
	}
	if rel == nil {
		return res, refuse("pin refused: %s is not a published release of this repository; publish the release first, then move the pin", version)
	}
	if rel.Draft {
		return res, refuse("pin refused: release %s is a draft", version)
	}
	if rel.TagName != version {
		return res, refuse("pin refused: the release found is for tag %q, not %s", rel.TagName, version)
	}
	switch {
	case rel.Immutable == nil:
		res.Notes = append(res.Notes, "residual: the API does not expose release/tag immutability; tag protection is not checked")
	case !*rel.Immutable:
		return res, refuse("pin refused: release %s is not immutable (a mutable release or tag can be moved after the pin); enable immutable releases and cut again", version)
	}
	commit, err := f.TagCommit(version)
	if err != nil {
		return res, refuse("pin refused: tag %s cannot be resolved: %v", version, err)
	}
	if !refRE.MatchString(commit) || commit != ref {
		return res, refuse("pin refused: tag %s resolves to %s, not to the pinned ref %s", version, commit, ref)
	}
	on, err := f.OnMain(ref)
	if err != nil {
		return res, refuse("pin refused: cannot tell whether %s is on main: %v", ref, err)
	}
	if !on {
		return res, refuse("pin refused: the pinned ref %s is not an ancestor of main", ref)
	}
	if err := f.VerifyAssets(version, ref, rel); err != nil {
		return res, refuse("pin refused: %v", err)
	}
	return res, nil
}
