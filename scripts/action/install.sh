#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs the prufyx binary for the composite GitHub Action.
#
# Inputs (environment):
#   PRUFYX_IN_VERSION          a release tag such as v0.1.0, or "source"
#   PRUFYX_IN_ARCHIVE_SHA256   optional pinned SHA-256 of the release archive
#   PRUFYX_IN_VERIFY_ATTESTATION   auto (default), true or false
#   GH_TOKEN                   token for `gh attestation verify`
#   PRUFYX_ACTION_PATH         the action's own checkout (for "source")
#   RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP   set by the runner
# Output: $RUNNER_TEMP/prufyx-action/bin/prufyx
#
# The download path fails closed: any missing release, missing checksum,
# checksum mismatch or unexpected archive layout stops the job. Nothing is
# executed before the archive digest has been verified.
set -euo pipefail
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=lib.sh
. "$here/lib.sh"

version="${PRUFYX_IN_VERSION:-}"
pin="${PRUFYX_IN_ARCHIVE_SHA256:-}"
temp="${RUNNER_TEMP:?RUNNER_TEMP is not set}"
bindir="$temp/prufyx-action/bin"
verify="${PRUFYX_IN_VERIFY_ATTESTATION:-auto}"
# The token is only for `gh attestation verify`. Take it out of the
# environment so curl, tar and the source build never see it.
gh_token="${GH_TOKEN:-}"
unset GH_TOKEN GITHUB_TOKEN
repo_url="https://github.com/prufyx/prufyx/releases/download"
attest_repo="prufyx/prufyx"
attest_workflow="prufyx/prufyx/.github/workflows/release.yml"

[ -n "$version" ] || die "input 'version' is empty; pass a release tag such as v0.1.0, or 'source'"
if has_control "$version" || [ "$(printf '%s' "$version" | wc -l)" -gt 0 ]; then
  die "input 'version' has a control character or a newline"
fi
if [ -n "$pin" ] && ! grep -Eqx '[0-9a-f]{64}' <<<"$pin"; then
  die "input 'archive-sha256' must be 64 lowercase hexadecimal characters"
fi

case "$verify" in
  auto | true | false) ;;
  *) die "input 'verify-attestation' must be auto, true or false" ;;
esac
# Without the attestation the checksum comes from the same release as the
# archive, so it proves nothing about who built it. Turning the check off is
# only accepted together with a pin the caller holds.
if [ "$verify" = false ] && [ "$version" != source ] && [ -z "$pin" ]; then
  die "'verify-attestation: false' needs 'archive-sha256': without the attestation the release's own checksum is the only check, so pin the archive digest"
fi

# Only the binary and download directories are replaced: report files of an
# earlier use of the action in the same job stay.
prepare_workdir
rm -rf "$temp/prufyx-action/bin" "$temp/prufyx-action/download"
mkdir -p "$bindir"
chmod 700 "$bindir"

if [ "$version" = "source" ]; then
  [ "$verify" != true ] || die "'verify-attestation: true' needs a release archive and cannot be used with version 'source'"
  [ -z "$pin" ] || die "'archive-sha256' applies to a release archive and cannot be used with version 'source'"
  src="${PRUFYX_ACTION_PATH:?PRUFYX_ACTION_PATH is not set}/cli"
  [ -f "$src/go.mod" ] || die "version 'source' needs the Prufyx source tree at the action's ref, but cli/go.mod was not found"
  command -v go >/dev/null 2>&1 || die "version 'source' needs Go on the runner; the action sets it up from cli/go.mod"
  (cd "$src" && GOWORK=off GOTOOLCHAIN=local GOENV=off GOFLAGS="-mod=vendor" CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$bindir/prufyx" ./cmd/prufyx-community) \
    || die "building prufyx from source failed"
  echo "built prufyx from the action's source tree"
  exit 0
fi

if [ "$version" = "latest" ]; then
  die "version 'latest' is not accepted: pin a release tag so the binary and its checksum are reproducible"
fi
if ! grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?' <<<"$version"; then
  die "input 'version' must be a release tag like v0.1.0, or 'source'"
fi

case "${RUNNER_OS:-}" in
  Linux) goos=linux ;;
  macOS) goos=darwin ;;
  *) die "unsupported runner OS; the release archives are built for Linux and macOS" ;;
esac
case "${RUNNER_ARCH:-}" in
  X64) goarch=amd64 ;;
  ARM64) goarch=arm64 ;;
  *) die "unsupported runner architecture; the release archives are built for x64 and arm64" ;;
esac

name="prufyx_${version}_${goos}_${goarch}"
archive="$name.tar.gz"
dl="$temp/prufyx-action/download"
mkdir -p "$dl"

fetch() { # fetch URL DEST
  curl -q --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 2 --connect-timeout 20 --max-time 300 --output "$2" "$1"
}
no_release() {
  die "could not download $1 for release $version. If that release does not exist yet (for example no release has been published), use 'version: source' to build from the action's own ref. Nothing was installed."
}

fetch "$repo_url/$version/SHA256SUMS" "$dl/SHA256SUMS" 2>/dev/null || no_release SHA256SUMS
fetch "$repo_url/$version/$archive" "$dl/$archive" 2>/dev/null || no_release "$archive"

# Exactly one checksum line must name the archive.
count="$(awk -v f="$archive" '$2==f || $2=="*" f {n++} END{print n+0}' "$dl/SHA256SUMS")"
[ "$count" = "1" ] || die "SHA256SUMS for $version does not list $archive exactly once; refusing to install"
want="$(awk -v f="$archive" '$2==f || $2=="*" f {print $1}' "$dl/SHA256SUMS")"
grep -Eqx '[0-9a-f]{64}' <<<"$want" || die "SHA256SUMS holds a malformed digest for $archive; refusing to install"
got="$(sha256_of "$dl/$archive")"
[ "$got" = "$want" ] || die "checksum mismatch for $archive; refusing to install"
if [ -n "$pin" ] && [ "$got" != "$pin" ]; then
  die "$archive does not match the pinned 'archive-sha256'; refusing to install"
fi

if [ "$verify" = auto ]; then verify=true; fi
if [ "$verify" = true ]; then
  command -v gh >/dev/null 2>&1 || die "attestation check needs the GitHub CLI (gh) on the runner, and it was not found; install it or set 'verify-attestation: false' and pin 'archive-sha256'"
  GH_TOKEN="$gh_token" gh attestation verify "$dl/$archive" --repo "$attest_repo" \
    --signer-workflow "$attest_workflow" --deny-self-hosted-runners --source-ref "refs/tags/$version" >"$dl/attestation.txt" 2>&1 \
    || die "the build attestation of $archive could not be verified for $version; refusing to install"
  echo "build attestation verified"
fi

member="$name/prufyx"
listing="$dl/listing.txt"
tar -tzf "$dl/$archive" >"$listing" 2>/dev/null || die "$archive is not a readable archive; refusing to install"
# No name may appear twice, every entry must be the package directory or one
# plain name inside it (compared as text, not as a pattern).
[ -z "$(sort "$listing" | uniq -d)" ] || die "$archive lists a name more than once; refusing to install"
bad="$(awk -v n="$name" 'BEGIN{p=n "/"}
  $0==n || $0==p {next}
  substr($0,1,length(p))==p { r=substr($0,length(p)+1); if (r!="" && r!=".." && index(r,"/")==0) next }
  {print; exit}' "$listing")"
[ -z "$bad" ] || die "$archive contains unexpected paths; refusing to install"
[ "$(grep -Fxc -- "$member" "$listing")" = 1 ] || die "$archive does not hold $member exactly once; refusing to install"
# Entry types: only plain files and directories (no links, devices, fifos).
# Read without an early-exit reader (grep -q) in a pipe: under pipefail a
# writer that gets SIGPIPE would turn a found link into "no link found".
tar -tvzf "$dl/$archive" >"$dl/listing-types.txt" 2>/dev/null || die "$archive is not a readable archive; refusing to install"
types="$(cut -c1 <"$dl/listing-types.txt" | tr -d 'd-')"
[ -z "$types" ] || die "$archive holds a link or special file; refusing to install"
tar -xzf "$dl/$archive" -C "$dl" "$member"
{ [ -f "$dl/$member" ] && [ ! -L "$dl/$member" ]; } || die "$member is not a regular file; refusing to install"
cp -P "$dl/$member" "$bindir/prufyx"
chmod 755 "$bindir/prufyx"
echo "installed prufyx $version ($goos/$goarch), archive sha256 $got"
