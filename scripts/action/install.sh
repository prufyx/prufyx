#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs the prufyx binary for the composite GitHub Action.
#
# Inputs (environment):
#   PRUFYX_IN_VERSION          a release tag such as v0.1.0, or "source"
#   PRUFYX_IN_ARCHIVE_SHA256   optional pinned SHA-256 of the release archive
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
repo_url="${PRUFYX_RELEASE_BASE:-https://github.com/prufyx/prufyx/releases/download}"

[ -n "$version" ] || die "input 'version' is empty; pass a release tag such as v0.1.0, or 'source'"
if has_control "$version" || [ "$(printf '%s' "$version" | wc -l)" -gt 0 ]; then
  die "input 'version' has a control character or a newline"
fi
if [ -n "$pin" ] && ! printf '%s' "$pin" | grep -Eqx '[0-9a-f]{64}'; then
  die "input 'archive-sha256' must be 64 lowercase hexadecimal characters"
fi

rm -rf "$temp/prufyx-action"
mkdir -p "$bindir"
chmod 700 "$temp/prufyx-action" "$bindir"

if [ "$version" = "source" ]; then
  [ -z "$pin" ] || die "'archive-sha256' applies to a release archive and cannot be used with version 'source'"
  src="${PRUFYX_ACTION_PATH:?PRUFYX_ACTION_PATH is not set}/cli"
  [ -f "$src/go.mod" ] || die "version 'source' needs the Prufyx source tree at the action's ref, but cli/go.mod was not found"
  command -v go >/dev/null 2>&1 || die "version 'source' needs Go on the runner; the action sets it up from cli/go.mod"
  (cd "$src" && GOFLAGS="-mod=vendor" CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$bindir/prufyx" ./cmd/prufyx-community) \
    || die "building prufyx from source failed"
  echo "built prufyx from the action's source tree"
  exit 0
fi

if [ "$version" = "latest" ]; then
  die "version 'latest' is not accepted: pin a release tag so the binary and its checksum are reproducible"
fi
if ! printf '%s' "$version" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?'; then
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
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
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
printf '%s' "$want" | grep -Eqx '[0-9a-f]{64}' || die "SHA256SUMS holds a malformed digest for $archive; refusing to install"
got="$(sha256_of "$dl/$archive")"
[ "$got" = "$want" ] || die "checksum mismatch for $archive; refusing to install"
if [ -n "$pin" ] && [ "$got" != "$pin" ]; then
  die "$archive does not match the pinned 'archive-sha256'; refusing to install"
fi

member="$name/prufyx"
# The archive must hold the expected file and nothing outside its directory.
if tar -tzf "$dl/$archive" | grep -Evx "$name/?|$name/[A-Za-z0-9._-]+" | grep -q .; then
  die "$archive contains unexpected paths; refusing to install"
fi
tar -tvzf "$dl/$archive" "$member" | grep -q '^-' || die "$archive does not hold a regular file $member; refusing to install"
tar -xzf "$dl/$archive" -C "$dl" "$member"
cp "$dl/$member" "$bindir/prufyx"
chmod 755 "$bindir/prufyx"
echo "installed prufyx $version ($goos/$goarch), archive sha256 $got"
