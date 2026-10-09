#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared helpers for the Prufyx composite GitHub Action (action.yml).
# Sourced by install.sh and run.sh. Every value that reaches these scripts
# arrives in an environment variable and is only ever expanded inside double
# quotes or "${array[@]}"; nothing is passed to eval, a shell string or a
# workflow command.

# emit_untrusted copies standard input to standard output inside a
# stop-commands block with an unguessable token, so nothing in the text can
# act as a workflow command. Control characters are removed and the legacy
# "##[" command form is broken as well (belt and braces: the token already
# makes the runner ignore commands inside the block).
emit_untrusted() {
  local token
  token="$(LC_ALL=C head -c 24 /dev/urandom | LC_ALL=C od -An -tx1 | LC_ALL=C tr -d ' \n')"
  [ "${#token}" -ge 32 ] || die "could not create a random token"
  printf '::stop-commands::%s\n' "$token"
  LC_ALL=C tr -d '\000-\010\013-\037\177' | sed 's/##\[/# #[/g'
  # Always start the end token on its own line, even when the text has no
  # trailing newline.
  printf '\n::%s::\n' "$token"
}

# die reports an error and stops. The message must not contain raw input.
die() {
  printf '::error title=Prufyx::%s\n' "$*" >&2
  exit "${PRUFYX_DIE_STATUS:-1}"
}

# has_control returns 0 when the value holds a control character other than
# a newline (carriage return, tab and NUL-adjacent bytes are refused).
has_control() {
  # Pure bash: no forked tool whose failure could read as "no control character".
  local LC_ALL=C v="${1//$'\n'/}"
  case "$v" in *[[:cntrl:]]*) return 0 ;; esac
  return 1
}

# split_lines reads a newline separated input into the named array, dropping
# blank lines and trimming surrounding spaces.
split_lines() {
  local __name="$1" __text="$2" __line
  eval "$__name=()"
  while IFS= read -r __line || [ -n "$__line" ]; do
    __line="${__line#"${__line%%[![:space:]]*}"}"
    __line="${__line%"${__line##*[![:space:]]}"}"
    [ -n "$__line" ] || continue
    eval "$__name+=(\"\$__line\")"
  done <<<"$__text"
}

# sha256_of prints the SHA-256 of a file as 64 lowercase hex characters.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "no sha256sum or shasum on this runner; cannot verify the download"
  fi
}

# prepare_workdir checks RUNNER_TEMP and creates a private
# $RUNNER_TEMP/prufyx-action owned by the current user. It refuses a value
# with a newline or control character (the path is written to GITHUB_OUTPUT),
# a relative path, and a symlink or foreign-owned directory left there by an
# earlier step (rm -rf and chmod would follow it). Files are created with
# umask 077 whatever the runner's umask is.
prepare_workdir() {
  umask 077
  local temp="${RUNNER_TEMP:?RUNNER_TEMP is not set}" base
  if has_control "$temp" || [[ "$temp" == *$'\n'* ]]; then
    die "RUNNER_TEMP has a control character or a newline"
  fi
  case "$temp" in /*) ;; *) die "RUNNER_TEMP must be an absolute path" ;; esac
  base="$temp/prufyx-action"
  if [ -L "$base" ]; then die "$base is a symbolic link; refusing to use it"; fi
  mkdir -p "$base"
  { [ -d "$base" ] && [ -O "$base" ]; } || die "$base is not a directory owned by the current user; refusing to use it"
  chmod 700 "$base"
}
