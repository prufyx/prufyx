#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared helpers for the Prufyx composite GitHub Action (action.yml).
# Sourced by install.sh and run.sh. Every value that reaches these scripts
# arrives in an environment variable and is only ever expanded inside double
# quotes or "${array[@]}"; nothing is passed to eval, a shell string or a
# workflow command.

# show prints a value for a message with control characters removed and a
# length limit, so an input value cannot add a workflow command (::...::) or
# extra lines to the log.
show() {
  local v
  v="$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177' | cut -c1-80)"
  printf '%s' "$v"
}

# die reports an error and stops. The message must not contain raw input.
die() {
  printf '::error title=Prufyx::%s\n' "$*" >&2
  exit "${PRUFYX_DIE_STATUS:-1}"
}

# has_control returns 0 when the value holds a control character other than
# a newline (carriage return, tab and NUL-adjacent bytes are refused).
has_control() {
  [ -n "$(printf '%s' "$1" | LC_ALL=C tr -d '\n' | LC_ALL=C tr -cd '\000-\037\177')" ]
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
