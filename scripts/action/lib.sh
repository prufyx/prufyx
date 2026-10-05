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
