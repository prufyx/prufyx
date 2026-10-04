#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Script-level tests for install.sh and run.sh. Uses a fake prufyx binary
# that records its arguments (one per line) and a fake curl, so it needs no
# network and no release. Run: bash scripts/action/test.sh
# (also run by the Go test in cli/internal/actionscript).
set -u
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
root="$(mktemp -d "${TMPDIR:-/tmp}/prufyx-action-test.XXXXXX")"
trap 'rm -rf "$root"' EXIT
fails=0
n=0

ok() { n=$((n + 1)); printf 'ok   %s\n' "$1"; }
bad() { n=$((n + 1)); fails=$((fails + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# new_env prepares an isolated runner directory and fake binary.
new_env() {
  rm -rf "$root/w"
  mkdir -p "$root/w/temp/prufyx-action/bin" "$root/w/fakebin"
  : >"$root/w/out"; : >"$root/w/summary"
  cat >"$root/w/temp/prufyx-action/bin/prufyx" <<'FAKE'
#!/usr/bin/env bash
# fake prufyx: record argv, one per line, per call
for a in "$@"; do printf '%s\n' "$a"; done >>"$FAKE_ARGV"
printf -- '--call--\n' >>"$FAKE_ARGV"
printf '%s' "${FAKE_STDOUT:-fake-report}"
[ -z "${FAKE_STDERR:-}" ] || printf '%s\n' "$FAKE_STDERR" >&2
exit "${FAKE_EXIT:-0}"
FAKE
  chmod +x "$root/w/temp/prufyx-action/bin/prufyx"
  : >"$root/w/argv"
}

# run_scan NAME [VAR=VALUE ...] runs run.sh with a clean environment.
run_scan() {
  RC=0
  env -i PATH="$PATH" HOME="$root/w" RUNNER_TEMP="$root/w/temp" \
    GITHUB_OUTPUT="$root/w/out" GITHUB_STEP_SUMMARY="$root/w/summary" \
    FAKE_ARGV="$root/w/argv" \
    PRUFYX_IN_PATHS=manifests PRUFYX_IN_TO=kubernetes=1.25.3 \
    "$@" bash "$here/run.sh" >"$root/w/log" 2>&1 || RC=$?
}

expect_fail() { # name [message fragment]
  if [ "$RC" -eq 0 ]; then bad "$1" "expected failure, got success"; return; fi
  if [ -n "${2:-}" ] && ! grep -qF -- "$2" "$root/w/log"; then bad "$1" "message lacks '$2': $(cat "$root/w/log")"; return; fi
  if [ -s "$root/w/argv" ]; then bad "$1" "binary was run after a rejected input"; return; fi
  ok "$1"
}
expect_ok() {
  if [ "$RC" -ne 0 ]; then bad "$1" "exit $RC: $(cat "$root/w/log")"; else ok "$1"; fi
}
argv_has() { grep -qxF -- "$1" "$root/w/argv"; }

# --- accepted inputs ---------------------------------------------------------
new_env
run_scan PRUFYX_IN_FROM=$'kubernetes=1.24.17\nfoo=1.2.3' PRUFYX_IN_TO=$'kubernetes=1.25.3' \
  PRUFYX_IN_FORMAT=sarif PRUFYX_IN_REDACT=true PRUFYX_IN_REQUIRE_BASIS=reviewed,mechanical \
  PRUFYX_IN_DISTRIBUTION=official_upstream PRUFYX_IN_RESOURCE_SCOPE_COMPLETE=true \
  PRUFYX_IN_TARGET_API_APPLY_REQUIRED=false PRUFYX_IN_KNOWLEDGE_DB=kdb
expect_ok "valid inputs run"
for want in scan manifests --to kubernetes=1.25.3 --from kubernetes=1.24.17 foo=1.2.3 --redact \
  --require-basis reviewed,mechanical --distribution official_upstream \
  --resource-scope-complete=true --target-api-apply-required=false --knowledge-db kdb --format sarif markdown; do
  argv_has "$want" || bad "valid inputs argv" "missing argument '$want'"
done
grep -q '^verdict=pass$' "$root/w/out" && grep -q '^exit-code=0$' "$root/w/out" && ok "outputs written" || bad outputs "$(cat "$root/w/out")"
[ "$(grep -c -- '--call--' "$root/w/argv")" = 2 ] && ok "second run for markdown summary" || bad "summary run" "calls: $(grep -c -- '--call--' "$root/w/argv")"
[ -s "$root/w/summary" ] && ok "summary written" || bad "summary" "empty"

# --- multiple paths, spaces and shell characters are plain data --------------
new_env
nasty_path="dir with space/it's \"q\" \$(touch $root/PWNED) \`touch $root/PWNED2\` ;&|"
run_scan PRUFYX_IN_PATHS="$nasty_path"$'\nsecond/path'
expect_ok "adversarial path is data"
argv_has "$nasty_path" && argv_has second/path && ok "adversarial path reaches the binary verbatim" || bad "path verbatim" "$(cat "$root/w/argv")"
if [ -e "$root/PWNED" ] || [ -e "$root/PWNED2" ]; then bad "no command execution" "a command substitution ran"; else ok "no command execution"; fi

# --- rejected inputs ---------------------------------------------------------
new_env; run_scan PRUFYX_IN_PATHS=''; expect_fail "empty paths" "paths"
new_env; run_scan PRUFYX_IN_PATHS=$'ok\n--help'; expect_fail "path starting with dash" "must not start"
new_env; run_scan PRUFYX_IN_PATHS=$'a\x01b'; expect_fail "path with control character" "control"
new_env; run_scan PRUFYX_IN_TO=''; expect_fail "missing to" "'to'"
new_env; run_scan PRUFYX_IN_TO='kubernetes=1.25.3 --redact'; expect_fail "to with extra flag" "COMPONENT=VERSION"
new_env; run_scan PRUFYX_IN_TO='kubernetes=$(id)'; expect_fail "to with command substitution" "COMPONENT=VERSION"
new_env; run_scan PRUFYX_IN_TO=$'kubernetes=1.25.3\n--knowledge-db=x'; expect_fail "to with injected flag line" "COMPONENT=VERSION"
new_env; run_scan PRUFYX_IN_FROM='k="1"'; expect_fail "from with quote" "COMPONENT=VERSION"
new_env; run_scan PRUFYX_IN_FORMAT=human; expect_fail "format human" "format"
new_env; run_scan PRUFYX_IN_FORMAT='json; id'; expect_fail "format injection" "format"
new_env; run_scan PRUFYX_IN_REDACT=yes; expect_fail "redact not boolean" "redact"
new_env; run_scan PRUFYX_IN_REQUIRE_BASIS='reviewed,$(id)'; expect_fail "require-basis injection" "require-basis"
new_env; run_scan PRUFYX_IN_REQUIRE_BASIS=$'reviewed\n--redact'; expect_fail "require-basis newline" "require-basis"
new_env; run_scan PRUFYX_IN_KNOWLEDGE_DB='--now=2026-01-01T00:00:00Z'; expect_fail "knowledge-db flag" "must not start"
new_env; run_scan PRUFYX_IN_KNOWLEDGE_DB=$'db\n--redact'; expect_fail "knowledge-db newline" "single line"
new_env; run_scan PRUFYX_IN_CONFIG=-x; expect_fail "config flag" "must not start"
new_env; run_scan PRUFYX_IN_FAIL_ON='blocked;id'; expect_fail "fail-on injection" "fail-on"
new_env; run_scan PRUFYX_IN_DISTRIBUTION=other; expect_fail "distribution" "distribution"
new_env; run_scan PRUFYX_IN_RESOURCE_SCOPE_COMPLETE=maybe; expect_fail "scope bool" "resource-scope-complete"

# A rejected value never lands in a workflow command: the log must not echo it.
new_env
run_scan PRUFYX_IN_FORMAT=$'x\n::set-output name=pwn::1'
if grep -q '^::set-output' "$root/w/log"; then bad "no workflow command echo" "value echoed"; else ok "no workflow command echo"; fi

# --- config can stand in for to ----------------------------------------------
new_env; run_scan PRUFYX_IN_TO='' PRUFYX_IN_CONFIG=prufyx.yaml
expect_ok "config without to"

# --- exit code handling ------------------------------------------------------
new_env; run_scan FAKE_EXIT=10
[ "$RC" -ne 0 ] && grep -q '^verdict=blocked$' "$root/w/out" && ok "blocked fails by default" || bad "blocked default" "rc=$RC"
new_env; run_scan FAKE_EXIT=10 PRUFYX_IN_FAIL_ON=none
[ "$RC" -eq 0 ] && ok "fail-on none passes blocked" || bad "fail-on none" "rc=$RC"
new_env; run_scan FAKE_EXIT=11
[ "$RC" -eq 0 ] && grep -q '^verdict=unknown$' "$root/w/out" && ok "unknown passes by default" || bad "unknown default" "rc=$RC"
new_env; run_scan FAKE_EXIT=11 PRUFYX_IN_FAIL_ON=blocked,unknown
[ "$RC" -ne 0 ] && ok "fail-on unknown fails" || bad "fail-on unknown" "rc=$RC"
new_env; run_scan FAKE_EXIT=3 PRUFYX_IN_FAIL_ON=none
[ "$RC" -ne 0 ] && grep -q '^verdict=integrity-failure$' "$root/w/out" && ok "integrity failure always fails" || bad "integrity" "rc=$RC"
new_env; run_scan FAKE_EXIT=2 PRUFYX_IN_FAIL_ON=none
[ "$RC" -ne 0 ] && ok "invalid input always fails" || bad "invalid input" "rc=$RC"
new_env; run_scan FAKE_EXIT=3
[ ! -s "$root/w/summary" ] && ok "no summary after integrity failure" || bad "summary on failure" "written"
new_env; run_scan FAKE_EXIT=0 FAKE_STDERR=$'note\n::error::forged'
if grep -q '^::error::forged' "$root/w/log"; then bad "stderr cannot form a command" "forged command at line start"; else ok "stderr cannot form a command"; fi

# --- install.sh --------------------------------------------------------------
# Fake curl serves files from $FAKE_SERVE keyed by the last URL path element.
mk_curl() {
  cat >"$root/w/fakebin/curl" <<'CURL'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    --fail|--silent|--show-error|--location) shift ;;
    --proto|--tlsv1.2|--retry|--connect-timeout|--max-time) case "$1" in --tlsv1.2) shift ;; *) shift 2 ;; esac ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >>"$FAKE_CURL_LOG"
f="$FAKE_SERVE/$(basename "$url")"
[ -f "$f" ] || exit 22
cp "$f" "$out"
CURL
  chmod +x "$root/w/fakebin/curl"
}

run_install() {
  RC=0
  rm -rf "$root/w/temp/prufyx-action"; : >"$root/w/curl.log"
  env -i PATH="$root/w/fakebin:$PATH" HOME="$root/w" RUNNER_TEMP="$root/w/temp" \
    RUNNER_OS=Linux RUNNER_ARCH=ARM64 FAKE_SERVE="$root/w/serve" FAKE_CURL_LOG="$root/w/curl.log" \
    "$@" bash "$here/install.sh" >"$root/w/log" 2>&1 || RC=$?
}

mk_release() { # mk_release TAG [member-name] : writes archive + SHA256SUMS into serve/
  local tag="$1" name="prufyx_$1_linux_arm64" member="${2:-}"
  rm -rf "$root/w/serve" "$root/w/pkg"; mkdir -p "$root/w/serve" "$root/w/pkg/$name"
  printf '#!/bin/sh\necho prufyx-fake\n' >"$root/w/pkg/$name/prufyx"; chmod +x "$root/w/pkg/$name/prufyx"
  [ -z "$member" ] || printf 'x' >"$root/w/pkg/$name/$member"
  tar -C "$root/w/pkg" -czf "$root/w/serve/$name.tar.gz" "$name"
  (cd "$root/w/serve" && { sha256sum "$name.tar.gz" 2>/dev/null || shasum -a 256 "$name.tar.gz"; } >SHA256SUMS)
}

new_env; mk_curl
mk_release v0.1.0
run_install PRUFYX_IN_VERSION=v0.1.0
if [ "$RC" -eq 0 ] && [ -x "$root/w/temp/prufyx-action/bin/prufyx" ]; then ok "install verified release"; else bad "install" "rc=$RC $(cat "$root/w/log")"; fi

want="$(awk '{print $1}' "$root/w/serve/SHA256SUMS")"
run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_IN_ARCHIVE_SHA256="$want"
[ "$RC" -eq 0 ] && ok "install with matching pin" || bad "pin match" "$(cat "$root/w/log")"
run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_IN_ARCHIVE_SHA256="$(printf 'a%.0s' $(seq 64))"
if [ "$RC" -ne 0 ] && [ ! -e "$root/w/temp/prufyx-action/bin/prufyx" ] && grep -q pinned "$root/w/log"; then ok "install with wrong pin fails"; else bad "pin mismatch" "rc=$RC"; fi

# checksum mismatch
mk_release v0.1.0
printf '%s  prufyx_v0.1.0_linux_arm64.tar.gz\n' "$(printf '0%.0s' $(seq 64))" >"$root/w/serve/SHA256SUMS"
run_install PRUFYX_IN_VERSION=v0.1.0
if [ "$RC" -ne 0 ] && [ ! -e "$root/w/temp/prufyx-action/bin/prufyx" ] && grep -q 'checksum mismatch' "$root/w/log"; then ok "checksum mismatch fails closed"; else bad "mismatch" "rc=$RC $(cat "$root/w/log")"; fi

# archive not listed
mk_release v0.1.0
printf '%s  other.tar.gz\n' "$(printf '0%.0s' $(seq 64))" >"$root/w/serve/SHA256SUMS"
run_install PRUFYX_IN_VERSION=v0.1.0
[ "$RC" -ne 0 ] && grep -q 'exactly once' "$root/w/log" && ok "unlisted archive fails" || bad "unlisted" "rc=$RC"

# no release exists
rm -rf "$root/w/serve"; mkdir -p "$root/w/serve"
run_install PRUFYX_IN_VERSION=v9.9.9
if [ "$RC" -ne 0 ] && grep -q "version: source" "$root/w/log" && [ ! -e "$root/w/temp/prufyx-action/bin/prufyx" ]; then ok "no release fails closed with a clear message"; else bad "no release" "rc=$RC $(cat "$root/w/log")"; fi

# unexpected extra member in the archive
mk_release v0.1.0 extra.txt
run_install PRUFYX_IN_VERSION=v0.1.0
[ "$RC" -eq 0 ] && ok "extra file in the package directory is not extracted" || bad "extra member" "$(cat "$root/w/log")"
[ ! -e "$root/w/temp/prufyx-action/download/prufyx_v0.1.0_linux_arm64/extra.txt" ] && ok "only the binary is extracted" || bad "extract scope" "extra.txt extracted"

# version validation
for v in latest v1 '1.2.3' 'v1.2.3;id' 'v1.2.3 ' "v1.2.3\$(id)" '../v1.2.3' ''; do
  run_install PRUFYX_IN_VERSION="$v"
  label="$(printf '%s' "$v" | tr -d '\000-\037')"
  if [ "$RC" -ne 0 ] && grep -Eq "release tag|is empty|not accepted" "$root/w/log" && [ ! -s "$root/w/curl.log" ]; then ok "version rejected before any download: $label"; else bad "version $label" "rc=$RC $(cat "$root/w/log")"; fi
done
run_install PRUFYX_IN_VERSION=$'v1.2.3\nv1.2.4'
[ "$RC" -ne 0 ] && [ ! -s "$root/w/curl.log" ] && ok "version with newline rejected" || bad "version newline" "accepted"
run_install PRUFYX_IN_VERSION=v0.1.0 RUNNER_OS=Windows
[ "$RC" -ne 0 ] && ok "unsupported OS rejected" || bad "os" "accepted"
run_install PRUFYX_IN_VERSION=source PRUFYX_IN_ARCHIVE_SHA256="$(printf 'a%.0s' $(seq 64))"
[ "$RC" -ne 0 ] && ok "pin with source rejected" || bad "pin+source" "accepted"

printf '\n%s checks, %s failed\n' "$n" "$fails"
[ "$fails" -eq 0 ]
