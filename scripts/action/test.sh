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
# --- workflow commands in tool output ----------------------------------------
# unquoted_commands prints lines that the runner would treat as workflow
# commands: it models stop-commands blocks, and allows only the action's own
# fixed-text annotations (title=Prufyx) and the stop-commands markers.
unquoted_commands() { # unquoted_commands LOGFILE
  awk '
    stopped != "" { if ($0 == "::" stopped "::") stopped = ""; next }
    { line = $0; sub(/^[ \t]+/, "", line) }
    line ~ /^::stop-commands::[0-9a-f]+$/ { t = line; sub(/^::stop-commands::/, "", t); if (length(t) < 32) print "SHORT-TOKEN: " $0; stopped = t; next }
    line ~ /^::(error|warning|notice) title=Prufyx::/ { next }
    line ~ /^::/ || line ~ /^##\[/ { print }
  ' "$1"
}
check_stderr_case() { # check_stderr_case NAME STDERR
  new_env; run_scan FAKE_EXIT=2 FAKE_STDERR="$2"
  out="$(unquoted_commands "$root/w/log")"
  if [ -n "$out" ]; then bad "$1" "command outside stop block: $out"; else ok "$1"; fi
}
check_stderr_case "stderr leading ::" $'note\n::error::forged'
check_stderr_case "stderr newline from a file name" $'prufyx: INPUT NOT ACCEPTED: (d/b\n::error::forged-from-filename.yaml)'
check_stderr_case "stderr tab then ::" $'x\n\t::add-mask::hidden'
check_stderr_case "stderr space then ::" $'x\n   ::warning::forged'
check_stderr_case "stderr stop-commands" $'x\n::stop-commands::tok'
check_stderr_case "stderr end token guess" $'x\n::endtoken::\n::error::after'
check_stderr_case "stderr legacy ##[" $'note ##[error]legacy-format\n##[add-mask]x'
check_stderr_case "stderr CR before ::" $'x\r::error::cr'
new_env; run_scan FAKE_EXIT=2 FAKE_STDERR=$'x'
t1="$(grep -o '^::stop-commands::.*' "$root/w/log" | head -1)"
new_env; run_scan FAKE_EXIT=2 FAKE_STDERR=$'x'
t2="$(grep -o '^::stop-commands::.*' "$root/w/log" | head -1)"
if [ -n "$t1" ] && [ "$t1" != "$t2" ]; then ok "stop token differs between runs"; else bad "stop token" "t1=$t1 t2=$t2"; fi
new_env; run_scan FAKE_EXIT=0 FAKE_STDOUT=$'::error::in-report'
if [ -z "$(unquoted_commands "$root/w/log")" ] && ! grep -q 'in-report' "$root/w/log"; then ok "report content is not echoed to the log"; else bad "report echo" "echoed"; fi

# --- fail-on against every exit code -----------------------------------------
# rows: fail-on value; columns: exit 0 10 11 2 3 (1 = the step fails)
check_failon() { # check_failon VALUE f0 f10 f11 f2 f3
  local v="$1"; shift
  local codes=(0 10 11 2 3) i=0 c want
  for c in "${codes[@]}"; do
    want="$1"; shift
    new_env; run_scan FAKE_EXIT="$c" PRUFYX_IN_FAIL_ON="$v"
    if { [ "$want" = 1 ] && [ "$RC" -ne 0 ]; } || { [ "$want" = 0 ] && [ "$RC" -eq 0 ]; }; then ok "fail-on=$v exit $c fails=$want"; else bad "fail-on=$v exit $c" "wanted fail=$want, rc=$RC"; fi
  done
}
check_failon none 0 0 0 1 1
check_failon blocked 0 1 0 1 1
check_failon unknown 0 1 1 1 1
check_failon blocked,unknown 0 1 1 1 1
check_failon unknown,blocked 0 1 1 1 1
new_env; run_scan FAKE_EXIT=7 PRUFYX_IN_FAIL_ON=none
[ "$RC" -ne 0 ] && ok "unexpected exit code fails" || bad "exit 7" "passed"
new_env; run_scan FAKE_EXIT=11
grep -q '^::warning title=Prufyx::' "$root/w/log" && ok "exit 11 under default adds a warning annotation" || bad "exit 11 warning" "$(cat "$root/w/log")"
new_env; run_scan FAKE_EXIT=11 PRUFYX_IN_FAIL_ON=unknown
grep -q '^::warning' "$root/w/log" && bad "no warning when failing" "warned" || ok "no warning when exit 11 fails the step"

# --- two uses in one job keep both reports -------------------------------------
new_env
run_scan FAKE_STDOUT=first-report PRUFYX_IN_FORMAT=json
first="$(grep '^report-file=' "$root/w/out" | tail -1 | cut -d= -f2-)"
RC=0; env -i PATH="$PATH" HOME="$root/w" RUNNER_TEMP="$root/w/temp" GITHUB_OUTPUT="$root/w/out" GITHUB_STEP_SUMMARY="$root/w/summary" \
  FAKE_ARGV="$root/w/argv" FAKE_STDOUT=second-report PRUFYX_IN_PATHS=m PRUFYX_IN_TO=kubernetes=1.25.3 bash "$here/run.sh" >/dev/null 2>&1 || RC=$?
second="$(grep '^report-file=' "$root/w/out" | tail -1 | cut -d= -f2-)"
if [ -n "$first" ] && [ "$first" != "$second" ] && [ "$(cat "$first")" = first-report ] && [ "$(cat "$second")" = second-report ]; then ok "second use keeps the first report"; else bad "two uses" "first=$first second=$second"; fi

# --- no environment override of the binary ------------------------------------
new_env; mkdir -p "$root/w/evil"; printf '#!/bin/sh\necho evil >>"$FAKE_ARGV"\n' >"$root/w/evil/p"; chmod +x "$root/w/evil/p"
run_scan PRUFYX_BIN="$root/w/evil/p"
grep -q '^evil$' "$root/w/argv" && bad "PRUFYX_BIN ignored" "override honoured" || ok "PRUFYX_BIN override is not honoured"

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
  cat >"$root/w/fakebin/gh" <<'GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
exit "${FAKE_GH_EXIT:-0}"
GH
  chmod +x "$root/w/fakebin/gh"
}

run_install() {
  RC=0
  rm -rf "$root/w/temp/prufyx-action"; : >"$root/w/curl.log"; : >"$root/w/gh.log"
  env -i PATH="$root/w/fakebin:$PATH" HOME="$root/w" RUNNER_TEMP="$root/w/temp" \
    RUNNER_OS=Linux RUNNER_ARCH=ARM64 FAKE_SERVE="$root/w/serve" FAKE_CURL_LOG="$root/w/curl.log" FAKE_GH_LOG="$root/w/gh.log" \
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


# --- attestation ---------------------------------------------------------------
new_env; mk_curl; mk_release v0.1.0
run_install PRUFYX_IN_VERSION=v0.1.0
want_args="attestation verify $root/w/temp/prufyx-action/download/prufyx_v0.1.0_linux_arm64.tar.gz --repo prufyx/prufyx --signer-workflow prufyx/prufyx/.github/workflows/release.yml --source-ref refs/tags/v0.1.0"
if [ "$RC" -eq 0 ] && [ "$(cat "$root/w/gh.log")" = "$want_args" ]; then ok "auto verifies the attestation for a release with the expected flags"; else bad "attestation auto" "rc=$RC gh: $(cat "$root/w/gh.log")"; fi
run_install PRUFYX_IN_VERSION=v0.1.0 FAKE_GH_EXIT=1
if [ "$RC" -ne 0 ] && [ ! -e "$root/w/temp/prufyx-action/bin/prufyx" ] && grep -q 'attestation' "$root/w/log"; then ok "failed attestation fails closed"; else bad "attestation fail" "rc=$RC"; fi
run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_IN_VERIFY_ATTESTATION=false
if [ "$RC" -eq 0 ] && [ ! -s "$root/w/gh.log" ]; then ok "verify-attestation false skips gh"; else bad "attestation off" "rc=$RC"; fi
run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_IN_VERIFY_ATTESTATION=maybe
[ "$RC" -ne 0 ] && ok "verify-attestation value validated" || bad "verify value" "accepted"
run_install PRUFYX_IN_VERSION=source PRUFYX_IN_VERIFY_ATTESTATION=true
[ "$RC" -ne 0 ] && grep -q "source" "$root/w/log" && ok "verify true with source refused" || bad "verify+source" "rc=$RC"
# gh missing: a PATH that has the needed tools but no gh
mkdir -p "$root/w/minbin"
for t in bash env tr cut awk grep sed tar cp chmod mkdir rm wc head od cat basename dirname sort uniq sha256sum shasum seq; do
  p="$(command -v "$t" 2>/dev/null || true)"; [ -n "$p" ] && [ -x "$p" ] && ln -sf "$p" "$root/w/minbin/$t"
done
cp "$root/w/fakebin/curl" "$root/w/minbin/curl"
RC=0; rm -rf "$root/w/temp/prufyx-action"
env -i PATH="$root/w/minbin" HOME="$root/w" RUNNER_TEMP="$root/w/temp" RUNNER_OS=Linux RUNNER_ARCH=ARM64 \
  FAKE_SERVE="$root/w/serve" FAKE_CURL_LOG="$root/w/curl.log" PRUFYX_IN_VERSION=v0.1.0 "$root/w/minbin/bash" "$here/install.sh" >"$root/w/log" 2>&1 || RC=$?
if [ "$RC" -ne 0 ] && grep -q 'GitHub CLI' "$root/w/log" && [ ! -e "$root/w/temp/prufyx-action/bin/prufyx" ]; then ok "missing gh fails closed"; else bad "gh missing" "rc=$RC $(cat "$root/w/log")"; fi

# --- archive layout (built with tar only) ------------------------------------
# mk_tar TAG MODE writes a gzip archive with SHA256SUMS into serve/.
mk_tar() {
  local tag="$1" mode="$2" name="prufyx_$1_linux_arm64" st="$root/w/stage"
  rm -rf "$root/w/serve" "$st"; mkdir -p "$root/w/serve" "$st/a/$name" "$st/b/$name" "$st/c"
  printf '#!/bin/sh\necho prufyx-fake\n' >"$st/a/$name/prufyx"; chmod +x "$st/a/$name/prufyx"
  local t="$root/w/serve/$name.tar"
  case "$mode" in
    dup-symlink)
      tar -cf "$t" -C "$st/a" "$name"
      ln -s "$root/SECRET" "$st/b/$name/prufyx"; tar -rf "$t" -C "$st/b" "$name/prufyx" ;;
    dup-regular)
      tar -cf "$t" -C "$st/a" "$name"
      printf 'other' >"$st/b/$name/prufyx"; tar -rf "$t" -C "$st/b" "$name/prufyx" ;;
    symlink-member)
      ln -s "$root/SECRET" "$st/b/$name/prufyx"; tar -cf "$t" -C "$st/b" "$name" ;;
    hardlink-extra)
      ln "$st/a/$name/prufyx" "$st/a/$name/second"; tar -cf "$t" -C "$st/a" "$name" ;;
    dir-symlink)
      ln -s "$root/outside" "$st/c/$name"; tar -cf "$t" -C "$st/c" "$name"
      tar -rf "$t" -C "$st/a" "$name/prufyx" ;;
    traversal)
      printf x >"$st/evil"; tar -cPf "$t" -C "$st/a" "$name"; (cd "$st/a/$name" && tar -rPf "$t" "../../evil") ;;
    abs)
      printf x >"$st/evil"; tar -cPf "$t" -C "$st/a" "$name" "$st/evil" ;;
    regex-dot)
      mkdir -p "$st/b/${name//./X}"; printf x >"$st/b/${name//./X}/sneaky"
      tar -cf "$t" -C "$st/a" "$name"; tar -rf "$t" -C "$st/b" "${name//./X}/sneaky" ;;
    *) echo "bad mode $mode" >&2; return 1 ;;
  esac
  gzip -f "$t"
  (cd "$root/w/serve" && { sha256sum "$name.tar.gz" 2>/dev/null || shasum -a 256 "$name.tar.gz"; } >SHA256SUMS)
}
printf 'TOPSECRET\n' >"$root/SECRET"; mkdir -p "$root/outside"
for mode in dup-symlink dup-regular symlink-member hardlink-extra dir-symlink traversal abs; do
  new_env; mk_curl; mk_tar v0.1.0 $mode
  run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_IN_VERIFY_ATTESTATION=false
  b="$root/w/temp/prufyx-action/bin/prufyx"
  if [ "$RC" -ne 0 ] && [ ! -e "$b" ] && [ ! -e "$root/outside/prufyx" ]; then ok "archive $mode refused: $(tail -1 "$root/w/log" | cut -c1-80)"; else bad "archive $mode" "rc=$RC installed=$([ -e "$b" ] && echo yes)"; fi
done
new_env; mk_curl; mk_tar v1.2.3 regex-dot; run_install PRUFYX_IN_VERSION=v1.2.3 PRUFYX_IN_VERIFY_ATTESTATION=false
[ "$RC" -ne 0 ] && ok "layout check compares names as text, not patterns" || bad "regex dot" "accepted prufyx_v1X2X3 entry"

# --- SHA256SUMS variants -------------------------------------------------------
new_env; mk_curl; mk_release v0.1.0; f=prufyx_v0.1.0_linux_arm64.tar.gz; d="$(awk '{print $1}' "$root/w/serve/SHA256SUMS")"
printf '%s *%s\n' "$d" "$f" >"$root/w/serve/SHA256SUMS"; run_install PRUFYX_IN_VERSION=v0.1.0; [ "$RC" -eq 0 ] && ok "sums: binary-mode star accepted" || bad "sums star" "$(cat "$root/w/log")"
printf '%s  %s\r\n' "$d" "$f" >"$root/w/serve/SHA256SUMS"; run_install PRUFYX_IN_VERSION=v0.1.0; [ "$RC" -ne 0 ] && ok "sums: CRLF fails closed" || bad "sums CRLF" "accepted"
printf '%s  %s\n%s  %s\n' "$d" "$f" "$d" "$f" >"$root/w/serve/SHA256SUMS"; run_install PRUFYX_IN_VERSION=v0.1.0; [ "$RC" -ne 0 ] && ok "sums: duplicate line refused" || bad "sums dup" "accepted"
printf '%s  %s.sig\n%s  x%s\n' "$d" "$f" "$d" "$f" >"$root/w/serve/SHA256SUMS"; run_install PRUFYX_IN_VERSION=v0.1.0; [ "$RC" -ne 0 ] && ok "sums: near names not matched" || bad "sums near" "accepted"
printf '%s  %s\n' "$(printf '%s' "$d" | tr a-f A-F)" "$f" >"$root/w/serve/SHA256SUMS"; run_install PRUFYX_IN_VERSION=v0.1.0; [ "$RC" -ne 0 ] && ok "sums: uppercase digest refused" || bad "sums upper" "accepted"

# --- no environment override of the download base ---------------------------------
new_env; mk_curl; mk_release v0.1.0; run_install PRUFYX_IN_VERSION=v0.1.0 PRUFYX_RELEASE_BASE=https://evil.example/x
if grep -q evil.example "$root/w/curl.log"; then bad "download base fixed" "redirected by job environment"; elif grep -q '^https://github.com/prufyx/prufyx/releases/download/v0.1.0/SHA256SUMS$' "$root/w/curl.log"; then ok "download base is fixed"; else bad "download base" "$(cat "$root/w/curl.log")"; fi

# --- source build environment --------------------------------------------------
grep -q 'GOWORK=off GOTOOLCHAIN=local GOENV=off' "$here/install.sh" && ok "source build isolates the Go environment" || bad "go env" "missing"

# --- input cases from the independent review ---------------------------------
# Option injection after trimming / unicode / odd values
new_env; run_scan PRUFYX_IN_PATHS=$'   --help  '; expect_fail "review: path ws+dash" "must not start"
new_env; run_scan PRUFYX_IN_PATHS='--'; expect_fail "review: path --" "must not start"
new_env; run_scan PRUFYX_IN_PATHS='-'; expect_fail "review: path - (stdin)" "must not start"
new_env; run_scan PRUFYX_IN_PATHS=$'a\rb'; expect_fail "review: path CR" "control"
new_env; run_scan PRUFYX_IN_PATHS=$'a\tb'; expect_fail "review: path TAB" "control"
new_env; run_scan PRUFYX_IN_PATHS=$'\xe2\x80\x94help'; expect_ok "review: path em-dash is a path"; argv_has $'\xe2\x80\x94help' && ok "review: em-dash verbatim" || bad "review: em-dash" "$(cat $root/w/argv)"
new_env; run_scan PRUFYX_IN_PATHS=$'a\xe2\x80\xa8--redact'; expect_ok "review: U+2028 inside path stays one arg"; argv_has '--redact' && bad "review: U+2028 split" "split" || ok "review: U+2028 not split"
new_env; run_scan PRUFYX_IN_TO=$'kubernetes=1.25.3\r'; expect_fail "review: to CR" ""
new_env; run_scan PRUFYX_IN_TO=$'kubernetes=1.25.3\n'; expect_ok "review: to trailing newline ok"
new_env; run_scan PRUFYX_IN_TO='kubernetes=1.25.3=--redact'; expect_fail "review: to double =" "COMPONENT"
new_env; run_scan PRUFYX_IN_TO=$'kubernetes=1.25.3\xe2\x80\xa8--redact'; expect_fail "review: to U+2028" "COMPONENT"
new_env; run_scan PRUFYX_IN_REQUIRE_BASIS=$'reviewed\n'; expect_fail "review: basis trailing NL" ""
new_env; run_scan PRUFYX_IN_FAIL_ON=$'none\n'; expect_fail "review: fail-on trailing NL" ""
new_env; run_scan PRUFYX_IN_FAIL_ON='NONE'; expect_fail "review: fail-on case" "fail-on"
new_env; run_scan PRUFYX_IN_FORMAT=$'json\n'; expect_fail "review: format NL" "format"
new_env; run_scan PRUFYX_IN_REDACT=$'true\n--verbose'; expect_fail "review: redact NL" "redact"
new_env; run_scan PRUFYX_IN_KNOWLEDGE_DB=' -x'; expect_ok "review: db leading space"; argv_has ' -x' && ok "review: db ' -x' passed as value" || bad "review: db" "$(cat $root/w/argv)"
new_env; run_scan PRUFYX_IN_CONFIG=$'c\x1b[2J'; expect_fail "review: config ESC" "single line"
# Values never echoed in errors
new_env; run_scan PRUFYX_IN_TO=$'k=1\n::error::fromto'; grep -q 'fromto' "$root/w/log" && bad "review: to echoed" "echoed" || ok "review: to not echoed"
# Output file is key=value only, single keys
new_env; run_scan FAKE_EXIT=10 PRUFYX_IN_FAIL_ON=none
[ "$(grep -c . "$root/w/out")" = 3 ] && ! grep -vE '^(exit-code|verdict|report-file)=' "$root/w/out" | grep -q . && ok "review: GITHUB_OUTPUT keys" || bad "review: out" "$(cat $root/w/out)"

printf '\n%s checks, %s failed\n' "$n" "$fails"
[ "$fails" -eq 0 ]
