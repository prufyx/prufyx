#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs `prufyx scan` for the composite GitHub Action.
#
# Every input arrives as PRUFYX_IN_* in the environment. Each one is validated
# and then added to an argument array; the command is run as
# "$bin" scan "${args[@]}" without a shell string, so a quote, `$(...)`,
# backtick or newline in a value is data, never code.
#
# Exit codes of `prufyx scan`: 0 pass, 10 BLOCKED, 11 undecided (UNKNOWN),
# 2 invalid input, 3 knowledge integrity failure. 2 and 3 and anything else
# always fail the step; 10 and 11 fail it only when listed in `fail-on`.
set -euo pipefail
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=lib.sh
. "$here/lib.sh"

temp="${RUNNER_TEMP:?RUNNER_TEMP is not set}"
bin="${PRUFYX_BIN:-$temp/prufyx-action/bin/prufyx}"
outdir="$temp/prufyx-action/out"
rm -rf "$outdir"
mkdir -p "$outdir"
chmod 700 "$outdir"

one_line() { # one_line NAME VALUE: no newline or control characters
  if has_control "$2" || [ "$(printf '%s' "$2" | wc -l)" -gt 0 ]; then
    die "input '$1' must be a single line without control characters"
  fi
}
no_dash() { # no_dash NAME VALUE: a value must not look like a flag
  case "$2" in -*) die "input '$1' must not start with '-'" ;; esac
}

# --- inputs ---------------------------------------------------------------
in_paths="${PRUFYX_IN_PATHS:-}"
in_from="${PRUFYX_IN_FROM:-}"
in_to="${PRUFYX_IN_TO:-}"
in_format="${PRUFYX_IN_FORMAT:-json}"
in_redact="${PRUFYX_IN_REDACT:-false}"
in_basis="${PRUFYX_IN_REQUIRE_BASIS:-}"
in_db="${PRUFYX_IN_KNOWLEDGE_DB:-}"
in_failon="${PRUFYX_IN_FAIL_ON:-blocked}"
in_config="${PRUFYX_IN_CONFIG:-}"
in_dist="${PRUFYX_IN_DISTRIBUTION:-}"
in_scope="${PRUFYX_IN_RESOURCE_SCOPE_COMPLETE:-}"
in_apply="${PRUFYX_IN_TARGET_API_APPLY_REQUIRED:-}"

args=()

# paths: one per line, each added as its own argument.
if has_control "$in_paths"; then die "input 'paths' has a control character"; fi
split_lines paths "$in_paths"
[ "${#paths[@]}" -gt 0 ] || die "input 'paths' is empty; list the manifest files or directories to scan, one per line"
for p in ${paths[@]+"${paths[@]}"}; do
  no_dash paths "$p"
  args+=("$p")
done

# to / from: COMPONENT=VERSION, one per line.
comp_re='[a-z0-9][a-z0-9_.-]*=[A-Za-z0-9][A-Za-z0-9._+-]*'
if has_control "$in_to"; then die "input 'to' has a control character"; fi
if has_control "$in_from"; then die "input 'from' has a control character"; fi
split_lines tos "$in_to"
split_lines froms "$in_from"
[ "${#tos[@]}" -gt 0 ] || [ -n "$in_config" ] || die "input 'to' is empty; pass COMPONENT=VERSION such as kubernetes=1.25.3, or a 'config' file that sets the targets"
for v in ${tos[@]+"${tos[@]}"}; do
  printf '%s' "$v" | grep -Eqx "$comp_re" || die "input 'to' entries must look like COMPONENT=VERSION (for example kubernetes=1.25.3)"
  args+=(--to "$v")
done
for v in ${froms[@]+"${froms[@]}"}; do
  printf '%s' "$v" | grep -Eqx "$comp_re" || die "input 'from' entries must look like COMPONENT=VERSION (for example kubernetes=1.24.17)"
  args+=(--from "$v")
done

# format
case "$in_format" in
  json) ext=json ;;
  sarif) ext=sarif ;;
  markdown) ext=md ;;
  *) die "input 'format' must be json, sarif or markdown" ;;
esac

# booleans
case "$in_redact" in
  true) args+=(--redact) ;;
  false | "") ;;
  *) die "input 'redact' must be true or false" ;;
esac
case "$in_scope" in
  true | false) args+=("--resource-scope-complete=$in_scope") ;;
  "") ;;
  *) die "input 'resource-scope-complete' must be true, false or empty" ;;
esac
case "$in_apply" in
  true | false) args+=("--target-api-apply-required=$in_apply") ;;
  "") ;;
  *) die "input 'target-api-apply-required' must be true, false or empty" ;;
esac

# distribution
case "$in_dist" in
  official_upstream | custom_build) args+=(--distribution "$in_dist") ;;
  "") ;;
  *) die "input 'distribution' must be official_upstream or custom_build" ;;
esac

# require-basis: comma separated words from the documented set.
if [ -n "$in_basis" ]; then
  one_line require-basis "$in_basis"
  printf '%s' "$in_basis" | grep -Eqx '(reviewed|mechanical|empirical|consensus|lead)(,(reviewed|mechanical|empirical|consensus|lead))*' \
    || die "input 'require-basis' must be a comma separated list of reviewed, mechanical, empirical, consensus, lead"
  args+=(--require-basis "$in_basis")
fi

# knowledge-db and config: a single path each.
if [ -n "$in_db" ]; then
  one_line knowledge-db "$in_db"; no_dash knowledge-db "$in_db"
  args+=(--knowledge-db "$in_db")
fi
if [ -n "$in_config" ]; then
  one_line config "$in_config"; no_dash config "$in_config"
  args+=(--config "$in_config")
fi

# fail-on: "none", or a comma separated list of blocked and unknown.
one_line fail-on "$in_failon"
fail_blocked=0; fail_unknown=0
case "$in_failon" in
  none) ;;
  blocked) fail_blocked=1 ;;
  unknown) fail_unknown=1 ;;
  blocked,unknown | unknown,blocked) fail_blocked=1; fail_unknown=1 ;;
  *) die "input 'fail-on' must be none, blocked, unknown or blocked,unknown" ;;
esac

[ -x "$bin" ] || die "the prufyx binary is missing; the install step did not run"

# --- run -------------------------------------------------------------------
report="$outdir/report.$ext"
errfile="$outdir/stderr.txt"
set +e
"$bin" scan "${args[@]}" --format "$in_format" >"$report" 2>"$errfile"
code=$?
set -e
# Standard error is the tool's own text; strip control characters before it
# reaches the log so it cannot form a workflow command.
if [ -s "$errfile" ]; then
  LC_ALL=C tr -d '\000-\010\013-\037\177' <"$errfile" | sed 's/^::/ ::/' >&2
fi

case "$code" in
  0) verdict=pass ;;
  10) verdict=blocked ;;
  11) verdict=unknown ;;
  3) verdict=integrity-failure ;;
  2) verdict=invalid-input ;;
  *) verdict=error ;;
esac

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'exit-code=%s\n' "$code"
    printf 'verdict=%s\n' "$verdict"
    if [ -s "$report" ]; then printf 'report-file=%s\n' "$report"; fi
  } >>"$GITHUB_OUTPUT"
fi

# --- step summary ------------------------------------------------------------
# The Markdown report escapes manifest and rule text itself; it is written
# as produced. A report from a failed run is not written.
if [ "$code" = 0 ] || [ "$code" = 10 ] || [ "$code" = 11 ]; then
  summary_src="$report"
  if [ "$in_format" != markdown ]; then
    summary_src="$outdir/summary.md"
    set +e
    "$bin" scan "${args[@]}" --format markdown >"$summary_src" 2>/dev/null
    scode=$?
    set -e
    [ "$scode" = "$code" ] || { printf '%s\n' "Prufyx: the summary run gave a different answer than the report run; summary not written." >"$summary_src"; }
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    size="$(wc -c <"$summary_src" | tr -d ' ')"
    if [ "$size" -gt 900000 ]; then
      printf '%s\n' "Prufyx: the Markdown report is larger than the job summary limit; download the report file instead." >>"$GITHUB_STEP_SUMMARY"
    else
      cat "$summary_src" >>"$GITHUB_STEP_SUMMARY"
    fi
  fi
fi

# --- result ------------------------------------------------------------------
case "$code" in
  0) echo "Prufyx: pass for the declared scope." ;;
  10) echo "Prufyx: BLOCKED."
      if [ "$fail_blocked" = 1 ]; then die "prufyx found problems that must be fixed (exit 10)"; fi ;;
  11) echo "Prufyx: no blockers found in covered checks, some areas were not checked."
      if [ "$fail_unknown" = 1 ]; then die "prufyx could not decide everything (exit 11)"; fi ;;
  3) die "prufyx knowledge integrity failure (exit 3); nothing was checked" ;;
  2) die "prufyx did not accept the inputs (exit 2); see the message above" ;;
  *) die "prufyx failed with exit code $code" ;;
esac
