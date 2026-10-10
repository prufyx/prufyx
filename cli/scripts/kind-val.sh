#!/usr/bin/env bash
# KIND-VAL: check Prufyx's Kubernetes knowledge against real API servers.
#
# For every release line of an image list, creates one kind cluster (one at a
# time), records the APIs it serves, applies the behavioural corpus with a
# server dry run and scans it with prufyx for the hop from the previous line,
# runs the custom-resource pairs on the line chosen for them, deletes the
# cluster, and finally evaluates every claim. See docs/kind-val.md.
#
# usage: kind-val.sh --images FILE --out DIR --prufyx BIN [--kindval BIN]
#                    [--crd-claims FILE] [--crd-line LINE] [--min-free-mb N]
#                    [--post-check CMD] [--keep]
#
# The image list has one line per release line: "<line> <image@sha256:...>".
# Needs kind, kubectl and docker on PATH. KINDVAL defaults to
# `go run ./internal/tools/kindval` from the cli directory. Clusters are
# named prufyx-kind-<line> and always deleted (also on error), unless --keep.
set -euo pipefail

images=""; out=""; prufyx=""; kindval=""; crd_claims=""; crd_line=""
min_free_mb=2000; post_check=""; keep=0
while [ $# -gt 0 ]; do
  case "$1" in
    --images) images="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --prufyx) prufyx="$2"; shift 2 ;;
    --kindval) kindval="$2"; shift 2 ;;
    --crd-claims) crd_claims="$2"; shift 2 ;;
    --crd-line) crd_line="$2"; shift 2 ;;
    --min-free-mb) min_free_mb="$2"; shift 2 ;;
    --post-check) post_check="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$images" ] && [ -n "$out" ] && [ -n "$prufyx" ] || { echo "--images, --out and --prufyx are required" >&2; exit 2; }
for tool in kind kubectl docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required on PATH" >&2; exit 2; }
done
if [ -z "$kindval" ]; then
  script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
  kindval="go run -C $script_dir/.. ./internal/tools/kindval"
fi

mkdir -p "$out/runs" "$out/corpus"
log="$out/run.log"
say() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$log" >&2; }

current=""
cleanup() {
  if [ -n "$current" ] && [ "$keep" -eq 0 ]; then
    say "deleting cluster $current"
    kind delete cluster --name "$current" >>"$log" 2>&1 || true
    current=""
  fi
}
trap cleanup EXIT

wait_for_memory() {
  local avail
  while :; do
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    [ "$avail" -ge "$min_free_mb" ] && return 0
    say "waiting: ${avail} MB available, need ${min_free_mb} MB"
    sleep 30
  done
}

lines=""
while read -r line image; do
  [ -n "$line" ] && [ "${line#\#}" = "$line" ] || continue
  lines="${lines:+$lines,}$line"
done <"$images"
[ -n "$lines" ] || { echo "no lines in $images" >&2; exit 2; }
last_line=${lines##*,}
[ -n "$crd_line" ] || crd_line="$last_line"
say "lines: $lines (custom resources on $crd_line)"

claims="$out/claims.json"
# shellcheck disable=SC2086
$kindval claims --lines "$lines" ${crd_claims:+--crd "$crd_claims"} --out "$claims"
say "claims written to $claims"

prev_line=""; prev_version=""
while read -r line image; do
  [ -n "$line" ] && [ "${line#\#}" = "$line" ] || continue
  version=${image#*:v}; version=${version%%@*}
  name="prufyx-kind-$line"
  kubeconfig="$out/kubeconfig-$line"
  wait_for_memory
  say "creating $name from $image"
  current="$name"
  kind create cluster --name "$name" --image "$image" --kubeconfig "$kubeconfig" --wait 180s >>"$log" 2>&1
  say "snapshot $line"
  # shellcheck disable=SC2086
  $kindval snapshot --kubeconfig "$kubeconfig" --line "$line" --image "$image" --out "$out/runs/snapshot-$line.json"
  say "verdicts $line"
  if [ -n "$prev_line" ]; then
    # shellcheck disable=SC2086
    $kindval verdicts --kubeconfig "$kubeconfig" --line "$line" --dir "$out/corpus" --out "$out/runs/verdicts-$line.json" \
      --prufyx "$prufyx" --from-version "$prev_version" --to-version "$version"
  else
    # shellcheck disable=SC2086
    $kindval verdicts --kubeconfig "$kubeconfig" --line "$line" --dir "$out/corpus" --out "$out/runs/verdicts-$line.json"
  fi
  if [ -n "$crd_claims" ] && [ "$line" = "$crd_line" ]; then
    say "custom resources on $line"
    # shellcheck disable=SC2086
    $kindval crd --kubeconfig "$kubeconfig" --line "$line" --claims "$claims" --out "$out/runs/crd-$line.json" 2>>"$log"
  fi
  cleanup
  rm -f "$kubeconfig"
  if [ -n "$post_check" ]; then
    say "post-check: $post_check"
    bash -c "$post_check" >>"$log" 2>&1 || { say "post-check failed after $line"; exit 1; }
  fi
  prev_line="$line"; prev_version="$version"
done <"$images"

say "evaluating"
# shellcheck disable=SC2086
$kindval evaluate --claims "$claims" --runs "$out/runs" --out "$out/results.json" --summary "$out/summary.md"
say "results: $out/results.json"
