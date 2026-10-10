#!/usr/bin/env bash
# KIND-VAL: check Prufyx's Kubernetes knowledge against real API servers.
#
# For every release line of an image list, creates one kind cluster (one at a
# time), records the APIs it serves, applies the behavioural corpus with a
# server dry run and scans it with prufyx for the hop from the previous line,
# runs the custom-resource pairs on the line chosen for them, deletes the
# cluster, and finally evaluates every claim. See docs/kind-val.md.
#
# usage: kind-val.sh --images FILE --out DIR --prufyx BIN [--prufyx-commit SHA]
#                    [--kindval BIN] [--crd-claims FILE] [--crd-line LINE]
#                    [--kind-config FILE] [--min-free-mb N] [--post-check CMD] [--keep]
#
# The image list has one line per release line: "<line> <image@sha256:...>".
# Needs kind, kubectl and docker on PATH. KINDVAL defaults to
# `go run ./internal/tools/kindval` from the cli directory. Clusters are
# named prufyx-kind-<line> and always deleted (also on error), unless --keep.
set -euo pipefail

images=""; out=""; prufyx=""; prufyx_commit=""; kindval=""; crd_claims=""; crd_line=""; kind_config=""
min_free_mb=2000; post_check=""; keep=0
while [ $# -gt 0 ]; do
  case "$1" in
    --images) images="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --prufyx) prufyx="$2"; shift 2 ;;
    --prufyx-commit) prufyx_commit="$2"; shift 2 ;;
    --kind-config) kind_config="$2"; shift 2 ;;
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
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ -z "$kindval" ]; then
  kindval="go run -C $script_dir/.. ./internal/tools/kindval"
fi
# The default cluster configuration serves every beta API (api/beta=true):
# beta APIs introduced since Kubernetes 1.24 are off by default, and a claim
# about a version a line serves is only checkable when the line serves it.
[ -n "$kind_config" ] || kind_config="$script_dir/kind-val-cluster.yaml"

mkdir -p "$out/runs" "$out/corpus"
# prufyx never follows symbolic links in input paths: use the physical path.
out=$(CDPATH= cd -- "$out" && pwd -P)
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
  kind create cluster --name "$name" --image "$image" --config "$kind_config" --kubeconfig "$kubeconfig" --wait 180s >>"$log" 2>&1
  say "snapshot $line"
  # shellcheck disable=SC2086
  $kindval snapshot --kubeconfig "$kubeconfig" --line "$line" --image "$image" --out "$out/runs/snapshot-$line.json"
  say "verdicts $line"
  if [ -n "$prev_line" ]; then
    # shellcheck disable=SC2086
    $kindval verdicts --kubeconfig "$kubeconfig" --line "$line" --dir "$out/corpus" --out "$out/runs/verdicts-$line.json" \
      --claims "$claims" --prufyx "$prufyx" --from-version "$prev_version" --to-version "$version"
  else
    # shellcheck disable=SC2086
    $kindval verdicts --kubeconfig "$kubeconfig" --line "$line" --dir "$out/corpus" --out "$out/runs/verdicts-$line.json" --claims "$claims"
  fi
  if [ -n "$crd_claims" ] && [ "$line" = "$crd_line" ]; then
    say "custom resources on $line"
    # shellcheck disable=SC2086
    $kindval crd --kubeconfig "$kubeconfig" --line "$line" --image "$image" --claims "$claims" --out "$out/runs/crd-$line.json" 2>>"$log"
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
$kindval evaluate --claims "$claims" --runs "$out/runs" --out "$out/results.json" --summary "$out/summary.md" \
  --prufyx "$prufyx" ${prufyx_commit:+--prufyx-commit "$prufyx_commit"} --log "$log"
say "results: $out/results.json"
