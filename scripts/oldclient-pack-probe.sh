#!/usr/bin/env bash
# Runs the oldest supported client against this tree's embedded CNCF rule pack
# and checks it either loads the pack and plans without ever reaching PASS, or
# refuses it cleanly (knowledge integrity failure, exit 3). No keys needed: the
# client is built from its release tag source with this tree's rules.json
# embedded, the same decoder the signed-package path uses.
#
# usage: scripts/oldclient-pack-probe.sh [--tag TAG] [--keep]
#   --tag TAG  client to test (default: version= in cli/knowledge/oldest-supported-client.txt)
# Needs git (with the tag) or OLDCLIENT_SRC_TAR=<tar of the tag's cli/ tree>, go, python3. Exit 0 when every case is acceptable.
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tag=""; keep=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag=${2:?}; shift 2 ;;
    --keep) keep=1; shift ;;
    *) echo "usage: $0 [--tag TAG] [--keep]" >&2; exit 2 ;;
  esac
done
[ -n "$tag" ] || tag=$(sed -n 's/^version=//p' "$root/cli/knowledge/oldest-supported-client.txt")
[ -n "$tag" ] || { echo "no oldest supported client version" >&2; exit 2; }
work=$(mktemp -d)
[ "$keep" = 1 ] || trap 'rm -rf "$work"' EXIT
mkdir "$work/src" "$work/in"
if [ -n "${OLDCLIENT_SRC_TAR:-}" ]; then tar -x -C "$work/src" -f "$OLDCLIENT_SRC_TAR"; else git -C "$root" archive "$tag" cli | tar -x -C "$work/src"; fi
cp "$root/cli/internal/cncfcheck/data/rules.json" "$work/src/cli/internal/cncfcheck/data/rules.json"
(cd "$work/src/cli" && GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=vendor cmd=prufyx; [ -d cmd/prufyx ] || cmd=prufyx-community; go build -o "$work/prufyx" "./cmd/$cmd")
: > "$work/in/empty.yaml"; chmod 700 "$work/in"; chmod 600 "$work/in/empty.yaml"
bin="$work/prufyx"; fail=0
check() { # name rc output
  local name=$1 rc=$2 out=$3 verdict
  verdict=$(printf '%s' "$out" | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print("PASS" if d.get("verdict")=="PASS" or any(s.get("verdict")=="PASS" for s in d.get("stages",[])) else "NOPASS")
except Exception:
    print("NOJSON")')
  if [ "$rc" = 3 ] && printf '%s' "$out" | grep -q 'KNOWLEDGE INTEGRITY FAILURE\|could not be loaded'; then
    printf '%-34s rc=%s clean refusal\n' "$name" "$rc"
  elif [ "$rc" = 11 ] && [ "$verdict" = NOPASS ]; then
    printf '%-34s rc=%s loads, no PASS (%s)\n' "$name" "$rc" "$(printf '%s' "$out" | python3 -I -c 'import json,sys;d=json.load(sys.stdin);r=d["routes"][0] if d.get("routes") else {};print("verdict",d.get("verdict"),"policy",r.get("policy") or "none","hops",r.get("hops"),"stages",len(d["stages"]))')"
  else
    printf '%-34s rc=%s UNACCEPTABLE (%s)\n' "$name" "$rc" "$verdict"; fail=1
  fi
}
set +e
out=$("$bin" catalog cncf 2>&1); rc=$?
if [ "$rc" = 0 ] || { [ "$rc" = 3 ] && printf '%s' "$out" | grep -q 'could not be loaded'; }; then printf '%-34s rc=%s ok\n' "catalog cncf" "$rc"; else printf '%-34s rc=%s UNACCEPTABLE\n' "catalog cncf" "$rc"; fail=1; fi
while read -r app from to; do
  out=$("$bin" plan "$work/in/empty.yaml" --from "$app=$from" --to "$app=$to" --format json 2>"$work/err"); rc=$?
  [ "$rc" = 11 ] || out=$out$(cat "$work/err")
  check "plan $app $from -> $to" "$rc" "$out"
done <<'L'
cilium 1.14.5 1.17.2
longhorn 1.4.4 1.7.3
crossplane 1.17.1 1.20.0
cilium 1.14.5 1.22.0
longhorn 1.4.4 1.14.0
crossplane 1.17.1 2.6.0
L
for app in cilium longhorn crossplane; do
  out=$("$bin" plan "$work/in/empty.yaml" --from "$app=1.0.0" --to "$app=newest-covered" --format json 2>"$work/err"); rc=$?
  [ "$rc" = 11 ] || out=$out$(cat "$work/err")
  case "$rc" in 2|3) printf '%-34s rc=%s refused (not resolved)\n' "plan $app -> newest-covered" "$rc" ;; *) check "plan $app -> newest-covered" "$rc" "$out" ;; esac
done
exit "$fail"
