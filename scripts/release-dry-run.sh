#!/usr/bin/env bash
# Dry run of the release workflow's build, package and checksum steps.
#
# The `run:` bodies of .github/workflows/release.yml are extracted by
# cli/internal/tools/workflowrun and executed verbatim, so this script keeps no
# copy of them. It uses a fixed dry-run tag, builds nothing for a real release,
# and reaches no secret, tag, release or attestation. Only the pinned nfpm
# download of the packages step uses the network.
#
# It checks: the tag grammar step, the knowledge root pin step, the freshness
# gate step, archives for the whole build matrix, a byte-identical rebuild of
# the same inputs, .deb/.rpm byte-identical when built under two host names,
# /usr/bin/prufyx equal to the archive binary, and the SHA256SUMS lines.
#
# usage: scripts/release-dry-run.sh [WORKDIR]
#   WORKDIR  scratch directory (default: a new temporary one, removed at the end;
#            a directory given here is kept).
#   KNOWLEDGE_ROOT_DIGEST  optional, as the repository variable of the same name.
# Needs: git, go (the version the workflow pins), bash, GNU tar, gzip, curl,
# dpkg-deb, rpm2cpio, cpio, unshare, and sudo unless run as root.
# The result table goes to $GITHUB_STEP_SUMMARY when set, and to stdout.
set -uo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
workflow="${root}/.github/workflows/release.yml"
tag="v0.0.0-dryrun.0"
keep=1
if [ $# -ge 1 ]; then
  work=$1
  mkdir -p "${work}"
else
  work=$(mktemp -d)
  keep=0
fi
work=$(CDPATH= cd -- "${work}" && pwd -P)
logs="${work}/logs"
mkdir -p "${logs}"
cleanup() { [ "${keep}" = 1 ] || rm -rf "${work}"; }
trap cleanup EXIT

rows=()
failed=0
record() { # name, PASS|FAIL, detail
  rows+=("| $1 | $2 | $3 |")
  [ "$2" = PASS ] || [ "$2" = WARN ] || failed=1
  printf '%s: %s %s\n' "$1" "$2" "$3"
}
tail_log() { [ -f "$1" ] && tail -n 25 "$1" | sed 's/^/    | /'; }

# Build the extractor once, from the checkout under test.
tool="${work}/workflowrun"
(cd "${root}/cli" && go build -o "${tool}" ./internal/tools/workflowrun) || {
  echo "cannot build workflowrun" >&2
  exit 1
}
matrix=()
while read -r os arch; do matrix+=("${os}/${arch}"); done < <("${tool}" MATRIX "${workflow}" build)
[ "${#matrix[@]}" -gt 0 ] || { echo "empty build matrix" >&2; exit 1; }

# step_script JOB NAME -> file with the verbatim step body.
step_script() {
  local file="${work}/step-$1-$(echo "$2" | tr -c 'A-Za-z0-9\n' '_').sh"
  "${tool}" STEP-SCRIPT "${workflow}" "$1" "$2" > "${file}" || return 1
  echo "${file}"
}

# run_step SCRIPT LOG: GitHub's default run shell, environment as exported.
run_step() { bash --noprofile --norc -eo pipefail "$1" > "$2" 2>&1; }

# clone_to DIR: a full local clone of the commit under test, as the workflow's
# checkout (fetch-depth 0) gives it.
clone_to() {
  git clone -q --no-hardlinks "${root}" "$1" && git -C "$1" -c advice.detachedHead=false checkout -q --detach "${head}"
}

head=$(git -C "${root}" rev-parse HEAD)

# with_hostname NAME CMD...: runs CMD in a UTS namespace whose host name is NAME.
with_hostname() {
  local name=$1
  shift
  if [ "$(id -u)" -eq 0 ]; then
    unshare --uts -- sh -c 'hostname "$1"; shift; exec "$@"' sh "${name}" "$@"
  else
    sudo -E env "PATH=${PATH}" unshare --uts -- sh -c \
      'uid=$1; name=$2; shift 2; hostname "$name"; exec setpriv --reuid="$uid" --regid="$(id -g "$uid")" --init-groups -- "$@"' \
      sh "$(id -u)" "${name}" "$@"
  fi
}

# 1. Tag grammar and knowledge root pin (release workflow steps, verbatim).
tagscript=$(step_script build "Check the tag")
if VERSION="${tag}" GITHUB_WORKSPACE="${root}" run_step "${tagscript}" "${logs}/tag.log"; then
  record "release tag grammar step (dry-run tag ${tag})" PASS ""
else
  record "release tag grammar step (dry-run tag ${tag})" FAIL "see log"; tail_log "${logs}/tag.log"
fi
pinscript=$(step_script build "Check the knowledge root pin")
if EXPECTED="${KNOWLEDGE_ROOT_DIGEST:-}" GITHUB_WORKSPACE="${root}" run_step "${pinscript}" "${logs}/pin.log"; then
  record "knowledge root pin step" PASS "$(head -n1 "${logs}/pin.log" | cut -c1-70)"
else
  record "knowledge root pin step" FAIL "see log"; tail_log "${logs}/pin.log"
fi

# 2. Freshness gate: the earliest embedded evidence expiry must be at least
# 30 days after the committer date of the commit that would be tagged.
fresh=$(step_script build "Check the embedded knowledge is fresh")
commit_date=$(git -C "${root}" log -1 --format=%cI "${head}")
if TAGGED_SHA="${head}" GITHUB_WORKSPACE="${root}" run_step "${fresh}" "${logs}/fresh.log"; then
  record "freshness gate (committer date <= end of validity - 30 days)" PASS "commit ${commit_date}; earliest expiry $(tail -n1 "${logs}/fresh.log")"
else
  # On a pull request the checked commit is the merge commit (dated now), so an
  # expiring evidence set would fail every unrelated pull request: WARN only.
  # On workflow_dispatch (the pre-tag check) it is a FAIL.
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    record "freshness gate (committer date <= end of validity - 30 days)" WARN "commit ${commit_date}; the freshness step failed (not blocking on pull_request, blocks a tag)"
    echo "::warning title=Release freshness gate::The embedded knowledge expires too soon for a tag at commit ${commit_date}; not blocking this pull request, but it blocks a tag until the evidence is renewed."
  else
    record "freshness gate (committer date <= end of validity - 30 days)" FAIL "commit ${commit_date}"
  fi
  tail_log "${logs}/fresh.log"
fi

# 3. Build the matrix twice from two clean clones at different paths.
buildscript=$(step_script build "Build binaries")
for n in 1 2; do
  ws="${work}/build${n}/ws"
  mkdir -p "${work}/build${n}"
  if ! clone_to "${ws}"; then record "clone for build ${n}" FAIL ""; continue; fi
  for target in "${matrix[@]}"; do
    if ! GOOS="${target%/*}" GOARCH="${target#*/}" VERSION="${tag}" SOURCE_REVISION="${head}" \
      GITHUB_WORKSPACE="${ws}" run_step "${buildscript}" "${logs}/build${n}-${target%/*}-${target#*/}.log"; then
      record "build ${n} ${target}" FAIL "see log"
      tail_log "${logs}/build${n}-${target%/*}-${target#*/}.log"
    fi
  done
done

expected=()
for target in "${matrix[@]}"; do
  for base in prufyx prufyx-collector; do expected+=("${base}_${tag}_${target%/*}_${target#*/}"); done
done
missing=""
badmembers=""
for name in "${expected[@]}"; do
  f="${work}/build1/ws/cli/dist/${name}.tar.gz"
  if [ ! -s "${f}" ]; then missing="${missing} ${name}"; continue; fi
  bin=prufyx
  case "${name}" in prufyx-collector_*) bin=prufyx-collector ;; esac
  members=$(tar -tzf "${f}" | LC_ALL=C sort | tr '\n' ' ')
  [ "${members}" = "${name}/ ${name}/${bin} " ] || badmembers="${badmembers} ${name}"
done
if [ -z "${missing}" ] && [ -z "${badmembers}" ]; then
  record "archives for the build matrix (${#expected[@]} tar.gz, one directory with one binary each)" PASS "${matrix[*]}"
else
  record "archives for the build matrix" FAIL "missing:${missing} bad members:${badmembers}"
fi

differ=""
for name in "${expected[@]}"; do
  cmp -s "${work}/build1/ws/cli/dist/${name}.tar.gz" "${work}/build2/ws/cli/dist/${name}.tar.gz" || differ="${differ} ${name}"
done
if [ -z "${differ}" ] && [ -z "${missing}" ]; then
  record "rebuild of the same inputs is byte-identical (second clean clone, other path)" PASS "${#expected[@]} archives"
else
  record "rebuild of the same inputs is byte-identical" FAIL "differ:${differ}"
fi

# 4. Packages under two host names (release workflow step, verbatim).
pkgscript=$(step_script packages "Build packages")
for host in hostA hostB; do
  ws="${work}/pkg-${host}/ws"
  mkdir -p "${work}/pkg-${host}"
  clone_to "${ws}" || { record "clone for packages on ${host}" FAIL ""; continue; }
  mkdir -p "${ws}/archives"
  cp "${work}"/build1/ws/cli/dist/*_linux_*.tar.gz "${ws}/archives/"
  seen=$(with_hostname "${host}" hostname 2>"${logs}/hostname-${host}.log")
  if [ "${seen}" != "${host}" ]; then
    record "host name switch to ${host}" FAIL "saw '${seen}'"; tail_log "${logs}/hostname-${host}.log"
    continue
  fi
  if TAG="${tag}" GITHUB_SHA="${head}" GITHUB_WORKSPACE="${ws}" with_hostname "${host}" \
    bash --noprofile --norc -eo pipefail "${pkgscript}" > "${logs}/pkg-${host}.log" 2>&1; then
    :
  else
    record "packages step on ${host}" FAIL "see log"; tail_log "${logs}/pkg-${host}.log"
  fi
done

pkgs=()
for arch in amd64 arm64; do
  for fmt in deb rpm; do pkgs+=("prufyx_${tag}_linux_${arch}.${fmt}"); done
done
pdiffer=""
pmissing=""
for p in "${pkgs[@]}"; do
  a="${work}/pkg-hostA/ws/dist/${p}"
  b="${work}/pkg-hostB/ws/dist/${p}"
  if [ ! -s "${a}" ] || [ ! -s "${b}" ]; then pmissing="${pmissing} ${p}"; continue; fi
  cmp -s "${a}" "${b}" || pdiffer="${pdiffer} ${p}"
done
if [ -z "${pmissing}" ] && [ -z "${pdiffer}" ]; then
  record ".deb and .rpm byte-identical across hostA and hostB" PASS "${#pkgs[@]} packages"
else
  record ".deb and .rpm byte-identical across hostA and hostB" FAIL "missing:${pmissing} differ:${pdiffer}"
fi

# 5. /usr/bin/prufyx in each package equals the archive binary (checked here
# independently of the check inside the packages step).
badbin=""
for p in "${pkgs[@]}"; do
  f="${work}/pkg-hostA/ws/dist/${p}"
  [ -s "${f}" ] || { badbin="${badbin} ${p}"; continue; }
  arch=${p##*_linux_}; arch=${arch%%.*}
  ext=${p##*.}
  u="${work}/unpack-${p}"
  rm -rf "${u}" && mkdir -p "${u}"
  if [ "${ext}" = deb ]; then
    dpkg-deb -x "${f}" "${u}" 2>/dev/null || badbin="${badbin} ${p}"
  else
    (cd "${u}" && rpm2cpio "${f}" | cpio -idm --quiet) 2>/dev/null || badbin="${badbin} ${p}"
  fi
  ref="${work}/ref-${arch}"
  rm -rf "${ref}" && mkdir -p "${ref}"
  tar -xzf "${work}/build1/ws/cli/dist/prufyx_${tag}_linux_${arch}.tar.gz" -C "${ref}" 2>/dev/null
  cmp -s "${u}/usr/bin/prufyx" "${ref}/prufyx_${tag}_linux_${arch}/prufyx" || badbin="${badbin} ${p}"
done
if [ -z "${badbin}" ]; then
  record "/usr/bin/prufyx equals the archive binary" PASS "${#pkgs[@]} packages"
else
  record "/usr/bin/prufyx equals the archive binary" FAIL "${badbin}"
fi

# 6. SHA256SUMS (release workflow step, verbatim) over the archives and packages.
coll="${work}/coll"
mkdir -p "${coll}/dist"
cp "${work}"/build1/ws/cli/dist/*.tar.gz "${coll}/dist/" 2>/dev/null
cp "${work}"/pkg-hostA/ws/dist/*.deb "${work}"/pkg-hostA/ws/dist/*.rpm "${coll}/dist/" 2>/dev/null
sumscript=$(step_script provenance "Generate SHA256SUMS")
if GITHUB_WORKSPACE="${coll}" run_step "${sumscript}" "${logs}/sums.log"; then
  want=$(( ${#expected[@]} + ${#pkgs[@]} ))
  lines=$(wc -l < "${coll}/dist/SHA256SUMS")
  badfmt=$(grep -Evc '^[0-9a-f]{64}  [A-Za-z0-9._~+-]+\.(tar\.gz|deb|rpm)$' "${coll}/dist/SHA256SUMS")
  listed=$(awk '{print $2}' "${coll}/dist/SHA256SUMS" | LC_ALL=C sort | tr '\n' ' ')
  have=$(cd "${coll}/dist" && ls *.tar.gz *.deb *.rpm | LC_ALL=C sort | tr '\n' ' ')
  if [ "${lines}" = "${want}" ] && [ "${badfmt}" = 0 ] && [ "${listed}" = "${have}" ] \
    && (cd "${coll}/dist" && sha256sum -c --quiet SHA256SUMS > "${logs}/sums-check.log" 2>&1); then
    record "SHA256SUMS (${want} lines, sha256sum format, every file listed once, verifies)" PASS "${lines} lines"
  else
    record "SHA256SUMS" FAIL "lines ${lines}, want ${want}; bad format lines ${badfmt}"
  fi
else
  record "SHA256SUMS step" FAIL "see log"; tail_log "${logs}/sums.log"
fi

# Summary.
{
  echo "## Release dry run"
  echo
  echo "Commit \`${head}\`, dry-run tag \`${tag}\`. Nothing was tagged, released or published; no secret was used."
  echo
  echo "| Check | Result | Detail |"
  echo "|---|---|---|"
  printf '%s\n' "${rows[@]}"
} > "${work}/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "${work}/summary.md" >> "${GITHUB_STEP_SUMMARY}"; fi
cat "${work}/summary.md"
exit "${failed}"
