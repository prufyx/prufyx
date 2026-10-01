// SPDX-License-Identifier: AGPL-3.0-only

package releasehelpers

const binaryGettingStartedGuide = `# First local check

Run this walkthrough from the extracted archive directory.
RELEASE-METADATA.json records the build identity.

The walkthrough runs in one subshell, so it preserves the caller's working
directory, umask, and shell options. It prints the binary identity, command
help, and both compatibility results.

~~~sh
(
  set +e
  umask 077
  base=$(pwd -P) || { printf '%s\n' 'cannot determine extracted archive directory' >&2; exit 2; }
  bin="$base/prufyx"
  metadata="$base/RELEASE-METADATA.json"

  if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    printf '%s\n' 'missing executable ./prufyx' >&2
    exit 2
  fi
  if [ ! -f "$metadata" ] || [ ! -r "$metadata" ]; then
    printf '%s\n' 'missing readable ./RELEASE-METADATA.json' >&2
    exit 2
  fi

  "$bin" version || { printf '%s\n' 'cannot read binary version' >&2; exit 2; }
  cat "$metadata" || { printf '%s\n' 'cannot read release metadata' >&2; exit 2; }
  "$bin" --help || { printf '%s\n' 'cannot read command help' >&2; exit 2; }

  tmp_root=${TMPDIR:-/tmp}
  case "$tmp_root" in
    /*) ;;
    *) printf '%s\n' 'temporary directory root must be absolute' >&2; exit 2 ;;
  esac
  work=$(mktemp -d "$tmp_root/prufyx-first-check.XXXXXX") || {
    printf '%s\n' 'cannot create private temporary directory' >&2
    exit 2
  }
  trap 'rm -rf -- "$work"' 0
  trap 'exit 130' HUP INT TERM
  chmod 700 "$work" || { printf '%s\n' 'cannot protect temporary directory' >&2; exit 2; }
  cd "$work" || { printf '%s\n' 'cannot enter temporary directory' >&2; exit 2; }

  if ! cat > blocked.json <<'JSON'
{"prometheus":{"servicemonitor":{"path":"/custom"}}}
JSON
  then
    printf '%s\n' 'cannot write BLOCKED example input' >&2
    exit 2
  fi
  printf '%s\n' '--- cert-manager BLOCKED example (expected exit 10) ---'
  "$bin" check cert-manager-values --from 1.20.3 --to 1.21.1 \
    --values blocked.json --format human
  prufyx_check_exit=$?
  if [ "$prufyx_check_exit" -ne 10 ]; then
    printf 'expected exit 10, got %s\n' "$prufyx_check_exit" >&2
    exit 1
  fi

  if ! cat > fixed.json <<'JSON'
{"prometheus":{"servicemonitor":{"enabled":true,"interval":"60s"}}}
JSON
  then
    printf '%s\n' 'cannot write PASS example input' >&2
    exit 2
  fi
  printf '%s\n' '--- cert-manager scoped PASS example (expected exit 0) ---'
  "$bin" check cert-manager-values --from 1.20.3 --to 1.21.1 \
    --values fixed.json --format human
  prufyx_check_exit=$?
  if [ "$prufyx_check_exit" -ne 0 ]; then
    printf 'expected exit 0, got %s\n' "$prufyx_check_exit" >&2
    exit 1
  fi
)
~~~

This exact check covers only three reviewed merged-values paths removed in the
cert-manager chart transition 1.20.3 to 1.21.1:
prometheus.servicemonitor.path, prometheus.servicemonitor.targetPort, and
prometheus.podmonitor.path.

BLOCKED means at least one of those removed paths is present in this local
values object. Scoped PASS means those paths are absent for this exact pair.
Neither result validates the complete chart schema, Helm rendering, a cluster,
runtime behavior, monitoring endpoints, or whole-upgrade safety. The commands
read the two local example files; use ./prufyx --help to discover other
bounded checks and their required inputs.
`

// BinaryGettingStartedGuide returns a fresh copy of the exact guide embedded
// in and verified for every native binary archive.
func BinaryGettingStartedGuide() []byte {
	return []byte(binaryGettingStartedGuide)
}
