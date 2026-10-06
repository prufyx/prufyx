#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../../../" && pwd -P)"
CORPUS_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$REPO_ROOT"
python3 -B "$CORPUS_ROOT/validate.py"
python3 -B -m unittest discover -s "$CORPUS_ROOT/tests" -p 'test_*.py' -q
node "$CORPUS_ROOT/tests/strict-ajv.mjs"
cd "$CORPUS_ROOT"
go test ./tests -count=1
