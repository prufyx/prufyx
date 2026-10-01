#!/bin/sh
set -eu
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../../../" && pwd)"
CORPUS_ROOT="$REPO_ROOT/testdata/synthetic-cluster-scenarios/v3"
cd "$REPO_ROOT"
python3 -B "$CORPUS_ROOT/validate.py"
python3 -B -m unittest discover -s "$CORPUS_ROOT/tests" -p 'test_*.py' -q
node "$REPO_ROOT/testdata/synthetic-cluster-scenarios/v3/tests/strict-ajv.mjs"
cd "$CORPUS_ROOT"
go test ./tests -count=1
