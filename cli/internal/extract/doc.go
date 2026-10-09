// SPDX-License-Identifier: AGPL-3.0-only

// Package extract runs mechanical rule extractors: deterministic programs
// that derive rule candidates from upstream source bytes pinned by full
// commit SHA, with no model and no network access.
//
// An Extractor names the release pairs it evaluates (Pairs) and derives
// candidates for one pair (Extract), reading upstream files only through a
// PinnedReader. Run wraps the reader in a Recorder, so every file the
// extractor read is logged with its repository, commit, path and whole-file
// sha256. Run then stamps each candidate with the provenance the engine
// requires of a mechanical rule (basis, extractor id, version and code
// digest, derivedAt) and with source citations whose digests come from the
// recorded reads, never from the extractor. It generates test vectors for
// every rule from the same data, checks the vectors through the constraint
// engine and the candidates through rulecheck, and writes:
//
//	candidates.json   pack entries (project, description, requiredFacts, rule)
//	vectors.json      engine inputs and the verdict each rule must give
//	manifest.json     extractor identity, pairs, per-pair proof, per-commit read summary
//	reads/<sha>.tsv   every file read at that commit: path, sha256, size
//
// All four are canonical JSON or sorted text, so running the same extractor
// version on the same pinned bytes with the same derivedAt yields
// byte-identical output. Verify re-derives and compares byte for byte.
//
// An extractor that cannot establish a pair completely withholds it
// (Withheld): no candidate is emitted and the manifest records why. Absence
// of evidence never becomes a rule.
//
// # Code digest
//
// A mechanical rule records extractor.codeDigest, the sha256 of the code that
// produced it. CodeDigest computes it over the Go source files (excluding
// _test.go files) of this package and of the extractor's own package, and
// over the reviewed top-level *.json data files the package embeds next to its
// code, all embedded into the binary at build time (testdata is not part of
// it). Each file contributes the line
//
//	<package dir>/<file name> NUL <hex sha256 of the file> LF
//
// and the lines, sorted by byte order, are hashed with sha256. The manifest
// lists every file and its digest, so anyone with the source tree can
// recompute the value with standard tools.
package extract
