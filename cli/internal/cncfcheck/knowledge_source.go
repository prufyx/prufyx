// SPDX-License-Identifier: AGPL-3.0-only

//go:build !prufyx_synthetic_knowledge

package cncfcheck

import "github.com/prufyx/prufyx/cli/internal/constraintengine"

// packagedRulePack returns the embedded rule pack. Every shipped build reads
// exactly these bytes.
func packagedRulePack() ([]byte, error) { return packagedFiles.ReadFile("data/rules.json") }

// embeddedMemo holds the embedded bundle of this process. It exists only in
// the default build: the synthetic-knowledge build swaps knowledge at run
// time and never caches (see knowledge_source_synthetic.go).
var embeddedMemo bundleMemo

// load returns the embedded bundle. The packaged files are parsed and
// strictly validated once per process; every call gets its own copy of the
// mutable parts (bundleMemo.get), so no caller can change what the next one
// reads. A failure is cached as a failure.
func load() (bundle, error) { return embeddedMemo.get(loadUncached) }

// additionalDefinitions is empty in every shipped build: the compiled
// registry is exactly the packaged definitions.
func additionalDefinitions() []constraintengine.FactDefinition { return nil }
