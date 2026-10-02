// SPDX-License-Identifier: AGPL-3.0-only

//go:build !prufyx_synthetic_knowledge

package cncfcheck

import "github.com/prufyx/prufyx/cli/internal/constraintengine"

// packagedRulePack returns the embedded rule pack. Every shipped build reads
// exactly these bytes.
func packagedRulePack() ([]byte, error) { return packagedFiles.ReadFile("data/rules.json") }

// additionalDefinitions is empty in every shipped build: the compiled
// registry is exactly the packaged definitions.
func additionalDefinitions() []constraintengine.FactDefinition { return nil }
