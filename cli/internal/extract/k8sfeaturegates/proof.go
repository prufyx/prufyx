// SPDX-License-Identifier: AGPL-3.0-only

package k8sfeaturegates

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// pairProof is recorded in the run manifest for every pair.
type pairProof struct {
	From            fromSummary `json:"from"`
	To              toSummary   `json:"to"`
	Components      []string    `json:"components"`
	Removed         []gateDecl  `json:"removed"`
	Unrepresentable []string    `json:"unrepresentable,omitempty"`
}

type fromSummary struct {
	Commit           string    `json:"commit"`
	Complete         bool      `json:"complete"`
	Problems         []string  `json:"problems,omitempty"`
	DeclarationFiles []fileRef `json:"declarationFiles"`
	Declared         []string  `json:"declared"`
}

type toSummary struct {
	Commit           string            `json:"commit"`
	Complete         bool              `json:"complete"`
	Problems         []string          `json:"problems,omitempty"`
	WalkRoots        map[string]string `json:"walkRoots"`
	GoFiles          int               `json:"goFiles"`
	DynamicKeys      int               `json:"dynamicKeys"`
	DeclarationFiles []fileRef         `json:"declarationFiles"`
	ReferenceLists   []fileRef         `json:"referenceLists"`
	UnrecognizedGate *pos              `json:"unrecognizedGateError"`
	// Names is every gate name the walk found (the absence proof); its
	// digest is sha256 over the names joined by LF.
	Names       []string `json:"names"`
	NamesDigest string   `json:"namesDigest"`
}

const maxProblems = 20

func capProblems(p []string) []string {
	if len(p) > maxProblems {
		return append(append([]string(nil), p[:maxProblems]...), "...")
	}
	return p
}

func summarizeFrom(reg *registry) fromSummary {
	names := make([]string, 0, len(reg.Declared))
	for n := range reg.Declared {
		names = append(names, n)
	}
	sort.Strings(names)
	return fromSummary{Commit: reg.Commit, Complete: len(reg.DeclProblems) == 0, Problems: capProblems(reg.DeclProblems), DeclarationFiles: nonNil(reg.DeclFiles), Declared: names}
}

func summarizeTo(reg *registry) toSummary {
	names := make([]string, 0, len(reg.All))
	for n := range reg.All {
		names = append(names, n)
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	problems := append(append([]string(nil), reg.Problems...), reg.DeclProblems...)
	sort.Strings(problems)
	return toSummary{
		Commit: reg.Commit, Complete: len(problems) == 0, Problems: capProblems(problems),
		WalkRoots: reg.Roots, GoFiles: reg.GoFiles, DynamicKeys: reg.DynamicKeys,
		DeclarationFiles: nonNil(reg.DeclFiles), ReferenceLists: nonNil(reg.ReferenceLists), UnrecognizedGate: reg.ErrorLine,
		Names: names, NamesDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

func nonNil(in []fileRef) []fileRef {
	if in == nil {
		return []fileRef{}
	}
	return in
}
