// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"errors"
	"fmt"
	"sort"
)

// ErrAmbiguousSpelling is the error of a line whose releases are spelled
// ambiguously: a padded and a canonical spelling of one version at two
// commits, or a padded-only release beside a release kept under the canonical
// spelling.
var ErrAmbiguousSpelling = errors.New("the line has release tags with a zero-padded minor and with a canonical minor, so its releases are ambiguous")

// FinalSet collects the final release tags of ONE release line, as read by
// ReadFinalTag, and applies the one rule for zero-padded twins that the
// extractor and the release completeness check of the knowledge gate share:
//
//   - a version tagged twice at one commit is one release, whatever the
//     spellings or prefixes; its twin spellings (v25.08.0, v25.8.0) are kept
//     under the canonical (unpadded) one;
//   - a version tagged at two commits is an error (ErrAmbiguousSpelling when
//     the spellings differ, a plain conflict otherwise);
//   - a release spelled only padded (v25.08.1) beside any release kept under
//     the canonical spelling (a canonical-only tag, or a twin) makes the line
//     ambiguous.
type FinalSet struct {
	versions map[string]*finalEntry
	err      error
}

type finalEntry struct {
	commit          string
	padded, canonic bool
}

// Add records one tag read as version (canonical X.Y.Z) with its spelling and
// commit. It returns the sticky error of the set (two commits of one release); the
// mixed-spelling check depends on the whole set and is read once, by Err.
func (s *FinalSet) Add(version string, padded bool, commit string) error {
	if s.versions == nil {
		s.versions = map[string]*finalEntry{}
	}
	e := s.versions[version]
	if e == nil {
		e = &finalEntry{commit: commit}
		s.versions[version] = e
	} else if e.commit != commit && s.err == nil {
		if (padded && e.canonic) || (!padded && e.padded) {
			s.err = ErrAmbiguousSpelling
		} else {
			s.err = fmt.Errorf("a release of the line is tagged twice, at two commits (%s)", version)
		}
	}
	if padded {
		e.padded = true
	} else {
		e.canonic = true
	}
	return s.err
}

// Err is the first error of the set, or the mixed-spelling error: a
// padded-only release beside a release kept under the canonical spelling.
func (s *FinalSet) Err() error {
	if s.err != nil {
		return s.err
	}
	var paddedOnly, canonical bool
	for _, e := range s.versions {
		if e.padded && !e.canonic {
			paddedOnly = true
		} else {
			canonical = true
		}
	}
	if paddedOnly && canonical {
		return ErrAmbiguousSpelling
	}
	return nil
}

// Versions lists the releases of the set, canonical spelling, unsorted order
// made deterministic (lexical).
func (s *FinalSet) Versions() []string {
	out := make([]string, 0, len(s.versions))
	for v := range s.versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
