// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"sync"
)

// bundleMemo memoizes one bundle load for the life of the process. The first
// get runs the loader (digest and strict checks included) under sync.Once; a
// failure is stored and returned to every later caller, with no retry and no
// fallback. Each caller receives its own copy of the parts a caller could
// mutate (landscape, priority list, rule pack and its byte sections); the
// registry and the section indexes have only unexported state and copying
// accessors, so they are shared.
type bundleMemo struct {
	once sync.Once
	b    bundle
	err  error
}

func (m *bundleMemo) get(loader func() (bundle, error)) (bundle, error) {
	m.once.Do(func() { m.b, m.err = loader() })
	if m.err != nil {
		return bundle{}, m.err
	}
	return m.b.clone(), nil
}

func cloneBytes(b json.RawMessage) json.RawMessage {
	if b == nil {
		return nil
	}
	return append(json.RawMessage{}, b...)
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string{}, s...)
}

// clone deep-copies every slice, map-free field and byte section of the
// bundle that is reachable and writable from outside the indexes.
func (b bundle) clone() bundle {
	out := b
	if b.landscape.Projects != nil {
		out.landscape.Projects = append([]projectIdentity{}, b.landscape.Projects...)
	}
	out.priority.Priority = cloneStrings(b.priority.Priority)
	out.pack.LineAttestations = cloneBytes(b.pack.LineAttestations)
	out.pack.PathPolicies = cloneBytes(b.pack.PathPolicies)
	out.pack.Distributions = cloneBytes(b.pack.Distributions)
	out.pack.ServedAPIs = cloneBytes(b.pack.ServedAPIs)
	if b.pack.Entries != nil {
		out.pack.Entries = make([]Entry, len(b.pack.Entries))
		for i, e := range b.pack.Entries {
			e.Rule = cloneBytes(e.Rule)
			if e.RequiredFacts != nil {
				facts := make([]Fact, len(e.RequiredFacts))
				for j, f := range e.RequiredFacts {
					f.EnumTokens = cloneStrings(f.EnumTokens)
					facts[j] = f
				}
				e.RequiredFacts = facts
			}
			out.pack.Entries[i] = e
		}
	}
	return out
}
