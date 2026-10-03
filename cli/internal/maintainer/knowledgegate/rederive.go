// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
)

// Source serves pinned upstream bytes and a repository's tags for
// re-derivation.
type Source interface {
	extract.PinnedReader
	extract.TagSource
}

// rederiveKey groups mechanical rules that one extractor run reproduces:
// same extractor identity, same derivation time and same lease.
type rederiveKey struct {
	id, version, codeDigest, derivedAt, validUntil string
}

// rederive re-runs, once per group, the extractor each mechanical rule
// names and requires every rule's head entry to be byte-identical
// (canonical JSON) to the re-derived one. It sets OK, Proof and Detail on
// every change it is given.
func rederive(ctx context.Context, src Source, catalog map[string]extractcli.Spec, concurrency int, layout Layout, changes []*Change) {
	admitted := map[string]func([]byte) (json.RawMessage, error){}
	for _, spec := range layout.Packs {
		admitted[spec.Name] = spec.Entry
	}
	groups := map[rederiveKey][]*Change{}
	for _, c := range changes {
		ev := c.head.Evidence
		if ev.Extractor == nil {
			c.fail("mechanical rule names no extractor")
			continue
		}
		k := rederiveKey{ev.Extractor.ID, ev.Extractor.Version, ev.Extractor.CodeDigest, ev.DerivedAt, ev.ValidUntil}
		groups[k] = append(groups[k], c)
	}
	keys := make([]rederiveKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	for _, k := range keys {
		group := groups[k]
		entries, err := rederiveGroup(ctx, src, catalog, concurrency, k)
		if err != nil {
			for _, c := range group {
				c.fail("re-derivation failed: " + err.Error())
			}
			continue
		}
		for _, c := range group {
			derived, ok := entries[c.RuleID]
			var want []byte
			if ok {
				// Compare the re-derived entry as admission would read
				// it, exactly as the head entry was read.
				want, err = admittedCanonical(admitted[c.Pack], derived)
			}
			switch {
			case !ok:
				c.fail(fmt.Sprintf("extractor %s %s does not derive this rule from the pinned upstream bytes", k.id, k.version))
			case err != nil:
				c.fail("the re-derived entry is not admissible: " + err.Error())
			case !bytes.Equal(want, c.head.Canonical):
				c.fail(fmt.Sprintf("rule differs from what extractor %s %s derives from the pinned upstream bytes", k.id, k.version))
			default:
				c.OK, c.Proof = true, ProofRederived
			}
		}
	}
}

func rederiveGroup(ctx context.Context, src Source, catalog map[string]extractcli.Spec, concurrency int, k rederiveKey) (map[string][]byte, error) {
	if src == nil {
		return nil, fmt.Errorf("no upstream source is configured")
	}
	spec, ok := catalog[k.id]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %q", k.id)
	}
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return nil, err
	}
	derived, err := time.Parse(time.RFC3339, k.derivedAt)
	if err != nil {
		return nil, fmt.Errorf("derivedAt %q", k.derivedAt)
	}
	until, err := time.Parse(time.RFC3339, k.validUntil)
	if err != nil || !until.After(derived) {
		return nil, fmt.Errorf("validUntil %q", k.validUntil)
	}
	ex := spec.New(concurrency)
	out, err := extract.Run(ctx, ex, src, src, extract.Options{Repo: repo, DerivedAt: derived, Lease: until.Sub(derived)})
	if err != nil {
		return nil, err
	}
	id := out.Manifest.Extractor
	if id.ID != k.id || id.Version != k.version || id.CodeDigest != k.codeDigest {
		return nil, fmt.Errorf("the rule names extractor %s %s %s, this gate runs %s %s %s", k.id, k.version, k.codeDigest, id.ID, id.Version, id.CodeDigest)
	}
	entries := map[string][]byte{}
	for _, e := range out.Entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		entries[e.Rule.ID] = raw
	}
	return entries, nil
}

// admittedCanonical is the canonical JSON of an entry as admission reads it.
func admittedCanonical(admit func([]byte) (json.RawMessage, error), raw []byte) ([]byte, error) {
	if admit == nil {
		return nil, fmt.Errorf("no admission reader for this pack")
	}
	view, err := admit(raw)
	if err != nil {
		return nil, err
	}
	return extract.Canonical(view)
}
