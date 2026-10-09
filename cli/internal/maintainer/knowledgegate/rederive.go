// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
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

// rederive re-runs, once per group, the extractor each mechanical rule or
// line attestation names and requires every head entry or record to be
// byte-identical (canonical JSON) to the re-derived one. It sets OK, Proof
// and Detail on every change it is given.
func rederive(ctx context.Context, src Source, catalog map[string]extractcli.Spec, concurrency int, layout Layout, changes []*Change) {
	admitted := map[string]func([]byte) (json.RawMessage, error){}
	for _, spec := range layout.Packs {
		admitted[spec.Name] = spec.Entry
	}
	groups := map[rederiveKey][]*Change{}
	for _, c := range changes {
		var x *constraintengine.Extractor
		var derivedAt, validUntil string
		switch {
		case c.rhead != nil:
			x, derivedAt, validUntil = c.rhead.Extractor, c.rhead.DerivedAt, c.rhead.ValidUntil
			if c.rhead.attestation == nil {
				c.fail("no extractor derives path policies")
				continue
			}
		case c.head != nil:
			x, derivedAt, validUntil = c.head.Evidence.Extractor, c.head.Evidence.DerivedAt, c.head.Evidence.ValidUntil
		default:
			c.fail("nothing to re-derive")
			continue
		}
		if x == nil {
			c.fail("mechanical rule names no extractor")
			continue
		}
		k := rederiveKey{x.ID, x.Version, x.CodeDigest, derivedAt, validUntil}
		groups[k] = append(groups[k], c)
	}
	keys := make([]rederiveKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	for _, k := range keys {
		group := groups[k]
		entries, attestations, err := rederiveGroup(ctx, src, catalog, concurrency, k)
		if err != nil {
			for _, c := range group {
				c.fail("re-derivation failed: " + err.Error())
			}
			continue
		}
		for _, c := range group {
			if c.rhead != nil {
				// A line attestation: the extractor's own record for
				// the scope, compared canonically.
				derived, ok := attestations[c.RuleID]
				switch {
				case !ok:
					c.fail(fmt.Sprintf("extractor %s %s does not attest this line from the pinned upstream bytes", k.id, k.version))
				case !bytes.Equal(derived, c.rhead.Canonical):
					c.fail(fmt.Sprintf("line attestation differs from what extractor %s %s derives from the pinned upstream bytes", k.id, k.version))
				default:
					c.OK, c.Proof = true, ProofRederived
				}
				continue
			}
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

// rederiveGroup runs one extractor at one derivation time and lease and
// returns its entries by rule ID and its line attestations, in canonical
// JSON, by record ID.
func rederiveGroup(ctx context.Context, src Source, catalog map[string]extractcli.Spec, concurrency int, k rederiveKey) (map[string][]byte, map[string][]byte, error) {
	if src == nil {
		return nil, nil, fmt.Errorf("no upstream source is configured")
	}
	spec, ok := catalog[k.id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown extractor %q", k.id)
	}
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return nil, nil, err
	}
	derived, err := time.Parse(time.RFC3339, k.derivedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("derivedAt %q", k.derivedAt)
	}
	until, err := time.Parse(time.RFC3339, k.validUntil)
	if err != nil || !until.After(derived) {
		return nil, nil, fmt.Errorf("validUntil %q", k.validUntil)
	}
	ex := spec.New(concurrency)
	out, err := extract.Run(ctx, ex, src, src, extract.Options{Repo: repo, DerivedAt: derived, Lease: until.Sub(derived)})
	if err != nil {
		return nil, nil, err
	}
	id := out.Manifest.Extractor
	if id.ID != k.id || id.Version != k.version || id.CodeDigest != k.codeDigest {
		return nil, nil, fmt.Errorf("the rule names extractor %s %s %s, this gate runs %s %s %s", k.id, k.version, k.codeDigest, id.ID, id.Version, id.CodeDigest)
	}
	entries := map[string][]byte{}
	for _, e := range out.Entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, nil, err
		}
		entries[e.Rule.ID] = raw
	}
	attestations := map[string][]byte{}
	for _, a := range out.Attestations {
		raw, err := extract.Canonical(a)
		if err != nil {
			return nil, nil, err
		}
		attestations[evidencerepin.LineAttestationRecordID(a.Component, a.FactFamily, a.Line)] = raw
	}
	return entries, attestations, nil
}

// attesterRun is one run of the extractor that attests a fact family for
// one component, with the first line the extractor declares it derives
// ("" when it declares none).
type attesterRun struct {
	out   *extract.Output
	floor string
	err   error
}

// runAttester runs the extractor of the catalog that attests family for
// component over the pinned upstream bytes, derived at now, and returns
// its output and its declared first line. An extractor that names the
// component it attests (extract.ComponentAttester) is chosen only for that
// component; one that does not is chosen only for a family with exactly
// that one component.
func runAttester(ctx context.Context, src Source, catalog map[string]extractcli.Spec, concurrency int, family, component string, now time.Time) (*extract.Output, string, error) {
	if src == nil {
		return nil, "", fmt.Errorf("no upstream source is configured")
	}
	f, ok := lineattest.LookupFamily(family)
	if !ok || !f.Admits(component) {
		return nil, "", fmt.Errorf("fact family %s does not cover %s", logSafe(family), logSafe(component))
	}
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		spec := catalog[id]
		ex := spec.New(concurrency)
		attester, ok := ex.(extract.LineAttester)
		if !ok || !slices.Contains(attester.AttestedFamilies(), family) {
			continue
		}
		if ca, named := ex.(extract.ComponentAttester); named && ca.AttestedComponent() != component {
			continue
		} else if !named && !slices.Equal(f.Components(), []string{component}) {
			continue
		}
		repo, err := extract.ParseRepo(spec.Repo)
		if err != nil {
			return nil, "", err
		}
		floor := attesterFloors[id]
		if floor != "" && !lineattest.ValidLine(floor) {
			return nil, "", fmt.Errorf("extractor %s has an invalid first line %q", id, floor)
		}
		out, err := extract.Run(ctx, ex, src, src, extract.Options{Repo: repo, DerivedAt: now.UTC().Truncate(time.Second)})
		return out, floor, err
	}
	return nil, "", fmt.Errorf("no extractor of this gate attests fact family %s for %s", logSafe(family), logSafe(component))
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
