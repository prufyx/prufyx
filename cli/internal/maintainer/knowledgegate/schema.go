// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// The first attested update of a pack that holds an older schema must move
// the pack to the schema its new content requires (line attestations need
// the attested level). The schema is a top-level pack member, which this
// gate never admits as a pack-member change; admitSchemaChanges admits that
// one member, and only that, under all of these conditions:
//
//  1. the head's schema is exactly the lowest schema the head's content
//     requires, computed by the function the pack parser and validator use
//     (PackSpec.RequiredSchema), so never a higher level than needed;
//  2. the base's schema is a known schema of a lower level (a bump upward
//     only, never a downgrade, never an unchanged level);
//  3. no other top-level member of the pack changes (a section of
//     records, which the gate reads record by record, aside);
//  4. every other change of the pack (rules, records) is admitted by its
//     own rules: re-derivation, a reattestation statement or an approval;
//  5. the change touches neither trust material nor a registry file.
//
// Any doubt refuses the change. The gate that decides is the one built from
// the base branch (pull_request_target), so this admission takes effect only
// for changes proposed after the code that holds it is in the base.
func admitSchemaChanges(cls *Classification, pending []*Change, changedPaths []string, opts Options) {
	for _, c := range pending {
		if err := checkSchemaChange(cls, c, changedPaths, opts); err != nil {
			if errors.Is(err, errNoSchemaLevels) {
				c.fail("only the pack's entries and records may change through this gate; the top-level member schema changed (" + err.Error() + ")")
				continue
			}
			c.fail("the pack's schema may change only to the lowest level its content requires: " + err.Error())
			continue
		}
		c.OK, c.Proof = true, ProofSchemaLevel
	}
}

var errNoSchemaLevels = errors.New("this pack has no schema levels the gate can compute")

func checkSchemaChange(cls *Classification, c *Change, changedPaths []string, opts Options) error {
	var spec PackSpec
	found := false
	for _, s := range opts.Layout.Packs {
		if s.Name == c.Pack {
			spec, found = s, true
		}
	}
	if !found || spec.RequiredSchema == nil || spec.SchemaLevel == nil {
		return errNoSchemaLevels
	}
	base, head := cls.base[c.Pack], cls.head[c.Pack]
	if base == nil || head == nil || !base.Present || !head.Present {
		return errors.New("the pack is missing from the base or the head")
	}
	baseSchema, err := memberString(base, "schema")
	if err != nil {
		return fmt.Errorf("base: %w", err)
	}
	headSchema, err := memberString(head, "schema")
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	required, err := spec.RequiredSchema(head.Raw)
	if err != nil {
		return fmt.Errorf("the level the head requires cannot be computed: %w", err)
	}
	if headSchema != required {
		return fmt.Errorf("the head's schema is not the lowest level its content requires (%q, not %q)", logSafe(headSchema), required)
	}
	headLevel, ok := spec.SchemaLevel(headSchema)
	if !ok {
		return errors.New("the head's schema is unknown")
	}
	baseLevel, ok := spec.SchemaLevel(baseSchema)
	if !ok {
		return errors.New("the base's schema is unknown")
	}
	if baseLevel >= headLevel {
		return errors.New("the schema is not raised (a downgrade or an unchanged level)")
	}
	// Nothing else at the top level changes.
	seen := map[string]bool{}
	var names []string
	for _, ms := range []map[string]json.RawMessage{base.Members, head.Members} {
		for m := range ms {
			if !seen[m] {
				seen[m] = true
				names = append(names, m)
			}
		}
	}
	sort.Strings(names)
	for _, m := range names {
		if m == "schema" || recordSection(head.Spec, m) {
			continue
		}
		b, bok := base.Members[m]
		h, hok := head.Members[m]
		if bok != hok || !bytes.Equal(canonicalRaw(b), canonicalRaw(h)) {
			return fmt.Errorf("the top-level member %s changed as well", logSafe(m))
		}
	}
	// Every other change of the pack is admitted by its own rules.
	for _, o := range cls.Changes {
		if o == c || o.Pack != c.Pack {
			continue
		}
		if o.Member != "" {
			return fmt.Errorf("the top-level member %s changed as well", logSafe(o.Member))
		}
		if !o.OK {
			return errors.New("a rule or record change of the pack is not admitted")
		}
	}
	for _, p := range changedPaths {
		if opts.Layout.trustPath(p) {
			return fmt.Errorf("trust material changed in the same change: %s", logSafe(p))
		}
		for _, reg := range opts.Layout.RegistryPaths {
			if p == reg {
				return fmt.Errorf("a registry file changed in the same change: %s", logSafe(p))
			}
		}
	}
	return nil
}

// memberString reads a top-level member that must be a JSON string.
func memberString(p *loadedPack, name string) (string, error) {
	raw, ok := p.Members[name]
	if !ok {
		return "", fmt.Errorf("no %s member", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", fmt.Errorf("the %s member is not a string", name)
	}
	return s, nil
}
