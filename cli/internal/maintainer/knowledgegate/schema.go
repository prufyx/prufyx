// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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
//  5. the change touches neither trust material nor a registry file;
//  6. a level the pack reaches only by declaring it (PackSpec.OptInSchema)
//     changes the answers of rules the change leaves alone, so the change must
//     carry an owner approval of subject packLevel for the raise itself, at
//     <approvals>/<pack>/member.schema.json. It names the pack, the base
//     schema and the head schema, and binds the digests of the base and head
//     pack files. No approval of a rule, however valid, stands in for it, and
//     a batch approval cannot: a batch admits no change of a pack member;
//  7. for such a level, at least one existing active rule of the same pack
//     must in addition have its range added or altered in the same change,
//     admitted by an owner approval of that rule. A reattestation or a
//     re-derivation does not count, nor does an approved rule whose range
//     stays as it was, or one that is not active in the head;
//  8. for such a level, the oldest-supported-client pin of both the base and
//     the head is at or above the version that reads it
//     (cncfcheck.BoundaryCoveredFloor): publication builds refuse the level
//     below it, so data that holds it would stop the whole feed. A missing or
//     unreadable pin refuses, as does one outside the form the publication
//     workflow accepts (publishPinVersion). The head's pin is held to the same
//     floor and form by every later run while the pack stays at the level
//     (optInPinCheck).
//
// Any doubt refuses the change. The gate that decides is the one built from
// the base branch (pull_request_target), so this admission takes effect only
// for changes proposed after the code that holds it is in the base.
func admitSchemaChanges(cls *Classification, pending []*Change, changedPaths []string, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) {
	for _, c := range pending {
		levelApproved, err := checkSchemaChange(cls, c, changedPaths, opts, loadKeys, approvals)
		if err != nil {
			if errors.Is(err, errNoSchemaLevels) {
				c.fail("only the pack's entries and records may change through this gate; the top-level member schema changed (" + err.Error() + ")")
				continue
			}
			c.fail("the pack's schema may change only to the lowest level its content requires: " + err.Error())
			continue
		}
		c.OK, c.Proof, c.levelApproved = true, ProofSchemaLevel, levelApproved
	}
}

var errNoSchemaLevels = errors.New("this pack has no schema levels the gate can compute")

// checkSchemaChange refuses a schema change with the reason. levelApproved
// reports that an owner approval of the pack level raise admitted it.
func checkSchemaChange(cls *Classification, c *Change, changedPaths []string, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) (levelApproved bool, err error) {
	spec, base, head, err := checkSchemaRaise(cls, c, changedPaths, opts)
	if err != nil {
		return false, err
	}
	headSchema, err := memberString(head, "schema")
	if err != nil {
		return false, fmt.Errorf("head: %w", err)
	}
	if spec.OptInSchema == nil || !spec.OptInSchema(headSchema) {
		return false, nil
	}
	if err := checkPackLevelApproval(spec, base, head, opts, loadKeys, approvals); err != nil {
		return false, fmt.Errorf("an opt-in schema level is admitted only with an owner approval of this pack level raise (%s): %w", packLevelApprovalPath(opts.Layout, spec.Name), err)
	}
	return true, nil
}

// checkSchemaRaise checks every condition of a schema change but the owner
// approval of an opt-in level.
func checkSchemaRaise(cls *Classification, c *Change, changedPaths []string, opts Options) (PackSpec, *loadedPack, *loadedPack, error) {
	var spec PackSpec
	refuse := func(err error) (PackSpec, *loadedPack, *loadedPack, error) {
		return PackSpec{}, nil, nil, err
	}
	found := false
	for _, s := range opts.Layout.Packs {
		if s.Name == c.Pack {
			spec, found = s, true
		}
	}
	if !found || spec.RequiredSchema == nil || spec.SchemaLevel == nil {
		return refuse(errNoSchemaLevels)
	}
	base, head := cls.base[c.Pack], cls.head[c.Pack]
	if base == nil || head == nil || !base.Present || !head.Present {
		return refuse(errors.New("the pack is missing from the base or the head"))
	}
	baseSchema, err := memberString(base, "schema")
	if err != nil {
		return refuse(fmt.Errorf("base: %w", err))
	}
	headSchema, err := memberString(head, "schema")
	if err != nil {
		return refuse(fmt.Errorf("head: %w", err))
	}
	required, err := spec.RequiredSchema(head.Raw)
	if err != nil {
		return refuse(fmt.Errorf("the level the head requires cannot be computed: %w", err))
	}
	if headSchema != required {
		return refuse(fmt.Errorf("the head's schema is not the lowest level its content requires (%q, not %q)", logSafe(headSchema), required))
	}
	headLevel, ok := spec.SchemaLevel(headSchema)
	if !ok {
		return refuse(errors.New("the head's schema is unknown"))
	}
	baseLevel, ok := spec.SchemaLevel(baseSchema)
	if !ok {
		return refuse(errors.New("the base's schema is unknown"))
	}
	if baseLevel >= headLevel {
		return refuse(errors.New("the schema is not raised (a downgrade or an unchanged level)"))
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
			return refuse(fmt.Errorf("the top-level member %s changed as well", logSafe(m)))
		}
	}
	// Every other change of the pack is admitted by its own rules.
	for _, o := range cls.Changes {
		if o == c || o.Pack != c.Pack {
			continue
		}
		if o.Member != "" {
			return refuse(fmt.Errorf("the top-level member %s changed as well", logSafe(o.Member)))
		}
		if !o.OK {
			return refuse(errors.New("a rule or record change of the pack is not admitted"))
		}
	}
	if spec.OptInSchema != nil && spec.OptInSchema(headSchema) {
		if !ownerApprovedRangeChange(cls, c.Pack) {
			return refuse(errors.New("an opt-in schema level is admitted only beside an owner approval of an existing active rule of the same pack whose range changes in the same change"))
		}
		if err := optInClientFloor(opts); err != nil {
			return refuse(err)
		}
	}
	for _, p := range changedPaths {
		if opts.Layout.trustPath(p) {
			return refuse(fmt.Errorf("trust material changed in the same change: %s", logSafe(p)))
		}
		for _, reg := range opts.Layout.RegistryPaths {
			if p == reg {
				return refuse(fmt.Errorf("a registry file changed in the same change: %s", logSafe(p)))
			}
		}
	}
	return spec, base, head, nil
}

const (
	// ApprovalSubjectPackLevel is the subject of the owner approval of one
	// raise of a pack to an opt-in schema level.
	ApprovalSubjectPackLevel = "packLevel"
	// PackLevelApprovalID is the rule id such an approval names; it is also
	// the approval's file name (<pack>/member.schema.json).
	PackLevelApprovalID = "member.schema"
)

// packLevelScopeRE is the scope of a packLevel approval: the base schema and
// the head schema, separated by a single space.
var packLevelScopeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]{0,127} [a-z0-9][a-z0-9./-]{0,127}$`)

// packLevelApprovalPath is where a change carries the approval of a pack's
// raise to an opt-in level.
func packLevelApprovalPath(layout Layout, pack string) string {
	return layout.ApprovalDir + "/" + pack + "/" + PackLevelApprovalID + ".json"
}

// packLevelSubject is what an approval of a pack level raise is for: the pack,
// both levels (the scope) and the bytes of the base and head pack files (the
// base and candidate digests). It refuses anything but a raise to an opt-in
// level.
func packLevelSubject(spec PackSpec, base, head *loadedPack) (ApprovalSubject, error) {
	if spec.OptInSchema == nil || spec.SchemaLevel == nil {
		return ApprovalSubject{}, errNoSchemaLevels
	}
	if base == nil || head == nil || !base.Present || !head.Present {
		return ApprovalSubject{}, errors.New("the pack is missing from the base or the head")
	}
	from, err := memberString(base, "schema")
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("base: %w", err)
	}
	to, err := memberString(head, "schema")
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("head: %w", err)
	}
	fromLevel, fromOK := spec.SchemaLevel(from)
	toLevel, toOK := spec.SchemaLevel(to)
	if !fromOK || !toOK || fromLevel >= toLevel || !spec.OptInSchema(to) {
		return ApprovalSubject{}, errors.New("the change does not raise the pack to an opt-in schema level: it needs no pack level approval, and the gate refuses an approval file for it")
	}
	return ApprovalSubject{Kind: ApprovalSubjectPackLevel, Pack: spec.Name, RuleID: PackLevelApprovalID, Scope: from + " " + to, Base: base.Raw, Candidate: head.Raw}, nil
}

// PackLevelApprovalSubject reads a pack's raise to an opt-in level between a
// base and a head checkout exactly as the gate reads it, for the owner to sign
// or check an approval of it.
func PackLevelApprovalSubject(spec PackSpec, base, head Tree) (ApprovalSubject, error) {
	b, err := loadPack(base, spec)
	if err != nil {
		return ApprovalSubject{}, err
	}
	h, err := loadPack(head, spec)
	if err != nil {
		return ApprovalSubject{}, err
	}
	return packLevelSubject(spec, b, h)
}

// checkPackLevelApproval requires the change to carry an owner approval of
// exactly this raise, under the base's pinned owner keys, that the base does
// not already hold or supersede.
func checkPackLevelApproval(spec PackSpec, base, head *loadedPack, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) error {
	subject, err := packLevelSubject(spec, base, head)
	if err != nil {
		return err
	}
	raw, err := opts.Head.ReadOptional(packLevelApprovalPath(opts.Layout, spec.Name), maxApprovalBytes+1)
	if err != nil {
		return fmt.Errorf("approval: %v", err)
	}
	if raw == nil {
		return errors.New("no owner approval of the pack level raise")
	}
	if loadKeys == nil || approvals == nil {
		return errors.New("approval: it cannot be checked")
	}
	if why, err := approvals.refuse(raw); err != nil {
		return fmt.Errorf("approval: %v", err)
	} else if why != "" {
		return errors.New(why)
	}
	keys, err := loadKeys()
	if err != nil {
		return err
	}
	return VerifyApprovalSubject(raw, *keys, subject, opts.Now)
}

// optInClientFloor refuses unless the oldest-supported-client pin of both the
// base and the head is at or above the version that reads an opt-in pack
// level: no publication build carries the level while an older client is still
// supported, so none is admitted either. A missing or unreadable pin refuses.
func optInClientFloor(opts Options) error {
	if err := optInPinFloor("base", opts.Base); err != nil {
		return err
	}
	return optInPinFloor("head", opts.Head)
}

// The two lines of the pin file exactly as the publication workflow
// (knowledge-publish.yml) accepts them; a test holds them to that file. A pin
// the workflow refuses stops every publication, so it admits nothing here.
var (
	publishPinRefRE     = regexp.MustCompile(`^ref=[0-9a-f]{40}$`)
	publishPinVersionRE = regexp.MustCompile(`^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+\.[0-9]+)?$`)
)

// publishPinVersion reads the version of a pin file in the publication
// workflow's form.
func publishPinVersion(raw []byte) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !publishPinRefRE.MatchString(lines[0]) || !publishPinVersionRE.MatchString(lines[1]) {
		return "", errors.New("the pin file does not hold exactly the lines ref=<40-hex commit> and version=vMAJOR.MINOR.PATCH[-pre.N]")
	}
	return strings.TrimPrefix(lines[1], "version="), nil
}

// optInPinFloor is optInClientFloor for one tree, named name in the refusal.
func optInPinFloor(name string, tree Tree) error {
	raw, err := tree.Read(OldestClientPinPath, 1024)
	if err != nil {
		return fmt.Errorf("the %s's oldest supported client pin: %v", name, err)
	}
	version, err := publishPinVersion(raw)
	if err != nil {
		return fmt.Errorf("the %s's oldest supported client pin: %v", name, err)
	}
	if !buildidentity.AtLeast(version, cncfcheck.BoundaryCoveredFloor) {
		return fmt.Errorf("the %s still supports client %s, which cannot read an opt-in schema level: none is admitted before the oldest supported client is %s or later", name, version, cncfcheck.BoundaryCoveredFloor)
	}
	return nil
}

// optInPinCheck holds the pin for as long as the head's pack is at an opt-in
// level, whether or not the change touches the pack: a later change that
// lowers, removes or breaks the pin would otherwise stop every publication
// build. A pack at any other level adds no check; a level that cannot be read
// refuses.
func (r *Report) optInPinCheck(spec PackSpec, h *loadedPack, opts Options) {
	if spec.OptInSchema == nil {
		return
	}
	name := "opt-in-client-pin/" + spec.Name
	schema, err := memberString(h, "schema")
	if err != nil {
		r.add(name, false, "the pack's level cannot be read: %v", err)
		return
	}
	if !spec.OptInSchema(schema) {
		return
	}
	if err := optInPinFloor("head", opts.Head); err != nil {
		r.add(name, false, "%v", err)
		return
	}
	r.add(name, true, "the oldest supported client reads the pack's opt-in level")
}

// ownerApprovedRangeChange reports an admitted rule change of the pack that
// rests on an owner approval and adds or alters the range of an existing
// rule that is active in the head.
func ownerApprovedRangeChange(cls *Classification, pack string) bool {
	for _, o := range cls.Changes {
		if o.Pack != pack || o.Member != "" || o.Section != "" || o.RuleID == "" || !o.OK {
			continue
		}
		if o.Proof != ProofApproval {
			continue
		}
		if o.base == nil || o.head == nil || len(o.head.Range) == 0 || string(o.head.Range) == "null" {
			continue
		}
		// A rule that is not active changes no answer.
		if o.head.Evidence.State != "active" {
			continue
		}
		if !sameAt(o.base.generic, o.head.generic, "rule", "range") {
			return true
		}
	}
	return false
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
