// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// A pack's registryDigest member is the digest of the fact registry
// compiled into the executable. The registry is Go code, not a file of
// RegistryPaths, so adding a fact definition moves the member: a top-level
// member change, which this gate never admits as such. admitRegistryChanges
// admits that one member, and only that, when every condition holds:
//
//  1. the pack has a fact registry the gate reads (PackSpec.FactDefinitions
//     and PackSpec.RegistrySourcePath);
//  2. the base member is the digest of the gate's own compiled registry, the
//     registry the base code holds;
//  3. the head's definition list, read from the head's Go source without
//     running it (headFactDefinitions), is the base list plus new
//     definitions: none removed, retyped, moved to another component or
//     given other enum tokens;
//  4. the head member is the digest of that list, and so of the registry
//     any build of the head must compile to admit its own pack (the engine
//     refuses a pack whose registryDigest differs from its registry);
//  5. no other top-level member of any pack changes (schema and revision
//     included), and the change touches neither trust material, a registry
//     file nor a reattestation chain;
//  6. an owner approval of subject registryDigest arrives with the change
//     and verifies under the base's pinned owner keys: its base digest is
//     the base registry digest and its candidate digest that of the
//     RegistryAddition statement naming both digests and every added
//     definition.
//
// Any doubt refuses the change. The pack is then admitted, and its corpus
// attestation regenerated, under the head's definition list.
const (
	// ApprovalSubjectRegistry is the subject of an approval of an additive
	// fact-registry change.
	ApprovalSubjectRegistry = "registryDigest"
	// RegistryApprovalID is the rule id such an approval names; it is also
	// the approval's file name (<pack>/member.registryDigest.json). It is
	// never a rule id (rule ids are lower case) or a record ID.
	RegistryApprovalID = "member.registryDigest"
	// RegistryApprovalScope is the scope such an approval names.
	RegistryApprovalScope = "registryDigest"
	// RegistryAdditionSchema is the schema of the statement an approval of
	// subject registryDigest binds.
	RegistryAdditionSchema = "prufyx.io/fact-registry-addition/v1"

	registryMember        = "registryDigest"
	maxRegistrySourceSize = 1 << 20
)

// RegistryAddition is the statement an approval of subject registryDigest
// binds (its canonical JSON is the candidate): the base and head registry
// digests and every added definition, sorted by ID.
type RegistryAddition struct {
	Schema             string                            `json:"schema"`
	BaseRegistryDigest string                            `json:"baseRegistryDigest"`
	HeadRegistryDigest string                            `json:"headRegistryDigest"`
	Added              []constraintengine.FactDefinition `json:"added"`
}

// registryChange is a verified additive registry change: the base and head
// registries, the added definitions and the canonical statement.
type registryChange struct {
	base, head constraintengine.Registry
	added      []constraintengine.FactDefinition
	statement  []byte
}

// readRegistryChange reads the registry change of one pack between base and
// head: the base list is the gate's own (spec.FactDefinitions), checked
// against the base member and against the base's Go source; the head list
// is the base list with the source's literal definitions replaced by the
// head's. It refuses anything but a pure addition, and a member that is not
// the digest of the list it names.
func readRegistryChange(spec PackSpec, base, head Tree, baseMember, headMember json.RawMessage) (*registryChange, error) {
	if spec.FactDefinitions == nil || spec.RegistrySourcePath == "" {
		return nil, errors.New("the pack has no fact registry this gate reads")
	}
	var baseDigest, headDigest string
	if json.Unmarshal(baseMember, &baseDigest) != nil || json.Unmarshal(headMember, &headDigest) != nil || !approvalDigestRE.MatchString(baseDigest) || !approvalDigestRE.MatchString(headDigest) {
		return nil, errors.New("the registryDigest member is not a digest in the base or the head")
	}
	baseRegistry, err := constraintengine.NewCompiledRegistry(spec.FactDefinitions())
	if err != nil {
		return nil, fmt.Errorf("the gate's own fact registry is invalid: %v", err)
	}
	if baseRegistry.Digest() != baseDigest {
		return nil, errors.New("the base registryDigest is not the digest of the gate's own fact registry")
	}
	baseSrc, err := base.Read(spec.RegistrySourcePath, maxRegistrySourceSize)
	if err != nil {
		return nil, fmt.Errorf("base fact registry source: %v", err)
	}
	headSrc, err := head.Read(spec.RegistrySourcePath, maxRegistrySourceSize)
	if err != nil {
		return nil, fmt.Errorf("head fact registry source: %v", err)
	}
	baseLiteral, err := parsePackagedDefinitions(baseSrc)
	if err != nil {
		return nil, fmt.Errorf("base fact registry source: %v", err)
	}
	headLiteral, err := parsePackagedDefinitions(headSrc)
	if err != nil {
		return nil, fmt.Errorf("head fact registry source: %v", err)
	}
	headRegistry, err := headFactDefinitions(baseRegistry, baseLiteral, headLiteral)
	if err != nil {
		return nil, err
	}
	added, err := additions(baseRegistry, headRegistry)
	if err != nil {
		return nil, err
	}
	if headRegistry.Digest() != headDigest {
		return nil, errors.New("the head registryDigest is not the digest of the head's fact definitions as this gate reads them (base list plus the definitions the head adds)")
	}
	statement, err := registryStatement(baseRegistry, headRegistry, added)
	if err != nil {
		return nil, err
	}
	return &registryChange{base: baseRegistry, head: headRegistry, added: added, statement: statement}, nil
}

// headFactDefinitions is the base registry with the base source's literal
// definitions replaced by the head source's. Every base literal must be in
// the base registry exactly: that proves the reader reads the code the gate
// was built from.
func headFactDefinitions(baseRegistry constraintengine.Registry, baseLiteral, headLiteral []constraintengine.FactDefinition) (constraintengine.Registry, error) {
	byID := map[string]constraintengine.FactDefinition{}
	for _, d := range baseRegistry.Definitions() {
		byID[d.ID] = d
	}
	literalIDs := map[string]bool{}
	for _, d := range baseLiteral {
		n, err := normalDefinition(d)
		if err != nil || !sameDefinition(byID[d.ID], n) || literalIDs[d.ID] {
			return constraintengine.Registry{}, errors.New("the base fact registry source does not read as the gate's own fact registry")
		}
		literalIDs[d.ID] = true
	}
	var list []constraintengine.FactDefinition
	for _, d := range baseRegistry.Definitions() {
		if !literalIDs[d.ID] {
			list = append(list, d)
		}
	}
	list = append(list, headLiteral...)
	headRegistry, err := constraintengine.NewCompiledRegistry(list)
	if err != nil {
		return constraintengine.Registry{}, fmt.Errorf("the head's fact definitions are not a valid registry: %v", err)
	}
	return headRegistry, nil
}

// additions returns the definitions the head adds, sorted by ID, and refuses
// any base definition the head removes or changes.
func additions(baseRegistry, headRegistry constraintengine.Registry) ([]constraintengine.FactDefinition, error) {
	head := map[string]constraintengine.FactDefinition{}
	for _, d := range headRegistry.Definitions() {
		head[d.ID] = d
	}
	var removed, retyped, moved, retokened []string
	inBase := map[string]bool{}
	for _, b := range baseRegistry.Definitions() {
		inBase[b.ID] = true
		h, ok := head[b.ID]
		switch {
		case !ok:
			removed = append(removed, b.ID)
		case h.Type != b.Type:
			retyped = append(retyped, b.ID)
		case h.Component != b.Component:
			moved = append(moved, b.ID)
		case !sameDefinition(h, b):
			retokened = append(retokened, b.ID)
		}
	}
	var reasons []string
	if len(removed) > 0 {
		reasons = append(reasons, "fact definitions removed or renamed: "+logSafe(strings.Join(removed, ", ")))
	}
	if len(retyped) > 0 {
		reasons = append(reasons, "fact definitions retyped: "+logSafe(strings.Join(retyped, ", ")))
	}
	if len(moved) > 0 {
		reasons = append(reasons, "fact definitions moved to another component: "+logSafe(strings.Join(moved, ", ")))
	}
	if len(retokened) > 0 {
		reasons = append(reasons, "fact definitions with other enum tokens: "+logSafe(strings.Join(retokened, ", ")))
	}
	if len(reasons) > 0 {
		return nil, errors.New("only additions are admitted; " + strings.Join(reasons, "; "))
	}
	var added []constraintengine.FactDefinition
	for _, h := range headRegistry.Definitions() {
		if !inBase[h.ID] {
			added = append(added, h)
		}
	}
	if len(added) == 0 {
		return nil, errors.New("the head adds no fact definition")
	}
	return added, nil
}

// normalDefinition is a definition as a registry holds it.
func normalDefinition(d constraintengine.FactDefinition) (constraintengine.FactDefinition, error) {
	r, err := constraintengine.NewCompiledRegistry([]constraintengine.FactDefinition{d})
	if err != nil {
		return constraintengine.FactDefinition{}, err
	}
	return r.Definitions()[0], nil
}

func sameDefinition(a, b constraintengine.FactDefinition) bool {
	if a.ID != b.ID || a.Component != b.Component || a.Type != b.Type || len(a.EnumTokens) != len(b.EnumTokens) {
		return false
	}
	for i := range a.EnumTokens {
		if a.EnumTokens[i] != b.EnumTokens[i] {
			return false
		}
	}
	return true
}

// registryStatement is the canonical JSON of the RegistryAddition.
func registryStatement(baseRegistry, headRegistry constraintengine.Registry, added []constraintengine.FactDefinition) ([]byte, error) {
	return extract.Canonical(RegistryAddition{Schema: RegistryAdditionSchema, BaseRegistryDigest: baseRegistry.Digest(), HeadRegistryDigest: headRegistry.Digest(), Added: added})
}

// parsePackagedDefinitions reads the literal definitions of the function
// packagedDefinitions from a Go source file, without running it. Only one
// form is read:
//
//	func packagedDefinitions() []constraintengine.FactDefinition {
//		return append([]constraintengine.FactDefinition{
//			{ID: "...", Component: "...", Type: constraintengine.FactBool, EnumTokens: nil},
//			...
//		}, customResourceVersionDefinitions()...)
//	}
//
// with string literals, a Type of constraintengine.FactBool, FactEnum or
// FactSet, and EnumTokens nil or a []string of string literals. Anything
// else is refused.
func parsePackagedDefinitions(src []byte) ([]constraintengine.FactDefinition, error) {
	errForm := errors.New("packagedDefinitions is not in the literal form this gate reads")
	file, err := parser.ParseFile(token.NewFileSet(), "registry.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, errors.New("the source does not parse")
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "packagedDefinitions" {
			if fn != nil {
				return nil, errForm
			}
			fn = d
		}
	}
	if fn == nil || fn.Recv != nil || fn.Type.TypeParams != nil || len(fn.Type.Params.List) != 0 || fn.Body == nil || len(fn.Body.List) != 1 {
		return nil, errForm
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, errForm
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || !isIdent(call.Fun, "append") || len(call.Args) != 2 || !call.Ellipsis.IsValid() {
		return nil, errForm
	}
	tail, ok := call.Args[1].(*ast.CallExpr)
	if !ok || !isIdent(tail.Fun, "customResourceVersionDefinitions") || len(tail.Args) != 0 || tail.Ellipsis.IsValid() {
		return nil, errForm
	}
	list, ok := call.Args[0].(*ast.CompositeLit)
	if !ok || !isSliceOf(list.Type, func(e ast.Expr) bool { return isSelector(e, "constraintengine", "FactDefinition") }) {
		return nil, errForm
	}
	out := make([]constraintengine.FactDefinition, 0, len(list.Elts))
	for _, elt := range list.Elts {
		d, err := literalDefinition(elt)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func literalDefinition(elt ast.Expr) (constraintengine.FactDefinition, error) {
	errForm := errors.New("a packagedDefinitions entry is not in the literal form this gate reads")
	lit, ok := elt.(*ast.CompositeLit)
	if !ok || lit.Type != nil {
		return constraintengine.FactDefinition{}, errForm
	}
	var d constraintengine.FactDefinition
	seen := map[string]bool{}
	for _, field := range lit.Elts {
		kv, ok := field.(*ast.KeyValueExpr)
		if !ok {
			return constraintengine.FactDefinition{}, errForm
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || seen[key.Name] {
			return constraintengine.FactDefinition{}, errForm
		}
		seen[key.Name] = true
		switch key.Name {
		case "ID", "Component":
			s, ok := stringLiteral(kv.Value)
			if !ok {
				return constraintengine.FactDefinition{}, errForm
			}
			if key.Name == "ID" {
				d.ID = s
			} else {
				d.Component = s
			}
		case "Type":
			switch {
			case isSelector(kv.Value, "constraintengine", "FactBool"):
				d.Type = constraintengine.FactBool
			case isSelector(kv.Value, "constraintengine", "FactEnum"):
				d.Type = constraintengine.FactEnum
			case isSelector(kv.Value, "constraintengine", "FactSet"):
				d.Type = constraintengine.FactSet
			default:
				return constraintengine.FactDefinition{}, errForm
			}
		case "EnumTokens":
			if isIdent(kv.Value, "nil") {
				continue
			}
			tokens, ok := kv.Value.(*ast.CompositeLit)
			if !ok || !isSliceOf(tokens.Type, func(e ast.Expr) bool { return isIdent(e, "string") }) {
				return constraintengine.FactDefinition{}, errForm
			}
			d.EnumTokens = []string{}
			for _, t := range tokens.Elts {
				s, ok := stringLiteral(t)
				if !ok {
					return constraintengine.FactDefinition{}, errForm
				}
				d.EnumTokens = append(d.EnumTokens, s)
			}
		default:
			return constraintengine.FactDefinition{}, errForm
		}
	}
	if !seen["ID"] || !seen["Component"] || !seen["Type"] {
		return constraintengine.FactDefinition{}, errForm
	}
	return d, nil
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg) && sel.Sel.Name == name
}

func isSliceOf(e ast.Expr, elem func(ast.Expr) bool) bool {
	arr, ok := e.(*ast.ArrayType)
	return ok && arr.Len == nil && elem(arr.Elt)
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// admitRegistryChanges decides every registryDigest member change once every
// other change has been classified, and returns the head definition list of
// each pack whose change it admitted.
func admitRegistryChanges(cls *Classification, pending []*Change, changedPaths []string, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) map[string][]constraintengine.FactDefinition {
	admitted := map[string][]constraintengine.FactDefinition{}
	for _, c := range pending {
		change, err := checkRegistryChange(cls, c, pending, changedPaths, opts, loadKeys, approvals)
		if err != nil {
			c.fail("the pack's registryDigest may change only by an addition of fact definitions with an owner approval: " + err.Error())
			continue
		}
		c.OK, c.Proof = true, ProofApproval
		admitted[c.Pack] = change.head.Definitions()
	}
	return admitted
}

func checkRegistryChange(cls *Classification, c *Change, pending []*Change, changedPaths []string, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) (*registryChange, error) {
	var spec PackSpec
	found := false
	for _, s := range opts.Layout.Packs {
		if s.Name == c.Pack {
			spec, found = s, true
		}
	}
	if !found {
		return nil, errors.New("unknown pack")
	}
	if len(pending) != 1 {
		return nil, errors.New("more than one pack's registryDigest changed")
	}
	base, head := cls.base[c.Pack], cls.head[c.Pack]
	if base == nil || head == nil || !base.Present || !head.Present {
		return nil, errors.New("the pack is missing from the base or the head")
	}
	// Nothing else at the top level of any pack changes.
	var others []string
	for _, o := range cls.Changes {
		if o == c || o.Member == "" {
			continue
		}
		if o.Member == "schema" {
			return nil, fmt.Errorf("a schema-level change of the %s pack is in the same change", logSafe(o.Pack))
		}
		others = append(others, o.Pack+" "+o.Member)
	}
	if len(others) > 0 {
		sort.Strings(others)
		return nil, fmt.Errorf("another top-level member changed in the same change: %s", logSafe(strings.Join(others, ", ")))
	}
	for _, name := range cls.ChainsChanged {
		if name == c.Pack {
			return nil, errors.New("a reattestation statement of the pack is appended in the same change")
		}
	}
	for _, p := range changedPaths {
		if opts.Layout.trustPath(p) {
			return nil, fmt.Errorf("trust material changed in the same change: %s", logSafe(p))
		}
		for _, reg := range opts.Layout.RegistryPaths {
			if p == reg {
				return nil, fmt.Errorf("a registry file changed in the same change: %s", logSafe(p))
			}
		}
	}
	change, err := readRegistryChange(spec, opts.Base, opts.Head, base.Members[registryMember], head.Members[registryMember])
	if err != nil {
		return nil, err
	}
	raw, err := opts.Head.ReadOptional(registryApprovalPath(opts.Layout, c.Pack), maxApprovalBytes+1)
	if err != nil {
		return nil, fmt.Errorf("approval: %v", err)
	}
	if raw == nil {
		return nil, errors.New("no owner approval")
	}
	if why, err := approvals.refuse(raw); err != nil {
		return nil, fmt.Errorf("approval: %v", err)
	} else if why != "" {
		return nil, errors.New(why)
	}
	keys, err := loadKeys()
	if err != nil {
		return nil, err
	}
	if err := VerifyRecordApproval(raw, *keys, c.Pack, ApprovalSubjectRegistry, RegistryApprovalID, RegistryApprovalScope, change.base.Document(), change.statement, opts.Now); err != nil {
		return nil, err
	}
	return change, nil
}

// registrySpec reports whether the named pack has a fact registry this gate
// reads (every field admitRegistryChanges needs is set).
func registrySpec(layout Layout, pack string) bool {
	for _, s := range layout.Packs {
		if s.Name == pack {
			return s.FactDefinitions != nil && s.RegistrySourcePath != "" && s.AdmitWith != nil && s.AttestWith != nil
		}
	}
	return false
}

// registryApprovalPath is where a change carries the approval of a pack's
// registry change.
func registryApprovalPath(layout Layout, pack string) string {
	return layout.ApprovalDir + "/" + pack + "/" + RegistryApprovalID + ".json"
}

// RegistryApprovalSubject reads the registry change of a pack between a base
// and a head checkout exactly as the gate reads it, for the owner to sign or
// check an approval of it.
func RegistryApprovalSubject(spec PackSpec, base, head Tree) (ApprovalSubject, RegistryAddition, error) {
	b, err := loadPack(base, spec)
	if err != nil {
		return ApprovalSubject{}, RegistryAddition{}, err
	}
	h, err := loadPack(head, spec)
	if err != nil {
		return ApprovalSubject{}, RegistryAddition{}, err
	}
	if !b.Present || !h.Present {
		return ApprovalSubject{}, RegistryAddition{}, errors.New("the pack is missing from the base or the head")
	}
	change, err := readRegistryChange(spec, base, head, b.Members[registryMember], h.Members[registryMember])
	if err != nil {
		return ApprovalSubject{}, RegistryAddition{}, err
	}
	addition := RegistryAddition{Schema: RegistryAdditionSchema, BaseRegistryDigest: change.base.Digest(), HeadRegistryDigest: change.head.Digest(), Added: change.added}
	return ApprovalSubject{Kind: ApprovalSubjectRegistry, Pack: spec.Name, RuleID: RegistryApprovalID, Scope: RegistryApprovalScope, Base: change.base.Document(), Candidate: change.statement}, addition, nil
}

// RegistryPathsConflict is the stable reason for a change that carries an
// onboarding batch and also changes the registry another way.
const RegistryPathsConflict = "an onboarding batch and a registry-member change are two registry-change paths and are never combined in one change"

// registryPathsChanged names the first path of a change that belongs to the
// registry-member path (a registry source or an approval of a registry
// change of a pack the gate reads a registry of), or "".
func registryPathsChanged(layout Layout, changedPaths []string) string {
	for _, spec := range layout.Packs {
		if !registrySpec(layout, spec.Name) {
			continue
		}
		for _, p := range changedPaths {
			if p == spec.RegistrySourcePath || p == registryApprovalPath(layout, spec.Name) {
				return logSafe(p)
			}
		}
	}
	return ""
}
