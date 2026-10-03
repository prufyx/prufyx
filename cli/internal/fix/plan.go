// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

const (
	// MaxEditsPerFile bounds the edits on one file.
	MaxEditsPerFile = 1024
	// MaxReplacementBytes bounds one replacement.
	MaxReplacementBytes = 4096
	// MaxRequests bounds the fix requests for one file.
	MaxRequests = 256
	// maxDisplayBytes bounds the display name used in edits and diffs.
	maxDisplayBytes = 4096
)

// Request asks one kind to plan its fix on a file.
type Request struct {
	Kind   string
	Params Params
	// Documents lists the indexes of the documents to fix among the
	// non-empty documents of the file; nil means every document.
	Documents []int
}

// Options tunes planning and in-memory application.
type Options struct {
	// SkipIdempotenceCheck turns off re-planning the requests on the edited
	// bytes. The check is on by default.
	SkipIdempotenceCheck bool
}

// FilePlan is the verified result of planning fixes on one file.
type FilePlan struct {
	Display string
	// Digest is the sha256 of the bytes the plan was made on, in the form
	// the intake uses ("sha256:<hex>").
	Digest   string
	Requests []Request
	// Edits are sorted by start offset, do not overlap and each changes
	// exactly one key or scalar token.
	Edits []Edit
	// Diff is the unified diff of the change; empty when there are no edits.
	Diff string
}

// boundRequest is a request whose kind was found and whose parameters were
// bounded and validated once.
type boundRequest struct {
	request Request
	kind    Kind
	parsed  any
}

// bind looks up the kind of every request and validates its parameters once.
// The parsed value is what the kind's Plan receives, at planning and at the
// idempotence re-plan alike.
func bind(requests []Request) ([]boundRequest, *Refusal) {
	if len(requests) > MaxRequests {
		return nil, refuse(ReasonLimit, "too many fix requests for one file")
	}
	bound := make([]boundRequest, len(requests))
	for i, request := range requests {
		kind, ok := Lookup(request.Kind)
		if !ok {
			return nil, refuse(ReasonUnknownKind, "no compiled fix kind has the requested id")
		}
		if r := checkParams(request.Params); r != nil {
			return nil, r
		}
		parsed, err := kind.Validate(bytes.Clone(request.Params))
		if err != nil {
			return nil, refuse(ReasonInvalidParams, "the fix parameters do not validate")
		}
		bound[i] = boundRequest{request: request, kind: kind, parsed: parsed}
	}
	return bound, nil
}

// Plan asks every requested kind for its edits on src, validates them and
// proves the result: the edited bytes must decode to the original values
// with exactly the targeted substitutions, and re-planning on them must
// yield no edits. Any failure refuses the whole file.
func Plan(display string, src []byte, requests []Request, opts Options) (FilePlan, error) {
	if r := checkDisplay(display); r != nil {
		return FilePlan{}, r
	}
	src = bytes.Clone(src)
	file, r := parseFile(src)
	if r != nil {
		return FilePlan{}, r
	}
	if file.hasSecret() {
		return FilePlan{}, refuse(ReasonSecretDocument, "the file holds a Secret; files with Secrets are never edited")
	}
	bound, r := bind(requests)
	if r != nil {
		return FilePlan{}, r
	}
	digest := digestOf(src)
	edits, r := collect(file, display, digest, bound)
	if r != nil {
		return FilePlan{}, r
	}
	edits, _, r = verify(file, display, edits, bound, opts)
	if r != nil {
		return FilePlan{}, r
	}
	plan := FilePlan{Display: display, Digest: digest, Requests: requests, Edits: edits}
	if len(edits) > 0 {
		diff, err := UnifiedDiff(display, src, edits)
		if err != nil {
			return FilePlan{}, err
		}
		plan.Diff = diff
	}
	return plan, nil
}

// ApplyInMemory applies a plan to src and returns the new bytes without
// touching any file. src must have the plan's digest. The plan is not
// trusted: the requested kinds are run again on src and must produce
// exactly the plan's edits and diff, so an altered plan is refused.
func ApplyInMemory(src []byte, plan FilePlan, opts Options) ([]byte, error) {
	after, _, err := applyPlan(src, plan, opts)
	return after, err
}

// applyPlan re-derives the edits of a plan from its requests, requires them
// to equal the plan's, and returns the new bytes together with the diff
// computed from the edits that were actually applied.
func applyPlan(src []byte, plan FilePlan, opts Options) ([]byte, string, error) {
	if r := checkDisplay(plan.Display); r != nil {
		return nil, "", r
	}
	if digestOf(src) != plan.Digest {
		return nil, "", refuse(ReasonFileChanged, "the bytes differ from the bytes the fix was planned on")
	}
	src = bytes.Clone(src)
	file, r := parseFile(src)
	if r != nil {
		return nil, "", r
	}
	if file.hasSecret() {
		return nil, "", refuse(ReasonSecretDocument, "the file holds a Secret; files with Secrets are never edited")
	}
	bound, r := bind(plan.Requests)
	if r != nil {
		return nil, "", r
	}
	edits, r := collect(file, plan.Display, plan.Digest, bound)
	if r != nil {
		return nil, "", r
	}
	applied, after, r := verify(file, plan.Display, edits, bound, opts)
	if r != nil {
		return nil, "", r
	}
	if len(applied) != len(plan.Edits) {
		return nil, "", refuse(ReasonInvalidEdit, "the plan's edits are not the edits its requests produce")
	}
	for i := range applied {
		if applied[i] != plan.Edits[i] {
			return nil, "", refuse(ReasonInvalidEdit, "the plan's edits are not the edits its requests produce")
		}
	}
	diff := ""
	if len(applied) > 0 {
		var err error
		if diff, err = UnifiedDiff(plan.Display, src, applied); err != nil {
			return nil, "", err
		}
	}
	if diff != plan.Diff {
		return nil, "", refuse(ReasonInvalidEdit, "the plan's diff is not the diff of its edits")
	}
	return after, diff, nil
}

func checkDisplay(display string) *Refusal {
	if display == "" || len(display) > maxDisplayBytes || !utf8.ValidString(display) {
		return refuse(ReasonInvalidEdit, "the file display name is empty, too long or not UTF-8")
	}
	for _, r := range display {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return refuse(ReasonInvalidEdit, "the file display name contains a control character")
		}
	}
	return nil
}

// collect runs the requested kinds over the selected mapping documents. The
// kinds get one private copy of the source; a kind that changes it is
// refused.
func collect(file *parsedFile, display, digest string, bound []boundRequest) ([]Edit, *Refusal) {
	var edits []Edit
	scratch := bytes.Clone(file.src)
	for _, bound := range bound {
		indexes := bound.request.Documents
		if indexes == nil {
			indexes = make([]int, len(file.docs))
			for j := range indexes {
				indexes[j] = j
			}
		}
		for _, index := range indexes {
			if index < 0 || index >= len(file.docs) {
				return nil, refuse(ReasonPathNotFound, "a requested document does not exist in the file")
			}
			object, ok := file.docs[index].value.(map[string]any)
			if !ok {
				continue
			}
			planned, err := bound.kind.Plan(documentFor(display, digest, index, object), scratch, bound.parsed)
			if !bytes.Equal(scratch, file.src) {
				return nil, refuse(ReasonKindRefused, "the fix kind modified the source bytes it was given")
			}
			if err != nil {
				return nil, kindError(err)
			}
			edits = append(edits, planned...)
			if len(edits) > MaxEditsPerFile {
				return nil, refuse(ReasonLimit, "too many edits for one file")
			}
		}
	}
	return edits, nil
}

func documentFor(display, digest string, index int, object map[string]any) intake.Document {
	value := copyValue(object).(map[string]any)
	document := intake.Document{
		Source: intake.Source{Display: display, Digest: digest, Document: index, Item: -1},
		Value:  value,
	}
	document.APIVersion, _ = value["apiVersion"].(string)
	document.Kind, _ = value["kind"].(string)
	if metadata, ok := value["metadata"].(map[string]any); ok {
		document.Namespace, _ = metadata["namespace"].(string)
		document.Name, _ = metadata["name"].(string)
	}
	return document
}

// target is the token an edit covers and the value it will hold.
type target struct {
	edit     Edit
	document int
	path     Path
	part     Part
	value    any
}

// verify validates the edits, applies them in memory and proves the result.
// It returns the normalised edits (sorted, without exact duplicates and
// without edits that change nothing) and the new bytes.
func verify(file *parsedFile, display string, edits []Edit, bound []boundRequest, opts Options) ([]Edit, []byte, *Refusal) {
	if len(edits) > MaxEditsPerFile {
		return nil, nil, refuse(ReasonLimit, "too many edits for one file")
	}
	for _, edit := range edits {
		if edit.File != display {
			return nil, nil, refuse(ReasonInvalidEdit, "an edit names another file")
		}
		if edit.StartByte < 0 || edit.StartByte >= edit.EndByte || edit.EndByte > len(file.src) {
			return nil, nil, refuse(ReasonInvalidEdit, "an edit span is empty or out of bounds")
		}
		if r := checkReplacement(edit.Replacement); r != nil {
			return nil, nil, r
		}
	}
	sorted := append([]Edit(nil), edits...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.StartByte != b.StartByte {
			return a.StartByte < b.StartByte
		}
		if a.EndByte != b.EndByte {
			return a.EndByte < b.EndByte
		}
		return a.Replacement < b.Replacement
	})
	normalized := sorted[:0:0]
	for _, edit := range sorted {
		if n := len(normalized); n > 0 {
			previous := normalized[n-1]
			if edit == previous {
				continue
			}
			if edit.StartByte < previous.EndByte {
				return nil, nil, refuse(ReasonConflictingEdits, "two edits on the file overlap")
			}
		}
		normalized = append(normalized, edit)
	}
	tokens := file.tokenIndex()
	var targets []target
	for _, edit := range normalized {
		token, ok := tokens[edit.StartByte]
		if !ok {
			return nil, nil, refuse(ReasonSpanNotIsolated, "an edit does not start at a key or scalar token")
		}
		span, r := file.tokenSpan(token.node, token.part)
		if r != nil {
			return nil, nil, r
		}
		if span.Start != edit.StartByte || span.End != edit.EndByte {
			return nil, nil, refuse(ReasonSpanNotIsolated, "an edit does not cover exactly one key or scalar token")
		}
		if string(file.src[edit.StartByte:edit.EndByte]) == edit.Replacement {
			continue
		}
		value, r := replacementValue(edit.Replacement, token.part)
		if r != nil {
			return nil, nil, r
		}
		targets = append(targets, target{edit: edit, document: token.document, path: token.path, part: token.part, value: value})
	}
	result := make([]Edit, len(targets))
	for i, t := range targets {
		result[i] = t.edit
	}
	if len(targets) == 0 {
		return result, file.src, nil
	}
	expected, r := expectedValues(file, targets)
	if r != nil {
		return nil, nil, r
	}
	after := splice(file.src, result)
	edited, r := parseFile(after)
	if r != nil {
		return nil, nil, refuse(ReasonDecodeMismatch, "the edited file no longer decodes with the strict decoder")
	}
	if edited.hasSecret() {
		return nil, nil, refuse(ReasonSecretDocument, "the edited file would hold a Secret")
	}
	if r := sameDocuments(edited, expected); r != nil {
		return nil, nil, r
	}
	if !opts.SkipIdempotenceCheck {
		again, r := collect(edited, display, digestOf(after), bound)
		if r != nil {
			return nil, nil, refuse(ReasonNotIdempotent, "planning the fix again on its output was refused")
		}
		for _, edit := range again {
			if edit.File != display || edit.StartByte < 0 || edit.StartByte > edit.EndByte || edit.EndByte > len(after) ||
				string(after[edit.StartByte:edit.EndByte]) != edit.Replacement {
				return nil, nil, refuse(ReasonNotIdempotent, "planning the fix again on its output yields further edits")
			}
		}
	}
	return result, after, nil
}

// sameDocuments requires the edited file to hold exactly the expected
// documents.
func sameDocuments(edited *parsedFile, expected []any) *Refusal {
	if len(edited.docs) != len(expected) {
		return refuse(ReasonDecodeMismatch, "the edited file has a different number of documents")
	}
	for i, doc := range edited.docs {
		if !reflect.DeepEqual(doc.value, expected[i]) {
			return refuse(ReasonDecodeMismatch, "the edited file changes more than the targeted values")
		}
	}
	return nil
}

// checkReplacement accepts a single-line UTF-8 token without control
// characters, document markers, byte order marks or template syntax.
func checkReplacement(replacement string) *Refusal {
	if replacement == "" {
		return refuse(ReasonInvalidEdit, "a replacement is empty")
	}
	if len(replacement) > MaxReplacementBytes {
		return refuse(ReasonLimit, "a replacement is larger than the limit")
	}
	if !utf8.ValidString(replacement) {
		return refuse(ReasonInvalidEdit, "a replacement is not valid UTF-8")
	}
	if hasControl(replacement) {
		return refuse(ReasonInvalidEdit, "a replacement contains a line break or control character")
	}
	if strings.HasPrefix(replacement, "---") || strings.HasPrefix(replacement, "...") {
		return refuse(ReasonInvalidEdit, "a replacement starts with a document marker")
	}
	if strings.Contains(replacement, "{{") || strings.Contains(replacement, "${") {
		return refuse(ReasonInvalidEdit, "a replacement contains template syntax")
	}
	return nil
}

// hasControl reports a control character, a line or paragraph separator or a
// byte order mark. Tab counts as a control character too.
func hasControl(text string) bool {
	for _, r := range text {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xfeff {
			return true
		}
	}
	return false
}

// replacementValue decodes a replacement on its own. It must be exactly one
// scalar token, and a key must decode to a non-empty string.
func replacementValue(replacement string, part Part) (any, *Refusal) {
	alone, ok := decodeLoneScalar([]byte(replacement))
	if !ok || alone.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || alone.Line != 1 || alone.Column != 1 {
		return nil, refuse(ReasonInvalidEdit, "a replacement is not a single scalar token")
	}
	end, r := scanToken([]byte(replacement), 0, alone)
	if r != nil || end != len(replacement) {
		return nil, refuse(ReasonInvalidEdit, "a replacement is not a single scalar token")
	}
	value, err := strictScalar(alone)
	if err != nil {
		return nil, refuse(ReasonInvalidEdit, "a replacement is outside the strict YAML subset")
	}
	// Escapes in a quoted token can produce characters the bytes do not
	// show, so the decoded text is checked as well.
	if text, isString := value.(string); isString {
		if !utf8.ValidString(text) || hasControl(text) {
			return nil, refuse(ReasonInvalidEdit, "a replacement decodes to text with a control character")
		}
		if strings.Contains(text, "{{") || strings.Contains(text, "${") {
			return nil, refuse(ReasonInvalidEdit, "a replacement decodes to text with template syntax")
		}
	}
	if alone.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 && ambiguousPlain(alone) {
		return nil, refuse(ReasonInvalidEdit, "a plain replacement reads as a boolean, number, null or date in YAML 1.1; quote it")
	}
	if part == PartKey {
		key, isString := value.(string)
		if alone.ShortTag() != "!!str" || !isString || key == "" || key == "<<" {
			return nil, refuse(ReasonInvalidEdit, "a key replacement does not decode to a usable string key")
		}
	}
	return value, nil
}

// expectedValues returns the decoded documents with the targeted
// substitutions: values first, then keys from the deepest path up, so every
// step navigates by the original key names.
func expectedValues(file *parsedFile, targets []target) ([]any, *Refusal) {
	expected := make([]any, len(file.docs))
	for i, doc := range file.docs {
		expected[i] = copyValue(doc.value)
	}
	ordered := append([]target(nil), targets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].part != ordered[j].part {
			return ordered[i].part == PartValue
		}
		return len(ordered[i].path) > len(ordered[j].path)
	})
	for _, t := range ordered {
		if !substitute(&expected[t.document], t.path, t.part, t.value) {
			return nil, refuse(ReasonDecodeMismatch, "the substitution cannot be expressed on the decoded values")
		}
	}
	return expected, nil
}

func substitute(at *any, path Path, part Part, value any) bool {
	if len(path) == 0 {
		if part != PartValue {
			return false
		}
		*at = value
		return true
	}
	segment := path[0]
	switch container := (*at).(type) {
	case map[string]any:
		if segment.isIndex {
			return false
		}
		child, ok := container[segment.key]
		if !ok {
			return false
		}
		if len(path) == 1 && part == PartKey {
			key := value.(string)
			if key == segment.key {
				return true
			}
			if _, taken := container[key]; taken {
				return false
			}
			delete(container, segment.key)
			container[key] = child
			return true
		}
		if !substitute(&child, path[1:], part, value) {
			return false
		}
		container[segment.key] = child
		return true
	case []any:
		if !segment.isIndex || segment.index < 0 || segment.index >= len(container) {
			return false
		}
		return substitute(&container[segment.index], path[1:], part, value)
	}
	return false
}

func splice(src []byte, edits []Edit) []byte {
	size := len(src)
	for _, edit := range edits {
		size += len(edit.Replacement) - (edit.EndByte - edit.StartByte)
	}
	out := make([]byte, 0, size)
	previous := 0
	for _, edit := range edits {
		out = append(out, src[previous:edit.StartByte]...)
		out = append(out, edit.Replacement...)
		previous = edit.EndByte
	}
	return append(out, src[previous:]...)
}

// tokenRef is a key or scalar token of the file and where it sits.
type tokenRef struct {
	node     *yaml.Node
	document int
	path     Path
	part     Part
}

// tokenIndex maps the start offset of every key and scalar token to it.
func (f *parsedFile) tokenIndex() map[int]tokenRef {
	index := map[int]tokenRef{}
	var walk func(node *yaml.Node, document int, path Path)
	add := func(node *yaml.Node, document int, path Path, part Part) {
		if offset, ok := f.offset(node.Line, node.Column); ok {
			index[offset] = tokenRef{node: node, document: document, path: append(Path(nil), path...), part: part}
		}
	}
	walk = func(node *yaml.Node, document int, path Path) {
		switch node.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				child := append(path[:len(path):len(path)], Key(node.Content[i].Value))
				add(node.Content[i], document, child, PartKey)
				walk(node.Content[i+1], document, child)
			}
		case yaml.SequenceNode:
			for i, item := range node.Content {
				walk(item, document, append(path[:len(path):len(path)], Index(i)))
			}
		case yaml.ScalarNode:
			add(node, document, path, PartValue)
		}
	}
	for i, doc := range f.docs {
		walk(doc.root, i, nil)
	}
	return index
}
