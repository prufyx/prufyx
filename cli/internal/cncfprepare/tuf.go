// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	TUFComponent     = "pkg:github/theupdateframework/python-tuf"
	TUFBootstrapFact = "component.tuf.updater_bootstrap_keyword_present"
	TUFFrom          = "6.0.0"
	TUFTo            = "7.0.0"
)

const (
	ReasonTUFUpdaterCallObserved    Reason = "TUF_UPDATER_CALL_SHAPE_OBSERVED"
	ReasonTUFUpdaterCallUnsupported Reason = "TUF_UPDATER_CALL_SHAPE_UNSUPPORTED"
)

var ErrTUFSourceParse = errors.New("TUF source is outside the admitted lexical syntax")

// TUFPrepared retains only the minimized bootstrap-presence fact and a bounded
// unsupported category. It never retains source text, call values, paths, or
// URLs.
type TUFPrepared struct {
	Prepared
	UnsupportedCategory string
}

type tufObservation struct {
	state, category string
	bootstrap       bool
}

var (
	tufFromImport   = regexp.MustCompile(`^from[ \t]+tuf\.ngclient[ \t]+import[ \t]+Updater[ \t]*$`)
	tufModuleImport = regexp.MustCompile(`^import[ \t]+tuf\.ngclient[ \t]*$`)
	tufIdentifier   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// PrepareTUFUpdater reads caller-supplied Python source as UTF-8 data. Its Go
// lexical parser admits one unaliased direct import and one top-level direct
// Updater call. It never imports, executes, or otherwise evaluates the source.
// Aliases, rebinding, dynamic calls, and source outside this deliberately small
// grammar produce an unsupported fact and therefore UNKNOWN.
func PrepareTUFUpdater(raw []byte, from, to string) (TUFPrepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return TUFPrepared{}, ErrInvalid
	}
	observed, err := inspectTUFUpdater(raw)
	if err != nil {
		return TUFPrepared{}, err
	}

	fact := inputFact{ID: TUFBootstrapFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonTUFUpdaterCallUnsupported
	if observed.state == "declared" {
		fact = inputFact{ID: TUFBootstrapFact, State: "declared", BoolValue: &observed.bootstrap}
		state, reason = StatePrepared, ReasonTUFUpdaterCallObserved
	}
	canonical, err := marshalComponentInput(TUFComponent, from, to, []inputFact{fact})
	if err != nil {
		return TUFPrepared{}, ErrInvalid
	}
	return TUFPrepared{Prepared: Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"GO_LEXICAL_PARSER_ADMITS_ONLY_ONE_DIRECT_UNALIASED_UPDATER_CALL",
			"INSTALLED_TUF_PACKAGE_AND_PROCESS_PROVENANCE_NOT_ESTABLISHED",
			"BOOTSTRAP_VALUE_CACHE_TRUST_METADATA_UPDATE_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, UnsupportedCategory: observed.category}, nil
}

func inspectTUFUpdater(raw []byte) (tufObservation, error) {
	lines, dynamicString, err := lexicalPythonLines(string(raw))
	if err != nil {
		return tufObservation{}, ErrTUFSourceParse
	}
	if dynamicString {
		return tufUnsupported("unsupported_lexical_form"), nil
	}
	index := tufNextCode(lines, 0)
	if index < 0 || lines[index].indent != 0 {
		return tufUnsupported("binding_missing"), nil
	}
	binding, form := "", ""
	switch {
	case tufFromImport.MatchString(lines[index].text):
		binding, form = "Updater", "from"
	case tufModuleImport.MatchString(lines[index].text):
		binding, form = "tuf", "module"
	default:
		return tufUnsupported("binding_missing"), nil
	}
	index = tufNextCode(lines, index+1)
	if index < 0 || lines[index].indent != 0 {
		return tufUnsupported("candidate_call_count"), nil
	}
	if tufTopLevelBindingRebound(lines[index].text, binding) {
		return tufUnsupported("binding_rebound"), nil
	}

	callSource := make([]string, 0, len(lines)-index)
	parenDepth := 0
	completed := false
	for cursor := index; cursor < len(lines); cursor++ {
		line := lines[cursor]
		if line.text == "" {
			continue
		}
		if completed || (cursor != index && line.indent == 0 && parenDepth == 0) {
			return tufUnsupported("candidate_call_count"), nil
		}
		callSource = append(callSource, line.text)
		for offset := 0; offset < len(line.text); offset++ {
			switch line.text[offset] {
			case '(':
				parenDepth++
			case ')':
				parenDepth--
				if parenDepth == 0 {
					completed = true
				}
			}
		}
	}
	return tufInspectDirectCall(strings.Join(callSource, " "), binding, form)
}

func tufNextCode(lines []lexicalPythonLine, start int) int {
	for index := start; index < len(lines); index++ {
		if lines[index].text != "" {
			return index
		}
	}
	return -1
}

func tufInspectDirectCall(source, binding, form string) (tufObservation, error) {
	function := "Updater"
	if form == "module" {
		function = "tuf.ngclient.Updater"
	}
	prefix := regexp.MustCompile(`^(?:([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*)?` + regexp.QuoteMeta(function) + `[ \t]*\(`)
	match := prefix.FindStringSubmatchIndex(source)
	if match == nil || match[0] != 0 {
		if tufTopLevelBindingRebound(source, binding) {
			return tufUnsupported("binding_rebound"), nil
		}
		return tufUnsupported("candidate_call_count"), nil
	}

	if match[2] >= 0 && !kubeflowSimpleIdentifier(source[match[2]:match[3]]) {
		return tufUnsupported("call_shape_unsupported"), nil
	}
	open := strings.LastIndex(source[:match[1]], "(")
	close, ok := tufClosingParen(source, open)
	if !ok {
		return tufObservation{}, ErrTUFSourceParse
	}
	if strings.TrimSpace(source[close+1:]) != "" {
		return tufUnsupported("candidate_call_count"), nil
	}
	return tufInspectArguments(source[open+1:close], binding)
}

func tufClosingParen(value string, open int) (int, bool) {
	depth := 0
	for index := open; index < len(value); index++ {
		switch value[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index, true
			}
			if depth < 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func tufInspectArguments(arguments, binding string) (tufObservation, error) {
	parts, ok := tufSplitArguments(arguments)
	if !ok {
		return tufObservation{}, ErrTUFSourceParse
	}
	shared := []string{"metadata_dir", "metadata_base_url", "target_dir", "target_base_url", "fetcher", "config"}
	allowed := map[string]bool{"bootstrap": true}
	for _, name := range shared {
		allowed[name] = true
	}
	bound := make(map[string]bool, len(shared)+1)
	positionals := 0
	seenKeyword := false
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return tufUnsupported("call_shape_unsupported"), nil
		}
		if strings.HasPrefix(strings.TrimSpace(part), "*") {
			return tufUnsupported("star_arguments"), nil
		}
		name, value, isKeyword := tufKeyword(part)
		if !isKeyword {
			if seenKeyword {
				return tufUnsupported("positional_after_keyword"), nil
			}
			if positionals >= len(shared) {
				return tufUnsupported("positional_bootstrap"), nil
			}

			if !tufSimpleExpression(strings.TrimSpace(part)) {
				return tufUnsupported("call_shape_unsupported"), nil
			}
			if tufContainsIdentifier(part, binding) {
				return tufUnsupported("binding_dynamic_use"), nil
			}
			bound[shared[positionals]] = true
			positionals++
			continue
		}

		if name == "" || strings.TrimSpace(value) == "" || !tufSimpleExpression(strings.TrimSpace(value)) {
			return tufUnsupported("call_shape_unsupported"), nil
		}
		seenKeyword = true
		if !allowed[name] {
			return tufUnsupported("unknown_keyword"), nil
		}
		if bound[name] {
			return tufUnsupported("duplicate_argument"), nil
		}
		if tufContainsIdentifier(value, binding) {
			return tufUnsupported("binding_dynamic_use"), nil
		}
		bound[name] = true
	}
	if !bound["metadata_dir"] || !bound["metadata_base_url"] {
		return tufUnsupported("missing_required_argument"), nil
	}
	return tufObservation{state: "declared", bootstrap: bound["bootstrap"]}, nil
}

func tufSplitArguments(value string) ([]string, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	parts := []string{}
	depth := 0
	start := 0
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	last := strings.TrimSpace(value[start:])
	if last != "" {
		parts = append(parts, last)
	}
	return parts, true
}

func tufKeyword(value string) (string, string, bool) {
	depth := 0
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth == 0 {
				name := strings.TrimSpace(value[:index])
				if !tufIdentifier.MatchString(name) || !kubeflowSimpleIdentifier(name) {
					return "", "", true
				}
				return name, strings.TrimSpace(value[index+1:]), true
			}
		}
	}
	return "", "", false
}

func tufContainsIdentifier(line, identifier string) bool {
	for start := 0; start < len(line); {
		index := strings.Index(line[start:], identifier)
		if index < 0 {
			return false
		}
		index += start
		leftOK := index == 0 || !lexicalIdentifierByte(line[index-1])
		right := index + len(identifier)
		rightOK := right == len(line) || !lexicalIdentifierByte(line[right])
		if leftOK && rightOK {
			return true
		}
		start = index + len(identifier)
	}
	return false
}

func tufTopLevelBindingRebound(line, binding string) bool {
	if strings.HasPrefix(line, "global ") || strings.HasPrefix(line, "nonlocal ") || strings.HasPrefix(line, "del ") || strings.HasPrefix(line, "for "+binding+" ") || strings.Contains(line, " as "+binding) || strings.HasPrefix(line, "case "+binding) {
		return true
	}
	assignment := regexp.MustCompile(`^` + regexp.QuoteMeta(binding) + `[ \t]*=`)
	return assignment.MatchString(line)
}

func tufUnsupported(category string) tufObservation {
	return tufObservation{state: "unsupported", category: category}
}

// tufSimpleExpression mirrors the source-reader contract: values are one
// masked string literal, one simple identifier, Python's three literal names,
// or a decimal number. Calls and compound expressions are intentionally
// unsupported because this is a lexical observer, not a Python parser.
func tufSimpleExpression(value string) bool {
	return kubeflowSimpleExpression(value)
}
