// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	KubeflowKFPComponent = "pkg:pypi/kfp"
	KubeflowKFPFact      = "component.kubeflow.kfp_component_authoring_api"
	KubeflowKFPFrom      = "1.8.22"
	KubeflowKFPTo        = "2.0.0"

	KubeflowKFPLegacyAPI = "legacy_create_component_from_func"
	KubeflowKFPV2API     = "dsl_component"
)

const (
	ReasonKubeflowKFPAuthoringAPIObserved    Reason = "KUBEFLOW_KFP_COMPONENT_AUTHORING_API_OBSERVED"
	ReasonKubeflowKFPAuthoringAPIUnsupported Reason = "KUBEFLOW_KFP_COMPONENT_AUTHORING_API_UNSUPPORTED"
)

var ErrKubeflowKFPSourceParse = errors.New("Kubeflow KFP source is outside the admitted lexical syntax")

// KubeflowKFPPrepared retains one closed enum observation and a bounded
// unsupported category. It never retains source text, paths, function names,
// imports, decorator values, or URLs.
type KubeflowKFPPrepared struct {
	Prepared
	UnsupportedCategory string
}

type kubeflowKFPObservation struct {
	state, category, api string
}

var (
	kubeflowLegacyImport = regexp.MustCompile(`^from[ \t]+kfp\.components[ \t]+import[ \t]+create_component_from_func[ \t]*$`)
	kubeflowModernImport = regexp.MustCompile(`^from[ \t]+kfp[ \t]+import[ \t]+dsl[ \t]*$`)
	kubeflowDef          = regexp.MustCompile(`^def[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(([^\n]*)\)[ \t]*:$`)
)

// PrepareKubeflowKFP reads caller-supplied Python source only as UTF-8 data.
// Its Go lexical parser admits exactly one unaliased direct import and one bare
// synchronous decorator: create_component_from_func or dsl.component. It does
// not import, execute, or otherwise evaluate the source. Aliases, wrappers,
// dynamic binding use, multiple candidate definitions, and syntax outside this
// deliberately small subset retain an unsupported fact and therefore UNKNOWN.
// The observation is independent of declared versions; knowledge rules own
// exact transition applicability.
func PrepareKubeflowKFP(raw []byte, from, to string) (KubeflowKFPPrepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return KubeflowKFPPrepared{}, ErrInvalid
	}
	observed, err := inspectKubeflowKFP(raw)
	if err != nil {
		return KubeflowKFPPrepared{}, err
	}

	fact := inputFact{ID: KubeflowKFPFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonKubeflowKFPAuthoringAPIUnsupported
	if observed.state == "declared" {
		fact = inputFact{ID: KubeflowKFPFact, State: "declared", EnumValue: observed.api}
		state, reason = StatePrepared, ReasonKubeflowKFPAuthoringAPIObserved
	}
	canonical, err := marshalComponentInput(KubeflowKFPComponent, from, to, []inputFact{fact})
	if err != nil {
		return KubeflowKFPPrepared{}, ErrInvalid
	}
	return KubeflowKFPPrepared{Prepared: Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"GO_LEXICAL_PARSER_ADMITS_ONLY_DIRECT_UNALIASED_DECORATOR_FORMS",
			"INSTALLED_KFP_PACKAGE_AND_PROCESS_PROVENANCE_NOT_ESTABLISHED",
			"COMPONENT_INPUT_OUTPUT_DEPENDENCY_COMPILATION_BACKEND_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, UnsupportedCategory: observed.category}, nil
}

func inspectKubeflowKFP(raw []byte) (kubeflowKFPObservation, error) {
	lines, dynamicString, err := lexicalPythonLines(string(raw))
	if err != nil {
		return kubeflowKFPObservation{}, ErrKubeflowKFPSourceParse
	}
	if dynamicString {
		return kubeflowUnsupported("unsupported_lexical_form"), nil
	}

	// The admitted module grammar is intentionally closed: comments/blank lines,
	// one exact direct import, one exact bare decorator, then one synchronous
	// top-level def with a simple parameter list and an indented `pass` or `return`
	// body. It accepts no conditional, nested, generated, or later top-level code.
	// This is a lexical observation,
	// not a Python grammar implementation.
	index := kubeflowNextCode(lines, 0)
	if index < 0 {
		return kubeflowUnsupported("binding_missing"), nil
	}
	first := lines[index]
	if first.indent != 0 {
		return kubeflowUnsupported("unsupported_lexical_form"), nil
	}
	binding, api := "", ""
	switch {
	case kubeflowLegacyImport.MatchString(first.text):
		binding, api = "create_component_from_func", KubeflowKFPLegacyAPI
	case kubeflowModernImport.MatchString(first.text):
		binding, api = "dsl", KubeflowKFPV2API
	default:
		return kubeflowUnsupported("binding_missing"), nil
	}

	index = kubeflowNextCode(lines, index+1)
	if index < 0 || lines[index].indent != 0 || !kubeflowDecoratorMatches(binding, api, lines[index].text) {
		return kubeflowUnsupported("unsupported_lexical_form"), nil
	}
	index = kubeflowNextCode(lines, index+1)
	if index < 0 || lines[index].indent != 0 {
		return kubeflowUnsupported("unsupported_lexical_form"), nil
	}
	definition := lines[index].text
	if strings.HasPrefix(definition, "async def ") {
		return kubeflowUnsupported("definition_shape_unsupported"), nil
	}
	match := kubeflowDef.FindStringSubmatch(definition)
	if match == nil {
		return kubeflowUnsupported("definition_shape_unsupported"), nil
	}
	if match[1] == binding || !kubeflowSimpleIdentifier(match[1]) || !kubeflowParametersAdmitted(match[2]) {
		return kubeflowUnsupported("definition_shape_unsupported"), nil
	}
	if kubeflowContainsIdentifier(match[2], binding) {
		return kubeflowUnsupported("binding_rebound"), nil
	}

	bodyIndex := kubeflowNextCode(lines, index+1)
	if bodyIndex < 0 || lines[bodyIndex].indent == 0 {
		return kubeflowUnsupported("definition_body_unsupported"), nil
	}
	bodyIndent := lines[bodyIndex].indent
	for cursor := bodyIndex; cursor < len(lines); cursor++ {
		line := lines[cursor]
		if line.text == "" {
			continue
		}
		if line.indent != bodyIndent {
			return kubeflowUnsupported("unsupported_lexical_form"), nil
		}
		if line.text == "pass" {
			continue
		}

		if !strings.HasPrefix(line.text, "return ") {
			return kubeflowUnsupported("definition_body_unsupported"), nil
		}
		value := strings.TrimSpace(strings.TrimPrefix(line.text, "return "))
		if !kubeflowSimpleExpression(value) {
			return kubeflowUnsupported("definition_body_unsupported"), nil
		}
		if kubeflowContainsIdentifier(value, binding) {
			if kubeflowBindingRebound(line.text, binding) {
				return kubeflowUnsupported("binding_rebound"), nil
			}
			return kubeflowUnsupported("binding_dynamic_use"), nil
		}
	}
	return kubeflowKFPObservation{state: "declared", api: api}, nil
}

func kubeflowNextCode(lines []lexicalPythonLine, start int) int {
	for index := start; index < len(lines); index++ {
		if lines[index].text != "" {
			return index
		}
	}
	return -1
}

func kubeflowUnsupported(category string) kubeflowKFPObservation {
	return kubeflowKFPObservation{state: "unsupported", category: category}
}

func kubeflowDecoratorMatches(binding, api, value string) bool {
	if api == KubeflowKFPLegacyAPI {
		return value == "@"+binding
	}
	return value == "@"+binding+".component"
}

func kubeflowContainsIdentifier(line, identifier string) bool {
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

func kubeflowBindingRebound(line, binding string) bool {
	if strings.HasPrefix(line, "global ") || strings.HasPrefix(line, "nonlocal ") || strings.HasPrefix(line, "del ") || strings.HasPrefix(line, "for "+binding+" ") || strings.Contains(line, " as "+binding) || strings.HasPrefix(line, "case "+binding) {
		return true
	}
	index := strings.Index(line, "=")
	return index >= 0 && kubeflowContainsIdentifier(line[:index], binding)
}

var kubeflowIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var kubeflowDecimal = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)

func kubeflowSimpleIdentifier(value string) bool {
	return kubeflowIdentifier.MatchString(value) && !pythonReservedWord(value) && value != "__debug__"
}

func kubeflowParametersAdmitted(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}

	seen := make(map[string]bool)
	for _, parameter := range strings.Split(value, ",") {
		parameter = strings.TrimSpace(parameter)
		if !kubeflowSimpleIdentifier(parameter) || seen[parameter] {
			return false
		}
		seen[parameter] = true
	}
	return true
}

// kubeflowSimpleExpression admits only one masked string literal, a
// simple identifier, the three Python literal names, or a decimal number. It
// intentionally rejects calls, operators, attributes, collections, semicolons,
// and every expression form this lexical reader does not validate.
func kubeflowSimpleExpression(value string) bool {
	return value == lexicalStringLiteralMarker || value == "None" || value == "True" || value == "False" || kubeflowSimpleIdentifier(value) || kubeflowDecimal.MatchString(value)
}

func pythonReservedWord(value string) bool {
	switch value {
	case "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield":
		return true
	default:
		return false
	}
}
