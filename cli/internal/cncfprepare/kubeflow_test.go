// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func kubeflowPreparedFact(t *testing.T, prepared KubeflowKFPPrepared) map[string]any {
	t.Helper()
	var input map[string]any
	if json.Unmarshal(prepared.CanonicalInputJSON, &input) != nil {
		t.Fatal("canonical input did not decode")
	}
	component := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)
	return component["facts"].([]any)[0].(map[string]any)
}

func TestPrepareKubeflowKFPObservedFormsAndStableProjection(t *testing.T) {
	tests := []struct{ name, source, value string }{
		{"legacy", "from kfp.components import create_component_from_func\n@create_component_from_func\ndef build_component():\n    return 'PRIVATE'\n", KubeflowKFPLegacyAPI},
		{"modern", "from kfp import dsl\n@dsl.component\ndef build_component():\n    return 'PRIVATE'\n", KubeflowKFPV2API},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeflowKFP([]byte(test.source), KubeflowKFPFrom, KubeflowKFPTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKubeflowKFPAuthoringAPIObserved || prepared.UnsupportedCategory != "" {
				t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
			}
			fact := kubeflowPreparedFact(t, prepared)
			if fact["id"] != KubeflowKFPFact || fact["state"] != "declared" || fact["enumValue"] != test.value {
				t.Fatalf("fact = %#v", fact)
			}
			variant := strings.Replace(test.source, "'PRIVATE'", "'OTHER'", 1)
			other, err := PrepareKubeflowKFP([]byte(variant), "1.8.21", "2.0.1")
			if err != nil || !strings.Contains(string(other.CanonicalInputJSON), test.value) || other.InputDigest == prepared.InputDigest || other.SourceDigest == prepared.SourceDigest {
				t.Fatalf("tuple/source projection = %#v, %v", other, err)
			}
			// With the same tuple, irrelevant source changes preserve the minimized input.
			other, err = PrepareKubeflowKFP([]byte(variant), KubeflowKFPFrom, KubeflowKFPTo)
			if err != nil || other.InputDigest != prepared.InputDigest || other.SourceDigest == prepared.SourceDigest {
				t.Fatalf("stable projection = %#v, %v", other, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "PRIVATE") || strings.Contains(string(prepared.CanonicalInputJSON), "build_component") {
				t.Fatal("private source leaked into canonical input")
			}
		})
	}
	legacy, _ := PrepareKubeflowKFP([]byte(tests[0].source), KubeflowKFPFrom, KubeflowKFPTo)
	modern, _ := PrepareKubeflowKFP([]byte(tests[1].source), KubeflowKFPFrom, KubeflowKFPTo)
	if legacy.InputDigest == modern.InputDigest {
		t.Fatal("legacy and modern observations must remain distinct")
	}
}

func TestPrepareKubeflowKFPUnsupportedShapes(t *testing.T) {
	tests := []struct{ name, source, category string }{
		{"alias", "from kfp.components import create_component_from_func as make\n@make\ndef c():\n    pass\n", "binding_missing"},
		{"mixed", "from kfp.components import create_component_from_func\nfrom kfp import dsl\n@create_component_from_func\ndef c():\n    pass\n", "unsupported_lexical_form"},
		{"rebound", "from kfp import dsl\ndsl = other\n@dsl.component\ndef c():\n    pass\n", "unsupported_lexical_form"},
		{"dynamic", "from kfp import dsl\nprint(dsl)\n@dsl.component\ndef c():\n    pass\n", "unsupported_lexical_form"},
		{"decorator-call", "from kfp import dsl\n@dsl.component()\ndef c():\n    pass\n", "unsupported_lexical_form"},
		{"multiple", "from kfp import dsl\n@dsl.component\ndef a():\n    pass\n@dsl.component\ndef b():\n    pass\n", "unsupported_lexical_form"},
		{"extra-decorator", "from kfp import dsl\n@other\n@dsl.component\ndef c():\n    pass\n", "unsupported_lexical_form"},
		{"async", "from kfp import dsl\n@dsl.component\nasync def c():\n    pass\n", "definition_shape_unsupported"},
		{"direct-factory", "from kfp.components import create_component_from_func\ndef c():\n    pass\nx = create_component_from_func(c)\n", "unsupported_lexical_form"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeflowKFP([]byte(test.source), KubeflowKFPFrom, KubeflowKFPTo)
			if err != nil || prepared.State != StateUnknown || prepared.UnsupportedCategory != test.category || kubeflowPreparedFact(t, prepared)["state"] != "unsupported" {
				t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
			}
		})
	}
}

func TestPrepareKubeflowKFPDoesNotExecuteSourceAndSeparatesSetupErrors(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "must-not-exist")
	source := "from kfp import dsl\n@dsl.component\ndef c():\n    return open(" + strconvQuote(canary) + ", 'w').write('executed')\n"
	prepared, err := PrepareKubeflowKFP([]byte(source), KubeflowKFPFrom, KubeflowKFPTo)
	if err != nil || prepared.State != StateUnknown || prepared.UnsupportedCategory != "definition_body_unsupported" {
		t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
	}
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supplied source executed: %v", err)
	}
	if _, err := PrepareKubeflowKFP([]byte("from kfp import dsl\n@dsl.component\ndef c("), KubeflowKFPFrom, KubeflowKFPTo); !errors.Is(err, ErrKubeflowKFPSourceParse) {
		t.Fatalf("syntax error = %v", err)
	}
}

func TestPrepareKubeflowKFPGoLexerTreatsCommentsAndStringsAsOpaque(t *testing.T) {
	source := `# direct import and decorator comments are ignored
from kfp import dsl  # the only admitted binding
@dsl.component  # one bare decorator
def component():
    return "literal"
`
	prepared, err := PrepareKubeflowKFP([]byte(source), KubeflowKFPFrom, KubeflowKFPTo)
	if err != nil || prepared.State != StatePrepared || prepared.UnsupportedCategory != "" {
		t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), "documentation") {
		t.Fatal("opaque source text crossed the minimized input")
	}
}

func TestPrepareKubeflowKFPGoLexerKeepsNonGrammarFormsUnknown(t *testing.T) {
	tests := []struct {
		name, source, category string
		parse                  bool
	}{
		{"conditional import", "if enabled:\n    from kfp import dsl\n@dsl.component\ndef c():\n    pass\n", "binding_missing", false},
		{"nested decorator", "from kfp import dsl\ndef outer():\n    @dsl.component\n    def c():\n    pass\n", "unsupported_lexical_form", false},
		{"candidate parameter shadows binding", "from kfp import dsl\n@dsl.component\ndef c(dsl):\n    pass\n", "binding_rebound", false},
		{"candidate name shadows binding", "from kfp import dsl\n@dsl.component\ndef dsl():\n    pass\n", "definition_shape_unsupported", false},
		{"f string expression", "from kfp import dsl\n@dsl.component\ndef c():\n    return f'{dsl}'\n", "unsupported_lexical_form", false},
		{"combined raw f string", "from kfp import dsl\n@dsl.component\ndef c():\n    return rf'{dsl}'\n", "unsupported_lexical_form", false},
		{"escaped string", `from kfp import dsl
@dsl.component
def c():
    return "line\n"
`, "unsupported_lexical_form", false},
		{"inline suite", "from kfp import dsl\n@dsl.component\ndef c(): pass\n", "definition_shape_unsupported", false},
		{"invalid parameter default", "from kfp import dsl\n@dsl.component\ndef c(value=1):\n    pass\n", "definition_shape_unsupported", false},
		{"reserved parameter", "from kfp import dsl\n@dsl.component\ndef c(for):\n    pass\n", "definition_shape_unsupported", false},
		{"debug parameter", "from kfp import dsl\n@dsl.component\ndef c(__debug__):\n    pass\n", "definition_shape_unsupported", false},
		{"tab indentation", "from kfp import dsl\n@dsl.component\ndef c():\n\tpass\n", "", true},
		{"quoted parameter is not an identifier", "from kfp import dsl\n@dsl.component\ndef c('name'):\n    pass\n", "definition_shape_unsupported", false},
		{"quoted function name is not an identifier", "from kfp import dsl\n@dsl.component\ndef 'component'():\n    pass\n", "definition_shape_unsupported", false},
		{"duplicate parameters", "from kfp import dsl\n@dsl.component\ndef c(value, value):\n    pass\n", "definition_shape_unsupported", false},
		{"reserved function name", "from kfp import dsl\n@dsl.component\ndef class():\n    pass\n", "definition_shape_unsupported", false},
		{"compound return", "from kfp import dsl\n@dsl.component\ndef c():\n    return value; other\n", "definition_body_unsupported", false},
		{"call return", "from kfp import dsl\n@dsl.component\ndef c():\n    return build(value)\n", "definition_body_unsupported", false},
		{"missing body", "from kfp import dsl\n@dsl.component\ndef c():\n", "definition_body_unsupported", false},
		{"unsupported body statement", "from kfp import dsl\n@dsl.component\ndef c():\n    yield value\n", "definition_body_unsupported", false},
		{"top level after definition", "from kfp import dsl\n@dsl.component\ndef c():\n    pass\nvalue = 1\n", "unsupported_lexical_form", false},
		{"decorator before import", "@dsl.component\ndef c():\n    pass\nfrom kfp import dsl\n", "binding_missing", false},
		{"mismatched brackets", "from kfp import dsl\n@dsl.component\ndef c([):\n    pass\n", "", true},
		{"unbalanced source", "from kfp import dsl\n@dsl.component\ndef c(:\n", "", true},
		{"source control byte", "from kfp import dsl\x00\n@dsl.component\ndef c():\n    pass\n", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeflowKFP([]byte(test.source), KubeflowKFPFrom, KubeflowKFPTo)
			if test.parse {
				if !errors.Is(err, ErrKubeflowKFPSourceParse) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || prepared.State != StateUnknown || prepared.UnsupportedCategory != test.category {
				t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
			}
		})
	}
}
