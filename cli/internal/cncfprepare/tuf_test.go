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

func tufPreparedFact(t *testing.T, prepared TUFPrepared) map[string]any {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
		t.Fatal(err)
	}
	proposed := input["proposed"].(map[string]any)
	component := proposed["components"].([]any)[0].(map[string]any)
	return component["facts"].([]any)[0].(map[string]any)
}

func TestPrepareTUFUpdaterObservedGoLexicalCallShapes(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		present bool
	}{
		{"from-import-omitted", "from tuf.ngclient import Updater\nclient = Updater('/metadata', 'https://metadata.invalid/')\n", false},
		{"module-import-present", "import tuf.ngclient\nclient = tuf.ngclient.Updater(metadata_dir='/metadata', metadata_base_url='https://metadata.invalid/', bootstrap=root_bytes)\n", true},
		{"none-is-explicit-presence", "from tuf.ngclient import Updater\nclient = Updater(metadata_dir='/metadata', metadata_base_url='https://metadata.invalid/', bootstrap=None)\n", true},
		{"six-shared-positional", "from tuf.ngclient import Updater\nclient = Updater(a, b, c, d, e, f)\n", false},
		{"multiline-call", "from tuf.ngclient import Updater\nclient = Updater(\n    metadata_dir='/metadata',\n    metadata_base_url='https://metadata.invalid/',\n)\n", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTUFUpdater([]byte(test.source), TUFFrom, TUFTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonTUFUpdaterCallObserved || prepared.UnsupportedCategory != "" {
				t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
			}
			fact := tufPreparedFact(t, prepared)
			if fact["id"] != TUFBootstrapFact || fact["state"] != "declared" || fact["boolValue"] != test.present {
				t.Fatalf("fact = %#v", fact)
			}
			if prepared.SourceDigest != digestBytes([]byte(test.source)) || prepared.InputDigest != digestBytes(prepared.CanonicalInputJSON) || strings.Contains(string(prepared.CanonicalInputJSON), "metadata.invalid") || strings.Contains(string(prepared.CanonicalInputJSON), "root_bytes") {
				t.Fatalf("source or digest boundary failed: %#v", prepared)
			}
		})
	}
}

func TestPrepareTUFUpdaterObservationIndependentOfTuple(t *testing.T) {
	prepared, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\n"), "6.0.1", "7.0.1")
	if err != nil || prepared.State != StatePrepared || tufPreparedFact(t, prepared)["boolValue"] != false {
		t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
	}
}

func TestPrepareTUFUpdaterUnsupportedGoLexicalForms(t *testing.T) {
	tests := []struct{ name, source, category string }{
		{"alias", "from tuf.ngclient import Updater as U\nU('/m', 'https://x.invalid/')\n", "binding_missing"},
		{"conditional-import", "if enabled:\n    from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\n", "binding_missing"},
		{"competing-imports", "from tuf.ngclient import Updater\nimport tuf.ngclient\nUpdater('/m', 'https://x.invalid/')\n", "candidate_call_count"},
		{"rebound", "from tuf.ngclient import Updater\nUpdater = factory\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"candidate-binding-parameter", "from tuf.ngclient import Updater\ndef scope(Updater):\n    pass\nUpdater('/m', 'https://x.invalid/')\n", "candidate_call_count"},
		{"dynamic-reference", "from tuf.ngclient import Updater\nclient = Updater('/m', 'https://x.invalid/', bootstrap=Updater)\n", "binding_dynamic_use"},
		{"multiple-calls", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\nUpdater('/n', 'https://y.invalid/')\n", "candidate_call_count"},
		{"star-args", "from tuf.ngclient import Updater\nUpdater(*args)\n", "star_arguments"},
		{"star-kwargs", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', **options)\n", "star_arguments"},
		{"duplicate-keyword", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m', metadata_dir='/n', metadata_base_url='https://x.invalid/')\n", "duplicate_argument"},
		{"duplicate-positional-keyword", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', metadata_dir='/n')\n", "duplicate_argument"},
		{"positional-after-keyword", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m', 'https://x.invalid/')\n", "positional_after_keyword"},
		{"reserved-keyword-name", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m', metadata_base_url='https://x.invalid/', for=True)\n", "call_shape_unsupported"},
		{"reserved-assignment-target", "from tuf.ngclient import Updater\nfor = Updater('/m', 'https://x.invalid/')\n", "call_shape_unsupported"},
		{"debug-assignment-target", "from tuf.ngclient import Updater\n__debug__ = Updater('/m', 'https://x.invalid/')\n", "call_shape_unsupported"},
		{"compound-expression", "from tuf.ngclient import Updater\nUpdater('/m' + suffix, 'https://x.invalid/')\n", "call_shape_unsupported"},
		{"call-expression", "from tuf.ngclient import Updater\nUpdater(resolve(), 'https://x.invalid/')\n", "call_shape_unsupported"},
		{"unknown-keyword", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', future=True)\n", "unknown_keyword"},
		{"missing-required", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m')\n", "missing_required_argument"},
		{"v6-seventh-positional-bootstrap", "from tuf.ngclient import Updater\nUpdater(a, b, c, d, e, f, root_bytes)\n", "positional_bootstrap"},
		{"f-string", "from tuf.ngclient import Updater\nUpdater(f'{root}', 'https://x.invalid/')\n", "unsupported_lexical_form"},
		{"combined-raw-f-string", "from tuf.ngclient import Updater\nUpdater(rf'{root}', 'https://x.invalid/')\n", "unsupported_lexical_form"},
		{"escaped-string", `from tuf.ngclient import Updater
Updater("line\n", 'https://x.invalid/')
`, "unsupported_lexical_form"},
		{"decorator", "from tuf.ngclient import Updater\n@wrap\ndef make():\n    return Updater('/m', 'https://x.invalid/')\n", "candidate_call_count"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTUFUpdater([]byte(test.source), TUFFrom, TUFTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonTUFUpdaterCallUnsupported || prepared.UnsupportedCategory != test.category {
				t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
			}
			fact := tufPreparedFact(t, prepared)
			if fact["state"] != "unsupported" {
				t.Fatalf("fact = %#v", fact)
			}
			if _, exists := fact["boolValue"]; exists {
				t.Fatalf("unsupported fact contains boolValue: %#v", fact)
			}
		})
	}
}

func TestPrepareTUFUpdaterDoesNotExecuteSuppliedSource(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "must-not-exist")
	source := "from tuf.ngclient import Updater\nclient = Updater('/m', 'https://x.invalid/', bootstrap=open(" + strconvQuote(canary) + ", 'w').write('executed'))\n"
	prepared, err := PrepareTUFUpdater([]byte(source), TUFFrom, TUFTo)
	if err != nil || prepared.State != StateUnknown || prepared.UnsupportedCategory != "call_shape_unsupported" {
		t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
	}
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supplied source executed: %v", err)
	}
}

func TestPrepareTUFUpdaterErrors(t *testing.T) {
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\n\tUpdater('/m', 'https://x.invalid/')\n"), TUFFrom, TUFTo); !errors.Is(err, ErrTUFSourceParse) {
		t.Fatalf("tab indentation = %v", err)
	}
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater("), TUFFrom, TUFTo); !errors.Is(err, ErrTUFSourceParse) {
		t.Fatalf("syntax error = %v", err)
	}
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/' ]\n"), TUFFrom, TUFTo); !errors.Is(err, ErrTUFSourceParse) {

		t.Fatalf("mismatched delimiter = %v", err)
	}
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\x00\nUpdater('/m', 'https://x.invalid/')\n"), TUFFrom, TUFTo); !errors.Is(err, ErrTUFSourceParse) {
		t.Fatalf("control byte = %v", err)
	}
}

func strconvQuote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
